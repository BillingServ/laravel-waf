package bsrbl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxEntries = 10000
const maxStateBytes = 16 << 20

var errInvalidReport = errors.New("BSRBL rejected an invalid report")

type entry struct {
	IP           string `json:"ip"`
	Reason       string `json:"reason"`
	LocalExpires int64  `json:"local_expires_at"`
	QueuedAt     int64  `json:"queued_at"`
}

type deliveryState struct {
	Version     int              `json:"version"`
	Destination string           `json:"destination"`
	Pending     map[string]entry `json:"pending"`
	Sent        map[string]int64 `json:"sent"`
	NextAttempt int64            `json:"next_attempt"`
}

type Options struct {
	Settings  func() (Settings, error)
	StateFile string
	Client    *http.Client
	Logger    *log.Logger
}

// Reporter sends network requests in its background Run loop. Report only
// records a private, durable outbox entry after the firewall accepted a ban.
type Reporter struct {
	mu       sync.Mutex
	state    deliveryState
	path     string
	settings func() (Settings, error)
	client   *http.Client
	logger   *log.Logger
	wake     chan struct{}
	warnAt   time.Time
}

func New(options Options) (*Reporter, error) {
	if options.Settings == nil || !filepath.IsAbs(options.StateFile) {
		return nil, errors.New("BSRBL requires settings and an absolute state path")
	}
	client := http.Client{Timeout: 5 * time.Second}
	if options.Client != nil {
		client = *options.Client
		if client.Timeout <= 0 || client.Timeout > 5*time.Second {
			client.Timeout = 5 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	r := &Reporter{
		path: options.StateFile, settings: options.Settings, client: &client,
		logger: options.Logger, wake: make(chan struct{}, 1),
		state: deliveryState{Version: 1, Pending: map[string]entry{}, Sent: map[string]int64{}},
	}
	body, err := readRegular(r.path, maxStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil || json.Unmarshal(body, &r.state) != nil || r.state.Version != 1 || r.state.Pending == nil || r.state.Sent == nil || len(r.state.Pending) > maxEntries || len(r.state.Sent) > maxEntries {
		return nil, errors.New("invalid BSRBL delivery state; existing data was not reset")
	}
	for ip, record := range r.state.Pending {
		address, valid := reportAddress(net.ParseIP(ip))
		if !valid || address != ip || record.IP != ip || !reasonPattern.MatchString(record.Reason) || record.LocalExpires < 1 || record.QueuedAt < 1 {
			return nil, errors.New("invalid BSRBL pending entry")
		}
	}
	for ip, until := range r.state.Sent {
		address, valid := reportAddress(net.ParseIP(ip))
		if !valid || address != ip || until < 1 {
			return nil, errors.New("invalid BSRBL acknowledgement")
		}
	}
	return r, nil
}

func (r *Reporter) Report(ip net.IP, expiresAt time.Time, reason string) error {
	settings, err := r.settings()
	if err != nil || settings.validate() != nil {
		return errors.New("invalid BSRBL settings")
	}
	if !settings.Enabled {
		return nil
	}
	address, valid := reportAddress(ip)
	if !valid || protectedProxy(address) {
		return nil
	}
	if !reasonPattern.MatchString(reason) || expiresAt.Unix() < 1 {
		return errors.New("invalid BSRBL report")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bindLocked(settings.URL)
	now := time.Now()
	r.pruneLocked(now.Unix())
	if r.state.Sent[address] > now.Unix() {
		return nil
	}
	if _, exists := r.state.Pending[address]; exists {
		r.signal()
		return nil
	}
	if len(r.state.Pending) >= maxEntries {
		return errors.New("BSRBL outbox capacity reached")
	}
	r.state.Pending[address] = entry{IP: address, Reason: reason, LocalExpires: expiresAt.Unix(), QueuedAt: now.UnixNano()}
	err = r.saveLocked()
	r.signal()
	return err
}

func (r *Reporter) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		r.deliver(ctx)
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-ticker.C:
		}
	}
}

func (r *Reporter) deliver(ctx context.Context) {
	settings, err := r.settings()
	if err != nil || settings.validate() != nil {
		r.warn("BSRBL configuration invalid; reporting paused")
		return
	}
	if !settings.Enabled {
		return
	}
	r.mu.Lock()
	r.bindLocked(settings.URL)
	if r.state.NextAttempt > time.Now().UnixNano() {
		r.mu.Unlock()
		return
	}
	var selected entry
	for ip, candidate := range r.state.Pending {
		if protectedProxy(ip) {
			delete(r.state.Pending, ip)
			continue
		}
		if selected.IP == "" || candidate.QueuedAt < selected.QueuedAt || (candidate.QueuedAt == selected.QueuedAt && candidate.IP < selected.IP) {
			selected = candidate
		}
	}
	r.mu.Unlock()
	if selected.IP == "" {
		return
	}
	err = r.post(ctx, settings, selected)
	if ctx.Err() != nil {
		return
	}
	r.mu.Lock()
	// Configuration may have changed while a request was in flight.
	if r.state.Destination != settings.URL {
		r.mu.Unlock()
		return
	}
	if err != nil {
		if errors.Is(err, errInvalidReport) {
			delete(r.state.Pending, selected.IP)
			r.state.NextAttempt = time.Now().Add(time.Second).UnixNano()
			_ = r.saveLocked()
			r.mu.Unlock()
			r.warn("BSRBL rejected an invalid report; other queued reports will continue")
			return
		}
		r.state.NextAttempt = time.Now().Add(time.Minute).UnixNano()
		_ = r.saveLocked()
		r.mu.Unlock()
		r.warn("BSRBL delivery failed; queued reports will retry")
		return
	}
	delete(r.state.Pending, selected.IP)
	r.pruneLocked(time.Now().Unix())
	if len(r.state.Sent) >= maxEntries {
		var oldest string
		for ip, until := range r.state.Sent {
			if oldest == "" || until < r.state.Sent[oldest] {
				oldest = ip
			}
		}
		delete(r.state.Sent, oldest)
	}
	r.state.Sent[selected.IP] = max(time.Now().Add(24*time.Hour).Unix(), selected.LocalExpires)
	// At most about 60 requests/minute, below BSRBL's per-key report limit.
	r.state.NextAttempt = time.Now().Add(time.Second).UnixNano()
	saveErr := r.saveLocked()
	r.mu.Unlock()
	if saveErr != nil {
		r.warn("BSRBL acknowledgement could not be saved")
	}
	if r.logger != nil {
		r.logger.Printf("BSRBL report acknowledged ip=%s", selected.IP)
	}
}

func (r *Reporter) post(ctx context.Context, settings Settings, record entry) error {
	body, _ := json.Marshal(struct {
		IP        string `json:"ip"`
		Reason    string `json:"reason"`
		ExpiresAt *int64 `json:"expires_at"`
	}{IP: record.IP, Reason: record.Reason})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.URL+"/api/v1/reports", bytes.NewReader(body))
	if err != nil {
		return errors.New("BSRBL request failed")
	}
	request.Header.Set("Authorization", "Bearer "+settings.APIKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "LWAF-BSRBL/1.0")
	response, err := r.client.Do(request)
	if err != nil {
		return errors.New("BSRBL request failed")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnprocessableEntity {
		return errInvalidReport
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(data) > 16384 || response.StatusCode != http.StatusOK {
		return errors.New("BSRBL report rejected")
	}
	var result struct {
		Status string `json:"status"`
		IP     string `json:"ip"`
		Result string `json:"result"`
	}
	if json.Unmarshal(data, &result) != nil || result.Status != "ok" || result.IP != record.IP || (result.Result != "accepted" && result.Result != "unchanged" && result.Result != "protected") {
		return errors.New("BSRBL acknowledgement invalid")
	}
	return nil
}

func (r *Reporter) bindLocked(destination string) {
	if r.state.Destination != destination {
		r.state = deliveryState{Version: 1, Destination: destination, Pending: map[string]entry{}, Sent: map[string]int64{}}
	}
}

func (r *Reporter) pruneLocked(now int64) {
	for ip, until := range r.state.Sent {
		if until <= now {
			delete(r.state.Sent, ip)
		}
	}
}

func (r *Reporter) signal() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *Reporter) warn(message string) {
	r.mu.Lock()
	if time.Now().Before(r.warnAt) {
		r.mu.Unlock()
		return
	}
	r.warnAt = time.Now().Add(time.Minute)
	r.mu.Unlock()
	if r.logger != nil {
		r.logger.Print(message)
	}
}

func (r *Reporter) saveLocked() error {
	body, err := json.Marshal(r.state)
	if err != nil || len(body) > maxStateBytes {
		return errors.New("BSRBL state size limit exceeded")
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(r.path), ".bsrbl-")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	if err := temporary.Chmod(0600); err != nil {
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), r.path)
}

func reportAddress(ip net.IP) (string, bool) {
	address, valid := netip.AddrFromSlice(ip)
	if !valid {
		return "", false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return "", false
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(address) {
			return "", false
		}
	}
	return address.String(), true
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001:db8::/32"),
}
