package bsrbl

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestReporter(t *testing.T, host *httptest.Server, state string) *Reporter {
	t.Helper()
	r, err := New(Options{Settings: func() (Settings, error) { return Settings{Enabled: true, URL: host.URL, APIKey: testKey()}, nil }, StateFile: state, Client: host.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func acknowledge(w http.ResponseWriter, req *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	_ = json.NewDecoder(req.Body).Decode(&body)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "ip": body.IP, "result": "accepted"})
}

func TestReportingUsesBackgroundHTTPAndDurablePrivateState(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)
	host := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v1/reports" || req.Method != "POST" || req.Header.Get("Authorization") != "Bearer "+testKey() {
			t.Error("incorrect authenticated reporting request")
		}
		body, _ := io.ReadAll(req.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		if payload["ip"] != "38.244.29.125" || payload["reason"] != "sig:env-vcs-probe" || payload["expires_at"] != nil || len(payload) != 3 {
			t.Errorf("incorrect report body: %s", body)
		}
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-req.Context().Done():
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","ip":"38.244.29.125","result":"accepted"}`))
	}))
	defer host.Close()
	path := filepath.Join(t.TempDir(), "outbox.json")
	r := newTestReporter(t, host, path)
	if err := r.Report(net.ParseIP("38.244.29.125"), time.Now().Add(time.Hour), "sig:env-vcs-probe"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil || bytes.Contains(body, []byte(testKey())) {
		t.Fatal("outbox missing or contains API key")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("outbox permissions are not private")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("report was not sent on wake")
	}
	// A stalled HTTP request must not hold the enqueue lock or delay another ban.
	queued := make(chan error, 1)
	go func() { queued <- r.Report(net.ParseIP("93.184.216.21"), time.Now().Add(time.Hour), "rate_limit") }()
	select {
	case err := <-queued:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queue waited on the network")
	}
}

func TestFailedReportsSurviveRestartAndLocalExpiry(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var requests atomic.Int32
	host := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		if fail.Load() {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(testKey()))
			return
		}
		acknowledge(w, req)
	}))
	defer host.Close()
	path := filepath.Join(t.TempDir(), "outbox.json")
	r := newTestReporter(t, host, path)
	var logs bytes.Buffer
	r.logger = log.New(&logs, "", 0)
	if err := r.Report(net.ParseIP("38.244.29.125"), time.Now().Add(-time.Hour), "sig:env-vcs-probe"); err != nil {
		t.Fatal(err)
	}
	r.deliver(context.Background())
	if strings.Contains(logs.String(), testKey()) {
		t.Fatal("provider response leaked a key")
	}
	r2 := newTestReporter(t, host, path)
	if len(r2.state.Pending) != 1 {
		t.Fatal("failed report was not retained")
	}
	r2.state.NextAttempt = 0
	fail.Store(false)
	r2.deliver(context.Background())
	r3 := newTestReporter(t, host, path)
	if len(r3.state.Pending) != 0 || r3.state.Sent["38.244.29.125"] <= time.Now().Unix() {
		t.Fatal("accepted report was not acknowledged")
	}
	if err := r3.Report(net.ParseIP("38.244.29.125"), time.Now().Add(time.Hour), "sig:env-vcs-probe"); err != nil {
		t.Fatal(err)
	}
	if len(r3.state.Pending) != 0 || requests.Load() != 2 {
		t.Fatal("acknowledged report was queued twice")
	}
}

func TestReporterRejectsRedirectsAndInvalidAcknowledgements(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { redirected.Add(1); acknowledge(w, req) }))
	defer target.Close()
	for _, mode := range []string{"redirect", "wrong-ip", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			host := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, req, target.URL, 302)
				case "wrong-ip":
					_, _ = w.Write([]byte(`{"status":"ok","ip":"8.8.8.8","result":"accepted"}`))
				case "oversized":
					_, _ = w.Write([]byte(strings.Repeat("x", 16385)))
				}
			}))
			defer host.Close()
			r := newTestReporter(t, host, filepath.Join(t.TempDir(), "outbox.json"))
			_ = r.Report(net.ParseIP("38.244.29.125"), time.Now().Add(time.Hour), "manual")
			r.deliver(context.Background())
			if len(r.state.Pending) != 1 || len(r.state.Sent) != 0 {
				t.Fatal("invalid response acknowledged a report")
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("followed a redirect with credentials")
	}
}

func TestReporterFiltersProxyPrivateAndDocumentationAddresses(t *testing.T) {
	r, err := New(Options{Settings: func() (Settings, error) {
		return Settings{Enabled: true, URL: "https://rbl.example", APIKey: testKey()}, nil
	}, StateFile: filepath.Join(t.TempDir(), "outbox.json")})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"172.64.198.63", "172.64.198.149", "::ffff:172.64.198.63", "2606:4700::1234", "10.0.0.1", "127.0.0.1", "::1", "224.0.0.1", "203.0.113.1", "2001:db8::1"} {
		if err := r.Report(net.ParseIP(ip), time.Now().Add(time.Hour), "manual"); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.state.Pending) != 0 {
		t.Fatal("queued a protected or non-public address")
	}
	for _, ip := range []string{"38.244.29.125", "::ffff:93.184.216.21", "2001:4860:4860::8888"} {
		if err := r.Report(net.ParseIP(ip), time.Now().Add(time.Hour), "manual"); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.state.Pending) != 3 || r.state.Pending["93.184.216.21"].IP != "93.184.216.21" {
		t.Fatal("public or mapped address was not normalized")
	}
}

func TestReporterConcurrentEnqueueAndCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.json")
	r, err := New(Options{Settings: func() (Settings, error) {
		return Settings{Enabled: true, URL: "https://rbl.example", APIKey: testKey()}, nil
	}, StateFile: path})
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 1; i <= 25; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			ip := net.IPv4(93, 184, 216, byte(i))
			if err := r.Report(ip, time.Now().Add(time.Hour), "manual"); err != nil {
				t.Error(err)
			}
		}(i)
	}
	group.Wait()
	reloaded, err := New(Options{Settings: r.settings, StateFile: path})
	if err != nil || len(reloaded.state.Pending) != 25 {
		t.Fatalf("concurrent reports lost: %v", err)
	}
	if err := os.WriteFile(path, []byte("{corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Settings: r.settings, StateFile: path}); err == nil {
		t.Fatal("corrupt state silently reset")
	}
	body, _ := os.ReadFile(path)
	if string(body) != "{corrupt" {
		t.Fatal("corrupt state overwritten")
	}
}

func TestReporterHotDisablingAndDestinationChange(t *testing.T) {
	settings := Settings{Enabled: true, URL: "https://one.example", APIKey: testKey()}
	r, err := New(Options{Settings: func() (Settings, error) { return settings, nil }, StateFile: filepath.Join(t.TempDir(), "outbox.json")})
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Report(net.ParseIP("38.244.29.125"), time.Now().Add(time.Hour), "manual")
	settings.Enabled = false
	_ = r.Report(net.ParseIP("93.184.216.21"), time.Now().Add(time.Hour), "manual")
	if len(r.state.Pending) != 1 {
		t.Fatal("disabled reporting queued a new IP")
	}
	settings.Enabled = true
	settings.URL = "https://two.example"
	_ = r.Report(net.ParseIP("93.184.216.21"), time.Now().Add(time.Hour), "manual")
	if len(r.state.Pending) != 1 || r.state.Pending["38.244.29.125"].IP != "" {
		t.Fatal("old destination reports leaked to new destination")
	}
}

func TestInvalidReportDoesNotBlockTheOutbox(t *testing.T) {
	host := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer host.Close()
	r := newTestReporter(t, host, filepath.Join(t.TempDir(), "outbox.json"))
	_ = r.Report(net.ParseIP("38.244.29.125"), time.Now().Add(time.Hour), "manual")
	r.deliver(context.Background())
	if len(r.state.Pending) != 0 || len(r.state.Sent) != 0 {
		t.Fatal("invalid report stayed queued or was marked accepted")
	}
}
