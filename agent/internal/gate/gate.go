package gate

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/metrics"
)

const (
	DefaultClientThreshold = 60
	DefaultBlockTTLSeconds = 900

	clientIPHeader    = "X-Laravel-Waf-Client-IP"
	originalURIHeader = "X-Laravel-Waf-Original-URI"
	maxTrackedClients = 65536
)

type Blocker interface {
	Block(context.Context, net.IP, int, string) error
}

type Config struct {
	Threshold       uint64
	ClientThreshold uint64
	Window          time.Duration
	BlockTTLSeconds int
	CookieName      string
	ChallengeSecret []byte
	MarkerToken     string
	BypassPrefixes  []string
	Methods         []string
}

type Handler struct {
	config  Config
	metrics *metrics.Registry
	blocker Blocker
	now     func() time.Time

	mu            sync.Mutex
	windowStarted time.Time
	requests      uint64
	clients       map[string]clientWindow
	clientPaths   map[string]uint64
	blockedUntil  map[string]time.Time
}

type clientWindow struct {
	requests       uint64
	blockAttempted bool
}

type hitResult struct {
	requests       uint64
	clientLimited  bool
	retryAfter     string
	blockAttempted bool
	alreadyBlocked bool
}

type passPayload struct {
	Kind      string `json:"kind"`
	IP        string `json:"ip"`
	Version   int    `json:"version"`
	ExpiresAt int64  `json:"expires_at"`
}

func NewHandler(config Config, registry *metrics.Registry, blocker Blocker) (*Handler, error) {
	if config.Threshold < 1 {
		return nil, &configError{"threshold must be at least 1"}
	}
	if config.Window < time.Second || config.Window > time.Hour {
		return nil, &configError{"window must be between 1s and 1h"}
	}
	if config.ClientThreshold > 0 {
		if config.ClientThreshold > ^uint64(0)/2 {
			return nil, &configError{"client threshold is too large"}
		}
		if blocker == nil {
			return nil, &configError{"client blocking requires a blocker"}
		}
		if config.BlockTTLSeconds < 1 || config.BlockTTLSeconds > 86400 {
			return nil, &configError{"block TTL must be between 1 and 86400 seconds"}
		}
	}
	if len(config.ChallengeSecret) < 32 {
		return nil, &configError{"challenge secret must contain at least 32 bytes"}
	}
	if !validMarkerToken(config.MarkerToken) {
		return nil, &configError{"gate marker token must contain between 32 and 256 safe bytes"}
	}
	if !validCookieName(config.CookieName) {
		return nil, &configError{"invalid challenge cookie name"}
	}
	if registry == nil {
		return nil, &configError{"metrics registry is required"}
	}

	methods := make([]string, 0, len(config.Methods))
	for _, method := range config.Methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "" {
			methods = append(methods, method)
		}
	}
	if len(methods) == 0 {
		methods = []string{http.MethodGet, http.MethodHead}
	}
	config.Methods = methods

	bypassPrefixes := make([]string, 0, len(config.BypassPrefixes))
	for _, prefix := range config.BypassPrefixes {
		prefix = strings.TrimRight(strings.TrimSpace(prefix), "/")
		if prefix == "" || prefix == "/" || !strings.HasPrefix(prefix, "/") || strings.HasPrefix(prefix, "//") || len(prefix) > 256 || strings.ContainsAny(prefix, "?\r\n") {
			return nil, &configError{"invalid gate bypass prefix"}
		}
		bypassPrefixes = append(bypassPrefixes, prefix)
	}
	config.BypassPrefixes = bypassPrefixes

	return &Handler{
		config:       config,
		metrics:      registry,
		blocker:      blocker,
		now:          time.Now,
		clients:      make(map[string]clientWindow),
		clientPaths:  make(map[string]uint64),
		blockedUntil: make(map[string]time.Time),
	}, nil
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/gate" {
		http.NotFound(response, request)
		return
	}

	ip := net.ParseIP(strings.TrimSpace(request.Header.Get(clientIPHeader)))
	if ip == nil {
		h.metrics.Gate("invalid")
		http.Error(response, "invalid gate request", http.StatusBadRequest)
		return
	}

	originalPath := requestPath(request.Header.Get(originalURIHeader))
	if originalPath == "" {
		h.metrics.Gate("invalid")
		http.Error(response, "invalid original URI", http.StatusBadRequest)
		return
	}

	if h.bypassed(originalPath) {
		h.metrics.Gate("bypassed")
		response.WriteHeader(http.StatusNoContent)
		return
	}

	now := h.now()
	passed := h.passed(request, ip, now)
	hit := h.hit(now, ip.String(), originalPath, !passed)
	if hit.alreadyBlocked {
		h.deny(response, hit.retryAfter, "blocked")
		return
	}
	if passed {
		h.metrics.Gate("allowed")
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if hit.clientLimited {
		outcome := "rate_blocked"
		if hit.blockAttempted {
			operationContext, cancel := context.WithTimeout(context.Background(), time.Second)
			err := h.blocker.Block(operationContext, ip, h.config.BlockTTLSeconds, "gate_rate_limit")
			cancel()
			if err != nil {
				outcome = "rate_block_error"
			} else {
				h.markBlocked(ip.String(), now.Add(time.Duration(h.config.BlockTTLSeconds)*time.Second))
			}
		}

		h.deny(response, strconv.Itoa(h.config.BlockTTLSeconds), outcome)
		return
	}
	if hit.requests <= h.config.Threshold {
		h.metrics.Gate("allowed")
		response.WriteHeader(http.StatusNoContent)
		return
	}

	if !h.challengeMethod(request.Header.Get("X-Laravel-Waf-Original-Method")) {
		h.metrics.Gate("allowed_method")
		response.WriteHeader(http.StatusNoContent)
		return
	}

	h.metrics.Gate("challenged")
	response.Header().Set("X-Laravel-Waf-Challenge", "required")
	response.Header().Set("X-Laravel-Waf-Gate", h.config.MarkerToken)
	response.Header().Set("Retry-After", hit.retryAfter)
	response.WriteHeader(http.StatusForbidden)
}

func (h *Handler) hit(now time.Time, ip, path string, trackClient bool) hitResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.windowStarted.IsZero() || !now.Before(h.windowStarted.Add(h.config.Window)) {
		h.windowStarted = now
		h.requests = 0
		h.clients = make(map[string]clientWindow)
		h.clientPaths = make(map[string]uint64)
		for blockedIP, expiresAt := range h.blockedUntil {
			if !now.Before(expiresAt) {
				delete(h.blockedUntil, blockedIP)
			}
		}
	}
	if expiresAt, ok := h.blockedUntil[ip]; ok && now.Before(expiresAt) {
		return hitResult{
			retryAfter:     roundedSeconds(expiresAt.Sub(now)),
			alreadyBlocked: true,
		}
	}

	h.requests++

	remaining := h.windowStarted.Add(h.config.Window).Sub(now)
	result := hitResult{
		requests:   h.requests,
		retryAfter: roundedSeconds(remaining),
	}
	if !trackClient || h.config.ClientThreshold == 0 {
		return result
	}

	client, exists := h.clients[ip]
	if !exists && len(h.clients) >= maxTrackedClients {
		return result
	}
	client.requests++
	pathKey := clientPathKey(ip, path)
	pathRequests, pathExists := h.clientPaths[pathKey]
	if pathExists || len(h.clientPaths) < maxTrackedClients {
		pathRequests++
		h.clientPaths[pathKey] = pathRequests
	}
	result.clientLimited = client.requests > h.config.ClientThreshold*2 || pathRequests > h.config.ClientThreshold
	if result.clientLimited && !client.blockAttempted {
		client.blockAttempted = true
		result.blockAttempted = true
	}
	h.clients[ip] = client

	return result
}

func clientPathKey(ip, path string) string {
	digest := sha256.Sum256([]byte(path))

	return ip + ":" + hex.EncodeToString(digest[:])
}

func (h *Handler) markBlocked(ip string, expiresAt time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.blockedUntil[ip]; exists || len(h.blockedUntil) < maxTrackedClients {
		h.blockedUntil[ip] = expiresAt
	}
}

func (h *Handler) ObserveBlock(ip net.IP, expiresAt time.Time) {
	if ip == nil || !h.now().Before(expiresAt) {
		return
	}

	h.markBlocked(ip.String(), expiresAt)
}

func (h *Handler) ObserveUnblock(ip net.IP) {
	if ip == nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.blockedUntil, ip.String())
}

func (h *Handler) deny(response http.ResponseWriter, retryAfter, outcome string) {
	h.metrics.Gate(outcome)
	response.Header().Set("X-Laravel-Waf-Blocked", "true")
	response.Header().Set("Retry-After", retryAfter)
	response.WriteHeader(http.StatusUnauthorized)
}

func roundedSeconds(duration time.Duration) string {
	seconds := int64(duration / time.Second)
	if duration%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}

	return strconv.FormatInt(seconds, 10)
}

func (h *Handler) passed(request *http.Request, ip net.IP, now time.Time) bool {
	cookie, err := request.Cookie(h.config.CookieName)
	if err != nil || cookie.Value == "" || len(cookie.Value) > 4096 {
		return false
	}

	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 || len(parts[1]) != 64 {
		return false
	}
	signature, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}

	digest := hmac.New(sha256.New, h.config.ChallengeSecret)
	_, _ = digest.Write([]byte(parts[0]))
	if !hmac.Equal(signature, digest.Sum(nil)) {
		return false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var payload passPayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return false
	}

	payloadIP := net.ParseIP(payload.IP)

	return payload.Version == 1 && payload.Kind == "pass" && payloadIP != nil && payloadIP.Equal(ip) && payload.ExpiresAt >= now.Unix()
}

func (h *Handler) bypassed(path string) bool {
	for _, prefix := range h.config.BypassPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}

	return false
}

func (h *Handler) challengeMethod(method string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, allowed := range h.config.Methods {
		if method == allowed {
			return true
		}
	}

	return false
}

func requestPath(originalURI string) string {
	if originalURI == "" || len(originalURI) > 4096 || strings.ContainsAny(originalURI, "\r\n") {
		return ""
	}
	parsed, err := url.ParseRequestURI(originalURI)
	if err != nil || parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") {
		return ""
	}

	return parsed.Path
}

func validCookieName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' {
			return false
		}
	}

	return true
}

func validMarkerToken(token string) bool {
	if len(token) < 32 || len(token) > 256 {
		return false
	}
	for _, character := range []byte(token) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}

	return true
}

type configError struct{ message string }

func (e *configError) Error() string { return e.message }
