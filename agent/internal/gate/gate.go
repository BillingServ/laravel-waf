package gate

import (
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
	clientIPHeader    = "X-Laravel-Waf-Client-IP"
	originalURIHeader = "X-Laravel-Waf-Original-URI"
)

type Config struct {
	Threshold       uint64
	Window          time.Duration
	CookieName      string
	ChallengeSecret []byte
	MarkerToken     string
	BypassPrefixes  []string
	Methods         []string
}

type Handler struct {
	config  Config
	metrics *metrics.Registry
	now     func() time.Time

	mu            sync.Mutex
	windowStarted time.Time
	requests      uint64
}

type passPayload struct {
	Kind      string `json:"kind"`
	IP        string `json:"ip"`
	Version   int    `json:"version"`
	ExpiresAt int64  `json:"expires_at"`
}

func NewHandler(config Config, registry *metrics.Registry) (*Handler, error) {
	if config.Threshold < 1 {
		return nil, &configError{"threshold must be at least 1"}
	}
	if config.Window < time.Second || config.Window > time.Hour {
		return nil, &configError{"window must be between 1s and 1h"}
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
		config:  config,
		metrics: registry,
		now:     time.Now,
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
	requests, retryAfter := h.hit(now)
	if requests <= h.config.Threshold || h.passed(request, ip, now) {
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
	response.Header().Set("Retry-After", retryAfter)
	response.WriteHeader(http.StatusForbidden)
}

func (h *Handler) hit(now time.Time) (uint64, string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.windowStarted.IsZero() || !now.Before(h.windowStarted.Add(h.config.Window)) {
		h.windowStarted = now
		h.requests = 0
	}
	h.requests++

	remaining := h.windowStarted.Add(h.config.Window).Sub(now)
	seconds := int64(remaining / time.Second)
	if remaining%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}

	return h.requests, strconv.FormatInt(seconds, 10)
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
