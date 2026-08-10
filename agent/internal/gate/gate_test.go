package gate

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/metrics"
)

var testNow = time.Unix(1_800_000_000, 0)

type recordingBlocker struct {
	calls  int
	ip     net.IP
	ttl    int
	reason string
	err    error
}

func (b *recordingBlocker) Block(_ context.Context, ip net.IP, ttl int, reason string) error {
	b.calls++
	b.ip = append(net.IP(nil), ip...)
	b.ttl = ttl
	b.reason = reason

	return b.err
}

func TestGateChallengesAfterSiteWideThreshold(t *testing.T) {
	handler := newTestHandler(t, 2)

	if status := gateRequest(handler, "203.0.113.10", "/order", http.MethodGet, "").Code; status != http.StatusNoContent {
		t.Fatalf("first request status = %d", status)
	}
	if status := gateRequest(handler, "203.0.113.11", "/admin/login", http.MethodGet, "").Code; status != http.StatusNoContent {
		t.Fatalf("second request status = %d", status)
	}
	response := gateRequest(handler, "203.0.113.12", "/order?plan=1", http.MethodGet, "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("third request status = %d", response.Code)
	}
	if response.Header().Get("X-Laravel-Waf-Challenge") != "required" {
		t.Fatal("expected challenge response header")
	}
	if response.Header().Get("X-Laravel-Waf-Gate") != "test-gate-marker-token-with-32-bytes" {
		t.Fatal("expected authenticated gate marker")
	}
	if response.Header().Get("Retry-After") != "60" {
		t.Fatalf("unexpected retry-after %q", response.Header().Get("Retry-After"))
	}
}

func TestGateAllowsLaravelPassCookieDuringPressure(t *testing.T) {
	handler := newTestHandler(t, 1)
	_ = gateRequest(handler, "203.0.113.20", "/", http.MethodGet, "")

	token := passToken("203.0.113.21", testNow.Add(time.Minute).Unix())
	response := gateRequest(handler, "203.0.113.21", "/admin/login", http.MethodGet, token)
	if response.Code != http.StatusNoContent {
		t.Fatalf("passed request status = %d", response.Code)
	}

	response = gateRequest(handler, "203.0.113.22", "/admin/login", http.MethodGet, token)
	if response.Code != http.StatusForbidden {
		t.Fatalf("IP-bound pass status = %d", response.Code)
	}
}

func TestGateBypassesInternalPathsWithoutConsumingThreshold(t *testing.T) {
	handler := newTestHandler(t, 1)

	if status := gateRequest(handler, "203.0.113.30", "/_waf/challenge/verify", http.MethodGet, "").Code; status != http.StatusNoContent {
		t.Fatalf("bypass request status = %d", status)
	}
	if status := gateRequest(handler, "203.0.113.30", "/order", http.MethodGet, "").Code; status != http.StatusNoContent {
		t.Fatalf("first counted request status = %d", status)
	}
}

func TestGateDoesNotChallengeUnsafeMethods(t *testing.T) {
	handler := newTestHandler(t, 1)
	_ = gateRequest(handler, "203.0.113.40", "/", http.MethodGet, "")

	if status := gateRequest(handler, "203.0.113.40", "/checkout", http.MethodPost, "").Code; status != http.StatusNoContent {
		t.Fatalf("POST request status = %d", status)
	}
}

func TestGateResetsItsFixedWindow(t *testing.T) {
	handler := newTestHandler(t, 1)
	_ = gateRequest(handler, "203.0.113.50", "/", http.MethodGet, "")
	if status := gateRequest(handler, "203.0.113.50", "/", http.MethodGet, "").Code; status != http.StatusForbidden {
		t.Fatalf("pressure request status = %d", status)
	}

	handler.now = func() time.Time { return testNow.Add(61 * time.Second) }
	if status := gateRequest(handler, "203.0.113.50", "/", http.MethodGet, "").Code; status != http.StatusNoContent {
		t.Fatalf("new window request status = %d", status)
	}
}

func TestGateBlocksOneClientWithoutBlockingAggregatePressureVisitors(t *testing.T) {
	blocker := &recordingBlocker{}
	handler := newClientTestHandler(t, 1000, DefaultClientThreshold, blocker)

	for requestNumber := uint64(1); requestNumber <= DefaultClientThreshold; requestNumber++ {
		if status := gateRequest(handler, "203.0.113.60", "/", http.MethodGet, "").Code; status != http.StatusNoContent {
			t.Fatalf("request %d status = %d", requestNumber, status)
		}
	}
	response := gateRequest(handler, "203.0.113.60", "/", http.MethodGet, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("rate-blocked request status = %d", response.Code)
	}
	if response.Header().Get("X-Laravel-Waf-Blocked") != "true" {
		t.Fatal("expected blocked response marker")
	}
	if response.Header().Get("Retry-After") != fmt.Sprint(DefaultBlockTTLSeconds) {
		t.Fatalf("unexpected retry-after %q", response.Header().Get("Retry-After"))
	}
	if blocker.calls != 1 || blocker.ip.String() != "203.0.113.60" || blocker.ttl != DefaultBlockTTLSeconds || blocker.reason != "gate_rate_limit" {
		t.Fatalf("unexpected block call: %#v", blocker)
	}

	if status := gateRequest(handler, "203.0.113.60", "/", http.MethodGet, "").Code; status != http.StatusUnauthorized {
		t.Fatalf("known blocked client status = %d", status)
	}
	if blocker.calls != 1 {
		t.Fatalf("block was dispatched %d times", blocker.calls)
	}
	if status := gateRequest(handler, "203.0.113.61", "/", http.MethodGet, "").Code; status != http.StatusNoContent {
		t.Fatalf("independent client status = %d", status)
	}
	if status := gateRequest(handler, "203.0.113.60", "/_waf/blocked", http.MethodGet, "").Code; status != http.StatusNoContent {
		t.Fatalf("blocked-page bypass status = %d", status)
	}
}

func TestGateSiteWideChallengeDoesNotCreateAClientBlock(t *testing.T) {
	blocker := &recordingBlocker{}
	handler := newClientTestHandler(t, 2, 10, blocker)

	_ = gateRequest(handler, "203.0.113.70", "/", http.MethodGet, "")
	_ = gateRequest(handler, "203.0.113.71", "/", http.MethodGet, "")
	if status := gateRequest(handler, "203.0.113.72", "/", http.MethodGet, "").Code; status != http.StatusForbidden {
		t.Fatalf("aggregate challenge status = %d", status)
	}
	if blocker.calls != 0 {
		t.Fatalf("aggregate pressure dispatched %d client blocks", blocker.calls)
	}
}

func TestGateUsesTheHigherTotalLimitAcrossDifferentPaths(t *testing.T) {
	blocker := &recordingBlocker{}
	handler := newClientTestHandler(t, 1000, DefaultClientThreshold, blocker)

	for requestNumber := uint64(1); requestNumber <= DefaultClientThreshold*2; requestNumber++ {
		path := fmt.Sprintf("/route/%d", requestNumber)
		if status := gateRequest(handler, "203.0.113.75", path, http.MethodGet, "").Code; status != http.StatusNoContent {
			t.Fatalf("request %d status = %d", requestNumber, status)
		}
	}
	if status := gateRequest(handler, "203.0.113.75", "/route/final", http.MethodGet, "").Code; status != http.StatusUnauthorized {
		t.Fatalf("total-limit request status = %d", status)
	}
	if blocker.calls != 1 {
		t.Fatalf("total limit dispatched %d blocks", blocker.calls)
	}
}

func TestGatePassCookieKeepsVerifiedClientOutOfAutomaticBlocking(t *testing.T) {
	blocker := &recordingBlocker{}
	handler := newClientTestHandler(t, 1, 1, blocker)
	token := passToken("203.0.113.80", testNow.Add(time.Minute).Unix())

	for range 3 {
		if status := gateRequest(handler, "203.0.113.80", "/", http.MethodGet, token).Code; status != http.StatusNoContent {
			t.Fatalf("verified request status = %d", status)
		}
	}
	if blocker.calls != 0 {
		t.Fatalf("verified client received %d blocks", blocker.calls)
	}
}

func TestGateDeniesAnObservedLaravelBlockAndRetainsInternalBypasses(t *testing.T) {
	blocker := &recordingBlocker{}
	handler := newClientTestHandler(t, 1000, DefaultClientThreshold, blocker)
	ip := net.ParseIP("203.0.113.90")
	handler.ObserveBlock(ip, testNow.Add(15*time.Minute))

	if status := gateRequest(handler, ip.String(), "/admin/login", http.MethodGet, "").Code; status != http.StatusUnauthorized {
		t.Fatalf("observed block status = %d", status)
	}
	if status := gateRequest(handler, ip.String(), "/_waf/blocked", http.MethodGet, "").Code; status != http.StatusNoContent {
		t.Fatalf("blocked-page bypass status = %d", status)
	}
	if blocker.calls != 0 {
		t.Fatalf("observed block was redispatched %d times", blocker.calls)
	}

	handler.ObserveUnblock(ip)
	if status := gateRequest(handler, ip.String(), "/admin/login", http.MethodGet, "").Code; status != http.StatusNoContent {
		t.Fatalf("unblocked request status = %d", status)
	}
}

func newTestHandler(t *testing.T, threshold uint64) *Handler {
	t.Helper()
	handler, err := NewHandler(Config{
		Threshold:       threshold,
		Window:          time.Minute,
		CookieName:      "laravel_waf_challenge",
		ChallengeSecret: []byte("test-challenge-secret-with-32-bytes"),
		MarkerToken:     "test-gate-marker-token-with-32-bytes",
		BypassPrefixes:  []string{"/_waf/challenge"},
	}, metrics.NewRegistry(), nil)
	if err != nil {
		t.Fatalf("create gate handler: %v", err)
	}
	handler.now = func() time.Time { return testNow }

	return handler
}

func newClientTestHandler(t *testing.T, threshold, clientThreshold uint64, blocker Blocker) *Handler {
	t.Helper()
	handler, err := NewHandler(Config{
		Threshold:       threshold,
		ClientThreshold: clientThreshold,
		Window:          time.Minute,
		BlockTTLSeconds: DefaultBlockTTLSeconds,
		CookieName:      "laravel_waf_challenge",
		ChallengeSecret: []byte("test-challenge-secret-with-32-bytes"),
		MarkerToken:     "test-gate-marker-token-with-32-bytes",
		BypassPrefixes:  []string{"/_waf/challenge", "/_waf/blocked"},
	}, metrics.NewRegistry(), blocker)
	if err != nil {
		t.Fatalf("create client gate handler: %v", err)
	}
	handler.now = func() time.Time { return testNow }

	return handler
}

func gateRequest(handler http.Handler, ip, uri, method, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "http://unix/gate", nil)
	request.Header.Set(clientIPHeader, ip)
	request.Header.Set(originalURIHeader, uri)
	request.Header.Set("X-Laravel-Waf-Original-Method", method)
	if token != "" {
		request.AddCookie(&http.Cookie{Name: "laravel_waf_challenge", Value: token})
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	return response
}

func passToken(ip string, expiresAt int64) string {
	payload := fmt.Sprintf(`{"kind":"pass","ip":"%s","version":1,"expires_at":%d,"nonce":"0123456789abcdef0123456789abcdef"}`, ip, expiresAt)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	digest := hmac.New(sha256.New, []byte("test-challenge-secret-with-32-bytes"))
	_, _ = digest.Write([]byte(encoded))

	return encoded + "." + hex.EncodeToString(digest.Sum(nil))
}
