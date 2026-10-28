package gate

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BillingServ/laravel-waf/agent/internal/metrics"
	"github.com/BillingServ/laravel-waf/agent/internal/signatures"
)

const testSignatures = `{"version":1,"rules":[
	{"id":"php-cgi","action":"ban","ttl":7200,"conditions":[{"target":"query","op":"contains","value":"allow_url_include"}]},
	{"id":"wp","action":"block","conditions":[{"target":"path","op":"suffix","value":"/wp-login.php"}]},
	{"id":"watch","action":"log","conditions":[{"target":"path","op":"prefix","value":"/watched"}]}
]}`

func newSignatureTestHandler(t *testing.T, blocker Blocker) *Handler {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(testSignatures), 0o644); err != nil {
		t.Fatal(err)
	}
	loader := signatures.NewLoader([]string{path})
	if result := loader.Reload(); len(result.Errors) > 0 {
		t.Fatal(result.Errors)
	}

	handler, err := NewHandler(Config{
		Threshold:       1000,
		Window:          time.Minute,
		CookieName:      "laravel_waf_challenge",
		ChallengeSecret: []byte("test-challenge-secret-with-32-bytes"),
		MarkerToken:     "test-gate-marker-token-with-32-bytes",
		BypassPrefixes:  []string{"/_waf/challenge", "/_waf/blocked"},
		Signatures:      loader,
	}, metrics.NewRegistry("test.example", "test"), blocker)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return testNow }

	return handler
}

func TestGateBansSignatureMatchesBeforePHP(t *testing.T) {
	blocker := &recordingBlocker{}
	handler := newSignatureTestHandler(t, blocker)

	// The URI is deliberately unparsable by net/url; signatures still run.
	response := gateRequest(handler, "203.0.113.150", "/index.php?%ADd+allow_url_include%3d1&x=%zz", http.MethodPost, "")
	if response.Code != http.StatusUnauthorized || response.Header().Get("X-Laravel-Waf-Blocked") != "true" {
		t.Fatalf("signature ban status = %d", response.Code)
	}
	if blocker.calls != 1 || blocker.ttl != 7200 || blocker.reason != "sig:php-cgi" {
		t.Fatalf("unexpected ban dispatch %+v", blocker)
	}

	// Subsequent clean requests from the banned client are denied without
	// dispatching a second firewall decision.
	if status := gateRequest(handler, "203.0.113.150", "/", http.MethodGet, "").Code; status != http.StatusUnauthorized {
		t.Fatalf("banned client status = %d", status)
	}
	if blocker.calls != 1 {
		t.Fatalf("ban was redispatched %d times", blocker.calls)
	}
}

func TestGateBlockSignatureDoesNotBanAndPassCookieDoesNotBypass(t *testing.T) {
	blocker := &recordingBlocker{}
	handler := newSignatureTestHandler(t, blocker)
	token := passToken("203.0.113.151", testNow.Add(time.Minute).Unix())

	if status := gateRequest(handler, "203.0.113.151", "/blog/wp-login.php", http.MethodGet, token).Code; status != http.StatusUnauthorized {
		t.Fatalf("block signature status = %d", status)
	}
	if blocker.calls != 0 {
		t.Fatalf("block action dispatched %d bans", blocker.calls)
	}
	if status := gateRequest(handler, "203.0.113.151", "/", http.MethodGet, token).Code; status != http.StatusNoContent {
		t.Fatalf("client should not stay blocked after a block action, status = %d", status)
	}
	if status := gateRequest(handler, "203.0.113.151", "/watched/page", http.MethodGet, "").Code; status != http.StatusNoContent {
		t.Fatalf("log-only signature must allow the request, status = %d", status)
	}
}

func TestGateSignaturesRequireABlocker(t *testing.T) {
	_, err := NewHandler(Config{
		Threshold:       1,
		Window:          time.Minute,
		CookieName:      "laravel_waf_challenge",
		ChallengeSecret: []byte("test-challenge-secret-with-32-bytes"),
		MarkerToken:     "test-gate-marker-token-with-32-bytes",
		Signatures:      signatures.NewLoader(nil),
	}, metrics.NewRegistry("test.example", "test"), nil)
	if err == nil {
		t.Fatal("expected a configuration error")
	}
}

type synchronizedSignatureBlocker struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	err     error
}

func (b *synchronizedSignatureBlocker) Block(_ context.Context, _ net.IP, _ int, _ string) error {
	b.calls.Add(1)
	if b.entered != nil {
		select {
		case b.entered <- struct{}{}:
		default:
		}
	}
	if b.release != nil {
		<-b.release
	}
	return b.err
}

func TestConcurrentSignatureBansDispatchOnlyOnce(t *testing.T) {
	blocker := &synchronizedSignatureBlocker{entered: make(chan struct{}, 16), release: make(chan struct{})}
	handler := newSignatureTestHandler(t, blocker)
	first := make(chan struct{})
	go func() {
		defer close(first)
		gateRequest(handler, "203.0.113.160", "/?allow_url_include=1", http.MethodGet, "")
	}()
	defer func() { close(blocker.release); <-first }()
	select {
	case <-blocker.entered:
	case <-time.After(time.Second):
		t.Fatal("first block did not start")
	}
	var peers sync.WaitGroup
	for i := 0; i < 15; i++ {
		peers.Add(1)
		go func() {
			defer peers.Done()
			if status := gateRequest(handler, "203.0.113.160", "/?allow_url_include=1", http.MethodGet, "").Code; status != http.StatusUnauthorized {
				t.Errorf("concurrent probe status = %d", status)
			}
		}()
	}
	done := make(chan struct{})
	go func() { peers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("duplicate probes waited on firewall work")
	}
	if calls := blocker.calls.Load(); calls != 1 {
		t.Fatalf("dispatched %d bans, want 1", calls)
	}
}

func TestFailedSignatureBansHaveCooldownWithoutBanningCleanRequests(t *testing.T) {
	blocker := &synchronizedSignatureBlocker{err: errors.New("backend unavailable")}
	handler := newSignatureTestHandler(t, blocker)
	for i := 0; i < 2; i++ {
		if status := gateRequest(handler, "203.0.113.161", "/?allow_url_include=1", http.MethodGet, "").Code; status != http.StatusUnauthorized {
			t.Fatalf("probe status = %d", status)
		}
	}
	if calls := blocker.calls.Load(); calls != 1 {
		t.Fatalf("dispatched %d attempts during cooldown", calls)
	}
	if status := gateRequest(handler, "203.0.113.161", "/", http.MethodGet, "").Code; status != http.StatusNoContent {
		t.Fatalf("failed firewall operation banned clean request: %d", status)
	}
	handler.now = func() time.Time { return testNow.Add(time.Minute + time.Second) }
	gateRequest(handler, "203.0.113.161", "/?allow_url_include=1", http.MethodGet, "")
	if calls := blocker.calls.Load(); calls != 2 {
		t.Fatalf("did not retry after cooldown: %d", calls)
	}
}

func TestSuccessfulSignatureBanKeepsDeduplicationWhenBlockTrackingIsFull(t *testing.T) {
	blocker := &synchronizedSignatureBlocker{}
	handler := newSignatureTestHandler(t, blocker)
	for i := 0; i < maxTrackedClients; i++ {
		handler.blockedUntil[strconv.Itoa(i)] = testNow.Add(time.Hour)
	}
	for i := 0; i < 2; i++ {
		gateRequest(handler, "203.0.113.162", "/?allow_url_include=1", http.MethodGet, "")
	}
	if calls := blocker.calls.Load(); calls != 1 {
		t.Fatalf("full block tracker caused %d duplicate bans", calls)
	}
}
