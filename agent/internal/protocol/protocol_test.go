package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDecisionSignature(t *testing.T) {
	decision := Decision{
		Version:    Version,
		Action:     "block_ip",
		IP:         "203.0.113.10",
		TTLSeconds: 900,
		Reason:     "rate_limit",
	}

	secret := []byte("test-secret")
	decision.Signature = sign(decision, secret)

	if err := decision.Validate(86400); err != nil {
		t.Fatalf("validate decision: %v", err)
	}

	if !decision.Verify(secret) {
		t.Fatal("expected signature to verify")
	}

	decision.TTLSeconds++
	if decision.Verify(secret) {
		t.Fatal("expected changed decision to fail verification")
	}
}

func TestDecisionSignatureMatchesLaravelCanonicalFixture(t *testing.T) {
	decision := Decision{
		Version:    Version,
		Action:     "block_ip",
		IP:         "203.0.113.10",
		TTLSeconds: 900,
		Reason:     "rate_limit",
	}

	const expected = "c6bf8a1b5fbda480a503dac32b2560545522e6d8bca0e9af8588d0447f2eda9b"
	if actual := sign(decision, []byte("test-secret")); actual != expected {
		t.Fatalf("unexpected cross-language signature: %s", actual)
	}
}

func TestDecisionRejectsUnsafeReason(t *testing.T) {
	decision := Decision{
		Version:    Version,
		Action:     "block_ip",
		IP:         "203.0.113.10",
		TTLSeconds: 900,
		Reason:     "rate limit",
	}

	if err := decision.Validate(86400); err == nil {
		t.Fatal("expected unsafe reason to be rejected")
	}
}

func sign(decision Decision, secret []byte) string {
	// The production signer lives in Laravel. This test only verifies the
	// canonical protocol format through the same HMAC primitives.
	digest := hmac.New(sha256.New, secret)
	_, _ = digest.Write([]byte(decision.Canonical()))

	return hex.EncodeToString(digest.Sum(nil))
}
