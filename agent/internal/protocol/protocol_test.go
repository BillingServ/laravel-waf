package protocol

import (
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
	decision.Sign(secret)

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
	decision.Sign([]byte("test-secret"))
	if decision.Signature != expected {
		t.Fatalf("unexpected cross-language signature: %s", decision.Signature)
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

func TestDecisionRejectsLocalBlockTargetsButAllowsTheirRemoval(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "127.0.0.42", "::1", "0.0.0.0", "::"} {
		t.Run(ip, func(t *testing.T) {
			decision := Decision{
				Version:    Version,
				Action:     "block_ip",
				IP:         ip,
				TTLSeconds: 900,
				Reason:     "rule_xss",
			}

			if err := decision.Validate(MaxTTLSeconds); err == nil {
				t.Fatal("expected local block target to be rejected")
			}

			decision.Action = "unblock_ip"
			decision.TTLSeconds = 0
			if err := decision.Validate(MaxTTLSeconds); err != nil {
				t.Fatalf("expected local unblock target to remain valid: %v", err)
			}
		})
	}
}
