package protocol

import "testing"

func TestMetricEventSignature(t *testing.T) {
	event := MetricEvent{
		Version:   Version,
		Action:    MetricAction,
		Operation: MetricIncrement,
		Name:      "decisions",
		Labels: map[string]string{
			"action": "blocked",
			"scope":  "rule",
			"route":  "admin.login",
		},
		Value: 1,
	}

	secret := []byte("test-secret")
	event.Sign(secret)
	const expected = "d3ec25e70de177734ef8e70487d9d528a703661469e8e6f0ad2e4b6444f351bd"
	if event.Signature != expected {
		t.Fatalf("unexpected cross-language signature: %s", event.Signature)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("validate metric event: %v", err)
	}
	if !event.Verify(secret) {
		t.Fatal("expected metric signature to verify")
	}

	event.Labels["scope"] = "adaptive"
	if event.Verify(secret) {
		t.Fatal("expected changed metric event to fail verification")
	}
}

func TestMetricEventRejectsUnboundedInput(t *testing.T) {
	tests := []MetricEvent{
		{Version: Version, Action: MetricAction, Operation: MetricIncrement, Name: "INVALID", Value: 1},
		{Version: Version, Action: MetricAction, Operation: MetricIncrement, Name: "decisions", Labels: map[string]string{"route": "unsafe value"}, Value: 1},
		{Version: Version, Action: MetricAction, Operation: MetricIncrement, Name: "decisions", Value: 2},
		{Version: Version, Action: MetricAction, Operation: MetricObserve, Name: "evaluation_duration_seconds", Value: MaxMetricObservationNanos + 1},
	}

	for _, event := range tests {
		if err := event.Validate(); err == nil {
			t.Fatalf("expected event to be rejected: %#v", event)
		}
	}
}
