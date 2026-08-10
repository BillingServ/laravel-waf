package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	MetricAction              = "record_metric"
	MetricIncrement           = "increment"
	MetricObserve             = "observe"
	MaxMetricEventBytes       = 8192
	MaxMetricLabels           = 8
	MaxMetricObservationNanos = int64(time.Hour)
)

var (
	safeMetricName       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	safeMetricLabelName  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	safeMetricLabelValue = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

// MetricEvent is a bounded, signed update sent by Laravel over the private
// metrics-ingest socket. Integer nanoseconds keep histogram signatures stable
// across PHP and Go without relying on language-specific float formatting.
type MetricEvent struct {
	Version   int               `json:"version"`
	Action    string            `json:"action"`
	Operation string            `json:"operation"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	Value     int64             `json:"value"`
	Signature string            `json:"signature,omitempty"`
}

func (e MetricEvent) Validate() error {
	if e.Version != Version {
		return fmt.Errorf("unsupported protocol version")
	}
	if e.Action != MetricAction {
		return fmt.Errorf("unsupported metric action")
	}
	if e.Operation != MetricIncrement && e.Operation != MetricObserve {
		return fmt.Errorf("unsupported metric operation")
	}
	if !safeMetricName.MatchString(e.Name) {
		return fmt.Errorf("invalid metric name")
	}
	if len(e.Labels) > MaxMetricLabels {
		return fmt.Errorf("too many metric labels")
	}

	for name, value := range e.Labels {
		if !safeMetricLabelName.MatchString(name) {
			return fmt.Errorf("invalid metric label name")
		}
		if !safeMetricLabelValue.MatchString(value) {
			return fmt.Errorf("invalid metric label value")
		}
	}

	if e.Operation == MetricIncrement && e.Value != 1 {
		return fmt.Errorf("metric increments must have value 1")
	}
	if e.Operation == MetricObserve && (e.Value < 0 || e.Value > MaxMetricObservationNanos) {
		return fmt.Errorf("metric observation is out of range")
	}

	return nil
}

func (e MetricEvent) Canonical() string {
	lines := []string{
		strconv.Itoa(e.Version),
		e.Action,
		e.Operation,
		e.Name,
		strconv.FormatInt(e.Value, 10),
	}

	names := make([]string, 0, len(e.Labels))
	for name := range e.Labels {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := base64.RawURLEncoding.EncodeToString([]byte(e.Labels[name]))
		lines = append(lines, name+"="+value)
	}

	return strings.Join(lines, "\n")
}

func (e MetricEvent) Verify(secret []byte) bool {
	if len(secret) == 0 {
		return true
	}

	signature, err := hex.DecodeString(strings.TrimSpace(e.Signature))
	if err != nil {
		return false
	}

	return hmac.Equal(signature, e.signature(secret))
}

func (e *MetricEvent) Sign(secret []byte) {
	e.Signature = ""
	if len(secret) > 0 {
		e.Signature = hex.EncodeToString(e.signature(secret))
	}
}

func (e MetricEvent) signature(secret []byte) []byte {
	digest := hmac.New(sha256.New, secret)
	_, _ = digest.Write([]byte(e.Canonical()))

	return digest.Sum(nil)
}
