package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BillingServ/laravel-waf/agent/internal/protocol"
)

const (
	metricCounter        = "counter"
	metricHistogram      = "histogram"
	maxApplicationSeries = 4096
)

type applicationMetricSchema struct {
	Name       string
	Help       string
	Kind       string
	LabelNames []string
}

var (
	applicationMetricOrder = []string{
		"decisions",
		"findings",
		"agent_blocks",
		"notifications",
		"behavior_events",
		"errors",
		"evaluation_duration_seconds",
	}
	applicationMetricSchemas = map[string]applicationMetricSchema{
		"decisions": {
			Name: "decisions", Help: "Laravel WAF request decisions.", Kind: metricCounter,
			LabelNames: []string{"action", "scope", "route"},
		},
		"findings": {
			Name: "findings", Help: "Laravel WAF request inspection findings.", Kind: metricCounter,
			LabelNames: []string{"category", "rule", "action", "route"},
		},
		"agent_blocks": {
			Name: "agent_blocks", Help: "Laravel WAF host-agent block decisions.", Kind: metricCounter,
			LabelNames: []string{"outcome"},
		},
		"notifications": {
			Name: "notifications", Help: "Laravel WAF security notification outcomes.", Kind: metricCounter,
			LabelNames: []string{"channel", "outcome"},
		},
		"behavior_events": {
			Name: "behavior_events", Help: "Laravel WAF response behavior events.", Kind: metricCounter,
			LabelNames: []string{"kind", "outcome", "route"},
		},
		"errors": {
			Name: "errors", Help: "Laravel WAF internal errors.", Kind: metricCounter,
			LabelNames: []string{"component"},
		},
		"evaluation_duration_seconds": {
			Name: "evaluation_duration_seconds", Help: "Laravel WAF middleware evaluation duration in seconds.", Kind: metricHistogram,
		},
	}
	evaluationDurationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	metricEventOutcomes       = []string{"accepted", "busy", "invalid", "invalid_json", "rejected", "rejected_schema"}
)

type counterKey struct {
	Name    string
	Action  string
	Outcome string
	Family  string
}

type applicationCounter struct {
	Name   string
	Labels map[string]string
	Value  uint64
}

type applicationHistogram struct {
	Name    string
	Labels  map[string]string
	Buckets []uint64
	Count   uint64
	Sum     float64
}

type Registry struct {
	mu                    sync.RWMutex
	instance              string
	version               string
	decisions             map[counterKey]uint64
	operations            map[counterKey]uint64
	gate                  map[counterKey]uint64
	metricEvents          map[counterKey]uint64
	applicationCounters   map[string]*applicationCounter
	applicationHistograms map[string]*applicationHistogram
	applicationSeries     int
}

func NewRegistry(instance, version string) *Registry {
	registry := &Registry{
		instance:              instance,
		version:               version,
		decisions:             make(map[counterKey]uint64),
		operations:            make(map[counterKey]uint64),
		gate:                  make(map[counterKey]uint64),
		metricEvents:          make(map[counterKey]uint64),
		applicationCounters:   make(map[string]*applicationCounter),
		applicationHistograms: make(map[string]*applicationHistogram),
	}
	for _, outcome := range metricEventOutcomes {
		registry.metricEvents[counterKey{Name: "metric_events", Outcome: outcome}] = 0
	}

	return registry
}

func (r *Registry) Gate(outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gate[counterKey{Name: "gate", Outcome: outcome}]++
}

func (r *Registry) Decision(action, outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decisions[counterKey{Name: "decisions", Action: action, Outcome: outcome}]++
}

func (r *Registry) Operation(operation, outcome, family string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.operations[counterKey{Name: "operations", Action: operation, Outcome: outcome, Family: family}]++
}

func (r *Registry) MetricEvent(outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metricEvents[counterKey{Name: "metric_events", Outcome: outcome}]++
}

func (r *Registry) RecordMetric(event protocol.MetricEvent) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("invalid metric event: %w", err)
	}

	schema, ok := applicationMetricSchemas[event.Name]
	if !ok {
		return fmt.Errorf("unsupported application metric")
	}
	if (schema.Kind == metricCounter && event.Operation != protocol.MetricIncrement) ||
		(schema.Kind == metricHistogram && event.Operation != protocol.MetricObserve) {
		return fmt.Errorf("metric operation does not match schema")
	}
	if len(event.Labels) != len(schema.LabelNames) {
		return fmt.Errorf("metric labels do not match schema")
	}
	for _, name := range schema.LabelNames {
		if _, exists := event.Labels[name]; !exists {
			return fmt.Errorf("metric labels do not match schema")
		}
	}

	key := applicationSeriesKey(schema, event.Labels)
	r.mu.Lock()
	defer r.mu.Unlock()

	if schema.Kind == metricCounter {
		series, exists := r.applicationCounters[key]
		if !exists {
			if r.applicationSeries >= maxApplicationSeries {
				return fmt.Errorf("application metric series limit reached")
			}
			series = &applicationCounter{Name: event.Name, Labels: copyLabels(event.Labels)}
			r.applicationCounters[key] = series
			r.applicationSeries++
		}
		series.Value += uint64(event.Value)

		return nil
	}

	series, exists := r.applicationHistograms[key]
	if !exists {
		if r.applicationSeries >= maxApplicationSeries {
			return fmt.Errorf("application metric series limit reached")
		}
		series = &applicationHistogram{
			Name:    event.Name,
			Labels:  copyLabels(event.Labels),
			Buckets: make([]uint64, len(evaluationDurationBuckets)),
		}
		r.applicationHistograms[key] = series
		r.applicationSeries++
	}

	value := float64(event.Value) / 1_000_000_000
	series.Count++
	series.Sum += value
	for index, boundary := range evaluationDurationBuckets {
		if value <= boundary {
			series.Buckets[index]++
		}
	}

	return nil
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		_, _ = w.Write([]byte(r.render()))
	})
}

func (r *Registry) render() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	lines := []string{
		"# HELP laravel_waf_info Build and host information for the Laravel WAF daemon.",
		"# TYPE laravel_waf_info gauge",
		fmt.Sprintf(
			`laravel_waf_info{instance="%s",application="lwafd",version="%s"} 1`,
			escape(r.instance), escape(r.version),
		),
	}
	lines = r.renderApplicationMetrics(lines)
	lines = append(lines,
		"# HELP laravel_waf_agent_decisions_total Decisions accepted or rejected by the Laravel WAF agent.",
		"# TYPE laravel_waf_agent_decisions_total counter",
	)

	decisionKeys := sortedCounterKeys(r.decisions)
	for _, key := range decisionKeys {
		lines = append(lines, fmt.Sprintf(
			`laravel_waf_agent_decisions_total{instance="%s",action="%s",outcome="%s"} %d`,
			escape(r.instance), escape(key.Action), escape(key.Outcome), r.decisions[key],
		))
	}

	lines = append(lines,
		"# HELP laravel_waf_agent_firewall_operations_total Firewall operations performed by the Laravel WAF agent.",
		"# TYPE laravel_waf_agent_firewall_operations_total counter",
	)

	operationKeys := sortedCounterKeys(r.operations)
	for _, key := range operationKeys {
		lines = append(lines, fmt.Sprintf(
			`laravel_waf_agent_firewall_operations_total{instance="%s",family="%s",operation="%s",outcome="%s"} %d`,
			escape(r.instance), escape(key.Family), escape(key.Action), escape(key.Outcome), r.operations[key],
		))
	}

	lines = append(lines,
		"# HELP laravel_waf_agent_gate_requests_total Requests evaluated by the pre-application traffic gate.",
		"# TYPE laravel_waf_agent_gate_requests_total counter",
	)

	gateKeys := sortedCounterKeys(r.gate)
	for _, key := range gateKeys {
		lines = append(lines, fmt.Sprintf(
			`laravel_waf_agent_gate_requests_total{instance="%s",outcome="%s"} %d`,
			escape(r.instance), escape(key.Outcome), r.gate[key],
		))
	}

	lines = append(lines,
		"# HELP laravel_waf_agent_metric_events_total Laravel metric events received by LWAFD.",
		"# TYPE laravel_waf_agent_metric_events_total counter",
	)
	metricEventKeys := sortedCounterKeys(r.metricEvents)
	for _, key := range metricEventKeys {
		lines = append(lines, fmt.Sprintf(
			`laravel_waf_agent_metric_events_total{instance="%s",outcome="%s"} %d`,
			escape(r.instance), escape(key.Outcome), r.metricEvents[key],
		))
	}

	return strings.Join(lines, "\n") + "\n"
}

func (r *Registry) renderApplicationMetrics(lines []string) []string {
	for _, name := range applicationMetricOrder {
		schema := applicationMetricSchemas[name]
		metricName := "laravel_waf_" + schema.Name
		if schema.Kind == metricCounter {
			metricName += "_total"
		}
		lines = append(lines,
			"# HELP "+metricName+" "+schema.Help,
			"# TYPE "+metricName+" "+schema.Kind,
		)

		if schema.Kind == metricCounter {
			keys := make([]string, 0)
			for key, series := range r.applicationCounters {
				if series.Name == schema.Name {
					keys = append(keys, key)
				}
			}
			sort.Strings(keys)
			for _, key := range keys {
				series := r.applicationCounters[key]
				lines = append(lines, sample(metricName, labelSet(r.instance, schema.LabelNames, series.Labels, "", ""), strconv.FormatUint(series.Value, 10)))
			}

			continue
		}

		keys := make([]string, 0)
		for key, series := range r.applicationHistograms {
			if series.Name == schema.Name {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			series := r.applicationHistograms[key]
			for index, boundary := range evaluationDurationBuckets {
				lines = append(lines, sample(
					metricName+"_bucket",
					labelSet(r.instance, schema.LabelNames, series.Labels, "le", strconv.FormatFloat(boundary, 'g', -1, 64)),
					strconv.FormatUint(series.Buckets[index], 10),
				))
			}
			lines = append(lines,
				sample(metricName+"_bucket", labelSet(r.instance, schema.LabelNames, series.Labels, "le", "+Inf"), strconv.FormatUint(series.Count, 10)),
				sample(metricName+"_sum", labelSet(r.instance, schema.LabelNames, series.Labels, "", ""), strconv.FormatFloat(series.Sum, 'g', -1, 64)),
				sample(metricName+"_count", labelSet(r.instance, schema.LabelNames, series.Labels, "", ""), strconv.FormatUint(series.Count, 10)),
			)
		}
	}

	return lines
}

func applicationSeriesKey(schema applicationMetricSchema, labels map[string]string) string {
	parts := []string{schema.Name}
	for _, name := range schema.LabelNames {
		parts = append(parts, name, labels[name])
	}

	return strings.Join(parts, "\xff")
}

func copyLabels(labels map[string]string) map[string]string {
	copy := make(map[string]string, len(labels))
	for name, value := range labels {
		copy[name] = value
	}

	return copy
}

func sortedCounterKeys(values map[counterKey]uint64) []counterKey {
	keys := make([]counterKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j])
	})

	return keys
}

func labelSet(instance string, names []string, labels map[string]string, extraName, extraValue string) string {
	values := make([]string, 0, len(names)+2)
	values = append(values, `instance="`+escape(instance)+`"`)
	for _, name := range names {
		values = append(values, name+`="`+escape(labels[name])+`"`)
	}
	if extraName != "" {
		values = append(values, extraName+`="`+escape(extraValue)+`"`)
	}
	if len(values) == 0 {
		return ""
	}

	return "{" + strings.Join(values, ",") + "}"
}

func sample(name, labels, value string) string {
	return name + labels + " " + value
}

func escape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)

	return value
}
