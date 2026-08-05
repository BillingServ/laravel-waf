package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type counterKey struct {
	Name    string
	Action  string
	Outcome string
	Family  string
}

type Registry struct {
	mu         sync.RWMutex
	decisions  map[counterKey]uint64
	operations map[counterKey]uint64
	gate       map[counterKey]uint64
}

func NewRegistry() *Registry {
	return &Registry{
		decisions:  make(map[counterKey]uint64),
		operations: make(map[counterKey]uint64),
		gate:       make(map[counterKey]uint64),
	}
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

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		_, _ = w.Write([]byte(r.render()))
	})
}

func (r *Registry) render() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lines []string
	lines = append(lines,
		"# HELP laravel_waf_agent_decisions_total Decisions accepted or rejected by the Laravel WAF agent.",
		"# TYPE laravel_waf_agent_decisions_total counter",
	)

	decisionKeys := make([]counterKey, 0, len(r.decisions))
	for key := range r.decisions {
		decisionKeys = append(decisionKeys, key)
	}
	sort.Slice(decisionKeys, func(i, j int) bool {
		return fmt.Sprint(decisionKeys[i]) < fmt.Sprint(decisionKeys[j])
	})
	for _, key := range decisionKeys {
		lines = append(lines, fmt.Sprintf(
			`laravel_waf_agent_decisions_total{action="%s",outcome="%s"} %d`,
			escape(key.Action), escape(key.Outcome), r.decisions[key],
		))
	}

	lines = append(lines,
		"# HELP laravel_waf_agent_firewall_operations_total Firewall operations performed by the Laravel WAF agent.",
		"# TYPE laravel_waf_agent_firewall_operations_total counter",
	)

	operationKeys := make([]counterKey, 0, len(r.operations))
	for key := range r.operations {
		operationKeys = append(operationKeys, key)
	}
	sort.Slice(operationKeys, func(i, j int) bool {
		return fmt.Sprint(operationKeys[i]) < fmt.Sprint(operationKeys[j])
	})
	for _, key := range operationKeys {
		lines = append(lines, fmt.Sprintf(
			`laravel_waf_agent_firewall_operations_total{family="%s",operation="%s",outcome="%s"} %d`,
			escape(key.Family), escape(key.Action), escape(key.Outcome), r.operations[key],
		))
	}

	lines = append(lines,
		"# HELP laravel_waf_agent_gate_requests_total Requests evaluated by the pre-application traffic gate.",
		"# TYPE laravel_waf_agent_gate_requests_total counter",
	)

	gateKeys := make([]counterKey, 0, len(r.gate))
	for key := range r.gate {
		gateKeys = append(gateKeys, key)
	}
	sort.Slice(gateKeys, func(i, j int) bool {
		return fmt.Sprint(gateKeys[i]) < fmt.Sprint(gateKeys[j])
	})
	for _, key := range gateKeys {
		lines = append(lines, fmt.Sprintf(
			`laravel_waf_agent_gate_requests_total{outcome="%s"} %d`,
			escape(key.Outcome), r.gate[key],
		))
	}

	return strings.Join(lines, "\n") + "\n"
}

func escape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)

	return value
}
