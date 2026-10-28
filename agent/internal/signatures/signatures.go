// Package signatures evaluates operator-managed request signatures before a
// request reaches PHP. The JSON format is shared with the Laravel package
// (src/Security/Signatures), so one file is enforced by both layers and can
// be changed without rebuilding the agent or deploying the application.
package signatures

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

const (
	ActionLog   = "log"
	ActionBlock = "block"
	ActionBan   = "ban"

	DefaultBanTTLSeconds = 3600
	MaxBanTTLSeconds     = 86400

	maxRules           = 1024
	maxConditions      = 16
	maxValues          = 256
	maxValueBytes      = 1024
	maxDecodePasses    = 2
	maxInspectedBytes  = 8192
	SupportedVersion   = 1
	targetBody         = "body"
	targetHeaderPrefix = "header:"
)

var (
	safeRuleID     = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)
	safeHeaderName = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	validOps       = map[string]bool{"equals": true, "prefix": true, "suffix": true, "contains": true, "regex": true}
	fixedTargets   = map[string]bool{"method": true, "path": true, "query": true, "user_agent": true, targetBody: true}
)

// Rule is one compiled signature. Every condition must match.
type Rule struct {
	ID           string
	Action       string
	TTLSeconds   int
	RequiresBody bool
	conditions   []condition
}

type condition struct {
	targets []string
	op      string
	values  []string
	pattern *regexp.Regexp
	negate  bool
}

// Set is an immutable, ordered list of rules. The first matching blocking
// rule wins; log-only rules are reported but never stop evaluation.
type Set struct {
	rules []*Rule
}

// Request is the request metadata available before PHP runs.
type Request struct {
	Method string
	URI    string
	Header http.Header
}

type document struct {
	Version int            `json:"version"`
	Disable []string       `json:"disable"`
	Rules   []ruleDocument `json:"rules"`
}

type ruleDocument struct {
	ID          string              `json:"id"`
	Description string              `json:"description"`
	Action      string              `json:"action"`
	TTL         int                 `json:"ttl"`
	Enabled     *bool               `json:"enabled"`
	Conditions  []conditionDocument `json:"conditions"`
}

type conditionDocument struct {
	Target stringList `json:"target"`
	Op     string     `json:"op"`
	Value  *string    `json:"value"`
	Values []string   `json:"values"`
	Negate bool       `json:"negate"`
}

// stringList accepts either "path" or ["path", "query"].
type stringList []string

func (l *stringList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*l = []string{single}
		return nil
	}

	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("target must be a string or a list of strings")
	}
	*l = many

	return nil
}

// parsed is one validated file before cross-file disable lists are applied.
type parsed struct {
	rules   []*Rule
	disable []string
}

// Parse validates one signature file. Any error rejects the whole file so a
// partially understood rule can never be enforced.
func Parse(data []byte) (parsed, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var doc document
	if err := decoder.Decode(&doc); err != nil {
		return parsed{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return parsed{}, fmt.Errorf("invalid JSON: expected one document")
	}
	if doc.Version != SupportedVersion {
		return parsed{}, fmt.Errorf("version must be %d", SupportedVersion)
	}
	if len(doc.Rules) > maxRules {
		return parsed{}, fmt.Errorf("a file may contain at most %d rules", maxRules)
	}

	result := parsed{rules: make([]*Rule, 0, len(doc.Rules))}
	for _, id := range doc.Disable {
		if !safeRuleID.MatchString(id) {
			return parsed{}, fmt.Errorf("disable: invalid rule id %q", id)
		}
		result.disable = append(result.disable, id)
	}

	for index, ruleDoc := range doc.Rules {
		rule, err := compileRule(ruleDoc)
		if err != nil {
			return parsed{}, fmt.Errorf("rule %d (%s): %w", index, ruleDoc.ID, err)
		}
		if rule != nil {
			result.rules = append(result.rules, rule)
		}
	}

	return result, nil
}

func compileRule(doc ruleDocument) (*Rule, error) {
	if !safeRuleID.MatchString(doc.ID) {
		return nil, fmt.Errorf("id must match %s", safeRuleID.String())
	}

	action := doc.Action
	if action == "" {
		action = ActionBlock
	}
	if action != ActionLog && action != ActionBlock && action != ActionBan {
		return nil, fmt.Errorf("action must be log, block, or ban")
	}

	ttl := doc.TTL
	if ttl == 0 {
		ttl = DefaultBanTTLSeconds
	}
	if ttl < 1 || ttl > MaxBanTTLSeconds {
		return nil, fmt.Errorf("ttl must be between 1 and %d seconds", MaxBanTTLSeconds)
	}

	if len(doc.Conditions) == 0 || len(doc.Conditions) > maxConditions {
		return nil, fmt.Errorf("a rule needs between 1 and %d conditions", maxConditions)
	}

	rule := &Rule{ID: doc.ID, Action: action, TTLSeconds: ttl}
	for index, conditionDoc := range doc.Conditions {
		compiled, err := compileCondition(conditionDoc)
		if err != nil {
			return nil, fmt.Errorf("condition %d: %w", index, err)
		}
		for _, target := range compiled.targets {
			if target == targetBody {
				rule.RequiresBody = true
			}
		}
		rule.conditions = append(rule.conditions, compiled)
	}

	// Validate everything before honouring enabled=false so a disabled rule
	// cannot hide a mistake that would surface when it is switched on.
	if doc.Enabled != nil && !*doc.Enabled {
		return nil, nil
	}

	return rule, nil
}

func compileCondition(doc conditionDocument) (condition, error) {
	if len(doc.Target) == 0 {
		return condition{}, fmt.Errorf("target is required")
	}

	targets := make([]string, 0, len(doc.Target))
	for _, target := range doc.Target {
		target = asciiLower(strings.TrimSpace(target))
		if strings.HasPrefix(target, targetHeaderPrefix) {
			if !safeHeaderName.MatchString(strings.TrimPrefix(target, targetHeaderPrefix)) {
				return condition{}, fmt.Errorf("invalid header target %q", target)
			}
		} else if !fixedTargets[target] {
			return condition{}, fmt.Errorf("unknown target %q", target)
		}
		targets = append(targets, target)
	}

	if !validOps[doc.Op] {
		return condition{}, fmt.Errorf("op must be equals, prefix, suffix, contains, or regex")
	}

	values := append([]string(nil), doc.Values...)
	if doc.Value != nil {
		values = append(values, *doc.Value)
	}
	if len(values) == 0 || len(values) > maxValues {
		return condition{}, fmt.Errorf("a condition needs between 1 and %d values", maxValues)
	}

	compiled := condition{targets: targets, op: doc.Op, negate: doc.Negate}
	if doc.Op == "regex" {
		if len(values) != 1 {
			return condition{}, fmt.Errorf("regex conditions take exactly one value")
		}
		if len(values[0]) == 0 || len(values[0]) > maxValueBytes {
			return condition{}, fmt.Errorf("regex must be between 1 and %d bytes", maxValueBytes)
		}
		pattern, err := regexp.Compile("(?i)" + values[0])
		if err != nil {
			return condition{}, fmt.Errorf("invalid regex: %w", err)
		}
		compiled.pattern = pattern

		return compiled, nil
	}

	for _, value := range values {
		if len(value) > maxValueBytes || (value == "" && doc.Op != "equals") {
			return condition{}, fmt.Errorf("values must be between 1 and %d bytes", maxValueBytes)
		}
		compiled.values = append(compiled.values, asciiLower(value))
	}

	return compiled, nil
}

// NewSet orders the rules from each file and drops any disabled rule ID.
func newSet(files []parsed) *Set {
	disabled := make(map[string]bool)
	for _, file := range files {
		for _, id := range file.disable {
			disabled[id] = true
		}
	}

	set := &Set{}
	for _, file := range files {
		for _, rule := range file.rules {
			if !disabled[rule.ID] {
				set.rules = append(set.rules, rule)
			}
		}
	}

	return set
}

// Len reports the number of active rules.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}

	return len(s.rules)
}

// Match returns the first blocking rule, plus every log-only rule that
// matched before it. Rules that inspect the request body are skipped
// because the body is not available before PHP; Laravel evaluates them.
func (s *Set) Match(request Request) (*Rule, []*Rule) {
	if s == nil || len(s.rules) == 0 {
		return nil, nil
	}

	view := newRequestView(request)
	var logged []*Rule
	for _, rule := range s.rules {
		if rule.RequiresBody || !rule.matches(view) {
			continue
		}
		if rule.Action == ActionLog {
			logged = append(logged, rule)
			continue
		}

		return rule, logged
	}

	return nil, logged
}

func (r *Rule) matches(view *requestView) bool {
	for _, condition := range r.conditions {
		if condition.matches(view) == condition.negate {
			return false
		}
	}

	return true
}

func (c condition) matches(view *requestView) bool {
	for _, target := range c.targets {
		value := view.value(target)
		if c.pattern != nil {
			if c.pattern.MatchString(value) {
				return true
			}
			continue
		}
		for _, expected := range c.values {
			if compare(c.op, value, expected) {
				return true
			}
		}
	}

	return false
}

func compare(op, value, expected string) bool {
	switch op {
	case "equals":
		return value == expected
	case "prefix":
		return strings.HasPrefix(value, expected)
	case "suffix":
		return strings.HasSuffix(value, expected)
	case "contains":
		return strings.Contains(value, expected)
	}

	return false
}

type requestView struct {
	method string
	path   string
	query  string
	header http.Header
}

func newRequestView(request Request) *requestView {
	uri := request.URI
	if len(uri) > maxInspectedBytes {
		uri = uri[:maxInspectedBytes]
	}
	path, query, _ := strings.Cut(uri, "?")

	return &requestView{
		method: strings.ToUpper(request.Method),
		path:   NormalizePath(path),
		query:  NormalizeQuery(query),
		header: request.Header,
	}
}

func (v *requestView) value(target string) string {
	switch target {
	case "method":
		return asciiLower(v.method)
	case "path":
		return v.path
	case "query":
		return v.query
	case "user_agent":
		return v.headerValue("User-Agent")
	}
	if name, ok := strings.CutPrefix(target, targetHeaderPrefix); ok {
		return v.headerValue(name)
	}

	return ""
}

func (v *requestView) headerValue(name string) string {
	if v.header == nil {
		return ""
	}
	value := strings.Join(v.header.Values(name), ", ")
	if len(value) > maxInspectedBytes {
		value = value[:maxInspectedBytes]
	}

	return asciiLower(value)
}

// NormalizePath mirrors PHP: up to two rawurldecode() passes, then ASCII
// lower-casing. Invalid escapes are kept literally, as PHP does.
func NormalizePath(path string) string {
	return asciiLower(decodeRepeatedly(path, false))
}

// NormalizeQuery mirrors PHP: up to two urldecode() passes ("+" is a space).
func NormalizeQuery(query string) string {
	return asciiLower(decodeRepeatedly(query, true))
}

func decodeRepeatedly(value string, plusAsSpace bool) string {
	for pass := 0; pass < maxDecodePasses; pass++ {
		decoded := percentDecode(value, plusAsSpace)
		if decoded == value {
			break
		}
		value = decoded
	}

	return value
}

func percentDecode(value string, plusAsSpace bool) string {
	if !strings.ContainsAny(value, "%+") {
		return value
	}

	var builder strings.Builder
	builder.Grow(len(value))
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '+' && plusAsSpace {
			builder.WriteByte(' ')
			continue
		}
		if character == '%' && index+2 < len(value) && isHex(value[index+1]) && isHex(value[index+2]) {
			builder.WriteByte(unhex(value[index+1])<<4 | unhex(value[index+2]))
			index += 2
			continue
		}
		builder.WriteByte(character)
	}

	return builder.String()
}

func isHex(character byte) bool {
	return (character >= '0' && character <= '9') ||
		(character >= 'a' && character <= 'f') ||
		(character >= 'A' && character <= 'F')
}

func unhex(character byte) byte {
	switch {
	case character >= '0' && character <= '9':
		return character - '0'
	case character >= 'a' && character <= 'f':
		return character - 'a' + 10
	default:
		return character - 'A' + 10
	}
}

// asciiLower matches PHP 8.2+ strtolower(): only A-Z change and every other
// byte, including invalid UTF-8, is preserved.
func asciiLower(value string) string {
	for index := 0; index < len(value); index++ {
		if value[index] >= 'A' && value[index] <= 'Z' {
			bytes := []byte(value)
			for position := index; position < len(bytes); position++ {
				if bytes[position] >= 'A' && bytes[position] <= 'Z' {
					bytes[position] += 'a' - 'A'
				}
			}

			return string(bytes)
		}
	}

	return value
}
