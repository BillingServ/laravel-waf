package signatures

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	coreRulesPath = "../../../resources/rules/core.json"
	casesPath     = "../../../tests/fixtures/signature-cases.tsv"
)

func TestCoreRulesMatchTheSharedFixture(t *testing.T) {
	loader := NewLoader([]string{coreRulesPath})
	if result := loader.Reload(); len(result.Errors) > 0 || result.Rules == 0 {
		t.Fatalf("core rules did not load: %+v", result)
	}

	file, err := os.Open(casesPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	cases := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("malformed fixture line %q", line)
		}
		expected, method, uri, userAgent := fields[0], fields[1], fields[2], fields[3]
		header := http.Header{}
		if userAgent != "-" {
			header.Set("User-Agent", userAgent)
		}

		rule, _ := loader.Current().Match(Request{Method: method, URI: uri, Header: header})
		actual := "-"
		if rule != nil {
			actual = rule.ID
		}
		if actual != expected {
			t.Errorf("%s %s: matched %q, want %q", method, uri, actual, expected)
		}
		cases++
	}
	if cases < 40 {
		t.Fatalf("only %d fixture cases were read", cases)
	}
}

func TestNormalizationMirrorsPHPDecoding(t *testing.T) {
	cases := map[string]string{
		"/cgi-bin/%%32%65%%32%65/bin": "/cgi-bin/../bin",
		"/A%2FB%":                     "/a/b%",
		"/%252e%252e/x":               "/../x",
		"/%25252e":                    "/%2e",
		"/a+b":                        "/a+b",
	}
	for input, expected := range cases {
		if actual := NormalizePath(input); actual != expected {
			t.Errorf("NormalizePath(%q) = %q, want %q", input, actual, expected)
		}
	}
	if actual := NormalizeQuery("%ADd+Allow_URL_Include%3d1"); actual != "\xadd allow_url_include=1" {
		t.Errorf("NormalizeQuery kept %q", actual)
	}
}

func TestParseRejectsInvalidRules(t *testing.T) {
	invalid := map[string]string{
		"trailing garbage": `{"version":1,"rules":[]}garbage`,
		"second document":  `{"version":1,"rules":[]}{"version":1}`,
		"trailing scalar":  `{"version":1,"rules":[]} false`,
		"version":          `{"version":2,"rules":[]}`,
		"unknown field":    `{"version":1,"rules":[{"id":"a","conditions":[{"target":"path","op":"contains","valeus":["x"]}]}]}`,
		"bad id":           `{"version":1,"rules":[{"id":"Bad ID","conditions":[{"target":"path","op":"contains","value":"x"}]}]}`,
		"bad action":       `{"version":1,"rules":[{"id":"a","action":"drop","conditions":[{"target":"path","op":"contains","value":"x"}]}]}`,
		"bad target":       `{"version":1,"rules":[{"id":"a","conditions":[{"target":"cookie","op":"contains","value":"x"}]}]}`,
		"bad op":           `{"version":1,"rules":[{"id":"a","conditions":[{"target":"path","op":"like","value":"x"}]}]}`,
		"bad regex":        `{"version":1,"rules":[{"id":"a","conditions":[{"target":"path","op":"regex","value":"(?<=x)"}]}]}`,
		"ttl":              `{"version":1,"rules":[{"id":"a","action":"ban","ttl":90000,"conditions":[{"target":"path","op":"contains","value":"x"}]}]}`,
		"no conditions":    `{"version":1,"rules":[{"id":"a","conditions":[]}]}`,
		"empty contains":   `{"version":1,"rules":[{"id":"a","conditions":[{"target":"path","op":"contains","value":""}]}]}`,
		"disabled bad":     `{"version":1,"rules":[{"id":"a","enabled":false,"conditions":[{"target":"path","op":"regex","value":"("}]}]}`,
	}
	for name, document := range invalid {
		if _, err := Parse([]byte(document)); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestConditionsNegationHeadersAndBodySkipping(t *testing.T) {
	document, err := Parse([]byte(`{"version":1,"rules":[
		{"id":"body-only","conditions":[{"target":"body","op":"contains","value":"x"}]},
		{"id":"logged","action":"log","conditions":[{"target":"header:x-probe","op":"equals","value":"1"}]},
		{"id":"empty-ua-post","conditions":[
			{"target":"method","op":"equals","value":"post"},
			{"target":"user_agent","op":"equals","value":""},
			{"target":"path","op":"prefix","values":["/webhooks/"],"negate":true}
		]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	set := newSet([]parsed{document})

	header := http.Header{"X-Probe": []string{"1"}}
	rule, logged := set.Match(Request{Method: "POST", URI: "/orders?x", Header: header})
	if rule == nil || rule.ID != "empty-ua-post" {
		t.Fatalf("expected empty-ua-post, got %+v", rule)
	}
	if len(logged) != 1 || logged[0].ID != "logged" {
		t.Fatalf("expected one log-only match, got %+v", logged)
	}
	if rule, _ := set.Match(Request{Method: "POST", URI: "/webhooks/stripe"}); rule != nil {
		t.Fatalf("negated prefix should exempt webhooks, got %s", rule.ID)
	}
	if rule, _ := set.Match(Request{Method: "GET", URI: "/", Header: http.Header{"User-Agent": []string{"x"}}}); rule != nil {
		t.Fatalf("body rules must not run before PHP, got %s", rule.ID)
	}
}

func TestLoaderKeepsLastValidFileAndHonoursDisable(t *testing.T) {
	directory := t.TempDir()
	local := filepath.Join(directory, "50-local.json")
	writeFile(t, local, `{"version":1,"rules":[{"id":"local-probe","conditions":[{"target":"path","op":"prefix","value":"/probe"}]}]}`)

	loader := NewLoader([]string{coreRulesPath, directory})
	if result := loader.Reload(); len(result.Errors) > 0 {
		t.Fatal(result.Errors)
	}
	if rule, _ := loader.Current().Match(Request{Method: "GET", URI: "/probe"}); rule == nil || rule.ID != "local-probe" {
		t.Fatal("local rule was not loaded")
	}

	// A broken edit must not drop the rules that were already enforced.
	writeFile(t, local, `{"version":1,"rules":[{"id":"local-probe"`)
	bump(t, local)
	if result := loader.Reload(); len(result.Errors) != 1 {
		t.Fatalf("expected one reload error, got %+v", result)
	}
	if rule, _ := loader.Current().Match(Request{Method: "GET", URI: "/probe"}); rule == nil {
		t.Fatal("last valid local rule was dropped")
	}
	if result := loader.Reload(); len(result.Errors) != 1 {
		t.Fatalf("unchanged invalid file stopped reporting its error: %+v", result)
	}

	writeFile(t, local, `{"version":1,"disable":["wordpress-probe"],"rules":[]}`)
	bump(t, local)
	if result := loader.Reload(); len(result.Errors) > 0 {
		t.Fatal(result.Errors)
	}
	if rule, _ := loader.Current().Match(Request{Method: "GET", URI: "/wp-login.php"}); rule != nil {
		t.Fatalf("disabled core rule still matched: %s", rule.ID)
	}
	if rule, _ := loader.Current().Match(Request{Method: "GET", URI: "/probe"}); rule != nil {
		t.Fatal("removed local rule still matched")
	}

	if err := os.Remove(local); err != nil {
		t.Fatal(err)
	}
	loader.Reload()
	if rule, _ := loader.Current().Match(Request{Method: "GET", URI: "/wp-login.php"}); rule == nil {
		t.Fatal("deleting the override file should restore the core rule")
	}
}

func TestMissingDirectoryIsNotAnError(t *testing.T) {
	result := NewLoader([]string{filepath.Join(t.TempDir(), "rules.d")}).Reload()
	if len(result.Errors) > 0 || result.Rules != 0 {
		t.Fatalf("unexpected result %+v", result)
	}
}

func TestUnavailableConfiguredRootsRetainTheirLastValidRules(t *testing.T) {
	for _, directory := range []bool{false, true} {
		name := "file"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "rules.d")
			if err := os.Mkdir(root, 0o755); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(root, "local.json")
			writeFile(t, file, `{"version":1,"rules":[{"id":"local","conditions":[{"target":"path","op":"equals","value":"/probe"}]}]}`)
			configured := file
			if directory {
				configured = root
			}
			loader := NewLoader([]string{configured})
			if result := loader.Reload(); len(result.Errors) != 0 || result.Rules != 1 {
				t.Fatalf("initial reload: %+v", result)
			}
			if err := os.Rename(configured, configured+".offline"); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if result := loader.Reload(); len(result.Errors) == 0 || result.Rules != 1 {
					t.Fatalf("unavailable root lost protection: %+v", result)
				}
				if rule, _ := loader.Current().Match(Request{URI: "/probe"}); rule == nil {
					t.Fatal("retained rule did not match")
				}
			}
			if err := os.Rename(configured+".offline", configured); err != nil {
				t.Fatal(err)
			}
			if directory {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if result := loader.Reload(); len(result.Errors) != 0 || result.Rules != 0 {
					t.Fatalf("intentional drop-in deletion was not applied: %+v", result)
				}
			}
		})
	}
}

func TestParseAcceptsOnlyWhitespaceAfterDocument(t *testing.T) {
	if _, err := Parse([]byte("{\"version\":1,\"rules\":[]} \n\t")); err != nil {
		t.Fatal(err)
	}
}

func TestSameSizeUpdateWithPreservedTimestampIsReloaded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.json")
	document := `{"version":1,"rules":[{"id":"local","conditions":[{"target":"path","op":"equals","value":"/before"}]}]}`
	writeFile(t, path, document)
	loader := NewLoader([]string{path})
	loader.Reload()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, strings.ReplaceAll(document, "/before", "/afterx"))
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if result := loader.Reload(); !result.Changed || len(result.Errors) != 0 {
		t.Fatalf("same-metadata content change was ignored: %+v", result)
	}
	if rule, _ := loader.Current().Match(Request{URI: "/afterx"}); rule == nil {
		t.Fatal("new rule was not activated")
	}
	if rule, _ := loader.Current().Match(Request{URI: "/before"}); rule != nil {
		t.Fatal("old rule is still active")
	}
}

func TestTooManyActiveRulesKeepThePreviousSetAndReportAnError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "00-keeper.json"), `{"version":1,"rules":[{"id":"keeper","conditions":[{"target":"path","op":"equals","value":"/keeper"}]}]}`)
	loader := NewLoader([]string{dir})
	loader.Reload()
	for file := 0; file < 5; file++ {
		rules := make([]map[string]any, maxRules)
		for index := range rules {
			rules[index] = map[string]any{"id": fmt.Sprintf("r-%d-%d", file, index), "conditions": []map[string]string{{"target": "path", "op": "equals", "value": "/probe"}}}
		}
		data, err := json.Marshal(map[string]any{"version": 1, "rules": rules})
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, fmt.Sprintf("%d.json", file)), string(data))
	}
	for i := 0; i < 2; i++ {
		if result := loader.Reload(); len(result.Errors) != 1 || result.Rules != 1 {
			t.Fatalf("oversized set was silently activated: %+v", result)
		}
		if rule, _ := loader.Current().Match(Request{URI: "/keeper"}); rule == nil {
			t.Fatal("previous set was not retained")
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// bump guarantees a visible change on filesystems with coarse timestamps.
func bump(t *testing.T, path string) {
	t.Helper()
	future := time.Now().Add(time.Duration(time.Now().UnixNano()%1000+1) * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}
