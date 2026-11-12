package bsrbl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey() string { return "bsai_" + strings.Repeat("a", 16) + "_" + strings.Repeat("b", 64) }

func cleanEnvironment(t *testing.T) {
	t.Helper()
	for _, prefix := range []string{"LARAVEL_WAF_BSRBL_", "LARAVEL_WAF_BSABUSEIP_"} {
		for _, suffix := range []string{"URL", "API_KEY", "REPORT_ENABLED"} {
			t.Setenv(prefix+suffix, "")
			_ = os.Unsetenv(prefix + suffix)
		}
	}
}

func TestConfigIsOptInLiteralAndReloaded(t *testing.T) {
	cleanEnvironment(t)
	path := filepath.Join(t.TempDir(), "bsrbl.env")
	settings, err := ReadSettings(path)
	if err != nil || settings.Enabled {
		t.Fatalf("missing config should disable reporting: %v", err)
	}
	body := "UNRELATED=$(touch should-not-exist)\nexport LARAVEL_WAF_BSRBL_URL='https://rbl.example/' # comment\nLARAVEL_WAF_BSRBL_API_KEY=\"" + testKey() + "\"\nLARAVEL_WAF_BSRBL_REPORT_ENABLED=true\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	settings, err = ReadSettings(path)
	if err != nil || !settings.Enabled || settings.URL != "https://rbl.example" || settings.APIKey != testKey() {
		t.Fatalf("unexpected settings: enabled=%v err=%v", settings.Enabled, err)
	}
	if err := os.WriteFile(path, []byte("LARAVEL_WAF_BSRBL_REPORT_ENABLED=false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	settings, err = ReadSettings(path)
	if err != nil || settings.Enabled {
		t.Fatalf("changed config was not reloaded: %v", err)
	}
}

func TestConfigRejectsUnsafeEndpointsAndKeepsKeysOutOfErrors(t *testing.T) {
	cleanEnvironment(t)
	for _, endpoint := range []string{"http://rbl.example", "https://user:pass@rbl.example", "https://rbl.example/api", "https://rbl.example?key=" + testKey(), "https://rbl.example#fragment"} {
		t.Run(endpoint[:min(len(endpoint), 30)], func(t *testing.T) {
			t.Setenv("LARAVEL_WAF_BSRBL_URL", endpoint)
			t.Setenv("LARAVEL_WAF_BSRBL_API_KEY", testKey())
			t.Setenv("LARAVEL_WAF_BSRBL_REPORT_ENABLED", "true")
			_, err := ReadSettings("")
			if err == nil || strings.Contains(err.Error(), testKey()) {
				t.Fatal("unsafe endpoint accepted or key leaked")
			}
		})
	}
}

func TestConfigPrecedenceAndLegacyCompatibility(t *testing.T) {
	cleanEnvironment(t)
	path := filepath.Join(t.TempDir(), "bsrbl.env")
	old := "LARAVEL_WAF_BSABUSEIP_URL=https://old.example\nLARAVEL_WAF_BSABUSEIP_API_KEY=" + testKey() + "\nLARAVEL_WAF_BSABUSEIP_REPORT_ENABLED=true\n"
	_ = os.WriteFile(path, []byte(old), 0600)
	settings, err := ReadSettings(path)
	if err != nil || !settings.Enabled || settings.URL != "https://old.example" {
		t.Fatalf("legacy config failed: %v", err)
	}
	t.Setenv("LARAVEL_WAF_BSRBL_URL", "https://new.example")
	t.Setenv("LARAVEL_WAF_BSRBL_REPORT_ENABLED", "true")
	if _, err := ReadSettings(path); err == nil {
		t.Fatal("mixed a new URL with the legacy API key")
	}
	t.Setenv("LARAVEL_WAF_BSRBL_API_KEY", testKey())
	settings, err = ReadSettings(path)
	if err != nil || settings.URL != "https://new.example" {
		t.Fatalf("new config failed: %v", err)
	}
}

func TestConfigRejectsNonRegularAndOversizedFiles(t *testing.T) {
	cleanEnvironment(t)
	if _, err := ReadSettings(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	path := filepath.Join(t.TempDir(), "large.env")
	_ = os.WriteFile(path, []byte(strings.Repeat("x", (1<<20)+1)), 0600)
	if _, err := ReadSettings(path); err == nil {
		t.Fatal("oversized config accepted")
	}
}
