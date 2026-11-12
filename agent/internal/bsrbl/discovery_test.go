package bsrbl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindEnvFileChoosesConfiguredApplication(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "site")
	rule := filepath.Join(app, "vendor/billingserv/laravel-waf/resources/rules/core.json")
	for _, signatures := range [][]string{
		{rule, "/etc/laravel-waf/rules.d"},
		{rule, filepath.Join(app, "vendor/billingserv/laravel-waf/resources/rules/extra.json")},
		{"vendor/billingserv/laravel-waf/resources/rules/core.json"},
	} {
		path, err := FindEnvFile("", signatures, "/usr/local/bin/lwafd", app)
		if err != nil || path != filepath.Join(app, ".env") {
			t.Fatalf("wrong application selected: path=%s err=%v", path, err)
		}
	}
	// Do not silently choose a second application's credentials when multiple
	// Composer roots are configured, even if one has a missing .env.
	other := filepath.Join(root, "other/vendor/billingserv/laravel-waf/resources/rules/core.json")
	if _, err := FindEnvFile("", []string{rule, other}, "", app); err == nil {
		t.Fatal("ambiguous application accepted")
	}
	explicit := filepath.Join(root, "chosen", ".env")
	path, err := FindEnvFile(explicit, []string{rule, other}, "", app)
	if err != nil || path != explicit {
		t.Fatalf("explicit selection failed: %v", err)
	}
	if _, err := FindEnvFile("relative/.env", nil, "", app); err == nil {
		t.Fatal("relative explicit path accepted")
	}
}

func TestFindEnvFileFallbacksRequireApplicationEvidence(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "site")
	if err := os.MkdirAll(app, 0700); err != nil {
		t.Fatal(err)
	}
	// An arbitrary directory containing a .env is not enough to identify Laravel.
	if err := os.WriteFile(filepath.Join(app, ".env"), []byte("UNRELATED=secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	paths := []string{"/etc/laravel-waf/rules.d", "/var/www/site/vendor/billingserv/laravel-waf-other/rules.json"}
	path, err := FindEnvFile("", paths, "/usr/local/bin/lwafd", app)
	if err != nil || path != "" {
		t.Fatalf("unrelated .env selected: path=%s err=%v", path, err)
	}
	for _, marker := range []string{"artisan", "composer.json"} {
		if err := os.WriteFile(filepath.Join(app, marker), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	path, err = FindEnvFile("", nil, "/usr/local/bin/lwafd", filepath.Join(app, "storage", "logs"))
	if err != nil || path != filepath.Join(app, ".env") {
		t.Fatalf("Laravel working directory not found: path=%s err=%v", path, err)
	}
	path, err = FindEnvFile("", nil, filepath.Join(app, "vendor/billingserv/laravel-waf/agent/bin/lwafd"), "/")
	if err != nil || path != filepath.Join(app, ".env") {
		t.Fatalf("Composer executable not found: path=%s err=%v", path, err)
	}
}

func TestLaravelEnvFollowsReleaseSwitchesAndKeyChanges(t *testing.T) {
	cleanEnvironment(t)
	root := t.TempDir()
	writeRelease := func(name, domain, key string) string {
		t.Helper()
		directory := filepath.Join(root, name)
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		body := "APP_NAME=\"A Laravel application\"\nAPP_KEY=base64:unrelated\nUNRELATED=${NOT_EXPANDED}\nLARAVEL_WAF_BSRBL_URL=" + domain + "\nLARAVEL_WAF_BSRBL_API_KEY=" + key + "\nLARAVEL_WAF_BSRBL_REPORT_ENABLED=true\n"
		if err := os.WriteFile(filepath.Join(directory, ".env"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return directory
	}
	first := writeRelease("release-one", "https://first.example", testKey())
	link := filepath.Join(root, "current")
	if err := os.Symlink(first, link); err != nil {
		t.Fatal(err)
	}
	path, err := FindEnvFile("", []string{filepath.Join(link, "vendor/billingserv/laravel-waf/resources/rules/core.json")}, "", "")
	if err != nil || path != filepath.Join(link, ".env") {
		t.Fatalf("stable symlink lost: path=%s err=%v", path, err)
	}
	settings, err := ReadSettings(path)
	if err != nil || !settings.Enabled || settings.URL != "https://first.example" || settings.APIKey != testKey() {
		t.Fatalf("initial Laravel settings failed: %v", err)
	}
	rotatedKey := "bsai_" + strings.Repeat("c", 16) + "_" + strings.Repeat("d", 64)
	second := writeRelease("release-two", "https://second.example", rotatedKey)
	if err := os.Symlink(second, link+".new"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(link+".new", link); err != nil {
		t.Fatal(err)
	}
	settings, err = ReadSettings(path)
	if err != nil || !settings.Enabled || settings.URL != "https://second.example" || settings.APIKey != rotatedKey {
		t.Fatalf("updated Laravel settings not reloaded: %v", err)
	}
}
