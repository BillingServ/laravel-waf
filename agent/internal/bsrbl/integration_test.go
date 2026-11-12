package bsrbl

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Optional contract check against the standalone app, using only disposable
// storage and credentials. TLS and URL validation are tested separately above.
func TestBSRBLApplicationContract(t *testing.T) {
	app := os.Getenv("BSRBL_APP_ROOT")
	if app == "" {
		t.Skip("set BSRBL_APP_ROOT for the local PHP API contract test")
	}
	php, err := exec.LookPath("php")
	if err != nil {
		t.Fatal("PHP is required for the requested API contract test")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	url := "http://" + address
	scratch := t.TempDir()
	environment := []string{"PATH=/usr/bin:/bin", "TMPDIR=" + scratch, "BSABUSEIP_ENV=development", "BSABUSEIP_URL=" + url,
		"BSABUSEIP_STORAGE=" + filepath.Join(scratch, "data"), "BSABUSEIP_TRUSTED_PROXIES="}
	command := func(args ...string) *exec.Cmd {
		cmd := exec.Command(php, append([]string{"-n"}, args...)...)
		cmd.Dir = app
		cmd.Env = environment
		return cmd
	}
	setup := command("bin/console", "setup", "--username=fixture-admin", "--password-stdin")
	setup.Stdin = strings.NewReader("local-fixture-password-only")
	if err := setup.Run(); err != nil {
		t.Fatalf("fixture setup failed: %v", err)
	}
	output, err := command("bin/console", "key:create", "--name=go-fixture", "--scopes=read,report", "--days=0").Output()
	if err != nil {
		t.Fatalf("fixture key creation failed: %v", err)
	}
	var key string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "API key (shown once): ") {
			key = strings.TrimPrefix(line, "API key (shown once): ")
		}
	}
	if !keyPattern.MatchString(key) {
		t.Fatal("fixture key not returned")
	}
	server := command("-S", address, "-t", "public", "router.php")
	logs, err := os.Create(filepath.Join(scratch, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	server.Stdout, server.Stderr = logs, logs
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Process.Kill(); _ = server.Wait() }()
	client := &http.Client{Timeout: time.Second}
	ready := false
	for attempt := 0; attempt < 100; attempt++ {
		response, err := client.Get(url + "/")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("temporary PHP API did not become ready")
	}
	// This fixture uses isolated loopback HTTP. Production settings reject HTTP.
	r := &Reporter{client: &http.Client{Timeout: 5 * time.Second}}
	if err := r.post(context.Background(), Settings{URL: url, APIKey: key}, entry{IP: "38.244.29.125", Reason: "sig:env-vcs-probe"}); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, url+"/api/v1/feed", nil)
	request.Header.Set("Authorization", "Bearer "+key)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var feed struct {
		Version int              `json:"version"`
		Blocks  []map[string]any `json:"blocks"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&feed) != nil || feed.Version != 1 {
		t.Fatal("authenticated feed failed")
	}
	for _, record := range feed.Blocks {
		if record["ip"] == "38.244.29.125" {
			if value, present := record["expires_at"]; !present || value != nil {
				t.Fatal("reported block was not permanent")
			}
			return
		}
	}
	t.Fatal("reported IP missing from feed")
}
