package unixsocket

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListenRejectsRelativePath(t *testing.T) {
	if _, err := Listen("agent.sock", "", "agent"); err == nil {
		t.Fatal("expected a relative socket path to be rejected")
	}
}

func TestListenRefusesToReplaceNonSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.sock")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatalf("create protected path: %v", err)
	}

	if _, err := Listen(path, "", "agent"); err == nil {
		t.Fatal("expected a non-socket path to be preserved")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read protected path: %v", err)
	}
	if string(contents) != "keep" {
		t.Fatalf("protected path was changed: %q", contents)
	}
}

func TestListenCreatesPrivateSocket(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "waf-socket-")
	if err != nil {
		t.Fatalf("create socket directory: %v", err)
	}
	defer os.RemoveAll(directory)

	path := filepath.Join(directory, "agent.sock")
	listener, err := Listen(path, "", "agent")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	defer os.Remove(path)

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("inspect socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected a Unix socket, got %v", info.Mode())
	}
	if info.Mode().Perm() != 0660 {
		t.Fatalf("expected socket permissions 0660, got %04o", info.Mode().Perm())
	}
}
