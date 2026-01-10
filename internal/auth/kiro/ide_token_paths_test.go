package kiro

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeWindowsPathToWSL(t *testing.T) {
	got := normalizeWindowsPathToWSL(`C:\Users\shiyi\.aws\sso\cache\kiro-auth-token.json`)
	want := "/mnt/c/Users/shiyi/.aws/sso/cache/kiro-auth-token.json"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFindWSLTokenFiles(t *testing.T) {
	root := t.TempDir()
	// Simulate /mnt/c/Users/<name>/.aws/sso/cache/kiro-auth-token.json
	fileA := filepath.Join(root, "alice", ".aws", "sso", "cache", "kiro-auth-token.json")
	fileB := filepath.Join(root, "bob", ".aws", "sso", "cache", "kiro-auth-token.json")
	if err := os.MkdirAll(filepath.Dir(fileA), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(fileB), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(fileA, []byte(`{"accessToken":"a","expiresAt":"2099-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(fileB, []byte(`{"accessToken":"b","expiresAt":"2099-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	paths, err := findWSLTokenFiles(root)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d: %#v", len(paths), paths)
	}
}

