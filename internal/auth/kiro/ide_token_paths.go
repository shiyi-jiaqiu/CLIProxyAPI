package kiro

import (
	"os"
	"path/filepath"
	"strings"
)

func normalizeWindowsPathToWSL(path string) string {
	trimmed := strings.TrimSpace(path)
	if len(trimmed) < 3 {
		return trimmed
	}
	if trimmed[1] != ':' {
		return trimmed
	}

	drive := trimmed[0]
	sep := trimmed[2]
	if sep != '\\' && sep != '/' {
		return trimmed
	}

	rest := trimmed[3:]
	rest = strings.ReplaceAll(rest, "\\", "/")
	rest = strings.TrimPrefix(rest, "/")
	return "/mnt/" + strings.ToLower(string(drive)) + "/" + rest
}

func findWSLTokenFiles(usersRoot string) ([]string, error) {
	entries, err := os.ReadDir(usersRoot)
	if err != nil {
		return nil, err
	}

	var matches []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(usersRoot, entry.Name(), ".aws", "sso", "cache", "kiro-auth-token.json")
		if st, err := os.Stat(candidate); err == nil && st != nil && !st.IsDir() {
			matches = append(matches, candidate)
		}
	}
	return matches, nil
}

