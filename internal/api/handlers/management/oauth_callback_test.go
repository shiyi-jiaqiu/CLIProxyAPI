package management

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

func TestPostOAuthCallback_KiroAuthURLSessionIsStillPending(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	h := &Handler{cfg: &config.Config{AuthDir: authDir}}

	state := "kiro-test-state"
	RegisterOAuthSession(state, "kiro")
	SetOAuthSessionError(state, "auth_url|https://example.com/login")
	t.Cleanup(func() { CompleteOAuthSession(state) })

	body, err := json.Marshal(map[string]any{
		"provider": "kiro",
		"state":    state,
		"code":     "abc123",
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	router := gin.New()
	router.POST("/oauth-callback", h.PostOAuthCallback)

	req := httptest.NewRequest(http.MethodPost, "/oauth-callback", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	callbackFile := filepath.Join(authDir, ".oauth-kiro-"+state+".oauth")
	data, err := os.ReadFile(callbackFile)
	if err != nil {
		t.Fatalf("expected callback file %s: %v", callbackFile, err)
	}

	var payload map[string]string
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal callback payload: %v", err)
	}
	if payload["state"] != state {
		t.Fatalf("expected state %q, got %q", state, payload["state"])
	}
	if payload["code"] != "abc123" {
		t.Fatalf("expected code %q, got %q", "abc123", payload["code"])
	}
}
