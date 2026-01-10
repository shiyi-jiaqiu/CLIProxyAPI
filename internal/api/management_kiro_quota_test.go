package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	gin "github.com/gin-gonic/gin"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	proxyusage "github.com/router-for-me/CLIProxyAPI/v6/internal/usage"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func TestManagementRefreshKiroQuota(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-password")

	gin.SetMode(gin.TestMode)

	tmpDir := t.TempDir()
	authDir := filepath.Join(tmpDir, "auth")
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		t.Fatalf("failed to create auth dir: %v", err)
	}

	var upstreamCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "daysUntilReset": 3,
  "usageBreakdownList": [
    { "usageLimit": 100, "currentUsage": 12, "unit": "credit" }
  ]
}`))
	}))
	t.Cleanup(upstream.Close)

	cfg := &proxyconfig.Config{
		SDKConfig: sdkconfig.SDKConfig{
			APIKeys: []string{"test-key"},
		},
		Port:                   0,
		AuthDir:                authDir,
		Debug:                  true,
		LoggingToFile:          false,
		UsageStatisticsEnabled: false,
	}

	authManager := coreauth.NewManager(nil, nil, nil)
	accessManager := sdkaccess.NewManager()
	configPath := filepath.Join(tmpDir, "config.yaml")
	server := NewServer(cfg, authManager, accessManager, configPath)

	_, _ = authManager.Register(nil, &coreauth.Auth{
		ID:       "kiro-1",
		Provider: "kiro",
		Attributes: map[string]string{
			"path":     "does-not-exist.json",
			"base_url": upstream.URL,
		},
		Metadata: map[string]any{
			"access_token": "test-access-token",
			"auth_method":  "builder-id",
		},
	})
	t.Cleanup(func() {
		// Avoid global shared state affecting other tests.
		proxyusage.DeleteKiroUsageSnapshot("kiro-1")
	})

	reqBody := []byte(`{"id":"kiro-1"}`)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/kiro-quota", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-management-password")

	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status=200, got %d: %s", rr.Code, rr.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected json response, got error: %v; body=%s", err, rr.Body.String())
	}
	authObj, ok := payload["auth"].(map[string]any)
	if !ok || authObj == nil {
		t.Fatalf("expected auth object, got: %#v", payload["auth"])
	}
	if _, ok := authObj["kiro_usage"]; !ok {
		t.Fatalf("expected kiro_usage in response auth, got keys: %#v", authObj)
	}
	if upstreamCalls == 0 {
		t.Fatalf("expected upstream to be called at least once")
	}
}
