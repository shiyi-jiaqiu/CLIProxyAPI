package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestFetchKiroUsageLimits_UsesResourceTypeForNonSocialAuth(t *testing.T) {
	var gotQuery url.Values
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"usageBreakdownList":[{"usageLimit":100,"currentUsage":1,"unit":"credit"}]}`))
	}))
	t.Cleanup(upstream.Close)

	auth := &coreauth.Auth{
		ID:       "kiro-1",
		Provider: "kiro",
		Attributes: map[string]string{
			"base_url":         upstream.URL,
			"agent_task_type":  "AGENTIC_REQUEST",
			"access_token":     "token-from-attrs",
		},
		Metadata: map[string]any{
			"auth_method": "builder-id",
		},
	}

	snap, err := FetchKiroUsageLimits(context.Background(), auth, &sdkconfig.Config{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if snap == nil {
		t.Fatalf("expected snapshot")
	}
	if got := gotQuery.Get("origin"); got != "AI_EDITOR" {
		t.Fatalf("expected origin=AI_EDITOR, got %q", got)
	}
	if got := gotQuery.Get("resourceType"); got != "AGENTIC_REQUEST" {
		t.Fatalf("expected resourceType=AGENTIC_REQUEST, got %q", got)
	}
	if got := gotQuery.Get("profileArn"); got != "" {
		t.Fatalf("expected no profileArn for non-social auth, got %q", got)
	}
}

func TestFetchKiroUsageLimits_UsesProfileArnForSocialAuth(t *testing.T) {
	var gotQuery url.Values
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"daysUntilReset":7}`))
	}))
	t.Cleanup(upstream.Close)

	auth := &coreauth.Auth{
		ID:       "kiro-2",
		Provider: "kiro",
		Attributes: map[string]string{
			"base_url": upstream.URL,
		},
		Metadata: map[string]any{
			"access_token": "token-from-metadata",
			"auth_method":  "social",
			"profile_arn":  "arn:aws:codewhisperer:us-east-1:123:profile/ABC",
		},
	}

	_, err := FetchKiroUsageLimits(context.Background(), auth, &sdkconfig.Config{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got := gotQuery.Get("profileArn"); got != "arn:aws:codewhisperer:us-east-1:123:profile/ABC" {
		t.Fatalf("expected profileArn to be included, got %q", got)
	}
	if got := gotQuery.Get("resourceType"); got != "" {
		t.Fatalf("expected no resourceType for social auth, got %q", got)
	}
}

func TestFetchKiroUsageLimits_ReturnsBannedReasonWhenPresent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason":"ACCOUNT_BANNED"}`))
	}))
	t.Cleanup(upstream.Close)

	auth := &coreauth.Auth{
		ID:       "kiro-3",
		Provider: "kiro",
		Attributes: map[string]string{
			"base_url":     upstream.URL,
			"access_token": "token",
		},
		Metadata: map[string]any{
			"auth_method": "builder-id",
		},
	}

	_, err := FetchKiroUsageLimits(context.Background(), auth, &sdkconfig.Config{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "banned") || !strings.Contains(err.Error(), "ACCOUNT_BANNED") {
		t.Fatalf("expected banned reason in error, got: %v", err)
	}
}

