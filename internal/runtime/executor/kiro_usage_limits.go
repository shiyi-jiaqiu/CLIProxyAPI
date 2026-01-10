package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/usage"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type kiroUsageLimitsResponse struct {
	DaysUntilReset    *int     `json:"daysUntilReset,omitempty"`
	NextDateReset     *float64 `json:"nextDateReset,omitempty"`
	UserInfo          *struct {
		Email  *string `json:"email,omitempty"`
		UserID *string `json:"userId,omitempty"`
	} `json:"userInfo,omitempty"`
	SubscriptionInfo *struct {
		Title *string `json:"subscriptionTitle,omitempty"`
		Type  *string `json:"type,omitempty"`
	} `json:"subscriptionInfo,omitempty"`
	UsageBreakdownList []struct {
		ResourceType *string `json:"resourceType,omitempty"`
		Unit         *string `json:"unit,omitempty"`
		UsageLimit   *int    `json:"usageLimit,omitempty"`
		CurrentUsage *int    `json:"currentUsage,omitempty"`
	} `json:"usageBreakdownList,omitempty"`
}

func fetchKiroAccessToken(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["access_token"].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["access_token"]); v != "" {
			return v
		}
	}
	return ""
}

func fetchKiroProfileArn(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["profile_arn"].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["profile_arn"]); v != "" {
			return v
		}
	}
	return ""
}

func fetchKiroAuthMethod(auth *cliproxyauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	if v, ok := auth.Metadata["auth_method"].(string); ok {
		return strings.ToLower(strings.TrimSpace(v))
	}
	return ""
}

func kiroUsageBaseURL(auth *cliproxyauth.Auth) string {
	if auth != nil && auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["usage_base_url"]); v != "" {
			return v
		}
		if v := strings.TrimSpace(auth.Attributes["base_url"]); v != "" {
			return v
		}
	}
	return "https://codewhisperer.us-east-1.amazonaws.com"
}

// FetchKiroUsageLimits queries CodeWhisperer /getUsageLimits and returns a parsed snapshot.
// This is best-effort observability for Kiro IDE quota information.
func FetchKiroUsageLimits(ctx context.Context, auth *cliproxyauth.Auth, cfg *config.Config) (*usage.KiroUsageSnapshot, error) {
	accessToken := fetchKiroAccessToken(auth)
	if accessToken == "" {
		return nil, fmt.Errorf("kiro quota: missing access token")
	}

	baseURL := strings.TrimRight(kiroUsageBaseURL(auth), "/")
	u, err := url.Parse(baseURL + "/getUsageLimits")
	if err != nil {
		return nil, fmt.Errorf("kiro quota: invalid base url: %w", err)
	}
	q := u.Query()
	q.Set("isEmailRequired", "true")
	q.Set("origin", "AI_EDITOR")

	authMethod := fetchKiroAuthMethod(auth)
	if authMethod == "social" {
		profileArn := fetchKiroProfileArn(auth)
		if profileArn == "" {
			return nil, fmt.Errorf("kiro quota: missing profile arn for social auth")
		}
		q.Set("profileArn", profileArn)
	} else {
		resourceType := ""
		if auth != nil && auth.Attributes != nil {
			resourceType = strings.TrimSpace(auth.Attributes["agent_task_type"])
		}
		if resourceType == "" {
			resourceType = "AGENTIC_REQUEST"
		}
		q.Set("resourceType", resourceType)
	}
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", kiroIDEUserAgent)
	httpReq.Header.Set("X-Amz-User-Agent", kiroIDEAmzUserAgent)
	httpReq.Header.Set("Amz-Sdk-Invocation-Id", uuid.NewString())
	httpReq.Header.Set("Amz-Sdk-Request", "attempt=1; max=1")
	httpReq.Header.Set("Connection", "close")

	httpClient := newProxyAwareHTTPClient(ctx, cfg, auth, 30*time.Second)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = httpResp.Body.Close() }()

	raw, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		var reasonHolder struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(raw, &reasonHolder) == nil && strings.TrimSpace(reasonHolder.Reason) != "" {
			return nil, fmt.Errorf("kiro quota: banned: %s", strings.TrimSpace(reasonHolder.Reason))
		}
		return nil, statusErr{code: httpResp.StatusCode, msg: string(raw)}
	}

	var resp kiroUsageLimitsResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("kiro quota: parse response failed: %w", err)
	}

	snap := &usage.KiroUsageSnapshot{
		DaysUntilReset: resp.DaysUntilReset,
		NextDateReset:  resp.NextDateReset,
	}
	if resp.UserInfo != nil {
		snap.UserInfo = &usage.KiroUserInfo{
			Email:  resp.UserInfo.Email,
			UserID: resp.UserInfo.UserID,
		}
	}
	if resp.SubscriptionInfo != nil {
		snap.Subscription = &usage.KiroSubscriptionInfo{
			Title: resp.SubscriptionInfo.Title,
			Type:  resp.SubscriptionInfo.Type,
		}
	}
	if len(resp.UsageBreakdownList) > 0 {
		snap.Breakdowns = make([]usage.KiroUsageBreakdown, 0, len(resp.UsageBreakdownList))
		for _, item := range resp.UsageBreakdownList {
			snap.Breakdowns = append(snap.Breakdowns, usage.KiroUsageBreakdown{
				ResourceType: item.ResourceType,
				Unit:         item.Unit,
				UsageLimit:   item.UsageLimit,
				CurrentUsage: item.CurrentUsage,
			})
		}
	}
	return snap, nil
}

