package management

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	kiroauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/kiro"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func convertKiroIDETokenToAuthRecord(data []byte) (*coreauth.Auth, bool, error) {
	var token kiroauth.KiroTokenData
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, false, nil
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return nil, false, nil
	}

	if strings.TrimSpace(token.Email) == "" {
		token.Email = kiroauth.ExtractEmailFromJWT(token.AccessToken)
	}

	providerRaw := strings.TrimSpace(token.Provider)
	provider := kiroauth.SanitizeEmailForFilename(strings.ToLower(providerRaw))
	if provider == "" {
		provider = "imported"
	}

	idPart := kiroauth.SanitizeEmailForFilename(strings.TrimSpace(token.Email))
	if idPart == "" {
		idPart = kiroauth.SanitizeEmailForFilename(strings.TrimSpace(token.ProfileArn))
	}
	if idPart == "" {
		idPart = fmt.Sprintf("%d", time.Now().UnixNano()%100000)
	}

	fileName := fmt.Sprintf("kiro-%s-%s.json", provider, idPart)
	now := time.Now()
	source := "kiro-ide-import"

	expiresAt, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if err != nil {
		expiresAt = now.Add(1 * time.Hour)
	}
	record := &coreauth.Auth{
		ID:        fileName,
		Provider:  "kiro",
		FileName:  fileName,
		Label:     fmt.Sprintf("kiro-%s", provider),
		Status:    coreauth.StatusActive,
		CreatedAt: now,
		UpdatedAt: now,
		Metadata: map[string]any{
			"type":          "kiro",
			"access_token":  token.AccessToken,
			"refresh_token": token.RefreshToken,
			"profile_arn":   token.ProfileArn,
			"expires_at":    token.ExpiresAt,
			"auth_method":   token.AuthMethod,
			"provider":      token.Provider,
			"email":         token.Email,
			"last_refresh":  now.Format(time.RFC3339),
		},
		Attributes: map[string]string{
			"profile_arn": token.ProfileArn,
			"source":      source,
			"email":       token.Email,
		},
		NextRefreshAfter: expiresAt.Add(-5 * time.Minute),
	}

	return record, true, nil
}
