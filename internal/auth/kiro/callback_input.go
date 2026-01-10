package kiro

import (
	"fmt"
	"net/url"
	"strings"
)

// parseOAuthCallbackInput parses an OAuth callback value copied from a browser.
// It accepts either:
// - a full URL (e.g. http://127.0.0.1:11123/oauth/callback?code=...&state=...)
// - a kiro:// URL (e.g. kiro://kiro.kiroAgent/authenticate-success?code=...&state=...)
// - a raw query string (e.g. code=...&state=...)
//
// It returns (code, state, errorParam, redirectURI).
func parseOAuthCallbackInput(raw string) (string, string, string, string, error) {
	input := strings.TrimSpace(raw)
	if input == "" {
		return "", "", "", "", fmt.Errorf("empty callback input")
	}

	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") || strings.HasPrefix(input, "kiro://") {
		parsedURL, err := url.Parse(input)
		if err != nil {
			return "", "", "", "", fmt.Errorf("invalid callback URL: %w", err)
		}
		code := parsedURL.Query().Get("code")
		state := parsedURL.Query().Get("state")
		errParam := parsedURL.Query().Get("error")
		if errParam != "" {
			redirectURI := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
			return "", state, errParam, redirectURI, nil
		}
		if code == "" {
			return "", "", "", "", fmt.Errorf("missing code in callback")
		}
		if state == "" {
			return "", "", "", "", fmt.Errorf("missing state in callback")
		}
		redirectURI := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
		return code, state, errParam, redirectURI, nil
	}

	// Query-string only form.
	values, err := url.ParseQuery(input)
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid callback query: %w", err)
	}
	code := values.Get("code")
	state := values.Get("state")
	errParam := values.Get("error")
	if errParam != "" {
		return "", state, errParam, "", nil
	}
	if code == "" {
		return "", "", "", "", fmt.Errorf("missing code in callback")
	}
	if state == "" {
		return "", "", "", "", fmt.Errorf("missing state in callback")
	}
	return code, state, errParam, "", nil
}

func parseAndValidateCallbackInput(expectedState string, raw string) (*AuthCallback, string, error) {
	code, state, errParam, redirectURI, err := parseOAuthCallbackInput(raw)
	if err != nil {
		return nil, "", err
	}
	if expectedState != "" && state != "" && state != expectedState {
		return nil, "", fmt.Errorf("state mismatch")
	}
	return &AuthCallback{
		Code:  code,
		State: state,
		Error: errParam,
	}, redirectURI, nil
}
