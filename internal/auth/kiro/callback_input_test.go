package kiro

import "testing"

func TestParseOAuthCallbackInput_HTTPURL(t *testing.T) {
	code, state, errParam, redirectURI, err := parseOAuthCallbackInput("http://127.0.0.1:11123/oauth/callback?code=abc123&state=st1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if code != "abc123" {
		t.Fatalf("expected code %q, got %q", "abc123", code)
	}
	if state != "st1" {
		t.Fatalf("expected state %q, got %q", "st1", state)
	}
	if errParam != "" {
		t.Fatalf("expected empty error param, got %q", errParam)
	}
	if redirectURI != "http://127.0.0.1:11123/oauth/callback" {
		t.Fatalf("expected redirectURI %q, got %q", "http://127.0.0.1:11123/oauth/callback", redirectURI)
	}
}

func TestParseOAuthCallbackInput_KiroURL(t *testing.T) {
	input := "kiro://kiro.kiroAgent/authenticate-success?code=c1&state=s1"
	code, state, errParam, redirectURI, err := parseOAuthCallbackInput(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if code != "c1" || state != "s1" || errParam != "" {
		t.Fatalf("unexpected parse result: code=%q state=%q err=%q", code, state, errParam)
	}
	if redirectURI != "kiro://kiro.kiroAgent/authenticate-success" {
		t.Fatalf("expected redirectURI %q, got %q", "kiro://kiro.kiroAgent/authenticate-success", redirectURI)
	}
}

func TestParseOAuthCallbackInput_QueryOnly(t *testing.T) {
	code, state, errParam, redirectURI, err := parseOAuthCallbackInput("code=abc&state=st2")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if code != "abc" || state != "st2" || errParam != "" {
		t.Fatalf("unexpected parse result: code=%q state=%q err=%q", code, state, errParam)
	}
	if redirectURI != "" {
		t.Fatalf("expected empty redirectURI, got %q", redirectURI)
	}
}

func TestParseOAuthCallbackInput_MissingCode(t *testing.T) {
	_, _, _, _, err := parseOAuthCallbackInput("http://127.0.0.1:11123/oauth/callback?state=st1")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseOAuthCallbackInput_ErrorOnly(t *testing.T) {
	code, state, errParam, redirectURI, err := parseOAuthCallbackInput("http://127.0.0.1:11123/oauth/callback?error=access_denied")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if code != "" {
		t.Fatalf("expected empty code, got %q", code)
	}
	if state != "" {
		t.Fatalf("expected empty state, got %q", state)
	}
	if errParam != "access_denied" {
		t.Fatalf("expected error param %q, got %q", "access_denied", errParam)
	}
	if redirectURI != "http://127.0.0.1:11123/oauth/callback" {
		t.Fatalf("expected redirectURI %q, got %q", "http://127.0.0.1:11123/oauth/callback", redirectURI)
	}
}
