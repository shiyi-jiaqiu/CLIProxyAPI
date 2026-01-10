package kiro

import "testing"

func TestParseAndValidateCallbackInput_StateMismatch(t *testing.T) {
	_, _, err := parseAndValidateCallbackInput("expected", "http://127.0.0.1:11123/oauth/callback?code=abc&state=other")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseAndValidateCallbackInput_OK(t *testing.T) {
	cb, redirectURI, err := parseAndValidateCallbackInput("st1", "http://127.0.0.1:11123/oauth/callback?code=abc&state=st1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cb == nil || cb.Code != "abc" || cb.State != "st1" || cb.Error != "" {
		t.Fatalf("unexpected callback: %#v", cb)
	}
	if redirectURI != "http://127.0.0.1:11123/oauth/callback" {
		t.Fatalf("unexpected redirect URI: %q", redirectURI)
	}
}

