package kiro

import (
	"context"
	"testing"
	"time"
)

func TestWaitForOAuthCallback_UsesManualInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	waitFn := func(waitCtx context.Context) (*AuthCallback, error) {
		<-waitCtx.Done()
		return nil, waitCtx.Err()
	}
	promptFn := func(prompt string) (string, error) {
		return "http://127.0.0.1:11123/oauth/callback?code=abc&state=st1", nil
	}

	cb, redirectURI, err := waitForOAuthCallback(ctx, "st1", "http://127.0.0.1:11123/oauth/callback", waitFn, promptFn)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cb == nil || cb.Code != "abc" || cb.State != "st1" || cb.Error != "" {
		t.Fatalf("unexpected callback: %#v", cb)
	}
	if redirectURI != "http://127.0.0.1:11123/oauth/callback" {
		t.Fatalf("unexpected redirectURI: %q", redirectURI)
	}
}
