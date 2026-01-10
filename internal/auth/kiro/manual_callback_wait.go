package kiro

import (
	"context"
	"fmt"
	"strings"
)

func waitForOAuthCallback(
	ctx context.Context,
	expectedState string,
	defaultRedirectURI string,
	waitFn func(context.Context) (*AuthCallback, error),
	promptFn func(string) (string, error),
) (*AuthCallback, string, error) {
	if waitFn == nil {
		return nil, "", fmt.Errorf("missing wait function")
	}
	if strings.TrimSpace(defaultRedirectURI) == "" {
		return nil, "", fmt.Errorf("missing default redirect URI")
	}

	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		cb          *AuthCallback
		redirectURI string
		err         error
	}

	resultChan := make(chan result, 2)

	go func() {
		cb, err := waitFn(waitCtx)
		resultChan <- result{cb: cb, redirectURI: defaultRedirectURI, err: err}
	}()

	if promptFn != nil {
		go func() {
			raw, err := promptFn("Paste the full callback URL (or code=...&state=...), or press Enter to keep waiting: ")
			if err != nil {
				resultChan <- result{err: err}
				return
			}
			if raw == "" {
				return
			}
			cb, redirectURI, err := parseAndValidateCallbackInput(expectedState, raw)
			if err != nil {
				resultChan <- result{err: err}
				return
			}
			if redirectURI == "" {
				redirectURI = defaultRedirectURI
			}
			resultChan <- result{cb: cb, redirectURI: redirectURI}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case r := <-resultChan:
			if r.err != nil {
				// If the protocol handler wait returned due to cancellation, keep waiting for manual input
				// unless the parent context is done.
				if promptFn != nil && waitCtx.Err() != nil && ctx.Err() == nil {
					continue
				}
				return nil, "", r.err
			}
			if r.cb == nil {
				return nil, "", fmt.Errorf("missing callback result")
			}
			cancel()
			return r.cb, r.redirectURI, nil
		}
	}
}
