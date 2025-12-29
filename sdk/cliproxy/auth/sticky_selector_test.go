package auth

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

func TestExtractStickySessionKey_PriorityOrder(t *testing.T) {
	headers := make(http.Header)
	headers.Set("session_id", "s123")
	headers.Set("Authorization", "Bearer api-key-1")
	headers.Set("User-Agent", "ua-test")
	opts := cliproxyexecutor.Options{
		Headers:         headers,
		OriginalRequest: []byte(`{"metadata":{"user_id":"user_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_account__session_11111111-2222-3333-4444-555555555555"}}`),
	}

	key := extractStickySessionKey(opts)
	if key == "" {
		t.Fatal("expected non-empty session key")
	}
	if !strings.HasPrefix(key, "codex:") {
		t.Fatalf("expected codex session_id to take priority, got %q", key)
	}

	opts.Headers.Del("session_id")
	key = extractStickySessionKey(opts)
	if !strings.HasPrefix(key, "claude:") {
		t.Fatalf("expected claude metadata.user_id to be used, got %q", key)
	}

	opts.OriginalRequest = []byte(`{"metadata":{"user_id":"not-a-match"}}`)
	key = extractStickySessionKey(opts)
	if !strings.HasPrefix(key, "apikey:") {
		t.Fatalf("expected api key fallback, got %q", key)
	}

	opts.Headers.Del("authorization")
	key = extractStickySessionKey(opts)
	if !strings.HasPrefix(key, "ua:") {
		t.Fatalf("expected user-agent fallback, got %q", key)
	}
}

func TestStickySelector_FailoverUpdatesBinding(t *testing.T) {
	sel := &StickySelector{}
	model := "gpt-test"
	provider := "codex"

	auth1 := &Auth{ID: "a", Provider: provider, Status: StatusActive}
	auth2 := &Auth{ID: "b", Provider: provider, Status: StatusActive}
	auths := []*Auth{auth1, auth2}

	headers := make(http.Header)
	headers.Set("session_id", "s123")
	opts := cliproxyexecutor.Options{Headers: headers, OriginalRequest: []byte(`{}`)}

	first, err := sel.Pick(nil, provider, model, opts, auths)
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	if first == nil || first.ID == "" {
		t.Fatalf("expected auth selection, got %#v", first)
	}

	var cooled *Auth
	var other *Auth
	if first.ID == auth1.ID {
		cooled = auth1
		other = auth2
	} else {
		cooled = auth2
		other = auth1
	}

	now := time.Now()
	cooled.ModelStates = map[string]*ModelState{
		model: {
			Unavailable:    true,
			NextRetryAfter: now.Add(30 * time.Minute),
			Quota: QuotaState{
				Exceeded:      true,
				NextRecoverAt: now.Add(30 * time.Minute),
			},
		},
	}

	second, err := sel.Pick(nil, provider, model, opts, auths)
	if err != nil {
		t.Fatalf("Pick (after cooldown): %v", err)
	}
	if second == nil {
		t.Fatal("expected auth selection after cooldown")
	}
	if second.ID != other.ID {
		t.Fatalf("expected failover to %q, got %q", other.ID, second.ID)
	}

	cooled.ModelStates = nil
	third, err := sel.Pick(nil, provider, model, opts, auths)
	if err != nil {
		t.Fatalf("Pick (after recovery): %v", err)
	}
	if third == nil {
		t.Fatal("expected auth selection after recovery")
	}
	if third.ID != other.ID {
		t.Fatalf("expected binding to remain on failover auth %q, got %q", other.ID, third.ID)
	}
}

func TestStickySelector_PriorityBeatsRendezvous(t *testing.T) {
	sel := &StickySelector{}
	model := "gpt-test"
	provider := "codex"

	high := &Auth{ID: "high", Provider: provider, Status: StatusActive, Metadata: map[string]any{"priority": 10}}
	low := &Auth{ID: "low", Provider: provider, Status: StatusActive, Metadata: map[string]any{"priority": 50}}

	headers := make(http.Header)
	headers.Set("session_id", "s123")
	opts := cliproxyexecutor.Options{Headers: headers, OriginalRequest: []byte(`{}`)}

	// Regardless of hashing, the lower priority value should be selected when available.
	selected, err := sel.Pick(nil, provider, model, opts, []*Auth{low, high})
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	if selected == nil {
		t.Fatal("expected selection")
	}
	if selected.ID != high.ID {
		t.Fatalf("expected highest priority auth %q, got %q", high.ID, selected.ID)
	}
}

func TestStickySelector_GCRemovesExpiredBindings(t *testing.T) {
	sel := &StickySelector{}
	provider := "codex"
	model := "gpt-test"

	now := time.Now()
	sel.bindings = map[string]stickyBinding{
		"codex:codex:dead": {authID: "a", expiresAt: now.Add(-time.Minute)},
		"codex:codex:live": {authID: "b", expiresAt: now.Add(time.Minute)},
	}
	sel.lastGC = now.Add(-time.Hour)

	headers := make(http.Header)
	headers.Set("session_id", "s123")
	opts := cliproxyexecutor.Options{Headers: headers, OriginalRequest: []byte(`{}`)}
	auths := []*Auth{{ID: "a", Provider: provider, Status: StatusActive}}

	_, _ = sel.Pick(nil, provider, model, opts, auths)

	if _, ok := sel.bindings["codex:codex:dead"]; ok {
		t.Fatal("expected expired binding to be removed by GC")
	}
	if _, ok := sel.bindings["codex:codex:live"]; !ok {
		t.Fatal("expected non-expired binding to remain after GC")
	}
}

func TestStickySelector_LoadBalancingPrefersLeastLoaded(t *testing.T) {
	sel := &StickySelector{}
	model := "gpt-test"
	provider := "codex"

	auth1 := &Auth{ID: "a", Provider: provider, Status: StatusActive, Metadata: map[string]any{"priority": 10}}
	auth2 := &Auth{ID: "b", Provider: provider, Status: StatusActive, Metadata: map[string]any{"priority": 10}}
	auths := []*Auth{auth1, auth2}

	// Find two different session_id values that would pick the same auth under plain rendezvous hashing
	// (this makes the test reliably fail before load balancing is implemented).
	pickID := func(sessionID string) string {
		headers := make(http.Header)
		headers.Set("session_id", sessionID)
		key := extractStickySessionKey(cliproxyexecutor.Options{Headers: headers, OriginalRequest: []byte(`{}`)})
		picked := pickRendezvous(key, []*Auth{auth1, auth2})
		if picked == nil {
			return ""
		}
		return picked.ID
	}

	base := "s0"
	basePick := pickID(base)
	if basePick == "" {
		t.Fatal("expected pick for base session_id")
	}

	other := ""
	for i := 1; i < 10_000; i++ {
		candidate := "s" + strconv.Itoa(i)
		if candidate == base {
			continue
		}
		if pickID(candidate) == basePick {
			other = candidate
			break
		}
	}
	if other == "" {
		t.Fatal("failed to find a second session_id that hashes to the same auth")
	}

	headers1 := make(http.Header)
	headers1.Set("session_id", base)
	opts1 := cliproxyexecutor.Options{Headers: headers1, OriginalRequest: []byte(`{}`)}
	first, err := sel.Pick(nil, provider, model, opts1, auths)
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	if first == nil {
		t.Fatal("expected first selection")
	}

	headers2 := make(http.Header)
	headers2.Set("session_id", other)
	opts2 := cliproxyexecutor.Options{Headers: headers2, OriginalRequest: []byte(`{}`)}
	second, err := sel.Pick(nil, provider, model, opts2, auths)
	if err != nil {
		t.Fatalf("Pick (second session): %v", err)
	}
	if second == nil {
		t.Fatal("expected second selection")
	}

	// With load balancing, the second session should prefer the least-loaded auth, which should be the other one.
	if second.ID == first.ID {
		t.Fatalf("expected second session to pick a different auth from first; got %q for both", second.ID)
	}
}
