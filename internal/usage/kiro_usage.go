package usage

import "sync"

// KiroUsageSnapshot captures CodeWhisperer (Kiro IDE) usage limits returned by /getUsageLimits.
// This is a best-effort in-memory snapshot for observability (it is not persisted).
type KiroUsageSnapshot struct {
	DaysUntilReset *int     `json:"days_until_reset,omitempty"`
	NextDateReset  *float64 `json:"next_date_reset,omitempty"`
	Subscription   *KiroSubscriptionInfo `json:"subscription,omitempty"`
	UserInfo       *KiroUserInfo         `json:"user_info,omitempty"`
	Breakdowns     []KiroUsageBreakdown  `json:"breakdowns,omitempty"`
}

type KiroUserInfo struct {
	Email  *string `json:"email,omitempty"`
	UserID *string `json:"user_id,omitempty"`
}

type KiroSubscriptionInfo struct {
	Title *string `json:"title,omitempty"`
	Type  *string `json:"type,omitempty"`
}

type KiroUsageBreakdown struct {
	ResourceType *string `json:"resource_type,omitempty"`
	Unit         *string `json:"unit,omitempty"`
	UsageLimit   *int    `json:"usage_limit,omitempty"`
	CurrentUsage *int    `json:"current_usage,omitempty"`
}

var kiroUsageByAuth sync.Map // authID -> KiroUsageSnapshot

// UpdateKiroUsageSnapshot stores the latest snapshot for an authID (in-memory).
func UpdateKiroUsageSnapshot(authID string, snapshot *KiroUsageSnapshot) {
	if authID == "" || snapshot == nil {
		return
	}
	kiroUsageByAuth.Store(authID, *snapshot)
}

// DeleteKiroUsageSnapshot removes the cached snapshot for an authID.
// Primarily intended for tests to avoid shared global state across test cases.
func DeleteKiroUsageSnapshot(authID string) {
	if authID == "" {
		return
	}
	kiroUsageByAuth.Delete(authID)
}

// GetKiroUsageSnapshot returns the most recent snapshot for an authID, if any.
func GetKiroUsageSnapshot(authID string) *KiroUsageSnapshot {
	if authID == "" {
		return nil
	}
	if v, ok := kiroUsageByAuth.Load(authID); ok {
		if snap, ok2 := v.(KiroUsageSnapshot); ok2 {
			out := snap
			return &out
		}
	}
	return nil
}

