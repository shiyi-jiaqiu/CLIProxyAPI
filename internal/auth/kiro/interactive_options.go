package kiro

// InteractiveLoginOptions carries optional interactive knobs for OAuth login flows.
// It is intentionally small to avoid import cycles with higher-level auth packages.
type InteractiveLoginOptions struct {
	NoBrowser bool
	Prompt    func(prompt string) (string, error)
}

