package app

import "strings"

// sanitizeEnvName converts an arbitrary secret name into a portable POSIX
// environment variable name: uppercase ASCII letters, digits, and '_'.
// Anything else becomes '_', consecutive '_' collapse, and a leading digit
// is prefixed with '_' so the result still matches `[A-Za-z_][A-Za-z0-9_]*`.
//
// Examples:
//
//	aws.cloudwatch.webhooks.primary.url -> AWS_CLOUDWATCH_WEBHOOKS_PRIMARY_URL
//	prysmid/oidc_apps/platform.client_id -> PRYSMID_OIDC_APPS_PLATFORM_CLIENT_ID
//	1password-token                      -> _1PASSWORD_TOKEN
//
// The function never returns an empty string: an input that sanitizes to
// only underscores is preserved as-is so the caller can decide what to do
// with it.
func sanitizeEnvName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	// Collapse repeated underscores so foo..bar doesn't become FOO__BAR.
	for strings.Contains(out, "__") {
		out = strings.ReplaceAll(out, "__", "_")
	}
	if out == "" {
		return ""
	}
	// Env vars can't start with a digit. Prefix with '_' if so.
	if out[0] >= '0' && out[0] <= '9' {
		out = "_" + out
	}
	return out
}
