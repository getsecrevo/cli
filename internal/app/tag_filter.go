package app

import (
	"fmt"
	"sort"
	"strings"

	"github.com/getsecrevo/cli/internal/client"
)

// normalizeTagFilter mirrors the server-side tag normalization (trim +
// lowercase, drop empties, dedup preserving first-seen order) so a filter typed
// as `--tag SUNAT` matches a secret stored with `sunat`. Keeping the two in sync
// matters: a filter that silently matches nothing would inject nothing and the
// child process would fail far from the cause.
func normalizeTagFilter(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		trimmed := strings.ToLower(strings.TrimSpace(t))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

// filterSecretsByTags keeps the secrets carrying EVERY tag in want (AND, not
// OR). AND is the deliberate choice: each extra --tag must NARROW the selection,
// so a typo shrinks the blast radius instead of widening it. With OR, adding a
// tag would inject more secrets than the operator had in mind — the opposite of
// what this flag exists for (it is `--all`, made smaller).
//
// An empty want returns the input untouched; callers gate on that themselves.
func filterSecretsByTags(secrets []client.Secret, want []string) []client.Secret {
	if len(want) == 0 {
		return secrets
	}
	out := make([]client.Secret, 0, len(secrets))
	for _, s := range secrets {
		have := make(map[string]struct{}, len(s.Tags))
		for _, t := range s.Tags {
			have[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
		}
		matches := true
		for _, w := range want {
			if _, ok := have[w]; !ok {
				matches = false
				break
			}
		}
		if matches {
			out = append(out, s)
		}
	}
	return out
}

// errNoSecretsForTags builds the error returned when --tag matches nothing.
// Injecting zero secrets silently is the failure mode worth preventing: the
// child process would start and fail on a missing variable, far from the cause.
// The message lists the tags actually present on the visible secrets so the
// operator can see the typo without a second command.
func errNoSecretsForTags(want []string, visible []client.Secret) error {
	present := make(map[string]struct{})
	for _, s := range visible {
		for _, t := range s.Tags {
			if trimmed := strings.ToLower(strings.TrimSpace(t)); trimmed != "" {
				present[trimmed] = struct{}{}
			}
		}
	}
	known := make([]string, 0, len(present))
	for t := range present {
		known = append(known, t)
	}
	sort.Strings(known)

	msg := fmt.Sprintf("no visible secret carries every tag [%s]", strings.Join(want, ", "))
	if len(want) > 1 {
		msg += " (--tag is AND: a secret must carry all of them)"
	}
	if len(known) == 0 {
		return fmt.Errorf("%s; none of the secrets visible to this token has any tag", msg)
	}
	return fmt.Errorf("%s; tags in use on visible secrets: %s", msg, strings.Join(known, ", "))
}
