package app

import (
	"fmt"
	"strings"
)

// fieldSpec is one --secret-field flag: which field of which secret goes into
// which env var.
type fieldSpec struct {
	secretName string
	fieldName  string
	envName    string
}

// parseFieldSpecs parses repeated --secret-field flags of the form
// SECRET.FIELD[=ENV_VAR].
//
// The separator problem is real and worth stating: a secret NAME may contain
// almost anything — the api only forbids control characters — so no character
// is reserved and no split can be unambiguous by construction. The CLI itself
// documents a secret called "aws.cloudwatch.webhooks.url".
//
// So the rule is explicit rather than clever, and it lives on its OWN flag so
// that nothing about --secret changes:
//
//   - the split is at the LAST dot (mirroring how --secret splits at the first
//     '=', an ambiguity the CLI already lives with);
//   - the suffix must be a valid FIELD name (lowercase snake_case), which
//     rejects most accidental matches;
//   - and when the resulting secret cannot be found, the error says plainly
//     that the split may be the problem instead of just reporting "not found".
//
// The failure is therefore loud and self-diagnosing, which is the property that
// actually matters — a silent wrong guess would inject the wrong credential.
func parseFieldSpecs(raw []string) ([]fieldSpec, error) {
	out := make([]fieldSpec, 0, len(raw))
	seen := make(map[string]string, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		lhs, envName := entry, ""
		if i := strings.Index(entry, "="); i >= 0 {
			lhs, envName = entry[:i], entry[i+1:]
		}
		lhs = strings.TrimSpace(lhs)
		envName = strings.TrimSpace(envName)

		dot := strings.LastIndex(lhs, ".")
		if dot <= 0 || dot == len(lhs)-1 {
			return nil, fmt.Errorf(
				"--secret-field %q: expected SECRET.FIELD[=ENV_VAR], e.g. --secret-field GANEMO_SUNAT_SOL.clave=SOL_PASSWORD", entry)
		}
		secretName, fieldName := lhs[:dot], lhs[dot+1:]
		if !fieldNamePattern.MatchString(fieldName) {
			return nil, fmt.Errorf(
				"--secret-field %q: %q is not a valid field name (lowercase snake_case, starting with a letter). "+
					"The part after the LAST dot is read as the field; if your secret's name itself ends in a dotted "+
					"segment, use --secret to inject the whole secret instead", entry, fieldName)
		}

		if envName == "" {
			envName = sanitizeEnvName(secretName) + "_" + strings.ToUpper(fieldName)
		}
		if previous, ok := seen[envName]; ok {
			return nil, fmt.Errorf(
				"env var %q would be set twice (from %q and %q); rename one with --secret-field SECRET.FIELD=ENV_VAR",
				envName, previous, lhs)
		}
		seen[envName] = lhs
		out = append(out, fieldSpec{secretName: secretName, fieldName: fieldName, envName: envName})
	}
	return out, nil
}

// fieldMissingError explains a field that is not in the revealed bundle. It
// lists the field NAMES the secret does have — never a value — so the caller
// can fix a typo without a second command and without exposing anything.
func fieldMissingError(secretName, fieldName string, available []string) error {
	if len(available) == 0 {
		return fmt.Errorf(
			"secret %q holds a single value, not named fields, so it has no %q. Use --secret %s instead",
			secretName, fieldName, secretName)
	}
	return fmt.Errorf("secret %q has no field %q; its fields are: %s",
		secretName, fieldName, strings.Join(available, ", "))
}
