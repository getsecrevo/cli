package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// fieldNamePattern mirrors the api's rule for field names. Validating client
// side is not a substitute for the server check — it is so a typo fails before
// a credential is put on the wire, not after.
var fieldNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// parseFieldsJSON decodes the flat name→value map used to write a multi-field
// secret.
//
// Values arrive as a FILE or on STDIN, never as command-line arguments. That is
// the same rule `--value` already follows, and it matters more here rather than
// less: a bundle is several credentials at once, so a single careless
// invocation would put the whole login into the shell history and into `ps`
// output for every user on the box.
//
// Nesting is rejected rather than flattened. A silent transformation of
// credential material is the last thing this should do, and the storage layer
// is a flat string→string map, so a nested document has no faithful
// representation anyway.
func parseFieldsJSON(raw []byte) (map[string]string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("no fields provided: expected a JSON object like {\"usuario\":\"...\",\"clave\":\"...\"}")
	}

	var generic map[string]any
	if err := json.Unmarshal([]byte(trimmed), &generic); err != nil {
		return nil, fmt.Errorf("fields must be a JSON object of string values, e.g. {\"usuario\":\"...\",\"clave\":\"...\"}: %w", err)
	}
	if len(generic) == 0 {
		return nil, fmt.Errorf("the JSON object is empty: a secret needs at least one field")
	}

	fields := make(map[string]string, len(generic))
	var badNames, badValues []string
	for name, value := range generic {
		if !fieldNamePattern.MatchString(name) {
			badNames = append(badNames, name)
			continue
		}
		s, ok := value.(string)
		if !ok {
			badValues = append(badValues, name)
			continue
		}
		if s == "" {
			return nil, fmt.Errorf("field %q is empty; remove it or give it a value", name)
		}
		fields[name] = s
	}
	sort.Strings(badNames)
	sort.Strings(badValues)
	if len(badNames) > 0 {
		return nil, fmt.Errorf("invalid field name(s): %s — use lowercase snake_case starting with a letter (a-z, 0-9, _)", strings.Join(badNames, ", "))
	}
	if len(badValues) > 0 {
		return nil, fmt.Errorf("field(s) %s are not strings; every field value must be a string (no nesting, numbers or booleans)", strings.Join(badValues, ", "))
	}
	return fields, nil
}

// readSecretFields resolves --fields-file / --fields-stdin into a field map, or
// returns nil when neither was given (meaning the caller wants the scalar path).
func readSecretFields(path string, fromStdin bool, stdin io.Reader) (map[string]string, error) {
	switch {
	case path != "" && fromStdin:
		return nil, fmt.Errorf("--fields-file and --fields-stdin are mutually exclusive")
	case path != "":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		return parseFieldsJSON(data)
	case fromStdin:
		if stdin == nil {
			stdin = os.Stdin
		}
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return parseFieldsJSON(data)
	}
	return nil, nil
}

// fieldNamesOf returns the sorted names of a field map, for messages that must
// describe a bundle without printing any of it.
func fieldNamesOf(fields map[string]string) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// SecretFieldsWriter is the OPTIONAL multi-field half of APIClient, discovered
// with a type assertion instead of being added to that interface. APIClient is
// implemented by test fakes; widening it would break the suite by compilation,
// which is the churn this feature has avoided throughout.
type SecretFieldsWriter interface {
	RotateSecretFields(ctx context.Context, workspaceID, secretID string, fields map[string]string, grace string) error
}
