package app

import (
	"strings"
	"testing"
)

func TestParseFieldSpecsSplitsAtLastDot(t *testing.T) {
	got, err := parseFieldSpecs([]string{"aws.cloudwatch.webhooks.url.clave=SOL"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got[0].secretName != "aws.cloudwatch.webhooks.url" || got[0].fieldName != "clave" {
		t.Fatalf("must split at the LAST dot so dotted secret names survive; got %+v", got[0])
	}
	if got[0].envName != "SOL" {
		t.Fatalf("explicit env var must win, got %q", got[0].envName)
	}
}

func TestParseFieldSpecsDefaultEnvName(t *testing.T) {
	got, err := parseFieldSpecs([]string{"GANEMO_SUNAT_SOL.clave"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got[0].envName != "GANEMO_SUNAT_SOL_CLAVE" {
		t.Fatalf("default env var must be SECRET_FIELD sanitized+uppercased, got %q", got[0].envName)
	}
}

// The suffix must look like a field name. This is what stops most accidental
// matches against a secret whose name simply contains dots.
func TestParseFieldSpecsRejectsNonFieldSuffix(t *testing.T) {
	for _, bad := range []string{"SECRET.URL", "SECRET.mi-campo", "SECRET.", ".clave", "SECRET"} {
		if _, err := parseFieldSpecs([]string{bad}); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

// A rejected suffix must explain the split rule, because the user cannot see it
// from the flag alone and the alternative (use --secret) has to be discoverable.
func TestParseFieldSpecsErrorExplainsTheSplit(t *testing.T) {
	_, err := parseFieldSpecs([]string{"SECRET.URL=X"})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"LAST dot", "--secret"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error must mention %q; got %s", want, err)
		}
	}
}

// Two fields landing in the same env var would silently overwrite one another.
func TestParseFieldSpecsRejectsEnvCollision(t *testing.T) {
	_, err := parseFieldSpecs([]string{"A.clave=SAME", "B.clave=SAME"})
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a duplicate env var must be refused; got %v", err)
	}
}

func TestFieldMissingErrorListsNamesNeverValues(t *testing.T) {
	err := fieldMissingError("SUNAT", "clve", []string{"clave", "ruc", "usuario"})
	for _, want := range []string{"SUNAT", "clve", "clave", "ruc", "usuario"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("must mention %q; got %s", want, err)
		}
	}
}

// A scalar secret deserves its own message: "no such field" would send the user
// hunting for a typo that isn't there.
func TestFieldMissingErrorOnScalarSecretPointsAtSecretFlag(t *testing.T) {
	err := fieldMissingError("OPENAI_API_KEY", "clave", nil)
	if !strings.Contains(err.Error(), "single value") || !strings.Contains(err.Error(), "--secret OPENAI_API_KEY") {
		t.Fatalf("a scalar secret must be named as such and point at --secret; got %s", err)
	}
}
