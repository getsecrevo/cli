package app

import (
	"strings"
	"testing"
)

func TestParseFieldsJSONHappyPath(t *testing.T) {
	got, err := parseFieldsJSON([]byte(`{"usuario":"u","clave":"c","ruc":"20551583041"}`))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 3 || got["clave"] != "c" {
		t.Fatalf("unexpected fields: %v", fieldNamesOf(got))
	}
}

// Credential material must never be silently transformed. A nested document has
// no faithful representation in a flat string map, so it is rejected rather than
// flattened or stringified.
func TestParseFieldsJSONRejectsNonStringValues(t *testing.T) {
	for _, body := range []string{
		`{"clave":{"inner":"x"}}`,
		`{"clave":["a"]}`,
		`{"port":5432}`,
		`{"enabled":true}`,
		`{"clave":null}`,
	} {
		if _, err := parseFieldsJSON([]byte(body)); err == nil {
			t.Fatalf("must reject non-string value: %s", body)
		}
	}
}

func TestParseFieldsJSONRejectsBadNamesAndNamesThem(t *testing.T) {
	_, err := parseFieldsJSON([]byte(`{"Usuario":"u","mi-campo":"x","ruc":"r"}`))
	if err == nil {
		t.Fatal("bad field names must be rejected")
	}
	for _, want := range []string{"Usuario", "mi-campo"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error must name %q so the typo is visible; got %s", want, err)
		}
	}
	if strings.Contains(err.Error(), `"u"`) || strings.Contains(err.Error(), `"x"`) {
		t.Fatalf("the error must never echo field VALUES; got %s", err)
	}
}

func TestParseFieldsJSONRejectsEmptyInputs(t *testing.T) {
	for _, body := range []string{``, `   `, `{}`, `not json`, `[]`} {
		if _, err := parseFieldsJSON([]byte(body)); err == nil {
			t.Fatalf("must reject %q", body)
		}
	}
	if _, err := parseFieldsJSON([]byte(`{"clave":""}`)); err == nil {
		t.Fatal("an empty field value must be rejected, not stored")
	}
}

// Values may legitimately begin or end with whitespace; the CLI must not tidy
// credential material on the user's behalf.
func TestParseFieldsJSONPreservesValuesVerbatim(t *testing.T) {
	got, err := parseFieldsJSON([]byte(`{"clave":"  pass  "}`))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got["clave"] != "  pass  " {
		t.Fatalf("value must be preserved verbatim, got %q", got["clave"])
	}
}

func TestReadSecretFieldsSources(t *testing.T) {
	got, err := readSecretFields("", true, strings.NewReader(`{"clave":"c"}`))
	if err != nil || got["clave"] != "c" {
		t.Fatalf("stdin path: %v %v", got, err)
	}

	if _, err := readSecretFields("some/path", true, nil); err == nil {
		t.Fatal("--fields-file and --fields-stdin must be mutually exclusive")
	}

	// Neither flag = the caller wants the scalar path, not an error.
	got, err = readSecretFields("", false, nil)
	if err != nil || got != nil {
		t.Fatalf("no flags must mean 'no fields', got %v %v", got, err)
	}
}

func TestFieldNamesOfIsSorted(t *testing.T) {
	got := fieldNamesOf(map[string]string{"usuario": "u", "clave": "c", "ruc": "r"})
	want := []string{"clave", "ruc", "usuario"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names must be sorted for stable output, got %v", got)
		}
	}
}
