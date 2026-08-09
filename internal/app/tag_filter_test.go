package app

import (
	"strings"
	"testing"

	"github.com/getsecrevo/cli/internal/client"
)

func tagged(name string, tags ...string) client.Secret {
	return client.Secret{Name: name, SecretID: "secret-" + name, Tags: tags}
}

func names(secrets []client.Secret) []string {
	out := make([]string, 0, len(secrets))
	for _, s := range secrets {
		out = append(out, s.Name)
	}
	return out
}

func TestNormalizeTagFilterMirrorsServerNormalization(t *testing.T) {
	got := normalizeTagFilter([]string{"  SUNAT ", "sunat", "", "   ", "Prod"})
	want := []string{"sunat", "prod"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// The AND semantics are the security-relevant part: every extra --tag must
// shrink the selection, never grow it.
func TestFilterSecretsByTagsIsAndNotOr(t *testing.T) {
	secrets := []client.Secret{
		tagged("A", "odoo", "prod"),
		tagged("B", "odoo"),
		tagged("C", "prod"),
		tagged("D"),
	}

	one := filterSecretsByTags(secrets, []string{"odoo"})
	if got := names(one); len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("single tag: got %v, want [A B]", got)
	}

	both := filterSecretsByTags(secrets, []string{"odoo", "prod"})
	if got := names(both); len(got) != 1 || got[0] != "A" {
		t.Fatalf("two tags must NARROW (AND): got %v, want [A]", got)
	}
	if len(both) > len(one) {
		t.Fatal("adding a tag widened the selection; --tag must only ever narrow")
	}
}

func TestFilterSecretsByTagsMatchesCaseInsensitively(t *testing.T) {
	secrets := []client.Secret{tagged("A", "  SUNAT  ")}
	got := filterSecretsByTags(secrets, normalizeTagFilter([]string{"sunat"}))
	if len(got) != 1 {
		t.Fatalf("stored tag with different case/spacing must match: got %v", names(got))
	}
}

func TestFilterSecretsByTagsEmptyFilterIsPassthrough(t *testing.T) {
	secrets := []client.Secret{tagged("A", "x"), tagged("B")}
	if got := filterSecretsByTags(secrets, nil); len(got) != 2 {
		t.Fatalf("empty filter must not drop anything: got %v", names(got))
	}
}

// A silent zero-match would start the child process and fail on a missing
// variable far from the cause, so the miss must be loud and self-diagnosing.
func TestErrNoSecretsForTagsListsTagsInUse(t *testing.T) {
	visible := []client.Secret{tagged("A", "odoo", "prod"), tagged("B", "sunat")}
	err := errNoSecretsForTags([]string{"sunta"}, visible)
	msg := err.Error()
	for _, want := range []string{"sunta", "odoo", "prod", "sunat"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error must mention %q so the typo is visible; got: %s", want, msg)
		}
	}
}

func TestErrNoSecretsForTagsExplainsAndWhenMultiple(t *testing.T) {
	err := errNoSecretsForTags([]string{"a", "b"}, []client.Secret{tagged("X", "a")})
	if !strings.Contains(err.Error(), "AND") {
		t.Fatalf("multi-tag miss must explain AND semantics; got: %s", err.Error())
	}
}

func TestErrNoSecretsForTagsWhenNothingIsTagged(t *testing.T) {
	err := errNoSecretsForTags([]string{"sunat"}, []client.Secret{tagged("A"), tagged("B")})
	if !strings.Contains(err.Error(), "has any tag") {
		t.Fatalf("the no-tags-at-all case deserves its own hint; got: %s", err.Error())
	}
}
