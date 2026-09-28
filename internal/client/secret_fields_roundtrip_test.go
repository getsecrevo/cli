package client

import (
	"encoding/json"
	"testing"
)

// TestSecretPreservesValueUpdatedAt guards a failure mode that is invisible by
// construction: `secrevo secret get` unmarshals the api response into Secret and
// then re-marshals it for output, so ANY field this struct does not name is
// silently dropped. No error, no warning — the field simply is not there, and it
// looks exactly like an api that never sent it.
//
// That is not hypothetical. On 2026-09-28 the api began sending
// value_updated_at; the published CLI did not know the field, so production
// appeared not to be recording rotations at all. Confirming otherwise took
// reading the api logs and building a patched binary.
//
// Whenever the api grows a field this CLI should surface, add it to Secret AND
// to this test.
func TestSecretPreservesValueUpdatedAt(t *testing.T) {
	// Shaped like a real single-secret GET.
	apiResponse := []byte(`{
		"workspace_id": "workspace-0001",
		"secret_id": "secret-0087",
		"name": "GANEMO_ODOO_FERNANDO_API_KEY",
		"description": "",
		"regeneration_instructions": "",
		"status": "active",
		"tags": [],
		"updated_at": "2026-08-08T20:38:29Z",
		"value_updated_at": "2026-09-28T06:33:59Z",
		"agent_raw_read_allowed": true
	}`)

	var secret Secret
	if err := json.Unmarshal(apiResponse, &secret); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if secret.ValueUpdatedAt == nil {
		t.Fatal("value_updated_at was dropped on unmarshal")
	}
	if *secret.ValueUpdatedAt != "2026-09-28T06:33:59Z" {
		t.Fatalf("ValueUpdatedAt = %q, want the api's value", *secret.ValueUpdatedAt)
	}

	out, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var reparsed map[string]any
	if err := json.Unmarshal(out, &reparsed); err != nil {
		t.Fatalf("re-Unmarshal() error = %v", err)
	}
	if got, ok := reparsed["value_updated_at"]; !ok || got != "2026-09-28T06:33:59Z" {
		t.Fatalf("value_updated_at did not survive the round trip: %s", out)
	}

	// The two timestamps mean different things and must both survive: metadata
	// edits move updated_at, rotations move value_updated_at. Collapsing them
	// would answer "when was this rotated?" with the wrong date, which is the
	// question the field exists to answer.
	if reparsed["updated_at"] != "2026-08-08T20:38:29Z" {
		t.Fatalf("updated_at was disturbed: %v", reparsed["updated_at"])
	}
}

// TestSecretOmitsValueUpdatedAtWhenAbsent pins the other half: a secret whose
// value predates the api recording rotations has NO value_updated_at, and the
// CLI must not invent one. "unknown" and "rotated at the epoch" must not look
// alike to someone deciding whether to rotate again.
func TestSecretOmitsValueUpdatedAtWhenAbsent(t *testing.T) {
	var secret Secret
	if err := json.Unmarshal([]byte(`{"name":"OLD","updated_at":"2026-01-01T00:00:00Z"}`), &secret); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if secret.ValueUpdatedAt != nil {
		t.Fatalf("want nil for an absent field, got %q", *secret.ValueUpdatedAt)
	}
	out, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var reparsed map[string]any
	_ = json.Unmarshal(out, &reparsed)
	if _, present := reparsed["value_updated_at"]; present {
		t.Fatalf("an absent stamp must stay absent, not be rendered: %s", out)
	}
}
