package app

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/getsecrevo/cli/internal/client"
)

const sampleDevvaultYAML = `
webhooks:
  primary:
    name: primary-alarms
    url: https://hook.us2.make.com/abc
  backup:
    name: backup-alarms
    url: https://hook.us2.make.com/xyz
flat: top-level
numbers:
  port: 5432
  enabled: true
list_value:
  - one
  - two
`

func TestFlattenYAMLBuildsDottedNames(t *testing.T) {
	leaves, skipped, err := ensureImportNotEmpty([]byte(sampleDevvaultYAML), "", ".")
	if err != nil {
		t.Fatalf("ensureImportNotEmpty() error = %v", err)
	}
	got := make([]string, 0, len(leaves))
	for _, l := range leaves {
		got = append(got, l.name+"="+l.value)
	}
	sort.Strings(got)

	want := []string{
		`list_value=["one","two"]`,
		"flat=top-level",
		"numbers.enabled=true",
		"numbers.port=5432",
		"webhooks.backup.name=backup-alarms",
		"webhooks.backup.url=https://hook.us2.make.com/xyz",
		"webhooks.primary.name=primary-alarms",
		"webhooks.primary.url=https://hook.us2.make.com/abc",
	}
	sort.Strings(want)
	if !equalStringSlices(got, want) {
		t.Fatalf("flatten output = %v, want %v", got, want)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v, want empty (scalar sequence is now serialized as JSON)", skipped)
	}
}

func TestFlattenYAMLSerializesScalarListAsJSON(t *testing.T) {
	yamlSrc := `app:
  redirect_uris:
    - https://a.example.com/cb
    - https://b.example.com/cb
`
	leaves, skipped, err := ensureImportNotEmpty([]byte(yamlSrc), "", ".")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v, want empty", skipped)
	}
	if len(leaves) != 1 {
		t.Fatalf("expected 1 leaf, got %d", len(leaves))
	}
	got := leaves[0]
	if got.name != "app.redirect_uris" {
		t.Fatalf("name = %q", got.name)
	}
	if got.value != `["https://a.example.com/cb","https://b.example.com/cb"]` {
		t.Fatalf("value = %q", got.value)
	}
	if got.description == "" {
		t.Fatalf("description should be auto-populated for serialized lists; got empty")
	}
}

func TestFlattenYAMLSkipsNestedSequence(t *testing.T) {
	// A sequence whose children are not all scalars (here: a list of
	// maps) should remain in "skipped" — we won't guess a serialization
	// for arbitrary structures.
	yamlSrc := `nested:
  - name: a
    value: 1
  - name: b
    value: 2
`
	leaves, skipped, err := ensureImportNotEmpty([]byte(yamlSrc), "", ".")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(leaves) != 0 {
		t.Fatalf("expected 0 leaves, got %+v", leaves)
	}
	if len(skipped) != 1 || skipped[0] != "nested" {
		t.Fatalf("skipped = %v, want [nested]", skipped)
	}
}

func TestFlattenYAMLAppliesPrefix(t *testing.T) {
	leaves, _, err := ensureImportNotEmpty([]byte("a:\n  b: c\n"), "wallet", ".")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(leaves) != 1 || leaves[0].name != "wallet.a.b" {
		t.Fatalf("leaves = %+v", leaves)
	}
}

func TestFlattenYAMLSeparator(t *testing.T) {
	leaves, _, err := ensureImportNotEmpty([]byte("a:\n  b: c\n"), "", "/")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(leaves) != 1 || leaves[0].name != "a/b" {
		t.Fatalf("leaves = %+v", leaves)
	}
}

func TestImportDryRunPrintsPlanWithoutAPICalls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.yml")
	if err := os.WriteFile(path, []byte(sampleDevvaultYAML), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var out bytes.Buffer
	fake := &secretWritingFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"import", path, "--dry-run"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.createCalls)+len(fake.rotateCalls) != 0 {
		t.Fatalf("dry-run should not touch the API; got %+v / %+v", fake.createCalls, fake.rotateCalls)
	}
	if !strings.Contains(out.String(), "Dry-run") {
		t.Fatalf("output = %q, want dry-run header", out.String())
	}
}

func TestImportRoutesNewVsExistingCorrectly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.yml")
	yamlBody := "alpha: one\nbeta: two\n"
	if err := os.WriteFile(path, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	fake := &secretWritingFake{
		existing: []client.Secret{{WorkspaceID: "workspace-1", SecretID: "secret-alpha", Name: "alpha", Status: "active"}},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"import", path})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.createCalls) != 1 || fake.createCalls[0].Name != "beta" {
		t.Fatalf("createCalls = %+v", fake.createCalls)
	}
	if len(fake.rotateCalls) != 1 {
		t.Fatalf("rotateCalls = %+v", fake.rotateCalls)
	}
}

func TestImportSkipExistingLeavesRotateOff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.yml")
	if err := os.WriteFile(path, []byte("alpha: one\nbeta: two\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	fake := &secretWritingFake{
		existing: []client.Secret{{WorkspaceID: "workspace-1", SecretID: "secret-alpha", Name: "alpha", Status: "active"}},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"import", path, "--skip-existing"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.rotateCalls) != 0 {
		t.Fatalf("rotateCalls should be 0 with --skip-existing; got %+v", fake.rotateCalls)
	}
	if len(fake.createCalls) != 1 || fake.createCalls[0].Name != "beta" {
		t.Fatalf("createCalls = %+v", fake.createCalls)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
