package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvCommandEmitsPosixExports(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{
		"env",
		"--shell", "posix",
		"--secret", "OPENAI_API_KEY",
		"--secret", "db-password=DB_PASSWORD",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "export OPENAI_API_KEY='sk-live-openai'") {
		t.Fatalf("output missing OPENAI line: %q", got)
	}
	if !strings.Contains(got, "export DB_PASSWORD='db-password-value'") {
		t.Fatalf("output missing DB_PASSWORD line: %q", got)
	}
}

func TestEnvCommandEmitsPowerShellExports(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"env", "--shell", "powershell", "--secret", "OPENAI_API_KEY"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := strings.TrimSpace(out.String())
	want := "$env:OPENAI_API_KEY = 'sk-live-openai'"
	if got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestEnvCommandRejectsSecretAndAllTogether(t *testing.T) {
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"env", "--all", "--secret", "OPENAI_API_KEY"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("Execute() error = %v, want mutually-exclusive error", err)
	}
}

func TestPosixSingleQuoteEscapesEmbeddedQuote(t *testing.T) {
	got := posixSingleQuote("hello 'world'")
	want := `'hello '\''world'\'''`
	if got != want {
		t.Fatalf("posixSingleQuote() = %q, want %q", got, want)
	}
}

func TestPowershellSingleQuoteEscapesEmbeddedQuote(t *testing.T) {
	got := powershellSingleQuote("hello 'world'")
	want := "'hello ''world'''"
	if got != want {
		t.Fatalf("powershellSingleQuote() = %q, want %q", got, want)
	}
}

func TestExportCommandWritesPayloadAndRefusesStdout(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "backup.json")

	var out, errBuf bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &errBuf,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"export", "--out", dest})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	body, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var payload exportPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(payload.Secrets) != 2 {
		t.Fatalf("secrets count = %d, want 2", len(payload.Secrets))
	}
	if payload.Secrets[0].Name != "OPENAI_API_KEY" {
		t.Fatalf("first secret name = %q, want OPENAI_API_KEY (sorted alphabetically)", payload.Secrets[0].Name)
	}
	if !strings.Contains(errBuf.String(), "PLAINTEXT") {
		t.Fatalf("expected warning on stderr; got %q", errBuf.String())
	}
}

func TestExportCommandRequiresOutPath(t *testing.T) {
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"export"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--out PATH is required") {
		t.Fatalf("Execute() error = %v, want missing-out error", err)
	}
}

func TestExportCommandRefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "backup.json")
	if err := os.WriteFile(dest, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"export", "--out", dest})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Execute() error = %v, want already-exists error", err)
	}
}
