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

func TestExportPlaintextWritesPayloadAndWarns(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "backup.json")

	var out, errBuf bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &errBuf,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"export", "--plaintext", "--out", dest})

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

func TestExportPlaintextRequiresOutPath(t *testing.T) {
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"export", "--plaintext"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--plaintext requires --out") {
		t.Fatalf("Execute() error = %v, want plaintext-requires-out error", err)
	}
}

func TestExportPlaintextRefusesOverwriteWithoutForce(t *testing.T) {
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
	cmd.SetArgs([]string{"export", "--plaintext", "--out", dest})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Execute() error = %v, want already-exists error", err)
	}
}

func TestExportKitProducesCiphertextPlusPassphraseFiles(t *testing.T) {
	dir := t.TempDir()
	// Pin the stamp so filename matching is stable.
	prev := nowStamp
	nowStamp = func() string { return "2026-05-13" }
	t.Cleanup(func() { nowStamp = prev })

	var out, errBuf bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &errBuf,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"export", "--kit", "--out-dir", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	cipherPath := filepath.Join(dir, "secrevo-backup-2026-05-13.json.kit")
	passPath := filepath.Join(dir, "secrevo-backup-2026-05-13.passphrase")

	cipher, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatalf("read cipher: %v", err)
	}
	if !strings.HasPrefix(string(cipher), kitMagic) {
		t.Fatalf("ciphertext missing kit magic prefix; got %q", cipher[:min(len(cipher), 32)])
	}

	pass, err := os.ReadFile(passPath)
	if err != nil {
		t.Fatalf("read passphrase: %v", err)
	}
	// Extract the bare passphrase (last non-comment line, trimmed).
	lines := strings.Split(strings.TrimSpace(string(pass)), "\n")
	passphrase := strings.TrimSpace(lines[len(lines)-1])
	if len(passphrase) < 40 {
		t.Fatalf("passphrase = %q, want at least 40 base64 chars", passphrase)
	}

	// Round-trip: decrypt with the same passphrase, expect a JSON payload.
	plain, err := decryptRecoveryKit(cipher, passphrase)
	if err != nil {
		t.Fatalf("decrypt kit: %v", err)
	}
	var payload exportPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		t.Fatalf("decrypted not JSON: %v", err)
	}
	if len(payload.Secrets) != 2 {
		t.Fatalf("payload.Secrets count = %d, want 2 (from fakeAPIClient)", len(payload.Secrets))
	}

	if !strings.Contains(out.String(), "Recovery Kit written") {
		t.Fatalf("missing success summary on stdout: %q", out.String())
	}
	if !strings.Contains(out.String(), "DELETE this file") && !strings.Contains(string(pass), "DELETE this file") {
		t.Fatalf("operator instructions missing the DELETE warning")
	}
}

func TestExportKitDefaultModeWhenNoFlags(t *testing.T) {
	dir := t.TempDir()
	prev := nowStamp
	nowStamp = func() string { return "2026-05-13" }
	t.Cleanup(func() { nowStamp = prev })

	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"export", "--out-dir", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrevo-backup-2026-05-13.json.kit")); err != nil {
		t.Fatalf("kit ciphertext not created in default mode: %v", err)
	}
}

func TestExportKitAndPlaintextAreMutuallyExclusive(t *testing.T) {
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"export", "--kit", "--plaintext", "--out", "/tmp/x.json"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("Execute() error = %v, want mutually-exclusive", err)
	}
}
