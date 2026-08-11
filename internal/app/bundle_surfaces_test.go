package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getsecrevo/cli/internal/client"
)

// The by-NAME bundle fake already exists (bundleAPIClient, field_run_test.go)
// and is reused here as-is. What was missing is a by-ID one: `run --all`
// resolves ids from ListSecrets and calls RevealSecretValue, and no fake had
// ever returned a bundle down that path — which is precisely why the empty
// injection below survived. A separate type rather than a method on the
// existing fake, so no existing test changes behaviour.
//
// Value stays EMPTY on purpose. That is what the api actually sends for a
// multi-field secret: the mediator returns ("", fields), and the canonical-JSON
// rendering lives only in the recovery kit.
type bundleByIDAPIClient struct{ fakeAPIClient }

func (f bundleByIDAPIClient) RevealSecretValue(ctx context.Context, ws, secretID string) (client.SecretValue, error) {
	if secretID == "secret-2" { // OPENAI_API_KEY in the shared fake's listing
		return client.SecretValue{
			WorkspaceID: "workspace-1", SecretID: secretID,
			Fields: map[string]string{"usuario": "u-value", "clave": "c-value"},
		}, nil
	}
	return f.fakeAPIClient.RevealSecretValue(ctx, ws, secretID)
}

const canonicalBundle = `{"clave":"c-value","usuario":"u-value"}`

// TestSecretRevealRendersBundleInsteadOfBlankLine: `secrevo secret reveal` on a
// multi-field secret printed an EMPTY LINE. The api leaves `value` empty and
// puts everything in `fields`; the command rendered `value` regardless.
func TestSecretRevealRendersBundleInsteadOfBlankLine(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &errOut,
		ClientFactory: func() (APIClient, error) { return bundleAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "SUNAT_SOL", "--allow-stdout"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	// Sorted keys, so two reveals of an unchanged secret are byte-identical and
	// the output feeds straight back into `secret set --fields-stdin`.
	if got := strings.TrimRight(out.String(), "\r\n"); got != canonicalBundle {
		t.Fatalf("stdout = %q, want canonical bundle %q", got, canonicalBundle)
	}
	// The SHAPE goes to stderr, so stdout (and any redirect of it) stays exact.
	if !strings.Contains(errOut.String(), "holds named fields") ||
		!strings.Contains(errOut.String(), "clave, usuario") {
		t.Fatalf("stderr must name the fields, got %q", errOut.String())
	}
	if strings.Contains(errOut.String(), "c-value") {
		t.Fatalf("the shape note must never carry a value: %q", errOut.String())
	}
}

// TestSecretRevealToFileWritesBundleNotZeroBytes is the worse half of the same
// defect: --to-file wrote a ZERO-BYTE file and exited 0, so a backup script
// reported success and stored nothing.
func TestSecretRevealToFileWritesBundleNotZeroBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	var out, errOut bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &errOut,
		ClientFactory: func() (APIClient, error) { return bundleAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "SUNAT_SOL", "--to-file", path})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("wrote a zero-byte file for a multi-field secret")
	}
	if string(data) != canonicalBundle {
		t.Fatalf("file = %q, want %q", string(data), canonicalBundle)
	}
	if out.Len() != 0 {
		t.Fatalf("--to-file must not print the value: %q", out.String())
	}
}

// TestRunAllRefusesToInjectAnEmptyBundle is the third site, and the dangerous
// one: --all injected the EMPTY STRING as a credential and ran the command
// anyway, so the child authenticated as nothing. Its sibling
// buildInjectedEnvByName has always refused this; the two paths differed only
// because no multi-field secret existed to walk down this one.
func TestRunAllRefusesToInjectAnEmptyBundle(t *testing.T) {
	var out bytes.Buffer
	runner := &recordingRunner{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		Runner:        runner,
		ClientFactory: func() (APIClient, error) { return bundleByIDAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"run", "--all", "--", "python", "agent.py"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("--all must refuse rather than inject an empty credential")
	}
	for _, want := range []string{"OPENAI_API_KEY", "clave, usuario", "--secret-field"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must mention %q, got %q", want, err.Error())
		}
	}
	// Names, never values — neither the bundle's nor the scalar secret's.
	for _, leak := range []string{"c-value", "u-value", "db-password-value"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("no value may appear in the error: %q", err.Error())
		}
	}
	// Fail closed: the child must not have run at all, since part of its
	// environment would have been a credential that authenticates as nothing.
	if runner.spec.Command != "" {
		t.Fatalf("the child must not run when a credential could not be injected, ran %q", runner.spec.Command)
	}
}
