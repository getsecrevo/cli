package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/getsecrevo/cli/internal/client"
)

// bundleAPIClient reveals a MULTI-FIELD secret. The existing fake only ever
// returns scalars, which is exactly why the standalone --secret-field path
// shipped broken: every test of the feature stopped at parseFieldSpecs and
// nothing drove the command end to end.
type bundleAPIClient struct{ fakeAPIClient }

func (f bundleAPIClient) RevealSecretValueByName(_ context.Context, _ string, name, _ string) (client.SecretValue, error) {
	if name == "SUNAT_SOL" {
		return client.SecretValue{
			WorkspaceID: "workspace-1", SecretID: "secret-9",
			Fields: map[string]string{"usuario": "u-value", "clave": "c-value"},
		}, nil
	}
	// Everything else falls through to the scalar fake, so a bundle and a plain
	// secret can be injected side by side in one run.
	return f.fakeAPIClient.RevealSecretValueByName(context.Background(), "", name, "")
}

func bundleRunCommand(runner Runner, out *bytes.Buffer) *cobra.Command {
	return NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           out,
		Err:           out,
		Runner:        runner,
		ClientFactory: func() (APIClient, error) { return bundleAPIClient{}, nil },
	})
}

// TestRunSecretFieldAloneIsACompleteSelection: --secret-field names a secret AND
// the field to take from it, so it needs no companion --secret. Requiring one
// made the command's own documented example fail, and forced the operator to
// inject the whole credential they were narrowing away from.
func TestRunSecretFieldAloneIsACompleteSelection(t *testing.T) {
	var out bytes.Buffer
	runner := &recordingRunner{}
	cmd := bundleRunCommand(runner, &out)
	cmd.SetArgs([]string{"run", "--secret-field", "SUNAT_SOL.clave=SOL_PASSWORD", "--", "node", "bot.js"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got, ok := envValue(runner.spec.Env, "SOL_PASSWORD"); !ok || got != "c-value" {
		t.Fatalf("SOL_PASSWORD = %q ok=%v, want c-value", got, ok)
	}
	// Only the named field travels: the sibling must not be injected.
	if _, ok := envValue(runner.spec.Env, "SUNAT_SOL_USUARIO"); ok {
		t.Fatal("only the addressed field may be injected")
	}
}

// TestRunSecretFieldAndSecretCombine: the two flags still compose, so narrowing
// one credential does not cost the ability to inject others alongside it.
func TestRunSecretFieldAndSecretCombine(t *testing.T) {
	var out bytes.Buffer
	runner := &recordingRunner{}
	cmd := bundleRunCommand(runner, &out)
	cmd.SetArgs([]string{
		"run",
		"--secret-field", "SUNAT_SOL.usuario=SOL_USER",
		"--secret", "OPENAI_API_KEY",
		"--", "node", "bot.js",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got, ok := envValue(runner.spec.Env, "SOL_USER"); !ok || got != "u-value" {
		t.Fatalf("SOL_USER = %q ok=%v, want u-value", got, ok)
	}
	if _, ok := envValue(runner.spec.Env, "OPENAI_API_KEY"); !ok {
		t.Fatal("a companion --secret must still be injected")
	}
}

// TestRunWithNoSelectionNamesEveryWayToSelect: with nothing selected at all the
// error must not point only at --secret, or an operator who meant to inject one
// field is steered to the flag that injects the whole credential.
func TestRunWithNoSelectionNamesEveryWayToSelect(t *testing.T) {
	var out bytes.Buffer
	cmd := bundleRunCommand(&recordingRunner{}, &out)
	cmd.SetArgs([]string{"run", "--", "echo", "hello"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"--secret", "--secret-field", "--tag"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must name %q as a way to select; got %v", want, err)
		}
	}
}
