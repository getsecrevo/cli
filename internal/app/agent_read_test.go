package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/getsecrevo/cli/internal/client"
)

// capturingAgentReadFake records the SetAgentRead call so the command's
// resolve + allowed-flag mapping can be asserted.
type capturingAgentReadFake struct {
	fakeAPIClient
	gotSecretID string
	gotAllowed  bool
	called      bool
}

func (f *capturingAgentReadFake) SetAgentRead(_ context.Context, _ string, secretID string, allowed bool) error {
	f.gotSecretID, f.gotAllowed, f.called = secretID, allowed, true
	return nil
}

func TestSecretAgentReadAllowResolvesAndSetsTrue(t *testing.T) {
	var out bytes.Buffer
	fake := &capturingAgentReadFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "agent-read", "allow", "--secret", "OPENAI_API_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if !fake.called || fake.gotSecretID != "secret-2" || fake.gotAllowed != true {
		t.Fatalf("allow should resolve secret-2 + set true, got called=%v id=%q allowed=%v", fake.called, fake.gotSecretID, fake.gotAllowed)
	}
	if !strings.Contains(out.String(), "allowed") {
		t.Fatalf("output should confirm allowed: %s", out.String())
	}
}

func TestSecretAgentReadDenySetsFalse(t *testing.T) {
	var out bytes.Buffer
	fake := &capturingAgentReadFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "agent-read", "deny", "--secret", "OPENAI_API_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if !fake.called || fake.gotAllowed != false {
		t.Fatalf("deny should set false, got called=%v allowed=%v", fake.called, fake.gotAllowed)
	}
}

var _ = client.Cred{}
