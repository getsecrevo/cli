package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// recordingSSHRunner is the ssh-run analog of recordingRunner: it captures
// the spec the cobra command would have run, without actually touching
// ssh-agent or spawning a child.
type recordingSSHRunner struct {
	spec     sshRunSpec
	called   bool
	exitCode int
	runErr   error
}

func (r *recordingSSHRunner) Run(_ context.Context, spec sshRunSpec) error {
	r.called = true
	r.spec = spec
	if r.runErr != nil {
		return r.runErr
	}
	if r.exitCode != 0 {
		return cliExitError{Code: r.exitCode}
	}
	return nil
}

// stubRevealer fakes secretRevealer so reveal failures and empty-value
// guards can be exercised without standing up the full APIClient.
type stubRevealer struct {
	value string
	err   error
	calls []string
}

func (s *stubRevealer) RevealSecretValueByName(_ context.Context, _, name string) (revealedValue, error) {
	s.calls = append(s.calls, name)
	if s.err != nil {
		return revealedValue{}, s.err
	}
	return revealedValue{Value: s.value}, nil
}

func TestSSHRunHappyPath(t *testing.T) {
	var out bytes.Buffer
	runner := &recordingSSHRunner{}
	revealer := &stubRevealer{value: "PRIVATE_KEY_BYTES"}
	cmd := NewRootCommand(Options{
		WorkspaceID:    "workspace-1",
		Out:            &out,
		Err:            &out,
		SSHRunner:      runner,
		SecretRevealer: revealer,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{
		"ssh-run",
		"--key", "BASTION_KEY",
		"--", "ssh", "-N", "-L", "5432:127.0.0.1:5432", "odoo@example.com",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !runner.called {
		t.Fatalf("runner was not invoked")
	}
	if runner.spec.Command != "ssh" {
		t.Fatalf("command = %q, want ssh", runner.spec.Command)
	}
	wantArgs := []string{"-N", "-L", "5432:127.0.0.1:5432", "odoo@example.com"}
	if got := runner.spec.Args; !equalStrings(got, wantArgs) {
		t.Fatalf("args = %v, want %v", got, wantArgs)
	}
	// Assert presence/length only — NEVER print the key value into a test
	// transcript (memory/never_emit_file_contents.md).
	if got := len(runner.spec.KeyValue); got != len("PRIVATE_KEY_BYTES") {
		t.Fatalf("key value length = %d, want %d", got, len("PRIVATE_KEY_BYTES"))
	}
	if runner.spec.KeyName != "BASTION_KEY" {
		t.Fatalf("key name = %q, want BASTION_KEY", runner.spec.KeyName)
	}
	if got := revealer.calls; len(got) != 1 || got[0] != "BASTION_KEY" {
		t.Fatalf("revealer calls = %v, want [BASTION_KEY]", got)
	}
}

func TestSSHRunRevealFailureNeverSpawnsChild(t *testing.T) {
	var out bytes.Buffer
	runner := &recordingSSHRunner{}
	revealer := &stubRevealer{err: errors.New("not found")}
	cmd := NewRootCommand(Options{
		WorkspaceID:    "workspace-1",
		Out:            &out,
		Err:            &out,
		SSHRunner:      runner,
		SecretRevealer: revealer,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{"ssh-run", "--key", "MISSING", "--", "ssh", "host"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), `reveal secret "MISSING"`) {
		t.Fatalf("Execute() error = %v, want wrapped reveal error mentioning MISSING", err)
	}
	if runner.called {
		t.Fatalf("runner was invoked despite reveal failure; spec=%+v", runner.spec)
	}
}

func TestSSHRunEmptyKeyValueRefusesToSpawn(t *testing.T) {
	var out bytes.Buffer
	runner := &recordingSSHRunner{}
	revealer := &stubRevealer{value: ""}
	cmd := NewRootCommand(Options{
		WorkspaceID:    "workspace-1",
		Out:            &out,
		Err:            &out,
		SSHRunner:      runner,
		SecretRevealer: revealer,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{"ssh-run", "--key", "EMPTY", "--", "ssh", "host"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("Execute() error = %v, want empty-key refusal", err)
	}
	if runner.called {
		t.Fatalf("runner was invoked for empty key; this leaks an empty identity into ssh-agent")
	}
}

func TestSSHRunRequiresKeyFlag(t *testing.T) {
	var out bytes.Buffer
	runner := &recordingSSHRunner{}
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &out,
		Err:         &out,
		SSHRunner:   runner,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{"ssh-run", "--", "ssh", "host"})

	if err := cmd.Execute(); err == nil {
		t.Fatalf("Execute() error = nil, want missing-flag error")
	}
	if runner.called {
		t.Fatalf("runner invoked without --key")
	}
}

func TestSSHRunPropagatesChildExitCode(t *testing.T) {
	runner := &recordingSSHRunner{exitCode: 13}
	revealer := &stubRevealer{value: "PRIVATE_KEY_BYTES"}
	cmd := NewRootCommand(Options{
		WorkspaceID:    "workspace-1",
		Out:            &bytes.Buffer{},
		Err:            &bytes.Buffer{},
		SSHRunner:      runner,
		SecretRevealer: revealer,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{"ssh-run", "--key", "BASTION_KEY", "--", "ssh", "host"})

	err := cmd.Execute()
	if got := ExitCode(err); got != 13 {
		t.Fatalf("ExitCode = %d, want 13", got)
	}
}

func TestSSHRunWiresStdoutStderrFromOptions(t *testing.T) {
	var out, errOut bytes.Buffer
	runner := &recordingSSHRunner{}
	revealer := &stubRevealer{value: "PRIVATE_KEY_BYTES"}
	cmd := NewRootCommand(Options{
		WorkspaceID:    "workspace-1",
		Out:            &out,
		Err:            &errOut,
		SSHRunner:      runner,
		SecretRevealer: revealer,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{"ssh-run", "--key", "BASTION_KEY", "--", "ssh", "host"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if runner.spec.Stdout != &out {
		t.Fatalf("Stdout not threaded from Options.Out")
	}
	if runner.spec.Stderr != &errOut {
		t.Fatalf("Stderr not threaded from Options.Err")
	}
}

func equalStrings(a, b []string) bool {
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
