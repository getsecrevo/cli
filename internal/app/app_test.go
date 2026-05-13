package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/getsecrevo/cli/internal/client"
)

type fakeAPIClient struct {
	baseURL string
	session client.Session
}

func (f fakeAPIClient) BaseURL() string                                { return f.baseURL }
func (f fakeAPIClient) Whoami(context.Context) (client.Session, error) { return f.session, nil }
func (f fakeAPIClient) BootstrapWorkspace(context.Context, client.BootstrapWorkspaceRequest) (client.BootstrapWorkspaceResponse, error) {
	return client.BootstrapWorkspaceResponse{ID: "workspace-1", Name: "Secrevo", Status: "active", AdminEmail: "admin@example.com"}, nil
}
func (f fakeAPIClient) ListSecrets(context.Context, string) (client.SecretListResponse, error) {
	return client.SecretListResponse{
		Secrets: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-1", Name: "db-password", Status: "active"},
			{WorkspaceID: "workspace-1", SecretID: "secret-2", Name: "OPENAI_API_KEY", Status: "active"},
		},
	}, nil
}
func (f fakeAPIClient) GetSecret(context.Context, string, string) (client.Secret, error) {
	return client.Secret{WorkspaceID: "workspace-1", SecretID: "secret-1", Name: "db", Status: "active"}, nil
}
func (f fakeAPIClient) RevealSecretValue(_ context.Context, _ string, secretID string) (client.SecretValue, error) {
	switch secretID {
	case "secret-1":
		return client.SecretValue{WorkspaceID: "workspace-1", SecretID: secretID, Value: "db-password-value"}, nil
	case "secret-2":
		return client.SecretValue{WorkspaceID: "workspace-1", SecretID: secretID, Value: "sk-live-openai"}, nil
	}
	return client.SecretValue{}, errors.New("unknown secret id")
}
func (f fakeAPIClient) CreateAgent(context.Context, string, client.AgentCreateRequest) (client.AgentCreateResponse, error) {
	return client.AgentCreateResponse{Token: "token-1", Snippet: "export SECREVO_AGENT_TOKEN=token-1"}, nil
}
func (f fakeAPIClient) CreateSecret(context.Context, string, client.SecretCreateRequest) (client.Secret, error) {
	return client.Secret{}, errors.New("fakeAPIClient does not support CreateSecret; use secretWritingFake")
}
func (f fakeAPIClient) RotateSecretValue(context.Context, string, string, string) error {
	return errors.New("fakeAPIClient does not support RotateSecretValue; use secretWritingFake")
}

// secretWritingFake captures create/rotate calls so the secret-set/update
// tests can assert exactly which path was taken. The list of pre-existing
// secrets is the fixture; everything else accumulates in the call log.
type secretWritingFake struct {
	existing      []client.Secret
	createCalls   []client.SecretCreateRequest
	rotateCalls   []rotateCall
	rotateErr     error
	createErr     error
}

type rotateCall struct {
	secretID string
	value    string
}

func (f *secretWritingFake) BaseURL() string                                { return "" }
func (f *secretWritingFake) Whoami(context.Context) (client.Session, error) { return client.Session{}, nil }
func (f *secretWritingFake) BootstrapWorkspace(context.Context, client.BootstrapWorkspaceRequest) (client.BootstrapWorkspaceResponse, error) {
	return client.BootstrapWorkspaceResponse{}, nil
}
func (f *secretWritingFake) ListSecrets(context.Context, string) (client.SecretListResponse, error) {
	return client.SecretListResponse{Secrets: append([]client.Secret(nil), f.existing...)}, nil
}
func (f *secretWritingFake) GetSecret(context.Context, string, string) (client.Secret, error) {
	return client.Secret{}, errors.New("not implemented")
}
func (f *secretWritingFake) RevealSecretValue(context.Context, string, string) (client.SecretValue, error) {
	return client.SecretValue{}, errors.New("not implemented")
}
func (f *secretWritingFake) CreateAgent(context.Context, string, client.AgentCreateRequest) (client.AgentCreateResponse, error) {
	return client.AgentCreateResponse{}, nil
}
func (f *secretWritingFake) CreateSecret(_ context.Context, _ string, req client.SecretCreateRequest) (client.Secret, error) {
	if f.createErr != nil {
		return client.Secret{}, f.createErr
	}
	f.createCalls = append(f.createCalls, req)
	created := client.Secret{
		WorkspaceID: "workspace-1",
		SecretID:    "secret-new",
		Name:        req.Name,
		Description: req.Description,
		Status:      "active",
	}
	f.existing = append(f.existing, created)
	return created, nil
}
func (f *secretWritingFake) RotateSecretValue(_ context.Context, _ string, secretID string, value string) error {
	if f.rotateErr != nil {
		return f.rotateErr
	}
	f.rotateCalls = append(f.rotateCalls, rotateCall{secretID: secretID, value: value})
	return nil
}

func TestCommandParsing(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "version", args: []string{"version"}, want: "secrevo version"},
		{name: "whoami", args: []string{"auth", "whoami"}, want: "secrevo auth whoami"},
		{name: "bootstrap", args: []string{"workspace", "bootstrap"}, want: "secrevo workspace bootstrap"},
		{name: "secret-get", args: []string{"secret", "get", "db-password"}, want: "secrevo secret get"},
		{name: "agent-create", args: []string{"agent", "create", "runner"}, want: "secrevo agent create"},
		{name: "run", args: []string{"run", "--", "echo", "hello"}, want: "secrevo run"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewRootCommand(Options{Version: "1.2.3"})
			found, _, err := cmd.Find(tc.args)
			if err != nil {
				t.Fatalf("Find() error = %v", err)
			}
			if got := found.CommandPath(); got != tc.want {
				t.Fatalf("CommandPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVersionDoesNotRequireClient(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		Version: "1.2.3",
		Out:     &out,
		Err:     &out,
		ClientFactory: func() (APIClient, error) {
			return nil, errors.New("unexpected client use")
		},
	})
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "1.2.3" {
		t.Fatalf("output = %q, want 1.2.3", got)
	}
}

func TestRunRequiresConfiguredClient(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &out,
		Err:         &out,
		ClientFactory: func() (APIClient, error) {
			return nil, client.ErrNotConfigured
		},
	})
	cmd.SetArgs([]string{"run", "--secret", "OPENAI_API_KEY", "--", "echo", "hello"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil, want configuration error")
	}
	if !strings.Contains(err.Error(), "secrevo API client is not configured") {
		t.Fatalf("error = %v, want not configured", err)
	}
}

func TestRunRequiresAtLeastOneSecret(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &out,
		Err:         &out,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{"run", "--", "echo", "hello"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "at least one --secret flag is required") {
		t.Fatalf("Execute() error = %v, want missing-secret error", err)
	}
}

// recordingRunner captures the env the run command would have launched the
// child with, without actually exec-ing anything.
type recordingRunner struct {
	spec     RunSpec
	exitCode int
}

func (r *recordingRunner) Run(_ context.Context, spec RunSpec) error {
	r.spec = spec
	if r.exitCode != 0 {
		return cliExitError{Code: r.exitCode}
	}
	return nil
}

func envValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix), true
		}
	}
	return "", false
}

func TestRunInjectsRevealedSecretsIntoChildEnv(t *testing.T) {
	var out bytes.Buffer
	runner := &recordingRunner{}
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &out,
		Err:         &out,
		Runner:      runner,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{
		"run",
		"--secret", "OPENAI_API_KEY",
		"--secret", "db-password=DB_PASSWORD",
		"--", "node", "app.js",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if runner.spec.Command != "node" {
		t.Fatalf("command = %q, want node", runner.spec.Command)
	}
	if got := runner.spec.Args; len(got) != 1 || got[0] != "app.js" {
		t.Fatalf("args = %v, want [app.js]", got)
	}
	if got, ok := envValue(runner.spec.Env, "OPENAI_API_KEY"); !ok || got != "sk-live-openai" {
		t.Fatalf("OPENAI_API_KEY = %q ok=%v, want sk-live-openai", got, ok)
	}
	if got, ok := envValue(runner.spec.Env, "DB_PASSWORD"); !ok || got != "db-password-value" {
		t.Fatalf("DB_PASSWORD = %q ok=%v, want db-password-value", got, ok)
	}
}

func TestRunReportsUnknownSecretWithAvailableNames(t *testing.T) {
	var out bytes.Buffer
	runner := &recordingRunner{}
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &out,
		Err:         &out,
		Runner:      runner,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{"run", "--secret", "MISSING", "--", "echo", "x"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "Available:") {
		t.Fatalf("Execute() error = %v, want available-names hint", err)
	}
	if runner.spec.Command != "" {
		t.Fatalf("runner should not have been invoked; got %+v", runner.spec)
	}
}

func TestRunPropagatesChildExitCodeViaCLIExitError(t *testing.T) {
	runner := &recordingRunner{exitCode: 7}
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &bytes.Buffer{},
		Err:         &bytes.Buffer{},
		Runner:      runner,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{"run", "--secret", "OPENAI_API_KEY", "--", "false"})

	err := cmd.Execute()
	if got := ExitCode(err); got != 7 {
		t.Fatalf("ExitCode = %d, want 7", got)
	}
}

func TestParseSecretSpecsRejectsCollidingEnvNames(t *testing.T) {
	if _, err := parseSecretSpecs([]string{"a=X", "b=X"}); err == nil {
		t.Fatalf("expected an error when two specs share the same env var name")
	}
}

func TestWhoamiUsesFakeClient(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		Out: &out,
		Err: &out,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{
				baseURL: "http://api.example",
				session: client.Session{
					Issuer:   "https://issuer.example",
					Audience: []string{"client-id"},
					Tenant:   "tenant-1",
					Identity: client.Identity{Subject: "sub-1", Email: "alice@example.com", Name: "Alice"},
				},
			}, nil
		},
	})
	cmd.SetArgs([]string{"auth", "whoami"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(out.String(), "alice@example.com") {
		t.Fatalf("output = %q, want session JSON", out.String())
	}
}

func TestSecretSetCreatesWhenAbsent(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{
		"secret", "set", "NEW_KEY",
		"--value", "sk-live-xyz",
		"--description", "Stripe live key",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.createCalls) != 1 {
		t.Fatalf("createCalls = %d, want 1", len(fake.createCalls))
	}
	if got := fake.createCalls[0]; got.Name != "NEW_KEY" || got.Value != "sk-live-xyz" || got.Description != "Stripe live key" {
		t.Fatalf("create payload = %+v", got)
	}
	if len(fake.rotateCalls) != 0 {
		t.Fatalf("rotateCalls = %d, want 0", len(fake.rotateCalls))
	}
	if !strings.Contains(out.String(), "Created secret \"NEW_KEY\"") {
		t.Fatalf("output = %q, want creation confirmation", out.String())
	}
}

func TestSecretSetRotatesWhenExists(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-1", Name: "OPENAI_API_KEY", Status: "active"},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "set", "OPENAI_API_KEY", "--value", "sk-live-new"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.createCalls) != 0 {
		t.Fatalf("createCalls = %d, want 0", len(fake.createCalls))
	}
	if len(fake.rotateCalls) != 1 {
		t.Fatalf("rotateCalls = %d, want 1", len(fake.rotateCalls))
	}
	if got := fake.rotateCalls[0]; got.secretID != "secret-1" || got.value != "sk-live-new" {
		t.Fatalf("rotate call = %+v", got)
	}
}

func TestSecretSetUpdateOnlyRefusesToCreate(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "set", "MISSING", "--value", "x", "--update-only"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Execute() error = %v, want not-found", err)
	}
	if len(fake.createCalls)+len(fake.rotateCalls) != 0 {
		t.Fatalf("no API calls expected; got createCalls=%d rotateCalls=%d", len(fake.createCalls), len(fake.rotateCalls))
	}
}

func TestSecretSetCreateOnlyRefusesToRotate(t *testing.T) {
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-1", Name: "OPENAI_API_KEY", Status: "active"},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "set", "OPENAI_API_KEY", "--value", "x", "--create-only"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Execute() error = %v, want already-exists", err)
	}
}

func TestSecretSetRequiresValueSource(t *testing.T) {
	fake := &secretWritingFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "set", "NEW_KEY"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "exactly one of --value") {
		t.Fatalf("Execute() error = %v, want missing-source error", err)
	}
}

func TestSecretSetFromStdin(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		Stdin:         strings.NewReader("from-stdin-value\n"),
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "set", "STDIN_KEY", "--from-stdin"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.createCalls) != 1 {
		t.Fatalf("createCalls = %d, want 1", len(fake.createCalls))
	}
	if got := fake.createCalls[0].Value; got != "from-stdin-value" {
		t.Fatalf("stdin value = %q, want trimmed", got)
	}
}

func TestSecretUpdateAliasesUpdateOnly(t *testing.T) {
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-1", Name: "OPENAI_API_KEY", Status: "active"},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "update", "OPENAI_API_KEY", "--value", "sk-rotated"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.rotateCalls) != 1 || fake.rotateCalls[0].value != "sk-rotated" {
		t.Fatalf("rotateCalls = %+v", fake.rotateCalls)
	}
}

func TestSecretGetResolvesByName(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &out,
		Err:         &out,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{
				baseURL: "http://api.example",
			}, nil
		},
	})
	cmd.SetArgs([]string{"secret", "get", "db-password"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(out.String(), "\"secret_id\": \"secret-1\"") {
		t.Fatalf("output = %q, want secret JSON", out.String())
	}
}
