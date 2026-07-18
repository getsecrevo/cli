package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
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
func (f fakeAPIClient) RevealSecretValueByName(_ context.Context, _ string, name, _ string) (client.SecretValue, error) {
	switch name {
	case "db-password":
		return client.SecretValue{WorkspaceID: "workspace-1", SecretID: "secret-1", Value: "db-password-value"}, nil
	case "OPENAI_API_KEY":
		return client.SecretValue{WorkspaceID: "workspace-1", SecretID: "secret-2", Value: "sk-live-openai"}, nil
	}
	return client.SecretValue{}, errors.New("unknown secret name")
}

// trackingAPIClient counts list/by-name calls so tests can prove the run/env
// commands no longer touch ListSecrets when --secret is used.
type trackingAPIClient struct {
	fakeAPIClient
	listCalls   int
	byNameCalls []string
}

func (t *trackingAPIClient) ListSecrets(ctx context.Context, ws string) (client.SecretListResponse, error) {
	t.listCalls++
	return t.fakeAPIClient.ListSecrets(ctx, ws)
}

func (t *trackingAPIClient) RevealSecretValueByName(ctx context.Context, ws, name, version string) (client.SecretValue, error) {
	t.byNameCalls = append(t.byNameCalls, name)
	return t.fakeAPIClient.RevealSecretValueByName(ctx, ws, name, version)
}
func (f fakeAPIClient) CreateAgent(context.Context, string, client.AgentCreateRequest) (client.AgentCreateResponse, error) {
	return client.AgentCreateResponse{Token: "token-1", Snippet: "export SECREVO_AGENT_TOKEN=token-1"}, nil
}
func (f fakeAPIClient) CreateSecret(context.Context, string, client.SecretCreateRequest) (client.Secret, error) {
	return client.Secret{}, errors.New("fakeAPIClient does not support CreateSecret; use secretWritingFake")
}
func (f fakeAPIClient) RotateSecretValue(context.Context, string, string, string, string) error {
	return errors.New("fakeAPIClient does not support RotateSecretValue; use secretWritingFake")
}
func (f fakeAPIClient) UpdateSecret(context.Context, string, string, client.SecretUpdateRequest) (client.Secret, error) {
	return client.Secret{}, errors.New("fakeAPIClient does not support UpdateSecret; use secretWritingFake")
}
func (f fakeAPIClient) DeleteSecret(context.Context, string, string) error {
	return errors.New("fakeAPIClient does not support DeleteSecret; use secretWritingFake")
}
func (f fakeAPIClient) ProxyConsume(context.Context, string, string, client.ProxyRequest) (client.ProxyResponse, error) {
	return client.ProxyResponse{Status: 200, Body: `{"ok":1}`, Projected: true}, nil
}
func (f fakeAPIClient) OpenProxySession(context.Context, string, string) (client.ProxySession, error) {
	return client.ProxySession{SessionID: "psess_fake", ExpiresAt: "2026-01-01T00:00:00Z"}, nil
}
func (f fakeAPIClient) ProxySessionConsume(context.Context, string, string, client.ProxyRequest) (client.ProxyResponse, error) {
	return client.ProxyResponse{Status: 200, Body: `{"ok":1}`, Projected: true}, nil
}
func (f fakeAPIClient) CloseProxySession(context.Context, string, string) error {
	return nil
}
func (f fakeAPIClient) ListProxyTargets(context.Context, string, string) ([]client.ProxyTarget, error) {
	return nil, nil
}
func (f fakeAPIClient) PutProxyTarget(_ context.Context, _ string, _ string, t client.ProxyTarget) (client.ProxyTarget, error) {
	return t, nil
}
func (f fakeAPIClient) DeleteProxyTarget(context.Context, string, string, string) error {
	return nil
}
func (f fakeAPIClient) MintCreds(_ context.Context, _ string, _ string, ttl int) (client.Cred, error) {
	return client.Cred{
		Provider: client.CredProviderAWSSTS, AccessKeyID: "ASIAEXAMPLE", SecretAccessKey: "secretpart",
		SessionToken: "sessiontok", Expiration: "2030-01-01T00:00:00Z", TTLSeconds: 900,
	}, nil
}
func (f fakeAPIClient) GetCredScope(context.Context, string, string) (client.CredScope, error) {
	return client.CredScope{Provider: client.CredProviderAWSSTS, Config: map[string]string{"role_arn": "arn:aws:iam::007761758105:role/x"}, MaxTTLSeconds: 900}, nil
}
func (f fakeAPIClient) PutCredScope(_ context.Context, _ string, _ string, s client.CredScope) (client.CredScope, error) {
	return s, nil
}
func (f fakeAPIClient) DeleteCredScope(context.Context, string, string) error {
	return nil
}

// secretWritingFake captures create/rotate calls so the secret-set/update
// tests can assert exactly which path was taken. The list of pre-existing
// secrets is the fixture; everything else accumulates in the call log.
type secretWritingFake struct {
	existing    []client.Secret
	createCalls []client.SecretCreateRequest
	rotateCalls []rotateCall
	updateCalls []updateCall
	deleteCalls []deleteCall
	rotateErr   error
	createErr   error
	updateErr   error
	deleteErr   error
}

type deleteCall struct {
	secretID string
}

type updateCall struct {
	secretID string
	req      client.SecretUpdateRequest
}

type rotateCall struct {
	secretID string
	value    string
	grace    string
}

func (f *secretWritingFake) BaseURL() string { return "" }
func (f *secretWritingFake) Whoami(context.Context) (client.Session, error) {
	return client.Session{}, nil
}
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
func (f *secretWritingFake) RevealSecretValueByName(context.Context, string, string, string) (client.SecretValue, error) {
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
func (f *secretWritingFake) RotateSecretValue(_ context.Context, _ string, secretID, value, grace string) error {
	if f.rotateErr != nil {
		return f.rotateErr
	}
	f.rotateCalls = append(f.rotateCalls, rotateCall{secretID: secretID, value: value, grace: grace})
	return nil
}
func (f *secretWritingFake) DeleteSecret(_ context.Context, _ string, secretID string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleteCalls = append(f.deleteCalls, deleteCall{secretID: secretID})
	kept := f.existing[:0]
	for _, s := range f.existing {
		if s.SecretID != secretID {
			kept = append(kept, s)
		}
	}
	f.existing = kept
	return nil
}
func (f *secretWritingFake) ProxyConsume(context.Context, string, string, client.ProxyRequest) (client.ProxyResponse, error) {
	return client.ProxyResponse{}, errors.New("secretWritingFake does not support ProxyConsume")
}
func (f *secretWritingFake) OpenProxySession(context.Context, string, string) (client.ProxySession, error) {
	return client.ProxySession{}, errors.New("secretWritingFake does not support OpenProxySession")
}
func (f *secretWritingFake) ProxySessionConsume(context.Context, string, string, client.ProxyRequest) (client.ProxyResponse, error) {
	return client.ProxyResponse{}, errors.New("secretWritingFake does not support ProxySessionConsume")
}
func (f *secretWritingFake) CloseProxySession(context.Context, string, string) error {
	return errors.New("secretWritingFake does not support CloseProxySession")
}
func (f *secretWritingFake) ListProxyTargets(context.Context, string, string) ([]client.ProxyTarget, error) {
	return nil, nil
}
func (f *secretWritingFake) PutProxyTarget(_ context.Context, _ string, _ string, t client.ProxyTarget) (client.ProxyTarget, error) {
	return t, nil
}
func (f *secretWritingFake) DeleteProxyTarget(context.Context, string, string, string) error {
	return nil
}
func (f *secretWritingFake) MintCreds(context.Context, string, string, int) (client.Cred, error) {
	return client.Cred{}, errors.New("secretWritingFake does not support MintCreds")
}
func (f *secretWritingFake) GetCredScope(context.Context, string, string) (client.CredScope, error) {
	return client.CredScope{}, errors.New("secretWritingFake does not support GetCredScope")
}
func (f *secretWritingFake) PutCredScope(_ context.Context, _ string, _ string, s client.CredScope) (client.CredScope, error) {
	return s, nil
}
func (f *secretWritingFake) DeleteCredScope(context.Context, string, string) error {
	return nil
}
func (f *secretWritingFake) UpdateSecret(_ context.Context, _ string, secretID string, req client.SecretUpdateRequest) (client.Secret, error) {
	if f.updateErr != nil {
		return client.Secret{}, f.updateErr
	}
	f.updateCalls = append(f.updateCalls, updateCall{secretID: secretID, req: req})
	for i := range f.existing {
		if f.existing[i].SecretID == secretID {
			if req.Name != nil {
				f.existing[i].Name = *req.Name
			}
			if req.Description != nil {
				f.existing[i].Description = *req.Description
			}
			if req.RegenerationInstructions != nil {
				f.existing[i].RegenerationInstructions = *req.RegenerationInstructions
			}
			if req.Status != nil {
				f.existing[i].Status = *req.Status
			}
			if req.Tags != nil {
				f.existing[i].Tags = append([]string(nil), (*req.Tags)...)
			}
			return f.existing[i], nil
		}
	}
	return client.Secret{}, errors.New("secret not found in fake")
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

func TestCallCommandPrintsResponseNeverValue(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &out,
		Err:         &out,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{"call", "--secret", "OPENAI", "--url", "https://api.openai.com/v1/models", "-H", "Authorization: Bearer {{secret}}"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	got := out.String()
	if !strings.Contains(got, `"status": 200`) || !strings.Contains(got, `ok`) || !strings.Contains(got, `"projected": true`) {
		t.Fatalf("call output missing mediated response: %q", got)
	}
	// The command prints only the response; the placeholder/value must not leak.
	if strings.Contains(got, "{{secret}}") {
		t.Fatalf("call output leaked the placeholder: %q", got)
	}
}

// capturingProxyFake records the ProxyConsume request so provider-mode tests
// can assert the built URL/headers. Embeds fakeAPIClient for the rest.
type capturingProxyFake struct {
	fakeAPIClient
	gotWS, gotSecret string
	gotReq           client.ProxyRequest
}

func (f *capturingProxyFake) ProxyConsume(_ context.Context, ws, name string, req client.ProxyRequest) (client.ProxyResponse, error) {
	f.gotWS, f.gotSecret, f.gotReq = ws, name, req
	return client.ProxyResponse{Status: 200, Body: `{"ok":1}`, Projected: true}, nil
}

func TestCallProviderBuildsTypedRequest(t *testing.T) {
	var out bytes.Buffer
	fake := &capturingProxyFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1", Out: &out, Err: &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"call", "--secret", "OPENAI", "--provider", "openai", "--path", "/v1/models"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if fake.gotSecret != "OPENAI" {
		t.Fatalf("secret = %q", fake.gotSecret)
	}
	if fake.gotReq.URL != "https://api.openai.com/v1/models" {
		t.Fatalf("provider URL = %q", fake.gotReq.URL)
	}
	if fake.gotReq.Headers["Authorization"] != "Bearer {{secret}}" {
		t.Fatalf("provider auth header = %q", fake.gotReq.Headers["Authorization"])
	}
}

// sessionCapturingFake records session open + session-scoped consume calls.
type sessionCapturingFake struct {
	fakeAPIClient
	openWS, openSecret        string
	consumeWS, consumeSession string
	consumeReq                client.ProxyRequest
	closeWS, closeSess        string
	proxyConsumeCalled        bool
}

func (f *sessionCapturingFake) OpenProxySession(_ context.Context, ws, name string) (client.ProxySession, error) {
	f.openWS, f.openSecret = ws, name
	return client.ProxySession{SessionID: "psess_abc", ExpiresAt: "2026-07-15T00:05:00Z"}, nil
}
func (f *sessionCapturingFake) ProxySessionConsume(_ context.Context, ws, sid string, req client.ProxyRequest) (client.ProxyResponse, error) {
	f.consumeWS, f.consumeSession, f.consumeReq = ws, sid, req
	return client.ProxyResponse{Status: 200, Body: `{"ok":1}`, Projected: true}, nil
}
func (f *sessionCapturingFake) CloseProxySession(_ context.Context, ws, sid string) error {
	f.closeWS, f.closeSess = ws, sid
	return nil
}
func (f *sessionCapturingFake) ProxyConsume(context.Context, string, string, client.ProxyRequest) (client.ProxyResponse, error) {
	f.proxyConsumeCalled = true
	return client.ProxyResponse{}, errors.New("session flow must not use the one-shot proxy")
}

// TestSessionOpen: `secrevo session open` prints the handle from the API.
func TestSessionOpen(t *testing.T) {
	var out bytes.Buffer
	fake := &sessionCapturingFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1", Out: &out, Err: &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"session", "open", "--secret", "ODOO"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if fake.openSecret != "ODOO" {
		t.Fatalf("open secret = %q", fake.openSecret)
	}
	if !strings.Contains(out.String(), "psess_abc") {
		t.Fatalf("session open output missing handle: %q", out.String())
	}
}

// TestCallWithSessionRoutesToSessionEndpoint: `call --session` uses the session
// consume path (not the one-shot proxy) and does not require --secret.
func TestCallWithSessionRoutesToSessionEndpoint(t *testing.T) {
	var out bytes.Buffer
	fake := &sessionCapturingFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1", Out: &out, Err: &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"call", "--session", "psess_abc", "--url", "https://api.example.com/v1/models"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if fake.proxyConsumeCalled {
		t.Fatalf("call --session must not hit the one-shot proxy")
	}
	if fake.consumeSession != "psess_abc" || fake.consumeReq.URL != "https://api.example.com/v1/models" {
		t.Fatalf("session consume = %q %q", fake.consumeSession, fake.consumeReq.URL)
	}
}

// TestCallSessionAndSecretMutuallyExclusive: passing both is a usage error.
func TestCallSessionAndSecretMutuallyExclusive(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1", Out: &out, Err: &out,
		ClientFactory: func() (APIClient, error) { return &sessionCapturingFake{}, nil },
	})
	cmd.SetArgs([]string{"call", "--session", "psess_abc", "--secret", "ODOO", "--url", "https://api.example.com/x"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually-exclusive error, got %v", err)
	}
}

// TestCallRequiresSecretOrSession: neither given is a usage error.
func TestCallRequiresSecretOrSession(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1", Out: &out, Err: &out,
		ClientFactory: func() (APIClient, error) { return &sessionCapturingFake{}, nil },
	})
	cmd.SetArgs([]string{"call", "--url", "https://api.example.com/x"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--secret") {
		t.Fatalf("expected secret-or-session error, got %v", err)
	}
}

// TestSessionClose: `secrevo session close` forwards the id to the API.
func TestSessionClose(t *testing.T) {
	var out bytes.Buffer
	fake := &sessionCapturingFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1", Out: &out, Err: &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"session", "close", "--session", "psess_abc"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if fake.closeSess != "psess_abc" {
		t.Fatalf("close session = %q", fake.closeSess)
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

func TestRunReportsUnknownSecretWithName(t *testing.T) {
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
	if err == nil || !strings.Contains(err.Error(), `reveal secret "MISSING"`) {
		t.Fatalf("Execute() error = %v, want wrapped reveal-by-name error mentioning the secret", err)
	}
	if runner.spec.Command != "" {
		t.Fatalf("runner should not have been invoked; got %+v", runner.spec)
	}
}

// forbiddenRevealClient returns the api's 403 missing-capability shape from
// every by-name reveal, mimicking a human who holds secret.read but not
// secret.reveal after the human-reveal split.
type forbiddenRevealClient struct{ fakeAPIClient }

func (forbiddenRevealClient) RevealSecretValueByName(context.Context, string, string, string) (client.SecretValue, error) {
	return client.SecretValue{}, errors.New(`api returned 403 Forbidden: {"error":"forbidden","message":"missing required capability"}`)
}

func TestIsForbiddenMatchesApi403Only(t *testing.T) {
	if !isForbidden(errors.New(`api returned 403 Forbidden: {"error":"forbidden"}`)) {
		t.Fatal("expected a 403 forbidden body to be recognized")
	}
	if isForbidden(errors.New("api returned 404 Not Found: not_found")) {
		t.Fatal("a 404 must not be treated as forbidden")
	}
	if isForbidden(nil) {
		t.Fatal("nil must not be forbidden")
	}
}

func TestSecretGetForbiddenSuggestsRevealCapability(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &out,
		Err:         &out,
		ClientFactory: func() (APIClient, error) {
			return forbiddenRevealClient{}, nil
		},
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password", "--allow-stdout"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error when reveal is forbidden")
	}
	if !strings.Contains(err.Error(), "secret.reveal") {
		t.Fatalf("error should name the secret.reveal capability; got: %v", err)
	}
	// The raw 403 status line must not be the whole story — the hint replaces it.
	if !strings.Contains(err.Error(), "agent-only") {
		t.Fatalf("error should explain agent-only access; got: %v", err)
	}
}

func TestRunUsesByNameRevealAndSkipsListSecrets(t *testing.T) {
	var out bytes.Buffer
	runner := &recordingRunner{}
	client := &trackingAPIClient{}
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &out,
		Err:         &out,
		Runner:      runner,
		ClientFactory: func() (APIClient, error) {
			return client, nil
		},
	})
	cmd.SetArgs([]string{"run", "--secret", "OPENAI_API_KEY", "--", "echo", "x"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() err = %v", err)
	}
	if client.listCalls != 0 {
		t.Fatalf("ListSecrets called %d times; --secret path must not list (defeats the per-secret-grant goal)", client.listCalls)
	}
	if got := client.byNameCalls; len(got) != 1 || got[0] != "OPENAI_API_KEY" {
		t.Fatalf("RevealSecretValueByName calls = %v, want [OPENAI_API_KEY]", got)
	}
	var sawEnv bool
	for _, kv := range runner.spec.Env {
		if kv == "OPENAI_API_KEY=sk-live-openai" {
			sawEnv = true
		}
	}
	if !sawEnv {
		t.Fatalf("child env missing OPENAI_API_KEY injection; env=%v", runner.spec.Env)
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
	if _, err := parseSecretSpecs([]string{"a=X", "b=X"}, true); err == nil {
		t.Fatalf("expected an error when two specs share the same env var name")
	}
}

func TestRunAllInjectsEveryVisibleSecret(t *testing.T) {
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
	cmd.SetArgs([]string{"run", "--all", "--", "python", "agent.py"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got, ok := envValue(runner.spec.Env, "DB_PASSWORD"); !ok || got != "db-password-value" {
		t.Fatalf("DB_PASSWORD = %q ok=%v, want db-password-value (sanitized from db-password)", got, ok)
	}
	if got, ok := envValue(runner.spec.Env, "OPENAI_API_KEY"); !ok || got != "sk-live-openai" {
		t.Fatalf("OPENAI_API_KEY = %q ok=%v, want sk-live-openai", got, ok)
	}
}

func TestRunAllRejectsCombinedWithSecret(t *testing.T) {
	runner := &recordingRunner{}
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &bytes.Buffer{},
		Err:         &bytes.Buffer{},
		Runner:      runner,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{"run", "--all", "--secret", "OPENAI_API_KEY", "--", "echo"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--all cannot be combined with --secret") {
		t.Fatalf("Execute() error = %v, want combined-flag rejection", err)
	}
	if runner.spec.Command != "" {
		t.Fatalf("runner should not have been invoked")
	}
}

func TestRunInjectsContextVarsForChild(t *testing.T) {
	runner := &recordingRunner{}
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1",
		Out:         &bytes.Buffer{},
		Err:         &bytes.Buffer{},
		Runner:      runner,
		ClientFactory: func() (APIClient, error) {
			return fakeAPIClient{}, nil
		},
	})
	cmd.SetArgs([]string{"run", "--secret", "OPENAI_API_KEY", "--", "echo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got, ok := envValue(runner.spec.Env, "SECREVO_RUN"); !ok || got != "1" {
		t.Fatalf("SECREVO_RUN = %q ok=%v, want 1", got, ok)
	}
	if got, ok := envValue(runner.spec.Env, "SECREVO_WORKSPACE_ID"); !ok || got != "workspace-1" {
		t.Fatalf("SECREVO_WORKSPACE_ID = %q ok=%v, want workspace-1", got, ok)
	}
}

func TestAllSecretSpecsRejectsSanitizeCollisions(t *testing.T) {
	// Two distinct secret names that collide on the POSIX form must fail
	// loud so the operator either renames one or falls back to explicit
	// --secret specs.
	secrets := []client.Secret{
		{Name: "aws.cloudwatch.url"},
		{Name: "aws_cloudwatch_url"},
	}
	_, err := allSecretSpecs(secrets, true)
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("allSecretSpecs() error = %v, want collision error", err)
	}
}

func TestAllSecretSpecsRawNamePreservesLiteral(t *testing.T) {
	secrets := []client.Secret{
		{Name: "aws.cloudwatch.url"},
		{Name: "OPENAI_API_KEY"},
	}
	specs, err := allSecretSpecs(secrets, false)
	if err != nil {
		t.Fatalf("allSecretSpecs() error = %v", err)
	}
	if specs[0].envName != "aws.cloudwatch.url" || specs[1].envName != "OPENAI_API_KEY" {
		t.Fatalf("raw-mode envNames = %+v, want literal", specs)
	}
}

func TestParseSecretSpecsSanitizesByDefault(t *testing.T) {
	specs, err := parseSecretSpecs([]string{"aws.cloudwatch.url", "OPENAI_API_KEY"}, true)
	if err != nil {
		t.Fatalf("parseSecretSpecs() error = %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want 2", len(specs))
	}
	if specs[0].secretName != "aws.cloudwatch.url" || specs[0].envName != "AWS_CLOUDWATCH_URL" {
		t.Fatalf("spec[0] = %+v, want secretName=aws.cloudwatch.url envName=AWS_CLOUDWATCH_URL", specs[0])
	}
	if specs[1].secretName != "OPENAI_API_KEY" || specs[1].envName != "OPENAI_API_KEY" {
		t.Fatalf("spec[1] = %+v, want secretName=OPENAI_API_KEY envName=OPENAI_API_KEY", specs[1])
	}
}

func TestParseSecretSpecsExplicitEnvSurvivesSanitization(t *testing.T) {
	specs, err := parseSecretSpecs([]string{"aws.cloudwatch.url=WEBHOOK"}, true)
	if err != nil {
		t.Fatalf("parseSecretSpecs() error = %v", err)
	}
	if specs[0].envName != "WEBHOOK" {
		t.Fatalf("explicit envName = %q, want WEBHOOK", specs[0].envName)
	}
}

func TestParseSecretSpecsRawNameKeepsLiteral(t *testing.T) {
	specs, err := parseSecretSpecs([]string{"aws.cloudwatch.url"}, false)
	if err != nil {
		t.Fatalf("parseSecretSpecs() error = %v", err)
	}
	if specs[0].envName != "aws.cloudwatch.url" {
		t.Fatalf("raw-mode envName = %q, want literal", specs[0].envName)
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

func TestSecretListPrintsOneNamePerLine(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{SecretID: "secret-1", Name: "zeta", Status: "active"},
			{SecretID: "secret-2", Name: "alpha", Status: "active"},
			{SecretID: "secret-3", Name: "mu", Status: "active"},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := strings.TrimSpace(out.String())
	want := "alpha\nmu\nzeta"
	if got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestSecretRenameUpdatesNameWithoutTouchingValue(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{SecretID: "secret-1", Name: "aws.cloudwatch.url", Status: "active"},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "rename", "aws.cloudwatch.url", "AWS_CLOUDWATCH_URL"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.updateCalls) != 1 || fake.updateCalls[0].req.Name == nil || *fake.updateCalls[0].req.Name != "AWS_CLOUDWATCH_URL" {
		t.Fatalf("updateCalls = %+v, want one rename to AWS_CLOUDWATCH_URL", fake.updateCalls)
	}
	if len(fake.rotateCalls) != 0 {
		t.Fatalf("rotate must not be called; got %+v", fake.rotateCalls)
	}
	if !strings.Contains(out.String(), `Renamed "aws.cloudwatch.url" -> "AWS_CLOUDWATCH_URL"`) {
		t.Fatalf("output = %q, want rename confirmation", out.String())
	}
}

func TestSecretRenameSanitizeShortcut(t *testing.T) {
	fake := &secretWritingFake{
		existing: []client.Secret{
			{SecretID: "secret-1", Name: "prysmid.idp.google.client_id", Status: "active"},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	// Second positional ignored when --sanitize is set; using "_" as a
	// placeholder reads naturally.
	cmd.SetArgs([]string{"secret", "rename", "prysmid.idp.google.client_id", "_", "--sanitize"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := *fake.updateCalls[0].req.Name; got != "PRYSMID_IDP_GOOGLE_CLIENT_ID" {
		t.Fatalf("sanitize-mode rename = %q, want PRYSMID_IDP_GOOGLE_CLIENT_ID", got)
	}
}

func TestSecretRenameRefusesIfDestinationAlreadyExists(t *testing.T) {
	fake := &secretWritingFake{
		existing: []client.Secret{
			{SecretID: "secret-1", Name: "old", Status: "active"},
			{SecretID: "secret-2", Name: "new", Status: "active"},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "rename", "old", "new"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Execute() error = %v, want already-exists", err)
	}
	if len(fake.updateCalls) != 0 {
		t.Fatalf("must not call UpdateSecret on conflict; got %+v", fake.updateCalls)
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

func TestSecretDeleteWithYesCallsDelete(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-7", Name: "OPENAI_API_KEY", Status: "active"},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "delete", "OPENAI_API_KEY", "--yes"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.deleteCalls) != 1 {
		t.Fatalf("deleteCalls = %d, want 1", len(fake.deleteCalls))
	}
	if got := fake.deleteCalls[0].secretID; got != "secret-7" {
		t.Fatalf("deleted secretID = %q, want secret-7", got)
	}
	if !strings.Contains(out.String(), "Deleted secret \"OPENAI_API_KEY\"") {
		t.Fatalf("output = %q, want deletion confirmation", out.String())
	}
}

func TestSecretDeleteWithoutYesAndPipedStdinRefuses(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-7", Name: "OPENAI_API_KEY", Status: "active"},
		},
	}
	// A bytes.Reader is not an *os.File so isInteractive returns false:
	// the command must refuse rather than silently delete.
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		Stdin:         strings.NewReader("y\n"),
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "delete", "OPENAI_API_KEY"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "stdin is not a TTY") {
		t.Fatalf("Execute() error = %v, want non-TTY refusal", err)
	}
	if len(fake.deleteCalls) != 0 {
		t.Fatalf("deleteCalls = %d, want 0 (refused before API call)", len(fake.deleteCalls))
	}
}

func TestSecretDeleteUnknownNameReturnsNotFound(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-7", Name: "OPENAI_API_KEY", Status: "active"},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "delete", "DOES_NOT_EXIST", "--yes"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "secret not found") {
		t.Fatalf("Execute() error = %v, want not-found", err)
	}
	if len(fake.deleteCalls) != 0 {
		t.Fatalf("deleteCalls = %d, want 0 (resolve failed before API call)", len(fake.deleteCalls))
	}
}

func TestSecretDeletePropagatesAPIError(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-7", Name: "OPENAI_API_KEY", Status: "active"},
		},
		deleteErr: errors.New("boom"),
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "delete", "OPENAI_API_KEY", "--yes"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Execute() error = %v, want API error", err)
	}
}

func TestSecretEditPatchesOnlyGivenField(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{
				WorkspaceID:              "workspace-1",
				SecretID:                 "secret-7",
				Name:                     "DB_PASSWORD",
				Description:              "primary db",
				RegenerationInstructions: "old notes",
				Status:                   "active",
				Tags:                     []string{"prod"},
			},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "edit", "DB_PASSWORD", "--regeneration-instructions", "rotate in RDS console"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.rotateCalls) != 0 {
		t.Fatalf("rotateCalls = %d, want 0 (edit must never rotate the value)", len(fake.rotateCalls))
	}
	if len(fake.updateCalls) != 1 {
		t.Fatalf("updateCalls = %d, want 1", len(fake.updateCalls))
	}
	req := fake.updateCalls[0].req
	if req.RegenerationInstructions == nil || *req.RegenerationInstructions != "rotate in RDS console" {
		t.Fatalf("RegenerationInstructions = %v, want pointer to %q", req.RegenerationInstructions, "rotate in RDS console")
	}
	// Every other field must stay nil so the server leaves it untouched.
	if req.Name != nil || req.Description != nil || req.Status != nil || req.Tags != nil {
		t.Fatalf("partial patch leaked other fields: %+v", req)
	}
	if got := fake.existing[0].Description; got != "primary db" {
		t.Fatalf("description mutated to %q, want untouched", got)
	}
}

func TestSecretEditRegenerationFromStdinPreservesMultiline(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-7", Name: "DB_PASSWORD", Status: "active"},
		},
	}
	runbook := "Step 1: foo\nStep 2: bar\nStep 3: baz"
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		Stdin:         strings.NewReader(runbook + "\n"),
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "edit", "DB_PASSWORD", "--regeneration-instructions-file", "-"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.updateCalls) != 1 {
		t.Fatalf("updateCalls = %d, want 1", len(fake.updateCalls))
	}
	req := fake.updateCalls[0].req
	if req.RegenerationInstructions == nil || *req.RegenerationInstructions != runbook {
		t.Fatalf("RegenerationInstructions = %v, want multi-line %q", req.RegenerationInstructions, runbook)
	}
}

func TestSecretEditTagsReplaceSet(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-7", Name: "STRIPE_KEY", Status: "active", Tags: []string{"old"}},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "edit", "STRIPE_KEY", "--tag", "billing", "--tag", "prod"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	req := fake.updateCalls[0].req
	if req.Tags == nil || len(*req.Tags) != 2 || (*req.Tags)[0] != "billing" || (*req.Tags)[1] != "prod" {
		t.Fatalf("Tags = %v, want [billing prod]", req.Tags)
	}
}

func TestSecretEditClearTags(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-7", Name: "STRIPE_KEY", Status: "active", Tags: []string{"old"}},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "edit", "STRIPE_KEY", "--clear-tags"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	req := fake.updateCalls[0].req
	if req.Tags == nil || len(*req.Tags) != 0 {
		t.Fatalf("Tags = %v, want non-nil empty slice (clear)", req.Tags)
	}
}

func TestSecretEditWithNoFlagsErrors(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-7", Name: "DB_PASSWORD", Status: "active"},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "edit", "DB_PASSWORD"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "nothing to edit") {
		t.Fatalf("Execute() error = %v, want nothing-to-edit", err)
	}
	if len(fake.updateCalls) != 0 {
		t.Fatalf("updateCalls = %d, want 0 (no API call when nothing to edit)", len(fake.updateCalls))
	}
}

func TestSecretSetOnExistingRejectsMetadataFlags(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{
		existing: []client.Secret{
			{WorkspaceID: "workspace-1", SecretID: "secret-7", Name: "DB_PASSWORD", Status: "active"},
		},
	}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "set", "DB_PASSWORD", "--value", "new-secret", "--regeneration-instructions", "X"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "apply only when creating") {
		t.Fatalf("Execute() error = %v, want explicit rejection (not a silent no-op)", err)
	}
	if len(fake.rotateCalls) != 0 {
		t.Fatalf("rotateCalls = %d, want 0 (must fail before rotating)", len(fake.rotateCalls))
	}
	if !strings.Contains(err.Error(), "secrevo secret edit") {
		t.Fatalf("error should point at `secret edit`; got %v", err)
	}
}

func TestSecretRevealWithoutAllowStdoutRefuses(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &errOut,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--allow-stdout") {
		t.Fatalf("Execute() error = %v, want consent-required error mentioning --allow-stdout", err)
	}
	if !strings.Contains(err.Error(), "--to-file") {
		t.Fatalf("error should also point at --to-file alternative; got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must be empty when value is refused; got %q", out.String())
	}
}

func TestSecretRevealAllowStdoutPrintsValue(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &errOut,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password", "--allow-stdout"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := strings.TrimRight(out.String(), "\r\n"); got != "db-password-value" {
		t.Fatalf("stdout = %q, want exact value", got)
	}
}

func TestSecretRevealJSONEnvelope(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password", "--allow-stdout", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(out.String(), "\"value\": \"db-password-value\"") {
		t.Fatalf("output = %q, want JSON envelope containing value", out.String())
	}
	if !strings.Contains(out.String(), "\"secret_id\": \"secret-1\"") {
		t.Fatalf("output = %q, want JSON envelope containing secret_id", out.String())
	}
}

func TestSecretRevealToFileWritesAndDoesNotPrint(t *testing.T) {
	var out bytes.Buffer
	tmp := t.TempDir()
	path := filepath.Join(tmp, "secret.bin")
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password", "--to-file", path})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must be empty when --to-file is used; got %q", out.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read materialized file: %v", err)
	}
	if string(data) != "db-password-value" {
		t.Fatalf("file content length=%d, want exact value bytes", len(data))
	}
}

func TestSecretRevealRejectsToFileWithAllowStdout(t *testing.T) {
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password", "--allow-stdout", "--to-file", "/tmp/x"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("Execute() error = %v, want mutual-exclusion error", err)
	}
}

func TestSecretRevealRejectsJSONWithToFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "secret.bin")
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password", "--to-file", path, "--json"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--json applies only to --allow-stdout") {
		t.Fatalf("Execute() error = %v, want --json/--to-file conflict error", err)
	}
}
