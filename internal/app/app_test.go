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
		},
	}, nil
}
func (f fakeAPIClient) GetSecret(context.Context, string, string) (client.Secret, error) {
	return client.Secret{WorkspaceID: "workspace-1", SecretID: "secret-1", Name: "db", Status: "active"}, nil
}
func (f fakeAPIClient) CreateAgent(context.Context, string, client.AgentCreateRequest) (client.AgentCreateResponse, error) {
	return client.AgentCreateResponse{Token: "token-1", Snippet: "export SECREVO_AGENT_TOKEN=token-1"}, nil
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
	cmd.SetArgs([]string{"run", "--", "echo", "hello"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil, want configuration error")
	}
	if !strings.Contains(err.Error(), "secrevo API client is not configured") {
		t.Fatalf("error = %v, want not configured", err)
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
