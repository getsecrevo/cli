package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/getsecrevo/cli/internal/client"
)

// TestCredsAwsProcessFormat: `secrevo creds --format aws-process` emits exactly
// the shape the AWS CLI credential_process expects (Version:1 + the STS fields).
func TestCredsAwsProcessFormat(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"creds", "--secret", "AMBER_ODOO_AWS", "--format", "aws-process"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if v, _ := got["Version"].(float64); v != 1 {
		t.Fatalf("credential_process Version must be 1, got %v", got["Version"])
	}
	for _, k := range []string{"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("credential_process output missing %q: %s", k, out.String())
		}
	}
}

// TestCredsEnvFormat: `secrevo creds --format env` emits shell export lines for
// the AWS env vars (for `eval $(secrevo creds ...)`).
func TestCredsEnvFormat(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"creds", "--secret", "AMBER_ODOO_AWS", "--format", "env"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	got := out.String()
	for _, want := range []string{"export AWS_ACCESS_KEY_ID=ASIAEXAMPLE", "export AWS_SECRET_ACCESS_KEY=secretpart", "export AWS_SESSION_TOKEN=sessiontok"} {
		if !strings.Contains(got, want) {
			t.Fatalf("env output missing %q:\n%s", want, got)
		}
	}
}

// TestCredsRejectsBadTTL: an unparsable --ttl is rejected before any call.
func TestCredsRejectsBadTTL(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"creds", "--secret", "X", "--ttl", "notaduration"})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected an error for a bad --ttl, got nil (output %q)", out.String())
	}
}

// TestCredsRejectsBadFormat: an unknown --format is rejected.
func TestCredsRejectsBadFormat(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"creds", "--secret", "X", "--format", "yaml"})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected an error for a bad --format, got nil")
	}
}

// capturingCredScopeFake records the PutCredScope call so the add command's
// flag→request mapping can be asserted. Embeds fakeAPIClient for the rest.
type capturingCredScopeFake struct {
	fakeAPIClient
	putWS, putSecretID string
	putScope           client.CredScope
}

func (f *capturingCredScopeFake) PutCredScope(_ context.Context, ws, secretID string, s client.CredScope) (client.CredScope, error) {
	f.putWS, f.putSecretID, f.putScope = ws, secretID, s
	return s, nil
}

// TestCredScopeAddBuildsAwsScope: `secret cred-scope add` resolves the secret and
// builds an aws_sts scope from the role-arn + max-ttl flags.
func TestCredScopeAddBuildsAwsScope(t *testing.T) {
	var out bytes.Buffer
	fake := &capturingCredScopeFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "cred-scope", "add", "--secret", "OPENAI_API_KEY",
		"--provider", "aws_sts", "--role-arn", "arn:aws:iam::007761758105:role/ephemeral-x", "--max-ttl", "15m"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if fake.putSecretID != "secret-2" {
		t.Fatalf("expected the resolved secret id secret-2, got %q", fake.putSecretID)
	}
	if fake.putScope.Provider != "aws_sts" || fake.putScope.Config["role_arn"] != "arn:aws:iam::007761758105:role/ephemeral-x" {
		t.Fatalf("unexpected scope built: %+v", fake.putScope)
	}
	if fake.putScope.MaxTTLSeconds != 900 {
		t.Fatalf("expected max_ttl 900s, got %d", fake.putScope.MaxTTLSeconds)
	}
}

// TestCredScopeAddBuildsFederationScope: aws_federation needs no role/allowlist;
// --access-key-id / --region / --policy map into Config, none required.
func TestCredScopeAddBuildsFederationScope(t *testing.T) {
	var out bytes.Buffer
	fake := &capturingCredScopeFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "cred-scope", "add", "--secret", "OPENAI_API_KEY",
		"--provider", "aws_federation", "--access-key-id", "AKIAOWNER", "--policy", `{"Version":"2012-10-17"}`})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if fake.putScope.Provider != "aws_federation" {
		t.Fatalf("expected aws_federation provider, got %q", fake.putScope.Provider)
	}
	if fake.putScope.Config["access_key_id"] != "AKIAOWNER" || fake.putScope.Config["policy"] == "" {
		t.Fatalf("federation config not built: %+v", fake.putScope.Config)
	}
	if _, hasRole := fake.putScope.Config["role_arn"]; hasRole {
		t.Fatalf("aws_federation must not carry a role_arn: %+v", fake.putScope.Config)
	}
}

// TestCredScopeAddDefaultProviderIsFederation: with no --provider, the default is
// aws_federation (the self-serve recommended path), which needs no extra flags.
func TestCredScopeAddDefaultProviderIsFederation(t *testing.T) {
	var out bytes.Buffer
	fake := &capturingCredScopeFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "cred-scope", "add", "--secret", "OPENAI_API_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if fake.putScope.Provider != "aws_federation" {
		t.Fatalf("expected default provider aws_federation, got %q", fake.putScope.Provider)
	}
}

// TestCredScopeAddRequiresRoleARN: aws_sts without --role-arn is rejected.
func TestCredScopeAddRequiresRoleARN(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"secret", "cred-scope", "add", "--secret", "OPENAI_API_KEY", "--provider", "aws_sts"})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected an error when --role-arn is missing for aws_sts")
	}
}
