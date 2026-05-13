package app

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getsecrevo/cli/internal/credentials"
)

type recordingBrowser struct {
	opened string
	err    error
}

func (r *recordingBrowser) Open(url string) error {
	r.opened = url
	return r.err
}

func TestLoginPersistsTokenAfterVerify(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")

	verifierCalls := 0
	verifier := func(_ context.Context, baseURL, token string) error {
		verifierCalls++
		if token != "agt_pasted" {
			t.Fatalf("verifier got token %q, want agt_pasted", token)
		}
		if baseURL != "https://api.secrevo.local" {
			t.Fatalf("verifier got baseURL %q", baseURL)
		}
		return nil
	}

	browser := &recordingBrowser{}
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:     "workspace-1",
		Out:             &out,
		Err:             &out,
		Browser:         browser,
		LoginVerifier:   verifier,
		CredentialsPath: credPath,
		Stdin:           strings.NewReader("agt_pasted\n"),
	})
	cmd.SetArgs([]string{
		"login",
		"--base-url", "https://api.secrevo.local",
		"--dashboard-url", "https://app.secrevo.local",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if verifierCalls != 1 {
		t.Fatalf("verifier called %d times, want 1", verifierCalls)
	}
	if browser.opened != "https://app.secrevo.local/agents/new?from=cli" {
		t.Fatalf("browser opened %q", browser.opened)
	}

	stored, err := credentials.Load(credPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if stored.Token != "agt_pasted" || stored.BaseURL != "https://api.secrevo.local" || stored.WorkspaceID != "workspace-1" {
		t.Fatalf("stored = %+v", stored)
	}
}

func TestLoginRejectsTokenWhenVerifierFails(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")

	verifier := func(context.Context, string, string) error {
		return errors.New("invalid token")
	}

	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:     "workspace-1",
		Out:             &out,
		Err:             &out,
		Browser:         &recordingBrowser{},
		LoginVerifier:   verifier,
		CredentialsPath: credPath,
		Stdin:           strings.NewReader("agt_bad\n"),
	})
	cmd.SetArgs([]string{"login", "--base-url", "https://api.secrevo.local"})

	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("Execute() error = %v, want rejection", err)
	}
	if _, err := credentials.Load(credPath); err != credentials.ErrNotFound {
		t.Fatalf("credentials should not have been written; Load = %v", err)
	}
}

func TestLoginRequiresWorkspace(t *testing.T) {
	cmd := NewRootCommand(Options{
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		Browser:       &recordingBrowser{},
		LoginVerifier: func(context.Context, string, string) error { return nil },
		Stdin:         strings.NewReader("agt_x\n"),
	})
	cmd.SetArgs([]string{"login"})

	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "workspace id is required") {
		t.Fatalf("Execute() error = %v, want workspace-id error", err)
	}
}

func TestLoginAcceptsInlineToken(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")

	cmd := NewRootCommand(Options{
		WorkspaceID:     "workspace-1",
		Out:             &bytes.Buffer{},
		Err:             &bytes.Buffer{},
		Browser:         &recordingBrowser{},
		LoginVerifier:   func(context.Context, string, string) error { return nil },
		CredentialsPath: credPath,
	})
	cmd.SetArgs([]string{
		"login",
		"--no-browser",
		"--token", "agt_inline",
		"--base-url", "https://api.secrevo.local",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	stored, err := credentials.Load(credPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if stored.Token != "agt_inline" {
		t.Fatalf("token = %q", stored.Token)
	}
}

func TestLogoutDeletesCredentialsFile(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	if err := credentials.Save(credPath, credentials.File{Token: "agt_x", BaseURL: "u", WorkspaceID: "w"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		Out:             &out,
		Err:             &out,
		CredentialsPath: credPath,
	})
	cmd.SetArgs([]string{"logout"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if _, err := credentials.Load(credPath); err != credentials.ErrNotFound {
		t.Fatalf("expected file removed; Load = %v", err)
	}
	if !strings.Contains(out.String(), "Cleared") {
		t.Fatalf("output = %q, want Cleared message", out.String())
	}
}

// TestLoginSkipsBrowserWhenCredentialsAlreadyExist confirms the
// default-off behavior for the browser launch when a credentials
// file is already present. Re-running `secrevo login` to paste a
// fresh token should not pop a browser tab the operator does not
// need.
func TestLoginSkipsBrowserWhenCredentialsAlreadyExist(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	if err := credentials.Save(credPath, credentials.File{
		BaseURL:     "https://api.secrevo.local",
		WorkspaceID: "workspace-1",
		Token:       "agt_old",
	}); err != nil {
		t.Fatalf("seed credentials err = %v", err)
	}

	browser := &recordingBrowser{}
	cmd := NewRootCommand(Options{
		WorkspaceID:     "workspace-1",
		Out:             &bytes.Buffer{},
		Err:             &bytes.Buffer{},
		Browser:         browser,
		LoginVerifier:   func(context.Context, string, string) error { return nil },
		CredentialsPath: credPath,
	})
	cmd.SetArgs([]string{
		"login",
		"--base-url", "https://api.secrevo.local",
		"--dashboard-url", "https://app.secrevo.local",
		"--token", "agt_new",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if browser.opened != "" {
		t.Fatalf("expected browser to stay closed when creds already exist; opened %q", browser.opened)
	}
}

// TestLoginForceBrowserWithExplicitFlag confirms the operator can
// override the default-off behavior by passing --no-browser=false.
func TestLoginForceBrowserWithExplicitFlag(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")
	if err := credentials.Save(credPath, credentials.File{
		BaseURL:     "https://api.secrevo.local",
		WorkspaceID: "workspace-1",
		Token:       "agt_old",
	}); err != nil {
		t.Fatalf("seed credentials err = %v", err)
	}

	browser := &recordingBrowser{}
	cmd := NewRootCommand(Options{
		WorkspaceID:     "workspace-1",
		Out:             &bytes.Buffer{},
		Err:             &bytes.Buffer{},
		Browser:         browser,
		LoginVerifier:   func(context.Context, string, string) error { return nil },
		CredentialsPath: credPath,
	})
	cmd.SetArgs([]string{
		"login",
		"--base-url", "https://api.secrevo.local",
		"--dashboard-url", "https://app.secrevo.local",
		"--no-browser=false",
		"--token", "agt_new",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if browser.opened != "https://app.secrevo.local/agents/new?from=cli" {
		t.Fatalf("expected browser to open with --no-browser=false; opened %q", browser.opened)
	}
}
