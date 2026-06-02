package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getsecrevo/cli/internal/client"
)

// gracingFake extends secretWritingFake with a configurable previous-value
// response so the reveal-side tests can drive both the happy path and the
// 404 not_found_previous branch.
//
// We never echo the bare value in test assertions — only its length and
// hash-equivalent comparisons (per memory note never_emit_file_contents).
type gracingFake struct {
	secretWritingFake
	previousValue    string
	previousExpires  string
	previousNotFound bool
	revealCalls      []revealCall
}

type revealCall struct {
	name    string
	version string
}

func (f *gracingFake) RevealSecretValueByName(_ context.Context, _ string, name, version string) (client.SecretValue, error) {
	f.revealCalls = append(f.revealCalls, revealCall{name: name, version: version})
	if version == "previous" {
		if f.previousNotFound {
			// Mirror the shape `doJSON` produces for a 404 body so
			// `isNotFoundPrevious` recognises it. The api wraps the
			// JSON error body verbatim into the returned error.
			return client.SecretValue{}, errors.New(`api returned 404 Not Found: {"code":"not_found_previous","message":"no previous value"}`)
		}
		return client.SecretValue{
			WorkspaceID:    "workspace-1",
			SecretID:       "secret-1",
			Value:          f.previousValue,
			GraceExpiresAt: f.previousExpires,
		}, nil
	}
	// current
	for _, s := range f.existing {
		if s.Name == name {
			return client.SecretValue{WorkspaceID: "workspace-1", SecretID: s.SecretID, Value: "current-value"}, nil
		}
	}
	return client.SecretValue{}, errors.New("unknown secret name")
}

// ---------- secret set / update --grace -----------------------------------

func TestSecretSetGraceRejectsBadFormat(t *testing.T) {
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
	cmd.SetArgs([]string{"secret", "set", "OPENAI_API_KEY", "--value", "sk-live-new", "--grace", "1hour"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--grace must match") {
		t.Fatalf("Execute() error = %v, want format error", err)
	}
	if len(fake.rotateCalls) != 0 {
		t.Fatalf("rotateCalls = %d, want 0 (validation must short-circuit before HTTP)", len(fake.rotateCalls))
	}
}

func TestSecretSetGraceOnNonExistentSecretErrors(t *testing.T) {
	var out bytes.Buffer
	fake := &secretWritingFake{}
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "set", "BRAND_NEW", "--value", "x", "--grace", "1h"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--grace applies only to rotation") {
		t.Fatalf("Execute() error = %v, want clear error about rotation-only", err)
	}
	if len(fake.createCalls) != 0 || len(fake.rotateCalls) != 0 {
		t.Fatalf("createCalls=%d rotateCalls=%d, want both 0 (no PUT/POST when --grace + create)", len(fake.createCalls), len(fake.rotateCalls))
	}
}

func TestSecretSetGracePassesValueThroughToClient(t *testing.T) {
	cases := []string{"1m", "30m", "1h", "168h", "45s"}
	for _, g := range cases {
		t.Run(g, func(t *testing.T) {
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
			cmd.SetArgs([]string{"secret", "set", "OPENAI_API_KEY", "--value", "sk-live-new", "--grace", g})

			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if len(fake.rotateCalls) != 1 {
				t.Fatalf("rotateCalls = %d, want 1", len(fake.rotateCalls))
			}
			if got := fake.rotateCalls[0].grace; got != g {
				t.Fatalf("rotate.grace = %q, want %q", got, g)
			}
			if !strings.Contains(out.String(), "grace") {
				t.Fatalf("operator output should mention grace; got %q", out.String())
			}
		})
	}
}

func TestSecretUpdateAcceptsGrace(t *testing.T) {
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
	cmd.SetArgs([]string{"secret", "update", "OPENAI_API_KEY", "--value", "sk-live-new", "--grace", "2h"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.rotateCalls) != 1 || fake.rotateCalls[0].grace != "2h" {
		t.Fatalf("rotateCalls = %+v, want one rotate with grace=2h", fake.rotateCalls)
	}
}

// ---------- secret reveal --version previous ------------------------------

func TestSecretRevealVersionPreviousHappyPath(t *testing.T) {
	const expires = "2026-06-02T18:00:00Z"
	const prev = "old-secret-value"

	fake := &gracingFake{
		secretWritingFake: secretWritingFake{
			existing: []client.Secret{
				{WorkspaceID: "workspace-1", SecretID: "secret-1", Name: "db-password", Status: "active"},
			},
		},
		previousValue:   prev,
		previousExpires: expires,
	}
	var out, errOut bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &errOut,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password", "--allow-stdout", "--version", "previous"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fake.revealCalls) != 1 || fake.revealCalls[0].version != "previous" {
		t.Fatalf("reveal calls = %+v, want one with version=previous", fake.revealCalls)
	}
	stdoutTrimmed := strings.TrimRight(out.String(), "\r\n")
	if len(stdoutTrimmed) != len(prev) {
		t.Fatalf("stdout length = %d, want %d", len(stdoutTrimmed), len(prev))
	}
	if !strings.Contains(errOut.String(), "grace expires at "+expires) {
		t.Fatalf("stderr = %q, want grace-expiry line containing %q", errOut.String(), expires)
	}
}

func TestSecretRevealVersionPreviousJSONIncludesGraceExpiresAt(t *testing.T) {
	const expires = "2026-06-02T18:00:00Z"
	fake := &gracingFake{
		secretWritingFake: secretWritingFake{
			existing: []client.Secret{
				{WorkspaceID: "workspace-1", SecretID: "secret-1", Name: "db-password", Status: "active"},
			},
		},
		previousValue:   "old",
		previousExpires: expires,
	}
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password", "--allow-stdout", "--json", "--version", "previous"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON: %v (%q)", err, out.String())
	}
	if got, _ := envelope["grace_expires_at"].(string); got != expires {
		t.Fatalf("grace_expires_at = %q, want %q", got, expires)
	}
	if _, ok := envelope["value"]; !ok {
		t.Fatalf("envelope missing value key: %v", envelope)
	}
}

func TestSecretRevealVersionPreviousToFileWritesStderrLine(t *testing.T) {
	const expires = "2026-06-02T18:00:00Z"
	const prev = "old-secret-value"

	tmp := t.TempDir()
	path := filepath.Join(tmp, "prev.bin")

	fake := &gracingFake{
		secretWritingFake: secretWritingFake{
			existing: []client.Secret{
				{WorkspaceID: "workspace-1", SecretID: "secret-1", Name: "db-password", Status: "active"},
			},
		},
		previousValue:   prev,
		previousExpires: expires,
	}
	var out, errOut bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &errOut,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password", "--to-file", path, "--version", "previous"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must be empty with --to-file; got %q", out.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read materialized file: %v", err)
	}
	if len(data) != len(prev) {
		t.Fatalf("file length = %d, want %d", len(data), len(prev))
	}
	if !strings.Contains(errOut.String(), path) {
		t.Fatalf("stderr should mention path %q; got %q", path, errOut.String())
	}
	if !strings.Contains(errOut.String(), "grace expires at "+expires) {
		t.Fatalf("stderr should mention grace expiry %q; got %q", expires, errOut.String())
	}
}

func TestSecretRevealVersionPreviousNotFoundIsHumanError(t *testing.T) {
	fake := &gracingFake{
		secretWritingFake: secretWritingFake{
			existing: []client.Secret{
				{WorkspaceID: "workspace-1", SecretID: "secret-1", Name: "db-password", Status: "active"},
			},
		},
		previousNotFound: true,
	}
	var out, errOut bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &errOut,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password", "--allow-stdout", "--version", "previous"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil, want not-found-previous error")
	}
	if !strings.Contains(err.Error(), "No previous value available") {
		t.Fatalf("error = %v, want human-readable not-found-previous", err)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must be empty on error; got %q", out.String())
	}
}

func TestSecretRevealVersionRejectsUnknownValue(t *testing.T) {
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &bytes.Buffer{},
		Err:           &bytes.Buffer{},
		ClientFactory: func() (APIClient, error) { return fakeAPIClient{}, nil },
	})
	cmd.SetArgs([]string{"secret", "reveal", "db-password", "--allow-stdout", "--version", "bogus"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--version must be") {
		t.Fatalf("Execute() error = %v, want unknown-version error", err)
	}
}

// ---------- client.RotateSecretValue / RevealSecretValueByName URL shape ---

// These tests pin the URL shape so refactors of doJSON can't accidentally
// drop the query string. They run against an httptest.Server so the
// assertion is on the actual HTTP request the client emitted.

func TestClientRotateSecretValueGracePassedAsQuery(t *testing.T) {
	var gotURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	c, err := client.New(client.Config{BaseURL: server.URL, Token: "t", HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := c.RotateSecretValue(context.Background(), "ws-1", "sec-1", "v", "30m"); err != nil {
		t.Fatalf("RotateSecretValue() error = %v", err)
	}
	if !strings.Contains(gotURL, "?grace=30m") {
		t.Fatalf("request URL = %q, want ?grace=30m", gotURL)
	}
	if !strings.HasPrefix(gotURL, "/v1/workspaces/ws-1/secrets/sec-1/value") {
		t.Fatalf("request URL = %q, want value endpoint path", gotURL)
	}
}

func TestClientRotateSecretValueOmitsGraceWhenEmpty(t *testing.T) {
	var gotURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	c, _ := client.New(client.Config{BaseURL: server.URL, Token: "t", HTTPClient: server.Client()})
	if err := c.RotateSecretValue(context.Background(), "ws-1", "sec-1", "v", ""); err != nil {
		t.Fatalf("RotateSecretValue() error = %v", err)
	}
	if strings.Contains(gotURL, "grace") {
		t.Fatalf("request URL = %q, must not carry grace when empty (back-compat)", gotURL)
	}
}

func TestClientRevealSecretByNamePreviousVersion(t *testing.T) {
	const expires = "2026-06-02T18:00:00Z"
	var gotURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.RequestURI()
		w.Header().Set("X-Secrevo-Grace-Expires-At", expires)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"workspace_id":"ws-1","secret_id":"sec-1","value":"prev"}`))
	}))
	t.Cleanup(server.Close)

	c, _ := client.New(client.Config{BaseURL: server.URL, Token: "t", HTTPClient: server.Client()})
	got, err := c.RevealSecretValueByName(context.Background(), "ws-1", "needs encoding", "previous")
	if err != nil {
		t.Fatalf("RevealSecretValueByName() error = %v", err)
	}
	if !strings.Contains(gotURL, "version=previous") {
		t.Fatalf("request URL = %q, want version=previous query", gotURL)
	}
	// Ensure the name was URL-encoded along the path so a space doesn't
	// produce a malformed request line — `url.PathEscape` is what the
	// client already does for other path segments.
	if !strings.Contains(gotURL, url.PathEscape("needs encoding")) {
		t.Fatalf("request URL = %q, want path-encoded name", gotURL)
	}
	if got.GraceExpiresAt != expires {
		t.Fatalf("GraceExpiresAt = %q, want %q", got.GraceExpiresAt, expires)
	}
	if len(got.Value) == 0 {
		t.Fatalf("Value empty; response decode failed")
	}
}

func TestClientRevealSecretByNameCurrentVersionOmitsQuery(t *testing.T) {
	var gotURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"workspace_id":"ws-1","secret_id":"sec-1","value":"cur"}`))
	}))
	t.Cleanup(server.Close)

	c, _ := client.New(client.Config{BaseURL: server.URL, Token: "t", HTTPClient: server.Client()})
	for _, v := range []string{"", "current"} {
		gotURL = ""
		got, err := c.RevealSecretValueByName(context.Background(), "ws-1", "db-password", v)
		if err != nil {
			t.Fatalf("RevealSecretValueByName(%q) error = %v", v, err)
		}
		if strings.Contains(gotURL, "version=") {
			t.Fatalf("request URL = %q, must not carry version for %q (back-compat)", gotURL, v)
		}
		if got.GraceExpiresAt != "" {
			t.Fatalf("GraceExpiresAt = %q for current, want empty", got.GraceExpiresAt)
		}
	}
}
