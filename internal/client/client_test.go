package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewReturnsNotConfiguredWhenMissingSettings(t *testing.T) {
	if _, err := New(Config{}); err != ErrNotConfigured {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestWhoamiSendsBearerToken(t *testing.T) {
	t.Helper()

	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/v1/auth/sessions" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Session{
			Issuer:   "https://issuer.example",
			Audience: []string{"client-id"},
			Tenant:   "tenant-1",
			Identity: Identity{Subject: "sub-1", Email: "alice@example.com", Name: "Alice"},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(Config{
		BaseURL:    server.URL,
		Token:      "token-123",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	session, err := c.Whoami(context.Background())
	if err != nil {
		t.Fatalf("Whoami() error = %v", err)
	}
	if gotAuth != "Bearer token-123" {
		t.Fatalf("unexpected auth header %q", gotAuth)
	}
	if session.Identity.Email != "alice@example.com" {
		t.Fatalf("unexpected session %#v", session)
	}
}

func TestRevealSecretValueHitsValueEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v1/workspaces/ws-1/secrets/sec-1/value" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SecretValue{
			WorkspaceID: "ws-1",
			SecretID:    "sec-1",
			Value:       "sk-live-123",
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(Config{BaseURL: server.URL, Token: "t", HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got, err := c.RevealSecretValue(context.Background(), "ws-1", "sec-1")
	if err != nil {
		t.Fatalf("RevealSecretValue() error = %v", err)
	}
	if got.Value != "sk-live-123" {
		t.Fatalf("value = %q, want sk-live-123", got.Value)
	}
}

func TestProxyConsumeHitsProxyEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/workspaces/ws-1/secrets/by-name/OPENAI/proxy" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		var req ProxyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.URL != "https://api.openai.com/v1/models" || req.Headers["Authorization"] != "Bearer {{secret}}" {
			t.Fatalf("unexpected proxy request %#v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ProxyResponse{Status: 200, Body: `{"ok":1}`, Projected: true})
	}))
	t.Cleanup(server.Close)

	c, err := New(Config{BaseURL: server.URL, Token: "t", HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got, err := c.ProxyConsume(context.Background(), "ws-1", "OPENAI", ProxyRequest{
		Method: "GET", URL: "https://api.openai.com/v1/models", Headers: map[string]string{"Authorization": "Bearer {{secret}}"},
	})
	if err != nil {
		t.Fatalf("ProxyConsume() error = %v", err)
	}
	if got.Status != 200 || !got.Projected || got.Body != `{"ok":1}` {
		t.Fatalf("unexpected response %#v", got)
	}
}

func TestBootstrapWorkspaceSendsRequestBody(t *testing.T) {
	t.Helper()

	var payload BootstrapWorkspaceRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/v1/workspaces/bootstrap" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(BootstrapWorkspaceResponse{
			ID:         "workspace-1",
			Name:       payload.Name,
			Status:     "active",
			AdminEmail: payload.AdminEmail,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(Config{
		BaseURL:    server.URL,
		Token:      "token-123",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := c.BootstrapWorkspace(context.Background(), BootstrapWorkspaceRequest{
		Name:       "Secrevo",
		AdminEmail: "admin@example.com",
	})
	if err != nil {
		t.Fatalf("BootstrapWorkspace() error = %v", err)
	}
	if payload.Name != "Secrevo" || payload.AdminEmail != "admin@example.com" {
		t.Fatalf("unexpected payload %#v", payload)
	}
	if resp.ID != "workspace-1" {
		t.Fatalf("unexpected response %#v", resp)
	}
}

// TestSecretDecodesFieldNames: the api sends a multi-field secret's field NAMES
// on the single-secret GET, and the CLI used to silently drop them — so the one
// command every error message points at ("`secrevo secret get <NAME>` lists its
// field names") showed none, and an operator had no way to learn how to address
// --secret-field or {{secret.<field>}}.
func TestSecretDecodesFieldNames(t *testing.T) {
	var s Secret
	if err := json.Unmarshal([]byte(`{"name":"SUNAT","fields":["clave","ruc","usuario"]}`), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(s.Fields) != 3 || s.Fields[0] != "clave" {
		t.Fatalf("field names dropped: %+v", s.Fields)
	}
	// A scalar secret carries none, and omitempty keeps its output unchanged.
	out, err := json.Marshal(Secret{Name: "SCALAR"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "fields") {
		t.Fatalf("a scalar secret must not grow a fields key: %s", out)
	}
}
