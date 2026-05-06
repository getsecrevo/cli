package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
