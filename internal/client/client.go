package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/getsecrevo/cli/internal/credentials"
)

var ErrNotConfigured = errors.New("secrevo API client is not configured")

type Config struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
}

type Session struct {
	Issuer   string   `json:"issuer"`
	Audience []string `json:"audience"`
	Tenant   string   `json:"tenant"`
	Identity Identity `json:"identity"`
}

type Identity struct {
	Subject string `json:"subject"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

type BootstrapWorkspaceRequest struct {
	Name       string `json:"name,omitempty"`
	AdminEmail string `json:"admin_email,omitempty"`
}

type BootstrapWorkspaceResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	AdminEmail string `json:"admin_email"`
}

type Secret struct {
	WorkspaceID              string   `json:"workspace_id"`
	SecretID                 string   `json:"secret_id"`
	Name                     string   `json:"name"`
	Description              string   `json:"description"`
	RegenerationInstructions string   `json:"regeneration_instructions"`
	Status                   string   `json:"status"`
	Tags                     []string `json:"tags"`
	UpdatedAt                string   `json:"updated_at"`
}

type SecretListResponse struct {
	Secrets []Secret `json:"secrets"`
}

type SecretValue struct {
	WorkspaceID string `json:"workspace_id"`
	SecretID    string `json:"secret_id"`
	Value       string `json:"value"`
}

type Agent struct {
	ID              string `json:"id"`
	WorkspaceID     string `json:"workspace_id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	OwnerIdentityID string `json:"owner_identity_id"`
	TokenPrefix     string `json:"token_prefix"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	PausedAt        string `json:"paused_at"`
	RevokedAt       string `json:"revoked_at"`
}

type AgentCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type SecretCreateRequest struct {
	Name                     string `json:"name"`
	Description              string `json:"description,omitempty"`
	RegenerationInstructions string `json:"regeneration_instructions,omitempty"`
	Value                    string `json:"value,omitempty"`
}

type SecretValueWriteRequest struct {
	Value string `json:"value"`
}

// SecretUpdateRequest is the PATCH payload for secret metadata. Every
// field uses a pointer so a caller that wants to "only rename" sends just
// {"name": "NEW"} — omitted fields are not touched on the server.
type SecretUpdateRequest struct {
	Name                     *string `json:"name,omitempty"`
	Description              *string `json:"description,omitempty"`
	RegenerationInstructions *string `json:"regeneration_instructions,omitempty"`
	Status                   *string `json:"status,omitempty"`
}

type AgentCreateResponse struct {
	Agent   Agent  `json:"agent"`
	Token   string `json:"token"`
	Snippet string `json:"snippet"`
}

// NewFromEnv constructs a client from environment variables, falling back
// to the persisted credentials file (`secrevo login`) for any field the
// env didn't set. The env wins per-field so a CI job can override only the
// pieces it cares about (e.g. SECREVO_WORKSPACE_ID without re-supplying
// the token).
func NewFromEnv() (*Client, error) {
	baseURL := strings.TrimSpace(os.Getenv("SECREVO_API_BASE_URL"))
	token := strings.TrimSpace(os.Getenv("SECREVO_API_TOKEN"))

	if baseURL == "" || token == "" {
		path, err := credentials.DefaultPath()
		if err == nil {
			if stored, err := credentials.Load(path); err == nil {
				if baseURL == "" {
					baseURL = stored.BaseURL
				}
				if token == "" {
					token = stored.Token
				}
			}
		}
	}

	return New(Config{
		BaseURL:    baseURL,
		Token:      token,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	})
}

func New(cfg Config) (*Client, error) {
	baseURL := strings.TrimSpace(cfg.BaseURL)
	token := strings.TrimSpace(cfg.Token)
	if baseURL == "" || token == "" {
		return nil, ErrNotConfigured
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse API base URL: %w", err)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &Client{
		baseURL:    parsed,
		token:      token,
		httpClient: cfg.HTTPClient,
	}, nil
}

func (c *Client) BaseURL() string {
	if c == nil || c.baseURL == nil {
		return ""
	}
	return c.baseURL.String()
}

func (c *Client) Whoami(ctx context.Context) (Session, error) {
	var out Session
	err := c.doJSON(ctx, http.MethodPost, "/v1/auth/sessions", nil, &out)
	return out, err
}

func (c *Client) BootstrapWorkspace(ctx context.Context, req BootstrapWorkspaceRequest) (BootstrapWorkspaceResponse, error) {
	var out BootstrapWorkspaceResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/workspaces/bootstrap", req, &out)
	return out, err
}

func (c *Client) GetSecret(ctx context.Context, workspaceID, secretID string) (Secret, error) {
	var out Secret
	path := fmt.Sprintf("/v1/workspaces/%s/secrets/%s", url.PathEscape(workspaceID), url.PathEscape(secretID))
	err := c.doJSON(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

func (c *Client) RevealSecretValue(ctx context.Context, workspaceID, secretID string) (SecretValue, error) {
	var out SecretValue
	path := fmt.Sprintf("/v1/workspaces/%s/secrets/%s/value", url.PathEscape(workspaceID), url.PathEscape(secretID))
	err := c.doJSON(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

func (c *Client) ListSecrets(ctx context.Context, workspaceID string) (SecretListResponse, error) {
	var out SecretListResponse
	path := fmt.Sprintf("/v1/workspaces/%s/secrets", url.PathEscape(workspaceID))
	err := c.doJSON(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

// CreateSecret creates a new secret in the workspace and, when “req.Value“
// is non-empty, writes the value to OpenBao in a single API round-trip.
// The returned “Secret“ carries the metadata only — the value is never
// echoed back.
func (c *Client) CreateSecret(ctx context.Context, workspaceID string, req SecretCreateRequest) (Secret, error) {
	var out Secret
	path := fmt.Sprintf("/v1/workspaces/%s/secrets", url.PathEscape(workspaceID))
	err := c.doJSON(ctx, http.MethodPost, path, req, &out)
	return out, err
}

// RotateSecretValue overwrites the value of an existing secret without
// touching metadata. The previous value is unrecoverable from the API
// (the workspace's audit log records the rotation event).
func (c *Client) RotateSecretValue(ctx context.Context, workspaceID, secretID, value string) error {
	path := fmt.Sprintf("/v1/workspaces/%s/secrets/%s/value", url.PathEscape(workspaceID), url.PathEscape(secretID))
	return c.doJSON(ctx, http.MethodPut, path, SecretValueWriteRequest{Value: value}, nil)
}

// UpdateSecret patches secret metadata. Fields left nil in the request
// are not touched on the server side.
func (c *Client) UpdateSecret(ctx context.Context, workspaceID, secretID string, req SecretUpdateRequest) (Secret, error) {
	var out Secret
	path := fmt.Sprintf("/v1/workspaces/%s/secrets/%s", url.PathEscape(workspaceID), url.PathEscape(secretID))
	err := c.doJSON(ctx, http.MethodPatch, path, req, &out)
	return out, err
}

func (c *Client) CreateAgent(ctx context.Context, workspaceID string, req AgentCreateRequest) (AgentCreateResponse, error) {
	var out AgentCreateResponse
	path := fmt.Sprintf("/v1/workspaces/%s/agents", url.PathEscape(workspaceID))
	err := c.doJSON(ctx, http.MethodPost, path, req, &out)
	return out, err
}

func (c *Client) doJSON(ctx context.Context, method, path string, reqBody any, respBody any) error {
	if c == nil || c.baseURL == nil || c.httpClient == nil || c.token == "" {
		return ErrNotConfigured
	}

	var bodyReader io.Reader
	if reqBody != nil {
		payload, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("marshal request payload: %w", err)
		}
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.resolve(path), bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "secrevo-cli")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		message, _ := io.ReadAll(resp.Body)
		if len(message) == 0 {
			return fmt.Errorf("api returned %s", resp.Status)
		}
		return fmt.Errorf("api returned %s: %s", resp.Status, strings.TrimSpace(string(message)))
	}

	if respBody == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *Client) resolve(path string) string {
	return strings.TrimRight(c.baseURL.String(), "/") + "/" + strings.TrimLeft(path, "/")
}
