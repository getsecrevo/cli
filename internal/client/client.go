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
	// GraceExpiresAt is the ISO-8601 timestamp at which the previous value
	// referenced by `?version=previous` will be discarded. Populated from
	// the `X-Secrevo-Grace-Expires-At` response header. Empty for the
	// current version (the live value has no expiry).
	GraceExpiresAt string `json:"grace_expires_at,omitempty"`
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

// RevealSecretValueByName resolves the secret by (workspace, name) on the
// server and returns the plaintext value. Lets callers with only a per-secret
// grant skip ListSecrets — that endpoint requires secret.read@workspace, which
// is overbroad when the caller already knows the exact secret it needs.
//
// version selects which value to return: "" or "current" returns the live
// value; "previous" returns the snapshot captured by a `?grace=<duration>`
// rotation (api#46). For "previous", the response carries
// X-Secrevo-Grace-Expires-At which is surfaced as SecretValue.GraceExpiresAt.
// A 404 with body containing `not_found_previous` indicates the grace window
// expired or the rotation didn't request one.
func (c *Client) RevealSecretValueByName(ctx context.Context, workspaceID, name, version string) (SecretValue, error) {
	var out SecretValue
	path := fmt.Sprintf("/v1/workspaces/%s/secrets/by-name/%s/value", url.PathEscape(workspaceID), url.PathEscape(name))
	if v := strings.TrimSpace(version); v != "" && v != "current" {
		path += "?version=" + url.QueryEscape(v)
	}
	header, err := c.doJSONWithHeader(ctx, http.MethodGet, path, nil, &out)
	if err != nil {
		return out, err
	}
	if header != nil {
		out.GraceExpiresAt = header.Get("X-Secrevo-Grace-Expires-At")
	}
	return out, nil
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
// touching metadata.
//
// grace, when non-empty, requests a grace window during which the previous
// value remains retrievable via `?version=previous`. Format is
// `<int><h|m|s>` (validated by the server, range 1m..168h). When grace is
// empty the rotation is irrecoverable, matching pre-api#46 behavior.
func (c *Client) RotateSecretValue(ctx context.Context, workspaceID, secretID, value, grace string) error {
	path := fmt.Sprintf("/v1/workspaces/%s/secrets/%s/value", url.PathEscape(workspaceID), url.PathEscape(secretID))
	if g := strings.TrimSpace(grace); g != "" {
		path += "?grace=" + url.QueryEscape(g)
	}
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

// DeleteSecret removes a secret from the workspace. The server cascades
// secret-scoped grants and destroys the OpenBao value + history in the
// same request. Returns nil on 204; an error including the HTTP status
// on 4xx/5xx.
func (c *Client) DeleteSecret(ctx context.Context, workspaceID, secretID string) error {
	path := fmt.Sprintf("/v1/workspaces/%s/secrets/%s", url.PathEscape(workspaceID), url.PathEscape(secretID))
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil)
}

func (c *Client) CreateAgent(ctx context.Context, workspaceID string, req AgentCreateRequest) (AgentCreateResponse, error) {
	var out AgentCreateResponse
	path := fmt.Sprintf("/v1/workspaces/%s/agents", url.PathEscape(workspaceID))
	err := c.doJSON(ctx, http.MethodPost, path, req, &out)
	return out, err
}

func (c *Client) doJSON(ctx context.Context, method, path string, reqBody any, respBody any) error {
	_, err := c.doJSONWithHeader(ctx, method, path, reqBody, respBody)
	return err
}

// doJSONWithHeader is doJSON that exposes the response headers to the caller.
// Used by endpoints that surface server-side metadata via headers (e.g. the
// X-Secrevo-Grace-Expires-At header on `?version=previous` reads). Returns
// nil headers when the request failed before a response was produced.
func (c *Client) doJSONWithHeader(ctx context.Context, method, path string, reqBody any, respBody any) (http.Header, error) {
	if c == nil || c.baseURL == nil || c.httpClient == nil || c.token == "" {
		return nil, ErrNotConfigured
	}

	var bodyReader io.Reader
	if reqBody != nil {
		payload, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("marshal request payload: %w", err)
		}
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.resolve(path), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "secrevo-cli")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		message, _ := io.ReadAll(resp.Body)
		if len(message) == 0 {
			return resp.Header, fmt.Errorf("api returned %s", resp.Status)
		}
		return resp.Header, fmt.Errorf("api returned %s: %s", resp.Status, strings.TrimSpace(string(message)))
	}

	if respBody == nil {
		return resp.Header, nil
	}
	if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
		return resp.Header, fmt.Errorf("decode response: %w", err)
	}
	return resp.Header, nil
}

func (c *Client) resolve(path string) string {
	return strings.TrimRight(c.baseURL.String(), "/") + "/" + strings.TrimLeft(path, "/")
}
