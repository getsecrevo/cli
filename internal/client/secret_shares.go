package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// External shares: a single-use link that hands a COPY of a secret's value to
// someone outside the workspace. With an agent token the api only files a
// DRAFT that a person approves in the dashboard; with a person's own login and
// a fresh MFA step-up it shares at once. The value never passes through here.

// SecretShare is the api's view of a share (never ciphertext, links or codes).
type SecretShare struct {
	ID                 string   `json:"id"`
	WorkspaceID        string   `json:"workspace_id"`
	SecretID           string   `json:"secret_id"`
	SecretName         string   `json:"secret_name"`
	FieldNames         []string `json:"field_names"`
	SenderEmail        string   `json:"sender_email"`
	RequestedByAgentID string   `json:"requested_by_agent_id,omitempty"`
	RequesterAgentName string   `json:"requester_agent_name,omitempty"`
	RecipientEmail     string   `json:"recipient_email"`
	Status             string   `json:"status"`
	Opens              int      `json:"opens"`
	LockedUntil        string   `json:"locked_until,omitempty"`
	Delivery           string   `json:"delivery,omitempty"`
	RequireEmailCode   bool     `json:"require_email_code"`
	HasExtraCode       bool     `json:"has_extra_code"`
	ExpiresAt          string   `json:"expires_at"`
	CreatedAt          string   `json:"created_at"`
	ViewedAt           string   `json:"viewed_at,omitempty"`
	CancelledAt        string   `json:"cancelled_at,omitempty"`
}

// SecretShareCreateRequest is the body of POST .../secrets/by-name/{name}/shares.
// For an agent the api ignores everything but the recipient and the fields.
type SecretShareCreateRequest struct {
	RecipientEmail   string   `json:"recipient_email"`
	Message          string   `json:"message,omitempty"`
	Fields           []string `json:"fields,omitempty"`
	ExpiresInHours   int      `json:"expires_in_hours,omitempty"`
	RequireEmailCode *bool    `json:"require_email_code,omitempty"`
	ExtraCode        bool     `json:"extra_code,omitempty"`
	Delivery         string   `json:"delivery,omitempty"`
}

// SecretShareCreated is the api's answer. URL only for delivery=link to a
// person; ExtraCode only once, when asked.
type SecretShareCreated struct {
	Share     SecretShare `json:"share"`
	EmailSent bool        `json:"email_sent"`
	URL       string      `json:"url,omitempty"`
	ExtraCode string      `json:"extra_code,omitempty"`
	NextStep  string      `json:"next_step,omitempty"`
}

// CreateSecretShareByName shares (person) or drafts (agent) the secret with
// EXACTLY this name.
func (c *Client) CreateSecretShareByName(ctx context.Context, workspaceID, secretName string, req SecretShareCreateRequest) (SecretShareCreated, error) {
	var out SecretShareCreated
	path := fmt.Sprintf("/v1/workspaces/%s/secrets/by-name/%s/shares", url.PathEscape(workspaceID), url.PathEscape(secretName))
	err := c.doJSON(ctx, http.MethodPost, path, req, &out)
	return out, err
}

// ListSecretShares lists the shares the caller may see, optionally for one secret id.
func (c *Client) ListSecretShares(ctx context.Context, workspaceID, secretID string) ([]SecretShare, error) {
	var out struct {
		Shares []SecretShare `json:"shares"`
	}
	path := fmt.Sprintf("/v1/workspaces/%s/secret-shares", url.PathEscape(workspaceID))
	if secretID != "" {
		path += "?secret_id=" + url.QueryEscape(secretID)
	}
	err := c.doJSON(ctx, http.MethodGet, path, nil, &out)
	if out.Shares == nil {
		out.Shares = []SecretShare{}
	}
	return out.Shares, err
}

// SecretShareCancelled is the api's answer to a cancel.
type SecretShareCancelled struct {
	Share                SecretShare `json:"share"`
	MayHaveBeenDelivered bool        `json:"may_have_been_delivered"`
}

// CancelSecretShare cancels an open share (an agent: only its drafts).
func (c *Client) CancelSecretShare(ctx context.Context, workspaceID, shareID string) (SecretShareCancelled, error) {
	var out SecretShareCancelled
	path := fmt.Sprintf("/v1/workspaces/%s/secret-shares/%s/cancel", url.PathEscape(workspaceID), url.PathEscape(shareID))
	err := c.doJSON(ctx, http.MethodPost, path, struct{}{}, &out)
	return out, err
}
