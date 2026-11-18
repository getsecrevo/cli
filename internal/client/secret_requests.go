package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Secret requests: a single-use, WRITE-ONLY link that lets someone outside the
// workspace (a customer, a vendor) type a secret's value straight into the
// vault. No secret material passes through here: the link can only write.

// SecretRequestField is one field the recipient fills.
type SecretRequestField struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
}

// SecretRequest is the api's view of a request (never the link itself).
type SecretRequest struct {
	ID                 string               `json:"id"`
	WorkspaceID        string               `json:"workspace_id"`
	SecretID           string               `json:"secret_id"`
	SecretName         string               `json:"secret_name,omitempty"`
	RequestedBy        string               `json:"requested_by"`
	RequesterEmail     string               `json:"requester_email"`
	RequestedByAgentID string               `json:"requested_by_agent_id,omitempty"`
	RequesterAgentName string               `json:"requester_agent_name,omitempty"`
	RecipientEmail     string               `json:"recipient_email,omitempty"`
	Message            string               `json:"message,omitempty"`
	Fields             []SecretRequestField `json:"fields"`
	Status             string               `json:"status"`
	ApprovalReason     string               `json:"approval_reason,omitempty"`
	ExpiresAt          string               `json:"expires_at"`
	CreatedAt          string               `json:"created_at"`
	FulfilledAt        string               `json:"fulfilled_at,omitempty"`
	CancelledAt        string               `json:"cancelled_at,omitempty"`
}

// SecretRequestCreateRequest is the body of POST .../secrets/by-name/{name}/requests.
type SecretRequestCreateRequest struct {
	RecipientEmail      string            `json:"recipient_email,omitempty"`
	Message             string            `json:"message,omitempty"`
	FieldLabels         map[string]string `json:"field_labels,omitempty"`
	ExpiresInHours      int               `json:"expires_in_hours,omitempty"`
	SendEmail           *bool             `json:"send_email,omitempty"`
	ReplaceExisting     bool              `json:"replace_existing,omitempty"`
	ConfirmNewRecipient bool              `json:"confirm_new_recipient,omitempty"`
}

// SecretRequestCreated is the api's answer: the request plus the link, shown once.
type SecretRequestCreated struct {
	Request   SecretRequest `json:"request"`
	URL       string        `json:"url,omitempty"`
	EmailSent bool          `json:"email_sent"`
	// NextStep is set for agent callers when the request waits for a person.
	NextStep string `json:"next_step,omitempty"`
}

// CreateSecretRequestByName creates a request for the secret with EXACTLY this
// name (the api does no fuzzy matching).
func (c *Client) CreateSecretRequestByName(ctx context.Context, workspaceID, secretName string, req SecretRequestCreateRequest) (SecretRequestCreated, error) {
	var out SecretRequestCreated
	path := fmt.Sprintf("/v1/workspaces/%s/secrets/by-name/%s/requests", url.PathEscape(workspaceID), url.PathEscape(secretName))
	err := c.doJSON(ctx, http.MethodPost, path, req, &out)
	return out, err
}

// ListSecretRequests lists the requests the caller may see, optionally for one secret id.
func (c *Client) ListSecretRequests(ctx context.Context, workspaceID, secretID string) ([]SecretRequest, error) {
	var out struct {
		Requests []SecretRequest `json:"requests"`
	}
	path := fmt.Sprintf("/v1/workspaces/%s/secret-requests", url.PathEscape(workspaceID))
	if secretID != "" {
		path += "?secret_id=" + url.QueryEscape(secretID)
	}
	err := c.doJSON(ctx, http.MethodGet, path, nil, &out)
	if out.Requests == nil {
		out.Requests = []SecretRequest{}
	}
	return out.Requests, err
}

// CancelSecretRequest cancels a pending request so its link stops working.
func (c *Client) CancelSecretRequest(ctx context.Context, workspaceID, requestID string) (SecretRequest, error) {
	var out SecretRequest
	path := fmt.Sprintf("/v1/workspaces/%s/secret-requests/%s/cancel", url.PathEscape(workspaceID), url.PathEscape(requestID))
	err := c.doJSON(ctx, http.MethodPost, path, struct{}{}, &out)
	return out, err
}
