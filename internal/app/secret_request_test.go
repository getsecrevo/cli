package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/getsecrevo/cli/internal/client"
)

// secretRequestFake records what the `secret request` commands send.
type secretRequestFake struct {
	fakeAPIClient
	gotWS, gotName string
	gotReq         client.SecretRequestCreateRequest
	emailSent      bool
	listSecretID   string
	cancelled      string
}

func (f *secretRequestFake) CreateSecretRequestByName(_ context.Context, ws, name string, req client.SecretRequestCreateRequest) (client.SecretRequestCreated, error) {
	f.gotWS, f.gotName, f.gotReq = ws, name, req
	return client.SecretRequestCreated{
		Request:   client.SecretRequest{ID: "sr_1", SecretName: name, RecipientEmail: req.RecipientEmail, ExpiresAt: "2026-11-24T00:00:00Z"},
		URL:       "https://app.secrevo.com/r#tok",
		EmailSent: f.emailSent,
	}, nil
}

func (f *secretRequestFake) ListSecretRequests(_ context.Context, _ string, secretID string) ([]client.SecretRequest, error) {
	f.listSecretID = secretID
	return []client.SecretRequest{{ID: "sr_1", Status: "fulfilled"}}, nil
}

func (f *secretRequestFake) CancelSecretRequest(_ context.Context, _ string, id string) (client.SecretRequest, error) {
	f.cancelled = id
	return client.SecretRequest{ID: id, Status: "cancelled"}, nil
}

func runSR(t *testing.T, fake *secretRequestFake, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID:   "workspace-1",
		Out:           &out,
		Err:           &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestSecretRequestSendRotation(t *testing.T) {
	fake := &secretRequestFake{emailSent: true}
	out, err := runSR(t, fake, "secret", "request", "send", "--secret", "Stripe Acme", "--to", " pepito@acme.com ",
		"--replace", "--message", "Rotación programada", "--label", "value=Clave secreta")
	if err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	r := fake.gotReq
	if fake.gotWS != "workspace-1" || fake.gotName != "Stripe Acme" || r.RecipientEmail != "pepito@acme.com" || !r.ReplaceExisting ||
		r.ConfirmNewRecipient || r.SendEmail == nil || !*r.SendEmail || r.FieldLabels["value"] != "Clave secreta" {
		t.Fatalf("request = %+v (ws %q name %q)", r, fake.gotWS, fake.gotName)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not JSON: %s", out)
	}
	// Emailed: the link (a write capability) is not printed.
	if _, has := got["link"]; has || got["email_sent"] != true || got["request_id"] != "sr_1" {
		t.Fatalf("output = %s", out)
	}
}

func TestSecretRequestSendNoEmailPrintsLink(t *testing.T) {
	fake := &secretRequestFake{}
	out, err := runSR(t, fake, "secret", "request", "send", "--secret", "DB_PROD", "--no-email")
	if err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if fake.gotReq.SendEmail == nil || *fake.gotReq.SendEmail || !strings.Contains(out, "https://app.secrevo.com/r#tok") {
		t.Fatalf("req = %+v out = %s", fake.gotReq, out)
	}
}

// pendingApprovalFake answers like the api does for an agent whose request
// needs the owner's decision: 202, no link, no email.
type pendingApprovalFake struct{ secretRequestFake }

func (f *pendingApprovalFake) CreateSecretRequestByName(_ context.Context, ws, name string, req client.SecretRequestCreateRequest) (client.SecretRequestCreated, error) {
	f.gotWS, f.gotName, f.gotReq = ws, name, req
	return client.SecretRequestCreated{
		Request: client.SecretRequest{ID: "sr_2", SecretName: name, RecipientEmail: req.RecipientEmail, Status: "pending_approval",
			ApprovalReason: "x@else.com has never provided this secret"},
		NextStep: "Nothing was sent yet. The owner has to approve it.",
	}, nil
}

func TestSecretRequestSendPendingApproval(t *testing.T) {
	fake := &pendingApprovalFake{}
	var out bytes.Buffer
	cmd := NewRootCommand(Options{
		WorkspaceID: "workspace-1", Out: &out, Err: &out,
		ClientFactory: func() (APIClient, error) { return fake, nil },
	})
	cmd.SetArgs([]string{"secret", "request", "send", "--secret", "ERP", "--to", "x@else.com", "--replace"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %s", out.String())
	}
	if got["status"] != "pending_approval" || got["next_step"] == nil || got["approval_reason"] == nil {
		t.Fatalf("output = %s", out.String())
	}
	if _, has := got["link"]; has {
		t.Fatalf("no link may be printed for a held request: %s", out.String())
	}
}

func TestSecretRequestSendNeedsRecipientOrNoEmail(t *testing.T) {
	fake := &secretRequestFake{}
	if _, err := runSR(t, fake, "secret", "request", "send", "--secret", "DB_PROD"); err == nil || !strings.Contains(err.Error(), "--to is required") {
		t.Fatalf("err = %v", err)
	}
	if _, err := runSR(t, fake, "secret", "request", "send", "--secret", "X", "--to", "a@b.com", "--label", "novalue"); err == nil {
		t.Fatal("a malformed --label must be refused")
	}
	if fake.gotName != "" {
		t.Fatal("nothing must be sent when the input is invalid")
	}
}

func TestSecretRequestListAndCancel(t *testing.T) {
	fake := &secretRequestFake{}
	out, err := runSR(t, fake, "secret", "request", "list", "--secret", "OPENAI_API_KEY")
	if err != nil || fake.listSecretID != "secret-2" || !strings.Contains(out, "fulfilled") {
		t.Fatalf("list: err=%v id=%q out=%s", err, fake.listSecretID, out)
	}
	out, err = runSR(t, fake, "secret", "request", "cancel", "sr_9")
	if err != nil || fake.cancelled != "sr_9" || !strings.Contains(out, "cancelled") {
		t.Fatalf("cancel: err=%v out=%s", err, out)
	}
}
