package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/getsecrevo/cli/internal/client"
)

type secretShareFake struct {
	fakeAPIClient
	gotName  string
	gotReq   client.SecretShareCreateRequest
	answer   client.SecretShareCreated
	listID   string
	canceled string
}

func (f *secretShareFake) CreateSecretShareByName(_ context.Context, _, name string, req client.SecretShareCreateRequest) (client.SecretShareCreated, error) {
	f.gotName, f.gotReq = name, req
	a := f.answer
	a.Share.SecretName = name
	a.Share.RecipientEmail = req.RecipientEmail
	return a, nil
}

func (f *secretShareFake) ListSecretShares(_ context.Context, _, secretID string) ([]client.SecretShare, error) {
	f.listID = secretID
	return []client.SecretShare{{ID: "ss_1", Status: "viewed"}}, nil
}

func (f *secretShareFake) CancelSecretShare(_ context.Context, _, id string) (client.SecretShareCancelled, error) {
	f.canceled = id
	return client.SecretShareCancelled{Share: client.SecretShare{ID: id, Status: "cancelled"}}, nil
}

func runSS(t *testing.T, fake *secretShareFake, args ...string) (string, error) {
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

// An agent's call comes back as a draft: no link, no code, and the next step
// says a person must approve it.
func TestSecretShareSendAsAgentIsADraft(t *testing.T) {
	fake := &secretShareFake{answer: client.SecretShareCreated{
		Share:    client.SecretShare{ID: "ss_1", Status: "pending_approval", FieldNames: []string{"usuario"}},
		NextStep: "Nothing was read or sent. Tell the user to approve it.",
	}}
	out, err := runSS(t, fake, "secret", "share", "send", "--secret", "SUNAT SOL", "--to", " contador@acme.com ", "--field", "usuario")
	if err != nil {
		t.Fatalf("send: %v\n%s", err, out)
	}
	if fake.gotName != "SUNAT SOL" || fake.gotReq.RecipientEmail != "contador@acme.com" || len(fake.gotReq.Fields) != 1 ||
		fake.gotReq.RequireEmailCode == nil || !*fake.gotReq.RequireEmailCode || fake.gotReq.Delivery != "email" {
		t.Fatalf("request = %+v", fake.gotReq)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output not JSON: %s", out)
	}
	if got["status"] != "pending_approval" || got["next_step"] == nil || got["link"] != nil || got["extra_code"] != nil {
		t.Fatalf("out = %s", out)
	}
}

// A person who asked for the link and an extra code gets both, once, with a
// note on how to deliver each.
func TestSecretShareSendLinkAndExtraCode(t *testing.T) {
	fake := &secretShareFake{answer: client.SecretShareCreated{
		Share: client.SecretShare{ID: "ss_2", Status: "pending"},
		URL:   "https://app.secrevo.com/s#v1.t.k", ExtraCode: "ABCDE12345",
	}}
	out, err := runSS(t, fake, "secret", "share", "send", "--secret", "ROOT", "--to", "c@acme.com", "--link", "--extra-code", "--no-email-code")
	if err != nil {
		t.Fatalf("send: %v\n%s", err, out)
	}
	if fake.gotReq.Delivery != "link" || !fake.gotReq.ExtraCode || *fake.gotReq.RequireEmailCode {
		t.Fatalf("request = %+v", fake.gotReq)
	}
	// runSS merges stdout and stderr; the code must be there, but not inside
	// the JSON document that carries the link.
	if !strings.Contains(out, "s#v1.t.k") || !strings.Contains(out, "ABCDE12345") || !strings.Contains(out, "not by email") {
		t.Fatalf("out = %s", out)
	}
	jsonStart := strings.Index(out, "{")
	if jsonStart < 0 || strings.Contains(out[jsonStart:], "ABCDE12345") {
		t.Fatalf("extra code printed inside the JSON with the link: %s", out)
	}
}

func TestSecretShareSendGuards(t *testing.T) {
	fake := &secretShareFake{}
	if _, err := runSS(t, fake, "secret", "share", "send", "--secret", "X", "--to", "c@acme.com", "--link", "--no-email-code"); err == nil {
		t.Fatal("--link without any code was accepted")
	}
	if _, err := runSS(t, fake, "secret", "share", "send", "--secret", "X"); err == nil {
		t.Fatal("missing --to was accepted")
	}
	if fake.gotName != "" {
		t.Fatal("a refused command still called the api")
	}
}

func TestSecretShareListAndCancel(t *testing.T) {
	fake := &secretShareFake{}
	out, err := runSS(t, fake, "secret", "share", "list")
	if err != nil || !strings.Contains(out, "ss_1") {
		t.Fatalf("list: %v %s", err, out)
	}
	out, err = runSS(t, fake, "secret", "share", "cancel", "ss_9")
	if err != nil || fake.canceled != "ss_9" || !strings.Contains(out, "cancelled") {
		t.Fatalf("cancel: %v %s", err, out)
	}
}
