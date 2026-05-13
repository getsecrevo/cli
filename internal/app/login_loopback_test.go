package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoopbackHandlerAcceptsValidPost(t *testing.T) {
	const state = "expected-state"
	resultCh := make(chan loopbackResult, 1)
	errCh := make(chan error, 1)
	h := loopbackHandler(state, resultCh, errCh, "workspace-1")

	body, _ := json.Marshal(map[string]string{
		"token":        "agt_loopback_ok",
		"workspace_id": "workspace-1",
		"state":        state,
	})
	req := httptest.NewRequest(http.MethodPost, "/cb", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	select {
	case res := <-resultCh:
		if res.Token != "agt_loopback_ok" {
			t.Fatalf("captured token = %q", res.Token)
		}
		if res.WorkspaceID != "workspace-1" {
			t.Fatalf("captured workspace = %q", res.WorkspaceID)
		}
	default:
		t.Fatalf("no result captured")
	}
}

func TestLoopbackHandlerRejectsMismatchedState(t *testing.T) {
	resultCh := make(chan loopbackResult, 1)
	errCh := make(chan error, 1)
	h := loopbackHandler("the-real-state", resultCh, errCh, "workspace-1")

	body, _ := json.Marshal(map[string]string{
		"token":        "agt_attacker",
		"workspace_id": "workspace-1",
		"state":        "guessed-wrong",
	})
	req := httptest.NewRequest(http.MethodPost, "/cb", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on state mismatch, got %d", rr.Code)
	}
	select {
	case <-resultCh:
		t.Fatalf("result channel must stay empty when state mismatches")
	default:
	}
	// errCh should have received the state-mismatch error so the
	// outer select wakes and surfaces it to the operator.
	select {
	case err := <-errCh:
		if !strings.Contains(err.Error(), "state mismatch") {
			t.Fatalf("err = %v", err)
		}
	default:
		t.Fatalf("expected an error on the errCh channel")
	}
}

func TestLoopbackHandlerHandlesCORSPreflight(t *testing.T) {
	h := loopbackHandler("s", make(chan loopbackResult, 1), make(chan error, 1), "ws")
	req := httptest.NewRequest(http.MethodOptions, "/cb", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatalf("preflight missing Access-Control-Allow-Origin")
	}
	if !strings.Contains(rr.Header().Get("Access-Control-Allow-Methods"), "POST") {
		t.Fatalf("preflight missing POST in allowed methods: %q", rr.Header().Get("Access-Control-Allow-Methods"))
	}
}

func TestLoopbackHandlerRejectsSecondPost(t *testing.T) {
	const state = "s"
	resultCh := make(chan loopbackResult, 1)
	errCh := make(chan error, 1)
	h := loopbackHandler(state, resultCh, errCh, "ws")

	body, _ := json.Marshal(map[string]string{"token": "agt_x", "workspace_id": "ws", "state": state})
	req1 := httptest.NewRequest(http.MethodPost, "/cb", bytes.NewReader(body))
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first POST status = %d", rr1.Code)
	}
	<-resultCh // drain so the second one would have somewhere to land

	req2 := httptest.NewRequest(http.MethodPost, "/cb", bytes.NewReader(body))
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusGone {
		t.Fatalf("second POST status = %d, want 410 Gone", rr2.Code)
	}
}

func TestLoopbackHandlerRejectsMissingToken(t *testing.T) {
	resultCh := make(chan loopbackResult, 1)
	errCh := make(chan error, 1)
	h := loopbackHandler("s", resultCh, errCh, "ws")

	body, _ := json.Marshal(map[string]string{"token": "  ", "workspace_id": "ws", "state": "s"})
	req := httptest.NewRequest(http.MethodPost, "/cb", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestBuildCliLoginURLEscapesCallback(t *testing.T) {
	got := buildCliLoginURL("https://app.secrevo.com/", "http://127.0.0.1:65535/cb", "workspace-1", "state-xyz")
	want := "https://app.secrevo.com/cli-login?callback=http%3A%2F%2F127.0.0.1%3A65535%2Fcb&state=state-xyz&workspace=workspace-1"
	if got != want {
		t.Fatalf("URL = %q\nwant %q", got, want)
	}
}
