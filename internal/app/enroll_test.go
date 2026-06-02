package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getsecrevo/cli/internal/credentials"
)

// fakeToken is the canned agent token every enrollment-success test
// fixture returns. Kept as a package-level constant so each test can
// assert against the SAME literal in a single source of truth — and
// so the stdout-leak guard has an unambiguous target to grep for.
const fakeToken = "agt_test_redeemed_xyz123"

// newEnrollServer spins an httptest server whose POST handler asserts
// the inbound code, body shape, and method, then echoes the canned
// success response. Test bodies wire it into Options.EnrollPoster via
// a small adapter so we exercise the real defaultEnrollPoster code
// path end-to-end (request build, JSON encode, response parse).
func newEnrollServer(t *testing.T, expectedCode string) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost {
			t.Errorf("server got method %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/enrollment/redeem" {
			t.Errorf("server got path %s, want /v1/enrollment/redeem", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("server got Authorization header %q; enroll must never authenticate", got)
		}
		var body struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("server decode body: %v", err)
		}
		if body.Code != expectedCode {
			t.Errorf("server got code %q, want %q", body.Code, expectedCode)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":        fakeToken,
			"workspace_id": "ws_test_42",
			"api_base_url": "https://api.test.secrevo.local",
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestEnrollHappyPath_PersistsAndConfirms(t *testing.T) {
	srv, calls := newEnrollServer(t, "K3M9-X2PA")

	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")

	var out, errOut bytes.Buffer
	cmd := NewRootCommand(Options{
		Out:             &out,
		Err:             &errOut,
		CredentialsPath: credPath,
	})
	cmd.SetArgs([]string{"enroll", "K3M9-X2PA", "--api-base-url", srv.URL})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if *calls != 1 {
		t.Fatalf("server got %d calls, want 1", *calls)
	}

	stored, err := credentials.Load(credPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if stored.Token != fakeToken {
		// Compare by length to avoid embedding the literal in the
		// failure message — assertions against secret values use a
		// boolean / length proxy, never the value itself.
		t.Fatalf("stored.Token mismatch (got len=%d, want len=%d)", len(stored.Token), len(fakeToken))
	}
	if stored.WorkspaceID != "ws_test_42" {
		t.Fatalf("stored.WorkspaceID = %q, want ws_test_42", stored.WorkspaceID)
	}
	if stored.BaseURL != "https://api.test.secrevo.local" {
		t.Fatalf("stored.BaseURL = %q, want canonical api_base_url echoed by server", stored.BaseURL)
	}

	// Critical: the token must never leak to stdout or stderr.
	if strings.Contains(out.String(), fakeToken) {
		t.Fatalf("stdout contains the token literal; enroll must not echo it")
	}
	if strings.Contains(errOut.String(), fakeToken) {
		t.Fatalf("stderr contains the token literal; enroll must not echo it")
	}
	if !strings.Contains(out.String(), "Enrolled successfully") {
		t.Fatalf("stdout missing success confirmation: %q", out.String())
	}
	if !strings.Contains(out.String(), "ws_test_42") {
		t.Fatalf("stdout missing workspace id: %q", out.String())
	}
}

func TestEnrollLowercaseCodeNormalizedToUppercase(t *testing.T) {
	srv, calls := newEnrollServer(t, "K3M9-X2PA")

	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")

	cmd := NewRootCommand(Options{
		Out:             io.Discard,
		Err:             io.Discard,
		CredentialsPath: credPath,
	})
	cmd.SetArgs([]string{"enroll", "k3m9-x2pa", "--api-base-url", srv.URL})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if *calls != 1 {
		t.Fatalf("server got %d calls, want 1", *calls)
	}
}

func TestEnrollInvalidFormat_NoNetworkCall(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		wantSub string
	}{
		{"empty", "", "empty"},
		{"no dash", "K3M9X2PA1", "XXXX-XXXX"},
		{"too short", "K3M-X2P", "XXXX-XXXX"},
		{"too long", "K3M9-X2PAA", "XXXX-XXXX"},
		{"invalid letter L", "K3L9-X2PA", "Crockford"},
		{"invalid letter O", "K3O9-X2PA", "Crockford"},
		{"invalid letter U", "K3U9-X2PA", "Crockford"},
		{"invalid letter I", "K3I9-X2PA", "Crockford"},
	}

	posterCalled := false
	poster := func(context.Context, string, string) (enrollResponse, *enrollAPIError, error) {
		posterCalled = true
		return enrollResponse{}, nil, nil
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cmd := NewRootCommand(Options{
				Out:             io.Discard,
				Err:             io.Discard,
				CredentialsPath: filepath.Join(dir, "credentials.json"),
				EnrollPoster:    poster,
			})
			cmd.SetArgs([]string{"enroll", tc.code})

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("Execute() = nil, want format error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Execute() error = %v, want substring %q", err, tc.wantSub)
			}
			if posterCalled {
				t.Fatalf("poster was called despite format-invalid input %q", tc.code)
			}
		})
	}
}

// fakeAPIError is a tiny helper so each status-code test reads like a
// table row: pick a code + message, get a poster that surfaces it. We
// build the response inline instead of pulling from a fixture file so
// the failure modes are visible in the test source.
func fakeAPIError(status int, code, message, retryAfter string) enrollPoster {
	return func(context.Context, string, string) (enrollResponse, *enrollAPIError, error) {
		return enrollResponse{}, &enrollAPIError{
			Status:     status,
			Code:       code,
			Message:    message,
			RetryAfter: retryAfter,
		}, nil
	}
}

func TestEnrollAlreadyRedeemed_SurfacesActionableMessage(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")

	cmd := NewRootCommand(Options{
		Out:             io.Discard,
		Err:             io.Discard,
		CredentialsPath: credPath,
		EnrollPoster:    fakeAPIError(http.StatusGone, "already_redeemed", "", ""),
	})
	cmd.SetArgs([]string{"enroll", "K3M9-X2PA"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "already been redeemed") {
		t.Fatalf("Execute() error = %v, want 'already been redeemed' message", err)
	}
	if _, loadErr := credentials.Load(credPath); loadErr != credentials.ErrNotFound {
		t.Fatalf("credentials should not have been written; Load = %v", loadErr)
	}
}

func TestEnrollNotFound_SurfacesActionableMessage(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")

	cmd := NewRootCommand(Options{
		Out:             io.Discard,
		Err:             io.Discard,
		CredentialsPath: credPath,
		EnrollPoster:    fakeAPIError(http.StatusNotFound, "not_found_or_expired", "", ""),
	})
	cmd.SetArgs([]string{"enroll", "K3M9-X2PA"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "invalid or expired") {
		t.Fatalf("Execute() error = %v, want 'invalid or expired' message", err)
	}
	if _, loadErr := credentials.Load(credPath); loadErr != credentials.ErrNotFound {
		t.Fatalf("credentials should not have been written; Load = %v", loadErr)
	}
}

func TestEnrollRateLimited_SurfacesRetryAfter(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")

	cmd := NewRootCommand(Options{
		Out:             io.Discard,
		Err:             io.Discard,
		CredentialsPath: credPath,
		EnrollPoster:    fakeAPIError(http.StatusTooManyRequests, "rate_limited", "", "30"),
	})
	cmd.SetArgs([]string{"enroll", "K3M9-X2PA"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() = nil, want rate-limit error")
	}
	if !strings.Contains(err.Error(), "30") {
		t.Fatalf("Execute() error = %v, want Retry-After value '30'", err)
	}
	if !strings.Contains(err.Error(), "Too many redeem attempts") {
		t.Fatalf("Execute() error = %v, want rate-limit framing", err)
	}
}

func TestEnrollInvalidBaseURL_NoPost(t *testing.T) {
	posterCalled := false
	poster := func(context.Context, string, string) (enrollResponse, *enrollAPIError, error) {
		posterCalled = true
		return enrollResponse{}, nil, nil
	}

	dir := t.TempDir()
	cmd := NewRootCommand(Options{
		Out:             io.Discard,
		Err:             io.Discard,
		CredentialsPath: filepath.Join(dir, "credentials.json"),
		EnrollPoster:    poster,
	})
	cmd.SetArgs([]string{"enroll", "K3M9-X2PA", "--api-base-url", "ftp://nope"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "http:// or https://") {
		t.Fatalf("Execute() error = %v, want scheme rejection", err)
	}
	if posterCalled {
		t.Fatal("poster was called despite invalid base URL")
	}
}

func TestEnrollEmptyTokenInResponse_FailsLoud(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "credentials.json")

	cmd := NewRootCommand(Options{
		Out:             io.Discard,
		Err:             io.Discard,
		CredentialsPath: credPath,
		EnrollPoster: func(context.Context, string, string) (enrollResponse, *enrollAPIError, error) {
			return enrollResponse{WorkspaceID: "ws_test_42"}, nil, nil
		},
	})
	cmd.SetArgs([]string{"enroll", "K3M9-X2PA"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "empty token") {
		t.Fatalf("Execute() error = %v, want empty-token guard", err)
	}
	if _, loadErr := credentials.Load(credPath); loadErr != credentials.ErrNotFound {
		t.Fatalf("credentials should not have been written; Load = %v", loadErr)
	}
}
