package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/getsecrevo/cli/internal/credentials"
	"github.com/spf13/cobra"
)

// crockfordAlphabet is the subset of base32 the api uses to mint
// enrollment codes: digits + uppercase letters with the visually
// ambiguous I, L, O, U removed. Codes arrive case-insensitively; we
// normalize to uppercase before POSTing.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// enrollmentEnv overrides the resolved api base URL when the
// --api-base-url flag and the SECREVO_API_BASE_URL env var are both
// unset. Production default lives here so a fresh binary on a clean
// machine just works.
const enrollmentEnv = "SECREVO_API_BASE_URL"

// enrollResponse mirrors the POST /v1/enrollment/redeem 200 body.
// Fields are intentionally minimal; future server-side additions
// (e.g. agent display name) decode as no-ops.
type enrollResponse struct {
	Token       string `json:"token"`
	WorkspaceID string `json:"workspace_id"`
	APIBaseURL  string `json:"api_base_url"`
}

// enrollErrorBody matches the api's standard error envelope. The
// `code` field carries the machine-readable reason ("invalid_format",
// "not_found_or_expired", "already_redeemed", "rate_limited"); we map
// these to human messages before surfacing them. `message` is used as
// a fallback when the code is missing or unknown.
type enrollErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// enrollPoster is the HTTP edge `secrevo enroll` exercises. The
// production implementation posts JSON to the api with a 30s timeout;
// tests inject a stub backed by httptest so the table can assert on
// request/response without spinning a real socket.
type enrollPoster func(ctx context.Context, baseURL, code string) (enrollResponse, *enrollAPIError, error)

// enrollAPIError captures a non-2xx response so the command can build
// status-specific messages without re-parsing the body. The HTTP
// status is preserved verbatim; retryAfter is the parsed Retry-After
// header when present (only set for 429).
type enrollAPIError struct {
	Status     int
	Code       string
	Message    string
	RetryAfter string
}

func newEnrollCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll <code>",
		Short: "Redeem an enrollment code and persist the resulting agent token",
		Long: `Redeem a single-use enrollment code (` + "`XXXX-XXXX`" + ` Crockford
base32) against the public /v1/enrollment/redeem endpoint and persist
the returned agent token, workspace id, and api base URL to the
standard credentials file (` + "`%APPDATA%\\secrevo\\credentials.json`" + ` on
Windows, ` + "`~/.config/secrevo/credentials.json`" + ` on POSIX).

This is the bootstrap path for agents — the equivalent of
` + "`secrevo login`" + ` for a workload that has no browser. The operator
mints a code from the dashboard, hands it to the agent, the agent runs
` + "`secrevo enroll <code>`" + ` once, and from then on every ` + "`secrevo`" + `
invocation finds the persisted credentials automatically.

The code is single-use. Format is validated offline before any HTTP
call so typos don't burn a network round-trip. The token is NEVER
echoed: stdout only confirms enrollment and points at
` + "`secrevo auth whoami`" + ` for verification.

Examples:

  secrevo enroll K3M9-X2PA
  secrevo enroll K3M9-X2PA --api-base-url https://api.staging.secrevo.com
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnrollCommand(cmd, opts, args[0])
		},
	}
	cmd.Flags().String("api-base-url", "", "Override the api base URL (default: $SECREVO_API_BASE_URL or "+defaultAPIBaseURL+")")
	return cmd
}

func runEnrollCommand(cmd *cobra.Command, opts Options, rawCode string) error {
	normalized, err := normalizeEnrollmentCode(rawCode)
	if err != nil {
		return err
	}

	flagBase, _ := cmd.Flags().GetString("api-base-url")
	baseURL, err := resolveEnrollmentBaseURL(flagBase)
	if err != nil {
		return err
	}

	poster := opts.EnrollPoster
	if poster == nil {
		poster = defaultEnrollPoster
	}

	resp, apiErr, err := poster(cmd.Context(), baseURL, normalized)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if apiErr != nil {
		return enrollErrorMessage(apiErr)
	}

	if strings.TrimSpace(resp.Token) == "" {
		return errors.New("enroll: api returned an empty token")
	}
	if strings.TrimSpace(resp.WorkspaceID) == "" {
		return errors.New("enroll: api returned an empty workspace_id")
	}

	storedBase := strings.TrimSpace(resp.APIBaseURL)
	if storedBase == "" {
		// The api always echoes the canonical base URL it wants the
		// CLI to use, but fall back to the URL we POSTed against so
		// future requests don't accidentally hit a different origin.
		storedBase = baseURL
	}

	path := credentialsPath(opts)
	if path == "" {
		p, err := credentials.DefaultPath()
		if err != nil {
			return err
		}
		path = p
	}

	if err := credentials.Save(path, credentials.File{
		BaseURL:     storedBase,
		WorkspaceID: resp.WorkspaceID,
		Token:       resp.Token,
	}); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(opts.Out, "Enrolled successfully. Workspace: %s. Run 'secrevo auth whoami' to verify.\n", resp.WorkspaceID)
	return nil
}

// normalizeEnrollmentCode validates the input against the Crockford
// base32 XXXX-XXXX shape the api accepts and returns the uppercase
// canonical form. Returning an offline error here saves a network
// round-trip for the common "operator fat-fingered the code" case.
func normalizeEnrollmentCode(raw string) (string, error) {
	code := strings.ToUpper(strings.TrimSpace(raw))
	if code == "" {
		return "", errors.New("enrollment code is empty")
	}
	if len(code) != 9 || code[4] != '-' {
		return "", fmt.Errorf("invalid enrollment code %q: expected format XXXX-XXXX", raw)
	}
	for i, r := range code {
		if i == 4 {
			continue
		}
		if !strings.ContainsRune(crockfordAlphabet, r) {
			return "", fmt.Errorf("invalid enrollment code %q: character %q is not Crockford base32 (no I, L, O, U)", raw, string(r))
		}
	}
	return code, nil
}

// resolveEnrollmentBaseURL picks the api base URL per the precedence
// in the spec: explicit flag wins, then SECREVO_API_BASE_URL, then
// the production default. We DO NOT consult the credentials file:
// enrollment runs before any credentials exist by definition.
func resolveEnrollmentBaseURL(flagValue string) (string, error) {
	candidate := strings.TrimSpace(flagValue)
	if candidate == "" {
		candidate = strings.TrimSpace(os.Getenv(enrollmentEnv))
	}
	if candidate == "" {
		candidate = defaultAPIBaseURL
	}
	if !strings.HasPrefix(candidate, "http://") && !strings.HasPrefix(candidate, "https://") {
		return "", fmt.Errorf("invalid api base URL %q: must start with http:// or https://", candidate)
	}
	return strings.TrimRight(candidate, "/"), nil
}

// enrollErrorMessage maps the api's machine-readable error code to a
// human-readable, actionable message. Falls back to a generic message
// that surfaces the status when the code is missing/unknown so the
// operator still has something to ground a bug report on.
func enrollErrorMessage(e *enrollAPIError) error {
	switch e.Code {
	case "already_redeemed":
		return errors.New("This enrollment code has already been redeemed. Ask the operator to generate a new one.")
	case "not_found_or_expired":
		return errors.New("This enrollment code is invalid or expired.")
	case "invalid_format":
		return errors.New("The enrollment code format is invalid.")
	case "rate_limited":
		if e.RetryAfter != "" {
			return fmt.Errorf("Too many redeem attempts. Wait %s seconds and try again.", e.RetryAfter)
		}
		return errors.New("Too many redeem attempts. Wait a minute and try again.")
	}
	// Unmapped: fall back to the api's message or the HTTP status so
	// the operator still has something concrete to share with support.
	if msg := strings.TrimSpace(e.Message); msg != "" {
		return fmt.Errorf("enrollment failed (%d): %s", e.Status, msg)
	}
	return fmt.Errorf("enrollment failed with HTTP %d", e.Status)
}

// defaultEnrollPoster is the production HTTP edge for `secrevo
// enroll`. The 30s timeout matches the other unauthenticated client
// edges; the request body is JSON. We DO NOT attach Authorization —
// /v1/enrollment/redeem is the public bootstrap endpoint and a stray
// bearer would only confuse logs.
func defaultEnrollPoster(ctx context.Context, baseURL, code string) (enrollResponse, *enrollAPIError, error) {
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return enrollResponse{}, nil, fmt.Errorf("marshal enrollment body: %w", err)
	}
	url := strings.TrimRight(baseURL, "/") + "/v1/enrollment/redeem"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return enrollResponse{}, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return enrollResponse{}, nil, fmt.Errorf("post %s: %w", url, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return enrollResponse{}, nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var out enrollResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			return enrollResponse{}, nil, fmt.Errorf("parse response: %w", err)
		}
		return out, nil, nil
	}

	apiErr := &enrollAPIError{
		Status:     resp.StatusCode,
		RetryAfter: resp.Header.Get("Retry-After"),
	}
	var parsed enrollErrorBody
	if err := json.Unmarshal(raw, &parsed); err == nil {
		apiErr.Code = parsed.Code
		apiErr.Message = parsed.Message
	}
	// Map raw status to a synthetic code when the server didn't
	// provide one (legacy proxies, generic 5xx). Keeps the message
	// path deterministic.
	if apiErr.Code == "" {
		switch resp.StatusCode {
		case http.StatusBadRequest:
			apiErr.Code = "invalid_format"
		case http.StatusNotFound:
			apiErr.Code = "not_found_or_expired"
		case http.StatusGone:
			apiErr.Code = "already_redeemed"
		case http.StatusTooManyRequests:
			apiErr.Code = "rate_limited"
		}
	}
	return enrollResponse{}, apiErr, nil
}
