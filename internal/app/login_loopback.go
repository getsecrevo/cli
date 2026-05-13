package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Default timeout for the loopback handshake. Five minutes covers the
// common case of the operator authenticating in the dashboard, picking
// an agent, and clicking "Authorize" without rushing.
const defaultLoopbackTimeout = 5 * time.Minute

// loopbackResult is what the embedded HTTP server emits on a successful
// POST to /cb. The fields mirror the on-disk credentials file so the
// outer login flow can persist them directly.
type loopbackResult struct {
	Token       string `json:"token"`
	WorkspaceID string `json:"workspace_id"`
}

// runLoopbackLogin starts a one-shot HTTP server on 127.0.0.1:RANDOM,
// opens the dashboard's /cli-login page with the loopback URL as the
// `callback` query parameter, and waits for the dashboard to POST the
// authorized token back. Returns the captured token + workspace as
// soon as one valid POST arrives; the server is shut down before the
// function returns so the random port is released.
//
// The handshake carries a `state` parameter (32 cryptographically
// random bytes, base64-url-encoded) the dashboard echoes back; we
// reject any POST with a missing or mismatched state to keep a
// drive-by from any other tab on the operator's machine from feeding
// us a token.
//
// Dashboard contract:
//
//	GET  {dashboard}/cli-login?callback=<loopback>&workspace=<id>&state=<state>
//	POST <loopback>    Content-Type: application/json
//	                   { "token": "agt_...", "workspace_id": "<id>",
//	                     "state": "<state>" }
//
// The dashboard is also expected to handle the OPTIONS preflight that
// browsers send before a cross-origin JSON POST; the CLI handler below
// responds with permissive CORS so the browser will let the POST
// through.
func runLoopbackLogin(ctx context.Context, opts Options, dashboardURL, workspaceID string, browser BrowserOpener) (loopbackResult, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return loopbackResult{}, fmt.Errorf("listen on loopback: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/cb", port)

	state, err := randomState()
	if err != nil {
		_ = listener.Close()
		return loopbackResult{}, fmt.Errorf("generate state: %w", err)
	}

	resultCh := make(chan loopbackResult, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.Handle("/cb", loopbackHandler(state, resultCh, errCh, workspaceID))
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- srv.Serve(listener)
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	dashURL := buildCliLoginURL(dashboardURL, callbackURL, workspaceID, state)
	_, _ = fmt.Fprintf(opts.Out, "Open this URL to authorize the CLI:\n  %s\n", dashURL)
	if browser != nil {
		if err := browser.Open(dashURL); err != nil {
			_, _ = fmt.Fprintf(opts.Err, "Could not launch a browser (%v); open the URL manually.\n", err)
		}
	}

	select {
	case res := <-resultCh:
		return res, nil
	case err := <-errCh:
		return loopbackResult{}, err
	case err := <-serveErrCh:
		if errors.Is(err, http.ErrServerClosed) {
			return loopbackResult{}, errors.New("loopback server closed before receiving a token")
		}
		return loopbackResult{}, fmt.Errorf("loopback server error: %w", err)
	case <-time.After(defaultLoopbackTimeout):
		return loopbackResult{}, fmt.Errorf("timed out waiting for dashboard to post the token after %s", defaultLoopbackTimeout)
	case <-ctx.Done():
		return loopbackResult{}, ctx.Err()
	}
}

// loopbackHandler returns an http.Handler that accepts the dashboard's
// POST + the browser's OPTIONS preflight. The first valid POST emits
// the result; subsequent requests get 410 Gone (the channel is buffered
// for one delivery).
func loopbackHandler(expectedState string, resultCh chan<- loopbackResult, errCh chan<- error, expectedWorkspace string) http.Handler {
	delivered := false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Permissive CORS so a fetch() from the dashboard origin (or
		// any origin — the loopback is bound to 127.0.0.1 only) can
		// complete the preflight + POST. The origin reflection is
		// safe because nothing sensitive is returned to the caller;
		// we only ack the POST.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if delivered {
			http.Error(w, "loopback already consumed", http.StatusGone)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			errCh <- fmt.Errorf("read POST body: %w", err)
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		var payload struct {
			Token       string `json:"token"`
			WorkspaceID string `json:"workspace_id"`
			State       string `json:"state"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			errCh <- fmt.Errorf("parse loopback payload: %w", err)
			return
		}
		if payload.State == "" || payload.State != expectedState {
			http.Error(w, "state mismatch", http.StatusForbidden)
			errCh <- errors.New("loopback state mismatch — refusing token")
			return
		}
		if strings.TrimSpace(payload.Token) == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			errCh <- errors.New("loopback POST missing token")
			return
		}
		if payload.WorkspaceID == "" {
			payload.WorkspaceID = expectedWorkspace
		}
		delivered = true
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(loopbackSuccessHTML))
		resultCh <- loopbackResult{Token: payload.Token, WorkspaceID: payload.WorkspaceID}
	})
}

// buildCliLoginURL is split out so tests can assert the produced query
// string without spinning up the server.
func buildCliLoginURL(dashboardURL, callbackURL, workspaceID, state string) string {
	u := strings.TrimRight(dashboardURL, "/") + "/cli-login"
	q := url.Values{}
	q.Set("callback", callbackURL)
	q.Set("workspace", workspaceID)
	q.Set("state", state)
	return u + "?" + q.Encode()
}

func randomState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

const loopbackSuccessHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Secrevo CLI authorized</title>
<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:6rem auto;padding:0 1rem;color:#222}h1{font-size:1.4rem}p{line-height:1.5}</style>
</head><body><h1>CLI authorized</h1>
<p>You can close this tab and return to your terminal. The Secrevo CLI now has the token and you do not need to copy anything by hand.</p>
</body></html>
`
