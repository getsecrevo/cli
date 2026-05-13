package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/getsecrevo/cli/internal/client"
	"github.com/getsecrevo/cli/internal/credentials"
	"github.com/spf13/cobra"
)

// BrowserOpener launches the operator's default browser at “url“ so they
// can complete an authentication flow. Tests inject a no-op fake.
type BrowserOpener interface {
	Open(url string) error
}

type osBrowserOpener struct{}

func (osBrowserOpener) Open(target string) error {
	if _, err := url.Parse(target); err != nil {
		return fmt.Errorf("invalid URL %q: %w", target, err)
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", target)
	case "darwin":
		cmd = exec.Command("open", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open browser: %w", err)
	}
	// Detach: we don't care about the browser exiting.
	go func() { _ = cmd.Wait() }()
	return nil
}

const defaultDashboardURL = "https://app.secrevo.com"
const defaultAPIBaseURL = "https://api.secrevo.com"

func newLoginCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate the CLI by capturing an agent token from the dashboard",
		Long: `Open the Secrevo dashboard, prompt for an agent token, and
persist it locally so future ` + "`secrevo`" + ` invocations no longer need
` + "`SECREVO_API_TOKEN`" + ` exported in every shell.

Flow (v0, intentionally simple):
  1. CLI prints the dashboard URL to the agent-creation page and opens
     it in the operator's default browser.
  2. Operator creates an agent and copies its token.
  3. CLI reads the token from stdin (echo suppressed when stdin is a
     TTY).
  4. CLI verifies the token by calling /v1/auth/sessions and persists
     it to the credentials file (mode 0600).

Future v1 will use a loopback HTTP server to receive the token from
the dashboard automatically; v2 will replace the dashboard hop with a
direct OAuth Authorization Code + PKCE flow against Prysm:ID. See
project_management/11_Fase_Diferenciadores/decisiones.md (D-11.4).

Flags:
  --workspace-id   Workspace the token belongs to. Default: env or stored.
  --base-url       API base URL to verify the token against. Default: api.secrevo.com.
  --dashboard-url  Dashboard origin to open. Default: app.secrevo.com.
  --loopback       Use the v1 loopback handshake: start a local HTTP
                   server, open the dashboard's /cli-login page with
                   the loopback URL as ?callback, wait for the dashboard
                   to POST the authorized token back. Removes the
                   manual paste step entirely.
  --no-browser     Skip the browser launch; just print the URL. Defaults
                   to true when a credentials file already exists (the
                   operator is almost certainly re-pasting a token).
                   Pass --no-browser=false to force a browser launch.
  --token          Pass the token inline (useful for tests; bypasses prompt).
`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLoginCommand(cmd, opts)
		},
	}
	cmd.Flags().String("workspace-id", "", "Workspace the token belongs to (default: env or stored)")
	cmd.Flags().String("base-url", defaultAPIBaseURL, "API base URL to verify the token against")
	cmd.Flags().String("dashboard-url", defaultDashboardURL, "Dashboard origin to open")
	cmd.Flags().Bool("no-browser", false, "Skip launching the default browser")
	cmd.Flags().Bool("loopback", false, "Use the v1 loopback handshake (CLI starts a local HTTP server, dashboard POSTs the token back)")
	cmd.Flags().String("token", "", "Provide the agent token inline (bypasses the prompt)")
	return cmd
}

func newLogoutCommand(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove the credentials persisted by `secrevo login`",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := strings.TrimSpace(opts.CredentialsPath)
			if path == "" {
				var err error
				path, err = credentials.DefaultPath()
				if err != nil {
					return err
				}
			}
			if err := credentials.Delete(path); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(opts.Out, "Cleared %s\n", path)
			return nil
		},
	}
}

func runLoginCommand(cmd *cobra.Command, opts Options) error {
	dashboardURL, _ := cmd.Flags().GetString("dashboard-url")
	baseURL, _ := cmd.Flags().GetString("base-url")
	workspaceFlag, _ := cmd.Flags().GetString("workspace-id")
	skipBrowser, _ := cmd.Flags().GetBool("no-browser")
	useLoopback, _ := cmd.Flags().GetBool("loopback")
	tokenInline, _ := cmd.Flags().GetString("token")

	workspaceID := strings.TrimSpace(workspaceFlag)
	if workspaceID == "" {
		workspaceID = strings.TrimSpace(opts.WorkspaceID)
	}
	if workspaceID == "" {
		return errors.New("workspace id is required: pass --workspace-id, set SECREVO_WORKSPACE_ID, or log in to an existing workspace first")
	}

	credPath := credentialsPath(opts)

	var token string
	if useLoopback {
		if strings.TrimSpace(tokenInline) != "" {
			return errors.New("--loopback and --token are mutually exclusive (loopback captures the token automatically)")
		}
		opener := opts.Browser
		if opener == nil {
			opener = osBrowserOpener{}
		}
		res, err := runLoopbackLogin(cmd.Context(), opts, dashboardURL, workspaceID, opener)
		if err != nil {
			return fmt.Errorf("loopback handshake: %w", err)
		}
		token = res.Token
		if strings.TrimSpace(res.WorkspaceID) != "" {
			workspaceID = res.WorkspaceID
		}
	} else {
		// When credentials already exist on disk, the operator is
		// almost certainly running login to refresh / re-paste a
		// token — not to see the agent-creation page again. Default
		// to skipping the browser unless they passed --no-browser=
		// false explicitly.
		if !cmd.Flags().Changed("no-browser") && credPath != "" {
			if _, err := credentials.Load(credPath); err == nil {
				skipBrowser = true
			}
		}

		agentURL := strings.TrimRight(dashboardURL, "/") + "/agents/new?from=cli"
		_, _ = fmt.Fprintf(opts.Out, "Open this URL to create an agent and copy its token:\n  %s\n", agentURL)
		if !skipBrowser {
			opener := opts.Browser
			if opener == nil {
				opener = osBrowserOpener{}
			}
			if err := opener.Open(agentURL); err != nil {
				_, _ = fmt.Fprintf(opts.Err, "Could not launch a browser (%v); open the URL manually.\n", err)
			}
		}

		token = strings.TrimSpace(tokenInline)
		if token == "" {
			var err error
			token, err = readTokenFromStdin(opts)
			if err != nil {
				return err
			}
		}
	}
	if token == "" {
		return errors.New("empty token; aborting login")
	}

	// Verify the token against the API before persisting; surfaces typos
	// (truncated paste) immediately instead of waiting for the next call.
	verifier := opts.LoginVerifier
	if verifier == nil {
		verifier = verifyToken
	}
	if err := verifier(cmd.Context(), baseURL, token); err != nil {
		return fmt.Errorf("token rejected by %s: %w", baseURL, err)
	}

	path := credPath
	if path == "" {
		// Path resolution failed earlier (e.g. no $HOME); surface the
		// underlying error now so the operator gets the same message
		// as before — credentialsPath swallows it for the no-browser
		// check, where "we couldn't decide" should fall through to
		// the existing default behavior.
		var err error
		path, err = credentials.DefaultPath()
		if err != nil {
			return err
		}
	}
	if err := credentials.Save(path, credentials.File{
		BaseURL:     baseURL,
		WorkspaceID: workspaceID,
		Token:       token,
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(opts.Out, "Saved credentials to %s\n", path)
	return nil
}

// credentialsPath returns the on-disk credentials file path, preferring
// the explicit override in opts. Returns "" if no path could be resolved
// (test fixtures with no $HOME, or platforms where credentials.DefaultPath
// errors). Callers treat "" as "skip credential-aware behavior".
func credentialsPath(opts Options) string {
	if p := strings.TrimSpace(opts.CredentialsPath); p != "" {
		return p
	}
	p, err := credentials.DefaultPath()
	if err != nil {
		return ""
	}
	return p
}

// readTokenFromStdin prompts the operator for the token. When stdin is a
// terminal, echo is suppressed via x/term; otherwise the line is read
// verbatim so CI pipelines can pipe `echo $TOKEN | secrevo login` cleanly.
func readTokenFromStdin(opts Options) (string, error) {
	stdin := opts.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	_, _ = fmt.Fprint(opts.Out, "Paste the agent token (press Enter): ")
	reader := bufio.NewReader(stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read token: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// verifyToken calls /v1/auth/sessions with the supplied bearer to confirm
// the token is currently valid. The Whoami endpoint requires only the
// token (no workspace scope), so it works as a generic auth probe.
func verifyToken(ctx context.Context, baseURL, token string) error {
	api, err := client.New(client.Config{
		BaseURL: baseURL,
		Token:   token,
	})
	if err != nil {
		return err
	}
	if _, err := api.Whoami(ctx); err != nil {
		return err
	}
	return nil
}
