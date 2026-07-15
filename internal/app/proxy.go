package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/getsecrevo/cli/internal/client"
	"github.com/spf13/cobra"
)

// newCallCommand implements `secrevo call` — mediated consumption. The server
// injects the secret into an allowlisted outbound request and returns only the
// (projected/redacted) response. The plaintext value NEVER reaches this process,
// so unlike `secrevo run` there is nothing to leak to logs/env.
func newCallCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "call --secret NAME --url URL [flags]",
		Short: "Use a secret in a mediated HTTP call without ever seeing its value",
		Long: "The server injects the secret server-side and returns only the response.\n" +
			"Put {{secret}} where the value goes, e.g. -H 'Authorization: Bearer {{secret}}'.\n" +
			"The value is never returned to this process (contrast `secrevo run`, which injects it into a local env).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCall(cmd, opts)
		},
	}
	cmd.Flags().StringP("secret", "s", "", "secret name to consume (required)")
	cmd.Flags().StringP("method", "X", "GET", "HTTP method")
	cmd.Flags().StringP("url", "u", "", "absolute https URL of the allowlisted destination (required)")
	cmd.Flags().StringArrayP("header", "H", nil, "header 'Key: Value'; use {{secret}} for the value")
	cmd.Flags().StringP("body", "d", "", "request body, or @file to read from a file; may contain {{secret}}")
	_ = cmd.MarkFlagRequired("secret")
	_ = cmd.MarkFlagRequired("url")
	return cmd
}

func runCall(cmd *cobra.Command, opts Options) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	secret, _ := cmd.Flags().GetString("secret")
	method, _ := cmd.Flags().GetString("method")
	rawURL, _ := cmd.Flags().GetString("url")
	headerArgs, _ := cmd.Flags().GetStringArray("header")
	bodyArg, _ := cmd.Flags().GetString("body")

	headers, err := parseHeaders(headerArgs)
	if err != nil {
		return err
	}
	body, err := resolveBody(bodyArg)
	if err != nil {
		return err
	}

	req := client.ProxyRequest{Method: method, URL: rawURL, Headers: headers, Body: body}
	return withClient(opts, func(api APIClient) error {
		resp, err := api.ProxyConsume(cmd.Context(), ws, secret, req)
		if err != nil {
			return err
		}
		// The response never contains the secret value; print it as structured
		// JSON (status + projected/redacted body + flags).
		return writeJSON(opts.Out, resp)
	})
}

func parseHeaders(args []string) (map[string]string, error) {
	if len(args) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(args))
	for _, h := range args {
		k, v, ok := strings.Cut(h, ":")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("invalid --header %q: expected 'Key: Value'", h)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, nil
}

func resolveBody(arg string) (string, error) {
	if strings.HasPrefix(arg, "@") {
		b, err := os.ReadFile(arg[1:])
		if err != nil {
			return "", fmt.Errorf("read --body file: %w", err)
		}
		return string(b), nil
	}
	return arg, nil
}

// newSecretProxyTargetCommand manages a secret's mediated-proxy operation
// allowlist. Human-only server-side (agent tokens are refused): an agent can
// never widen its own allowlist.
func newSecretProxyTargetCommand(opts Options) *cobra.Command {
	pt := &cobra.Command{
		Use:   "proxy-target",
		Short: "Manage the mediated-proxy operation allowlist for a secret (human only)",
	}

	add := &cobra.Command{
		Use:   "add --secret NAME --host HOST --method M --path /PREFIX [flags]",
		Short: "Allow an operation (host + method + path [+ query/body/response contract])",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProxyTargetAdd(cmd, opts)
		},
	}
	add.Flags().String("secret", "", "secret name (required)")
	add.Flags().String("host", "", "exact destination host, e.g. api.stripe.com (required)")
	add.Flags().StringArray("method", nil, "allowed HTTP method(s), e.g. GET (required, repeatable)")
	add.Flags().StringArray("path", nil, "allowed path prefix(es), e.g. /v1/ (required, repeatable)")
	add.Flags().StringArray("query", nil, "allowed query key(s) (repeatable)")
	add.Flags().StringArray("response-field", nil, "JSON field(s) to project back (repeatable)")
	add.Flags().String("response-mode", "projection", "projection | redacted_body")
	add.Flags().String("body-template", "", "JSON body template pinning the operation (\"*\"=scalar wildcard)")
	_ = add.MarkFlagRequired("secret")
	_ = add.MarkFlagRequired("host")
	_ = add.MarkFlagRequired("method")
	_ = add.MarkFlagRequired("path")

	list := &cobra.Command{
		Use:   "list --secret NAME",
		Short: "List a secret's allowlist targets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProxyTargetList(cmd, opts)
		},
	}
	list.Flags().String("secret", "", "secret name (required)")
	_ = list.MarkFlagRequired("secret")

	rm := &cobra.Command{
		Use:   "rm --secret NAME --host HOST",
		Short: "Remove an allowlist target by host",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProxyTargetRemove(cmd, opts)
		},
	}
	rm.Flags().String("secret", "", "secret name (required)")
	rm.Flags().String("host", "", "host to remove (required)")
	_ = rm.MarkFlagRequired("secret")
	_ = rm.MarkFlagRequired("host")

	pt.AddCommand(add, list, rm)
	return pt
}

// resolveSecretName looks up a secret's id from its name in the workspace.
func resolveSecretName(cmd *cobra.Command, api APIClient, ws, name string) (string, error) {
	secrets, err := api.ListSecrets(cmd.Context(), ws)
	if err != nil {
		return "", err
	}
	return resolveSecretID(secrets.Secrets, name)
}

func runProxyTargetAdd(cmd *cobra.Command, opts Options) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	name, _ := cmd.Flags().GetString("secret")
	host, _ := cmd.Flags().GetString("host")
	methods, _ := cmd.Flags().GetStringArray("method")
	paths, _ := cmd.Flags().GetStringArray("path")
	query, _ := cmd.Flags().GetStringArray("query")
	fields, _ := cmd.Flags().GetStringArray("response-field")
	mode, _ := cmd.Flags().GetString("response-mode")
	bodyTemplate, _ := cmd.Flags().GetString("body-template")

	return withClient(opts, func(api APIClient) error {
		secretID, err := resolveSecretName(cmd, api, ws, name)
		if err != nil {
			return err
		}
		saved, err := api.PutProxyTarget(cmd.Context(), ws, secretID, client.ProxyTarget{
			Host: host, Methods: methods, PathPrefixes: paths, AllowedQuery: query,
			ResponseMode: mode, ResponseFields: fields, BodyTemplate: bodyTemplate,
		})
		if err != nil {
			return err
		}
		return writeJSON(opts.Out, saved)
	})
}

func runProxyTargetList(cmd *cobra.Command, opts Options) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	name, _ := cmd.Flags().GetString("secret")
	return withClient(opts, func(api APIClient) error {
		secretID, err := resolveSecretName(cmd, api, ws, name)
		if err != nil {
			return err
		}
		targets, err := api.ListProxyTargets(cmd.Context(), ws, secretID)
		if err != nil {
			return err
		}
		return writeJSON(opts.Out, map[string]any{"targets": targets})
	})
}

func runProxyTargetRemove(cmd *cobra.Command, opts Options) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	name, _ := cmd.Flags().GetString("secret")
	host, _ := cmd.Flags().GetString("host")
	return withClient(opts, func(api APIClient) error {
		secretID, err := resolveSecretName(cmd, api, ws, name)
		if err != nil {
			return err
		}
		return api.DeleteProxyTarget(cmd.Context(), ws, secretID, host)
	})
}
