package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/getsecrevo/cli/internal/client"
)

// secretRequester is the slice of the api client the `secret request`
// commands need. It is discovered by type assertion so the test fakes of the
// main APIClient interface do not all have to grow these methods.
type secretRequester interface {
	CreateSecretRequestByName(context.Context, string, string, client.SecretRequestCreateRequest) (client.SecretRequestCreated, error)
	ListSecretRequests(context.Context, string, string) ([]client.SecretRequest, error)
	CancelSecretRequest(context.Context, string, string) (client.SecretRequest, error)
}

// The real client must keep satisfying it: a drift would turn the commands
// into "not supported" at runtime instead of failing the build.
var _ secretRequester = (*client.Client)(nil)

func asSecretRequester(api APIClient) (secretRequester, error) {
	sr, ok := api.(secretRequester)
	if !ok {
		return nil, fmt.Errorf("this client does not support secret requests")
	}
	return sr, nil
}

// newSecretRequestCommand asks someone OUTSIDE the workspace for a secret's
// value through a single-use, write-only link emailed in your name.
func newSecretRequestCommand(opts Options) *cobra.Command {
	req := &cobra.Command{
		Use:   "request",
		Short: "Ask someone outside the workspace to enter or rotate a secret's value",
		Long: "Email a customer, vendor or contractor a single-use, WRITE-ONLY link to enter\n" +
			"(or rotate) one secret's value straight into the vault, instead of them sending\n" +
			"it by email or chat. Nobody, including you, reads the value through the link.\n" +
			"Works with a human login or an agent token: an agent sends it on its owner's\n" +
			"behalf, and the email says which agent sent it.\n\n" +
			"Safety rails enforced by the server:\n" +
			"  - --secret must be the EXACT name (no fuzzy match).\n" +
			"  - Replacing a value that may already exist needs --replace (no history is kept).\n" +
			"  - Once a secret has known contacts, emailing someone else is refused until you\n" +
			"    pass --confirm-new-recipient. Agents: only after the user confirmed it.",
	}

	send := &cobra.Command{
		Use:   "send --secret NAME --to EMAIL",
		Short: "Email a single-use link to enter (or, with --replace, rotate) the value",
		Example: "  secrevo secret request send --secret \"Stripe Acme\" --to pepito@acme.com --replace \\\n" +
			"      --message \"Scheduled key rotation\"\n" +
			"  secrevo secret request send --secret DB_PROD --no-email   # prints the link to hand over yourself",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSecretRequestSend(cmd, opts)
		},
	}
	send.Flags().String("secret", "", "the secret's EXACT name (required)")
	send.Flags().String("to", "", "recipient email; required unless --no-email")
	send.Flags().String("message", "", "short plain-text note for the recipient (no links or email addresses)")
	send.Flags().Bool("replace", false, "the link overwrites the current value (rotation); Secrevo keeps no history")
	send.Flags().Bool("confirm-new-recipient", false, "confirm the recipient is the new contact for this secret")
	send.Flags().Int("expires-in-hours", 0, "link lifetime in hours, 1-720 (default 168)")
	send.Flags().StringArray("label", nil, "friendly label as FIELD=Label (use value=Label for a single-value secret); repeatable")
	send.Flags().Bool("no-email", false, "do not email anyone; print the link so you can hand it over")
	_ = send.MarkFlagRequired("secret")

	list := &cobra.Command{
		Use:   "list [--secret NAME]",
		Short: "List secret requests and their status (never links or values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSecretRequestList(cmd, opts)
		},
	}
	list.Flags().String("secret", "", "only the requests for this secret")

	cancel := &cobra.Command{
		Use:   "cancel <request-id>",
		Short: "Cancel a pending request so its link stops working",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretRequestCancel(cmd, opts, args[0])
		},
	}

	req.AddCommand(send, list, cancel)
	return req
}

func parseLabels(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(raw))
	for _, kv := range raw {
		k, v, ok := strings.Cut(kv, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("--label must be FIELD=Label, got %q", kv)
		}
		out[k] = v
	}
	return out, nil
}

func runSecretRequestSend(cmd *cobra.Command, opts Options) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	name, _ := cmd.Flags().GetString("secret")
	to, _ := cmd.Flags().GetString("to")
	message, _ := cmd.Flags().GetString("message")
	replace, _ := cmd.Flags().GetBool("replace")
	confirm, _ := cmd.Flags().GetBool("confirm-new-recipient")
	hours, _ := cmd.Flags().GetInt("expires-in-hours")
	rawLabels, _ := cmd.Flags().GetStringArray("label")
	noEmail, _ := cmd.Flags().GetBool("no-email")

	to = strings.TrimSpace(to)
	if to == "" && !noEmail {
		return fmt.Errorf("--to is required (or pass --no-email to get the link and hand it over yourself)")
	}
	labels, err := parseLabels(rawLabels)
	if err != nil {
		return err
	}
	sendEmail := !noEmail
	return withClient(opts, func(api APIClient) error {
		sr, err := asSecretRequester(api)
		if err != nil {
			return err
		}
		created, err := sr.CreateSecretRequestByName(cmd.Context(), ws, name, client.SecretRequestCreateRequest{
			RecipientEmail:      to,
			Message:             message,
			FieldLabels:         labels,
			ExpiresInHours:      hours,
			SendEmail:           &sendEmail,
			ReplaceExisting:     replace,
			ConfirmNewRecipient: confirm,
		})
		if err != nil {
			return err
		}
		out := map[string]any{
			"request_id":              created.Request.ID,
			"secret":                  created.Request.SecretName,
			"recipient_email":         created.Request.RecipientEmail,
			"email_sent":              created.EmailSent,
			"expires_at":              created.Request.ExpiresAt,
			"replaces_existing_value": replace,
		}
		// The link is a write capability: print it only when nobody was
		// emailed and the caller has to deliver it.
		if !created.EmailSent {
			out["link"] = created.URL
		}
		return writeJSON(opts.Out, out)
	})
}

func runSecretRequestList(cmd *cobra.Command, opts Options) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	name, _ := cmd.Flags().GetString("secret")
	return withClient(opts, func(api APIClient) error {
		sr, err := asSecretRequester(api)
		if err != nil {
			return err
		}
		secretID := ""
		if name != "" {
			if secretID, err = resolveSecretName(cmd, api, ws, name); err != nil {
				return err
			}
		}
		reqs, err := sr.ListSecretRequests(cmd.Context(), ws, secretID)
		if err != nil {
			return err
		}
		return writeJSON(opts.Out, map[string]any{"requests": reqs})
	})
}

func runSecretRequestCancel(cmd *cobra.Command, opts Options, requestID string) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	return withClient(opts, func(api APIClient) error {
		sr, err := asSecretRequester(api)
		if err != nil {
			return err
		}
		r, err := sr.CancelSecretRequest(cmd.Context(), ws, requestID)
		if err != nil {
			return err
		}
		return writeJSON(opts.Out, r)
	})
}
