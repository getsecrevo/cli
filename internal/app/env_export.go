package app

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

func newEnvCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env [--secret NAME[=ENV_VAR]...] [--all]",
		Short: "Print shell-eval-friendly export lines for the requested secrets",
		Long: `Emit lines that the parent shell can ` + "`eval`" + ` to set Secrevo
secrets as environment variables for the current session — without
spawning a subprocess (which is what ` + "`secrevo run`" + ` does).

Useful for interactive debug sessions where you want one shell to have
the secrets resolved without exporting an ` + "`agt_*`" + ` token long-term:

    # POSIX
    eval "$(secrevo env --secret OPENAI_API_KEY --secret AWS_ACCESS_KEY_ID)"

    # PowerShell
    secrevo env --secret OPENAI_API_KEY --shell powershell | Invoke-Expression

    # fish
    secrevo env --secret OPENAI_API_KEY --shell fish | source

Each --secret accepts the same NAME or NAME=ENV_VAR syntax as ` +
			"`secrevo run`. " + `Combining --all reveals every secret visible to the
agent and exports each under its canonical name (use with care — a
typo in your shell history could expose them downstream).

The default shell is auto-detected from $SHELL on POSIX and from
$PSModulePath on Windows; override with --shell.
`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnvCommand(cmd, opts)
		},
	}
	cmd.Flags().StringArrayP("secret", "s", nil, "Secret to emit (repeatable). Format: NAME or NAME=ENV_VAR_NAME.")
	cmd.Flags().Bool("all", false, "Emit every secret visible to the token (mutually exclusive with --secret)")
	cmd.Flags().String("shell", "", "Shell format: posix, powershell, fish. Default: auto-detect.")
	return cmd
}

func runEnvCommand(cmd *cobra.Command, opts Options) error {
	workspaceID, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	rawSpecs, _ := cmd.Flags().GetStringArray("secret")
	emitAll, _ := cmd.Flags().GetBool("all")
	shellFlag, _ := cmd.Flags().GetString("shell")

	if emitAll && len(rawSpecs) > 0 {
		return fmt.Errorf("--all and --secret are mutually exclusive")
	}
	if !emitAll && len(rawSpecs) == 0 {
		return fmt.Errorf("provide --secret NAME (repeatable) or --all")
	}

	shell, err := pickShell(shellFlag)
	if err != nil {
		return err
	}

	return withClient(opts, func(api APIClient) error {
		list, err := api.ListSecrets(cmd.Context(), workspaceID)
		if err != nil {
			return fmt.Errorf("list secrets: %w", err)
		}

		var specs []secretSpec
		if emitAll {
			for _, s := range list.Secrets {
				specs = append(specs, secretSpec{secretName: s.Name, envName: s.Name})
			}
			sort.Slice(specs, func(i, j int) bool { return specs[i].envName < specs[j].envName })
		} else {
			specs, err = parseSecretSpecs(rawSpecs)
			if err != nil {
				return err
			}
		}

		for _, spec := range specs {
			id, err := resolveSecretID(list.Secrets, spec.secretName)
			if err != nil {
				return fmt.Errorf("resolve %s: %w", spec.secretName, err)
			}
			revealed, err := api.RevealSecretValue(cmd.Context(), workspaceID, id)
			if err != nil {
				return fmt.Errorf("reveal %s: %w", spec.secretName, err)
			}
			line, err := shellExportLine(shell, spec.envName, revealed.Value)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(opts.Out, line)
		}
		return nil
	})
}

// pickShell returns the canonical shell identifier the operator asked for,
// or the auto-detected one. Returns an error for unknown values.
func pickShell(explicit string) (string, error) {
	explicit = strings.ToLower(strings.TrimSpace(explicit))
	switch explicit {
	case "posix", "bash", "sh", "zsh":
		return "posix", nil
	case "powershell", "pwsh", "ps":
		return "powershell", nil
	case "fish":
		return "fish", nil
	case "":
		return detectShell(), nil
	}
	return "", fmt.Errorf("unknown shell %q (supported: posix, powershell, fish)", explicit)
}

// detectShell falls back to POSIX unless the runtime is windows and SHELL
// isn't set. The detection is intentionally simple — operators with non-
// standard shells should pass --shell explicitly.
func detectShell() string {
	if shell := strings.TrimSpace(os.Getenv("SHELL")); shell != "" {
		shellLower := strings.ToLower(shell)
		if strings.Contains(shellLower, "fish") {
			return "fish"
		}
		if strings.Contains(shellLower, "pwsh") || strings.Contains(shellLower, "powershell") {
			return "powershell"
		}
		return "posix"
	}
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "posix"
}

// shellExportLine renders a single export statement for the given shell.
// Values are single-quoted with the shell's standard escape so any
// printable character is safe to embed.
func shellExportLine(shell, name, value string) (string, error) {
	switch shell {
	case "posix":
		return fmt.Sprintf("export %s=%s", name, posixSingleQuote(value)), nil
	case "powershell":
		return fmt.Sprintf("$env:%s = %s", name, powershellSingleQuote(value)), nil
	case "fish":
		return fmt.Sprintf("set -gx %s %s", name, posixSingleQuote(value)), nil
	}
	return "", fmt.Errorf("unsupported shell: %s", shell)
}

func posixSingleQuote(value string) string {
	// Single-quote POSIX-style: '...'\''...' for embedded quotes.
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func powershellSingleQuote(value string) string {
	// PowerShell single-quote: embedded ' becomes ''.
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// ----------------------------------------------------------------------------
// export
// ----------------------------------------------------------------------------

func newExportCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export --out <file>",
		Short: "Dump every visible secret + value to a local file (PLAINTEXT)",
		Long: `Reveal every secret visible to the current agent token and write
the resulting name → value map to a local JSON file.

PLAINTEXT WARNING. This command writes secret values in cleartext to
the destination path. Use it only when you control the destination
disk and intend to wrap the output with your own encryption tool
(` + "`gpg --symmetric backup.json`" + `, ` + "`age -p backup.json > backup.json.age`" + `,
` + "`openssl enc`" + `, etc.). The CLI rejects writing to stdout to make
the audit trail obvious.

Use case: a recovery backup before Fernando dogfoods Secrevo for a
week. If Secrevo goes down, the operator restores from this file via
` + "`secrevo import --plaintext-restore`" + ` (planned).

The output schema is intentionally simple so an operator can decrypt
the encrypted wrapping and restore the values with grep + jq if our
CLI is unavailable.

Example:

    secrevo export --out /tmp/secrevo-backup-2026-05-12.json
    gpg --symmetric /tmp/secrevo-backup-2026-05-12.json
    rm /tmp/secrevo-backup-2026-05-12.json
`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExportCommand(cmd, opts)
		},
	}
	cmd.Flags().String("out", "", "Destination path (required; refuse stdout for safety)")
	cmd.Flags().Bool("force", false, "Overwrite if the destination file already exists")
	return cmd
}

type exportPayload struct {
	WorkspaceID string                  `json:"workspace_id"`
	GeneratedAt string                  `json:"generated_at,omitempty"`
	Note        string                  `json:"note"`
	Secrets     []exportSecretEntry     `json:"secrets"`
}

type exportSecretEntry struct {
	Name        string `json:"name"`
	SecretID    string `json:"secret_id"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

func runExportCommand(cmd *cobra.Command, opts Options) error {
	workspaceID, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	outPath, _ := cmd.Flags().GetString("out")
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("--out PATH is required; export refuses to write secrets to stdout")
	}
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		if _, err := os.Stat(outPath); err == nil {
			return fmt.Errorf("%s already exists; pass --force to overwrite", outPath)
		}
	}

	return withClient(opts, func(api APIClient) error {
		list, err := api.ListSecrets(cmd.Context(), workspaceID)
		if err != nil {
			return fmt.Errorf("list secrets: %w", err)
		}
		payload := exportPayload{
			WorkspaceID: workspaceID,
			Note: "PLAINTEXT secret backup generated by `secrevo export`. " +
				"Encrypt before sharing or storing remotely (gpg/age/openssl).",
			Secrets: make([]exportSecretEntry, 0, len(list.Secrets)),
		}
		for _, s := range list.Secrets {
			val, err := api.RevealSecretValue(cmd.Context(), workspaceID, s.SecretID)
			if err != nil {
				return fmt.Errorf("reveal %s: %w", s.Name, err)
			}
			payload.Secrets = append(payload.Secrets, exportSecretEntry{
				Name:        s.Name,
				SecretID:    s.SecretID,
				Value:       val.Value,
				Description: s.Description,
			})
		}
		sort.Slice(payload.Secrets, func(i, j int) bool {
			return payload.Secrets[i].Name < payload.Secrets[j].Name
		})

		buf, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal export: %w", err)
		}
		if err := writeFileTight(outPath, buf); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(opts.Err,
			"WARNING: %s contains %d secret value(s) in PLAINTEXT. Encrypt or delete after use.\n",
			outPath, len(payload.Secrets))
		_, _ = fmt.Fprintf(opts.Out, "Exported %d secret(s) to %s\n", len(payload.Secrets), outPath)
		return nil
	})
}

// writeFileTight writes the data to ``path`` with 0600 perms regardless of
// platform. Existing perms are not preserved.
func writeFileTight(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

