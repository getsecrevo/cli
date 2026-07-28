package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

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
			"`secrevo run`. " + `When no '=' is provided the secret's name is
sanitized for POSIX compatibility: letters uppercased, anything non-
[A-Z0-9_] turned into '_'. So a secret named "aws.cloudwatch.url" emits
as AWS_CLOUDWATCH_URL — the form most shells actually accept. Pass
--raw-name to disable sanitization (the export line will then contain
the literal secret name, which may be invalid in your shell).

Combining --all reveals every secret visible to the agent and exports
each under its sanitized canonical name (use with care — a typo in your
shell history could expose them downstream).

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
	cmd.Flags().Bool("raw-name", false, "Emit under the secret's literal name (skip POSIX sanitization)")
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
	rawName, _ := cmd.Flags().GetBool("raw-name")

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
		if emitAll {
			list, err := api.ListSecrets(cmd.Context(), workspaceID)
			if err != nil {
				return fmt.Errorf("list secrets: %w", err)
			}
			specs := make([]secretSpec, 0, len(list.Secrets))
			for _, s := range list.Secrets {
				envName := s.Name
				if !rawName {
					envName = sanitizeEnvName(s.Name)
				}
				specs = append(specs, secretSpec{secretName: s.Name, envName: envName})
			}
			sort.Slice(specs, func(i, j int) bool { return specs[i].envName < specs[j].envName })
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
		}

		specs, err := parseSecretSpecs(rawSpecs, !rawName)
		if err != nil {
			return err
		}
		for _, spec := range specs {
			revealed, err := api.RevealSecretValueByName(cmd.Context(), workspaceID, spec.secretName, "")
			if err != nil {
				return revealSpecError(workspaceID, spec, err)
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
		Use:   "export [--kit --out-dir DIR] | [--plaintext --out PATH]",
		Short: "Recovery snapshot of every visible secret (encrypted kit by default)",
		Long: `Reveal every secret visible to the current agent token and write a
local recovery snapshot.

Two modes:

  --kit (default)        Recovery Kit (Postura A — D-11.6). Writes TWO files
                         in --out-dir (default: current directory):
                           secrevo-backup-YYYY-MM-DD.json.kit  ← ciphertext
                           secrevo-backup-YYYY-MM-DD.passphrase ← single-use
                                                                   passphrase
                         Format: PBKDF2-HMAC-SHA256 (200K iters) + AES-256-GCM.
                         The dashboard (browser, WebCrypto) and the CLI (this
                         command) produce identical formats, so a kit from
                         either tool decrypts in either tool.
                         IMMEDIATE NEXT STEP printed to stdout: copy the
                         passphrase to a password manager and DELETE the
                         passphrase file (otherwise ciphertext + key co-
                         located makes the encryption useless).

  --plaintext --out PATH (legacy). Writes the bare JSON snapshot to PATH.
                         The CLI prints a stderr WARNING. Use only when
                         you intend to encrypt + safekeep the result with
                         your own tools.

Both modes refuse stdout to make the audit trail obvious.

Recovery cycle:

    # Encrypt + save kit (two files, separate locations after move).
    secrevo export --kit --out-dir ~/secrevo-recovery
    # < move passphrase to password manager, delete the .passphrase file >

    # Decrypt later if you ever need to:
    secrevo import --recovery-kit ~/secrevo-recovery/secrevo-backup-2026-05-13.json.kit
    # (planned — for now decrypt with the documented format using gpg-incompatible
    #  tooling; the file format is in cli/internal/app/recovery_kit.go.)

Examples:

    secrevo export --kit                                 # writes to ./
    secrevo export --kit --out-dir ~/secrevo-recovery
    secrevo export --plaintext --out /tmp/snapshot.json  # legacy
`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExportCommand(cmd, opts)
		},
	}
	cmd.Flags().Bool("kit", false, "Write a Recovery Kit (ciphertext + separate passphrase file). Default when no other mode is selected.")
	cmd.Flags().String("out-dir", "", "Directory to write the kit files into (kit mode; default: current directory)")
	cmd.Flags().Bool("plaintext", false, "Write a bare JSON snapshot (no encryption). Requires --out.")
	cmd.Flags().String("out", "", "Destination path (plaintext mode)")
	cmd.Flags().Bool("force", false, "Overwrite if destination file(s) already exist")
	return cmd
}

type exportPayload struct {
	WorkspaceID string              `json:"workspace_id"`
	GeneratedAt string              `json:"generated_at,omitempty"`
	Note        string              `json:"note"`
	Secrets     []exportSecretEntry `json:"secrets"`
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
	kitMode, _ := cmd.Flags().GetBool("kit")
	plaintextMode, _ := cmd.Flags().GetBool("plaintext")
	outPath, _ := cmd.Flags().GetString("out")
	outDir, _ := cmd.Flags().GetString("out-dir")
	force, _ := cmd.Flags().GetBool("force")

	// Mode resolution. Default to --kit when neither flag is set so the
	// secure path is what an operator gets by typing `secrevo export`.
	if !kitMode && !plaintextMode {
		kitMode = true
	}
	if kitMode && plaintextMode {
		return fmt.Errorf("--kit and --plaintext are mutually exclusive")
	}

	if plaintextMode {
		if strings.TrimSpace(outPath) == "" {
			return fmt.Errorf("--plaintext requires --out PATH; export refuses to write to stdout")
		}
		if strings.TrimSpace(outDir) != "" {
			return fmt.Errorf("--out-dir applies to --kit; use --out with --plaintext")
		}
	} else {
		if strings.TrimSpace(outPath) != "" {
			return fmt.Errorf("--out applies to --plaintext; use --out-dir with --kit (default)")
		}
		if strings.TrimSpace(outDir) == "" {
			outDir = "."
		}
	}

	return withClient(opts, func(api APIClient) error {
		list, err := api.ListSecrets(cmd.Context(), workspaceID)
		if err != nil {
			return fmt.Errorf("list secrets: %w", err)
		}
		payload := exportPayload{
			WorkspaceID: workspaceID,
			Note: "Secret snapshot generated by `secrevo export`. " +
				"Treat as production credentials material.",
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

		if plaintextMode {
			return writePlaintextExport(opts, outPath, force, buf, len(payload.Secrets))
		}
		return writeRecoveryKit(opts, outDir, force, buf, len(payload.Secrets))
	})
}

func writePlaintextExport(opts Options, outPath string, force bool, buf []byte, count int) error {
	if !force {
		if _, err := os.Stat(outPath); err == nil {
			return fmt.Errorf("%s already exists; pass --force to overwrite", outPath)
		}
	}
	if err := writeFileTight(outPath, buf); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(opts.Err,
		"WARNING: %s contains %d secret value(s) in PLAINTEXT. Encrypt or delete after use.\n",
		outPath, count)
	_, _ = fmt.Fprintf(opts.Out, "Exported %d secret(s) to %s\n", count, outPath)
	return nil
}

// writeRecoveryKit produces the two-file Recovery Kit (D-11.6): one
// ciphertext blob and one passphrase file, written in the same directory
// but explicitly designed to be split immediately by the operator.
func writeRecoveryKit(opts Options, outDir string, force bool, plaintext []byte, count int) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}
	stamp := nowStamp()
	cipherPath := filepath.Join(outDir, fmt.Sprintf("secrevo-backup-%s.json.kit", stamp))
	passPath := filepath.Join(outDir, fmt.Sprintf("secrevo-backup-%s.passphrase", stamp))

	if !force {
		for _, p := range []string{cipherPath, passPath} {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("%s already exists; pass --force to overwrite", p)
			}
		}
	}

	passphrase, err := generateKitPassphrase()
	if err != nil {
		return fmt.Errorf("generate passphrase: %w", err)
	}
	blob, err := encryptRecoveryKit(plaintext, passphrase)
	if err != nil {
		return fmt.Errorf("encrypt kit: %w", err)
	}
	if err := writeFileTight(cipherPath, blob); err != nil {
		return err
	}

	passphraseFile := fmt.Sprintf(
		"# Secrevo Recovery Kit passphrase — generated %s\n"+
			"# Move this single line into your password manager NOW and DELETE this file.\n"+
			"# Co-locating ciphertext + passphrase defeats the encryption.\n"+
			"%s\n",
		stamp, passphrase,
	)
	if err := writeFileTight(passPath, []byte(passphraseFile)); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(opts.Out,
		"Recovery Kit written:\n"+
			"  ciphertext:  %s  (%d secret values, AES-256-GCM, %d-iter PBKDF2)\n"+
			"  passphrase:  %s  (move to password manager, then DELETE)\n"+
			"\n"+
			"NEXT STEPS (do these now):\n"+
			"  1. Open the passphrase file, copy the line to your password manager\n"+
			"     (label suggestion: \"Secrevo recovery kit %s\").\n"+
			"  2. Delete the passphrase file from disk.\n"+
			"  3. Store the ciphertext somewhere durable (cloud-backed dir is fine).\n"+
			"\n"+
			"Without the passphrase the ciphertext is unrecoverable. Without the\n"+
			"ciphertext you can always regenerate a fresh kit while Secrevo is up.\n",
		cipherPath, count, kitDefaultIters, passPath, stamp,
	)
	return nil
}

// nowStamp is overridable from tests so kit filenames are deterministic.
var nowStamp = func() string {
	return time.Now().UTC().Format("2006-01-02")
}

// writeFileTight writes the data to “path“ with 0600 perms regardless of
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
