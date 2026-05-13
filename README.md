# getsecrevo/cli

`cli` is the operator-facing command line client for the **secrevo** product.
It is a Cat C product repo: product code that consumes the Secrevo API
contract and helps humans, CI jobs, and future automation drive the platform
from a local workspace.

## Install

**Linux / macOS** (downloads + sha256-verifies the latest release):

```sh
curl -fsSL https://github.com/getsecrevo/cli/releases/latest/download/install.sh | bash
```

**Windows** (PowerShell 5.1+):

```powershell
irm https://github.com/getsecrevo/cli/releases/latest/download/install.ps1 | iex
```

Both scripts install to a user-writable location (no sudo): `~/.local/bin` on
posix, `%LOCALAPPDATA%\secrevo\bin` on Windows. Override with
`SECREVO_INSTALL_DIR` / `$env:SECREVO_INSTALL_DIR`. Pin to a specific tag with
`SECREVO_VERSION=v0.2.0` (default: `latest`).

Release artefacts (one per OS/arch — linux/macos/windows × amd64/arm64) ship
from a tag-driven GitHub Actions workflow that runs goreleaser. See
[releases](https://github.com/getsecrevo/cli/releases) for the latest tag and
`checksums.txt`.

From source (requires Go ≥ 1.25):

```sh
go install github.com/getsecrevo/cli/cmd/secrevo@latest
```

## Purpose

The CLI provides the first local surface for Secrevo operators and developers.
It is intentionally small and focused: inspect the current identity, bootstrap
a workspace, fetch secret metadata, create agents, and reserve a `run`
command for the future secret-aware execution flow.

The repo does not own storage or business rules. It is a thin client over the
Secrevo API contract and the eventual automation boundary around it.

## Stack

- Go 1.23+
- [Cobra](https://github.com/spf13/cobra) for the command tree
- Standard library `net/http` for API access

## Architecture role

This repo sits at the edge of the product. It translates operator intent into
Secrevo API calls and prints machine-readable output that other tools can
consume.

The CLI depends on the API contract documented in:
- [Secrevo API contract](https://github.com/getsecrevo/api/blob/main/docs/contract.md)
- [OpenAPI draft](https://github.com/getsecrevo/api/blob/main/docs/openapi.yaml)

The API remains the source of truth for auth, workspace, member, agent,
secret, grant, access-request, and audit behavior. The CLI is a consumer, not
the authority.

## Primary consumers

- Developers working on Secrevo locally
- Operators bootstrapping or inspecting workspaces
- Future automation that needs a stable command surface
- CI jobs that need a small, scriptable control plane entrypoint

## API / contract

The initial command surface maps to the documented API contract:

- `secrevo version`
- `secrevo auth whoami`
- `secrevo workspace bootstrap`
- `secrevo secret get <secret-name>`
- `secrevo agent create <name>`
- `secrevo run -- <command>`

The API client uses:

- `SECREVO_API_BASE_URL`
- `SECREVO_API_TOKEN`
- `SECREVO_WORKSPACE_ID` or `--workspace-id` for workspace-scoped commands

`secrevo run` is the flagship execution command. It reveals one or more
secrets from the workspace and injects them into the environment of a
subprocess, so applications can keep secrets out of `.env` files, shell
history, and disk in general:

```bash
secrevo run --secret OPENAI_API_KEY -- python app.py
secrevo run --secret AWS_ACCESS_KEY_ID --secret AWS_SECRET_ACCESS_KEY -- aws s3 ls
secrevo run --secret prod-stripe=STRIPE_API_KEY -- npm test
```

The default env var name matches the secret name; pass `--secret name=ENV`
to rename. The CLI exits with the same status code as the child process,
so `secrevo run -- false` exits 1, `... -- true` exits 0.

## Local development

```bash
go test ./...
go run ./cmd/secrevo version
SECREVO_API_BASE_URL=http://localhost:8080 \
SECREVO_API_TOKEN=dev-token \
SECREVO_WORKSPACE_ID=workspace-123 \
go run ./cmd/secrevo auth whoami
```

If Go is not installed locally, use the same commands inside a Go container.

## Tests

The repo uses Go unit tests for two layers:

- command parsing and command wiring
- API client request boundaries and config validation

Run the full suite with:

```bash
go test ./...
```

The suite is intentionally small so it can stay fast while the CLI surface is
still being defined.

## Deployment

The CLI is not a server-side deployment target. It is shipped as a Go binary.

Planned delivery model:

- build in CI
- publish release artifacts
- consume the binary locally or in automation

The runtime services remain in `api/` and `infrastructure/`.

## Cross-references

- Governance: <https://github.com/getGanemo/docs-company/blob/main/governance/product-structure.md>
- Product project management: <https://github.com/getsecrevo/project_management>
- API implementation: <https://github.com/getsecrevo/api>
- Infrastructure: <https://github.com/getsecrevo/infrastructure>

