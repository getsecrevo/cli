# secrevo CLI installer for Windows (PowerShell 5.1+).
#
# Usage:
#   irm https://get.secrevo.com/cli.ps1 | iex
#   irm https://github.com/getsecrevo/cli/releases/latest/download/install.ps1 | iex
#
# Env overrides:
#   $env:SECREVO_VERSION  - install a specific tag (default: latest)
#   $env:SECREVO_INSTALL_DIR - target directory (default: $env:LOCALAPPDATA\secrevo\bin)
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = 'getsecrevo/cli'
$Version = if ($env:SECREVO_VERSION) { $env:SECREVO_VERSION } else { 'latest' }
$InstallDir = if ($env:SECREVO_INSTALL_DIR) { $env:SECREVO_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'secrevo\bin' }
$BinName = 'secrevo.exe'

function Write-Step($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Warn($msg)  { Write-Host "==> $msg" -ForegroundColor Yellow }
function Throw-Fail($msg)  { Write-Host "==> $msg" -ForegroundColor Red; throw $msg }

# Architecture detection. PROCESSOR_ARCHITECTURE on x64 is "AMD64"; on ARM64 it's "ARM64".
$Arch = switch -Regex ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'x86_64'; break }
  'ARM64' { 'arm64';  break }
  default { Throw-Fail "unsupported arch: $env:PROCESSOR_ARCHITECTURE" }
}

if ($Version -eq 'latest') {
  Write-Step "resolving latest release for $Repo"
  $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'Accept' = 'application/json' }
  $Version = $rel.tag_name
  if (-not $Version) { Throw-Fail "could not resolve latest tag (rate-limited? set `$env:SECREVO_VERSION = 'vX.Y.Z')" }
}

$VersionNoV = $Version.TrimStart('v')
$Asset = "secrevo_${VersionNoV}_windows_${Arch}.zip"
$Url = "https://github.com/$Repo/releases/download/$Version/$Asset"
$SumsUrl = "https://github.com/$Repo/releases/download/$Version/checksums.txt"

Write-Step "installing secrevo $Version (windows/$Arch) -> $InstallDir\$BinName"

$Tmp = Join-Path $env:TEMP "secrevo-install-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $Tmp -Force | Out-Null
try {
  $ZipPath = Join-Path $Tmp $Asset
  $SumsPath = Join-Path $Tmp 'checksums.txt'

  Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $ZipPath
  Invoke-WebRequest -UseBasicParsing -Uri $SumsUrl -OutFile $SumsPath

  # Verify sha256 against the release checksums file.
  $want = (Select-String -Path $SumsPath -Pattern "  $Asset$" -SimpleMatch:$false | Select-Object -First 1).Line
  if (-not $want) { Throw-Fail "checksums.txt has no entry for $Asset" }
  $wantHash = ($want -split '\s+')[0].ToLowerInvariant()
  $gotHash = (Get-FileHash -Algorithm SHA256 -Path $ZipPath).Hash.ToLowerInvariant()
  if ($wantHash -ne $gotHash) { Throw-Fail "sha256 mismatch: want $wantHash got $gotHash" }
  Write-Step "sha256 verified"

  Expand-Archive -Path $ZipPath -DestinationPath $Tmp -Force
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  $extracted = Join-Path $Tmp 'secrevo.exe'
  if (-not (Test-Path $extracted)) { Throw-Fail "extracted archive missing secrevo.exe" }
  Copy-Item -Path $extracted -Destination (Join-Path $InstallDir $BinName) -Force

  Write-Step "installed: $InstallDir\$BinName"
  & (Join-Path $InstallDir $BinName) version

  # PATH check — Process scope shows up immediately; User scope persists across shells.
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not ($userPath -split ';' | Where-Object { $_ -ieq $InstallDir })) {
    Write-Warn "$InstallDir is not in your User PATH"
    Write-Warn "to persist across shells, run:"
    Write-Warn "  [Environment]::SetEnvironmentVariable('Path', '`$InstallDir;' + [Environment]::GetEnvironmentVariable('Path','User'), 'User')"
    Write-Warn "and reopen the terminal."
  }
} finally {
  Remove-Item -Recurse -Force -Path $Tmp -ErrorAction SilentlyContinue
}
