<#
.SYNOPSIS
  weaverssh source-free installer for Windows PowerShell.

.DESCRIPTION
  Installs the single `wv.exe` binary for the current Windows user by default.
  The installer prefers a prebuilt archive and does not build from source unless
  WEAVERSSH_FROM_SOURCE=1 or WEAVERSSH_ALLOW_SOURCE=1 is set explicitly.

  Recommended install:
    irm https://raw.githubusercontent.com/jagg-ix/weaverssh/main/install.ps1 | iex

  Local archive install:
    $env:WEAVERSSH_ARCHIVE = 'C:\path\weaverssh_0.1.1_windows_amd64.zip'
    .\install.ps1

  Environment overrides:
    WEAVERSSH_REPO          owner/repo                         default jagg-ix/weaverssh
    WEAVERSSH_REF           branch/tag for source build         default main
    WEAVERSSH_VERSION       release tag or latest               default latest
    WEAVERSSH_BIN_DIR       install dir                         default %LOCALAPPDATA%\weaverssh\bin
    WEAVERSSH_ARCHIVE       local path or URL to release archive
    WEAVERSSH_CHECKSUM      sha256 value, checksum file path, or checksum URL
    WEAVERSSH_FROM_SOURCE   1 to force source build
    WEAVERSSH_ALLOW_SOURCE  1 to allow source fallback if release is missing
    WEAVERSSH_DRY_RUN       1 to print actions without writing
    WEAVERSSH_INSTALL_LOG   install audit log path
#>
$ErrorActionPreference = 'Stop'

$Repo           = if ($env:WEAVERSSH_REPO) { $env:WEAVERSSH_REPO } else { 'jagg-ix/weaverssh' }
$Ref            = if ($env:WEAVERSSH_REF) { $env:WEAVERSSH_REF } else { 'main' }
$Version        = if ($env:WEAVERSSH_VERSION) { $env:WEAVERSSH_VERSION } else { 'latest' }
$ArchiveSource  = $env:WEAVERSSH_ARCHIVE
$ChecksumSource = $env:WEAVERSSH_CHECKSUM
$FromSource     = $env:WEAVERSSH_FROM_SOURCE -eq '1'
$AllowSource    = $env:WEAVERSSH_ALLOW_SOURCE -eq '1'
$DryRun         = $env:WEAVERSSH_DRY_RUN -eq '1'
$BinDir         = if ($env:WEAVERSSH_BIN_DIR) { $env:WEAVERSSH_BIN_DIR } else { Join-Path $env:LOCALAPPDATA 'weaverssh\bin' }
$HomeRoot       = Join-Path $env:LOCALAPPDATA 'weaverssh'
$LogFile        = if ($env:WEAVERSSH_INSTALL_LOG) { $env:WEAVERSSH_INSTALL_LOG } else { Join-Path $HomeRoot 'logs\install.jsonl' }

function Say($m)  { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "warning: $m" -ForegroundColor Yellow }
function Have($c) { [bool](Get-Command $c -ErrorAction SilentlyContinue) }
function Run($scriptBlock) {
  if ($DryRun) { Write-Host "dry-run: $scriptBlock" } else { & $scriptBlock }
}
function JsonEscape([string]$s) { $s.Replace('\', '\\').Replace('"', '\"') }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'amd64' }
  'ARM64' { 'arm64' }
  'x86'   { '386' }
  default { 'amd64' }
}
Say "Platform: windows/$arch"

$tmp = Join-Path $env:TEMP ("weaverssh-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
if (-not $DryRun) {
  New-Item -ItemType Directory -Force -Path $BinDir, (Split-Path $LogFile -Parent) | Out-Null
}

function Copy-OrDownload([string]$source, [string]$dest) {
  if ($source -match '^https?://') {
    Invoke-WebRequest -Uri $source -OutFile $dest -UseBasicParsing
  } else {
    if (-not (Test-Path $source)) { throw "archive not found: $source" }
    Copy-Item $source $dest -Force
  }
}

function Get-Sha256([string]$path) {
  (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLowerInvariant()
}

function Get-ExpectedChecksum([string]$source, [string]$archivePath) {
  if (-not $source) { return $null }
  if ($source -match '^[A-Fa-f0-9]{64}$') { return $source.ToLowerInvariant() }
  $checksumPath = Join-Path $tmp 'checksum.txt'
  Copy-OrDownload $source $checksumPath
  $base = Split-Path $archivePath -Leaf
  foreach ($line in Get-Content $checksumPath) {
    $parts = $line.Trim() -split '\s+'
    if ($parts.Count -lt 2) { continue }
    if ($parts[1] -eq $base -or $parts[1] -eq "*$base") {
      return $parts[0].ToLowerInvariant()
    }
  }
  throw "could not read checksum for $base from $source"
}

function Verify-Checksum([string]$archivePath) {
  if (-not $ChecksumSource) { return }
  $want = Get-ExpectedChecksum $ChecksumSource $archivePath
  $got = Get-Sha256 $archivePath
  if ($got -ne $want) { throw "checksum mismatch for $(Split-Path $archivePath -Leaf): got $got want $want" }
  Say "Checksum verified: $got"
}

function Expand-InstallerArchive([string]$archivePath, [string]$dest) {
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  if ($archivePath -match '\.zip$') {
    Expand-Archive -Path $archivePath -DestinationPath $dest -Force
    return
  }
  if ($archivePath -match '\.tar\.gz$' -or $archivePath -match '\.tgz$') {
    if (-not (Have tar)) { throw "tar is required to extract $archivePath" }
    tar -xzf $archivePath -C $dest
    return
  }
  throw "unsupported archive type: $archivePath"
}

function Find-WvBinary([string]$root) {
  $match = Get-ChildItem -Path $root -Recurse -File -Filter 'wv.exe' | Select-Object -First 1
  if ($match) { return $match.FullName }
  throw "archive does not contain wv.exe"
}

function Install-Binary([string]$src, [string]$sourceLabel) {
  $dst = Join-Path $BinDir 'wv.exe'
  if ($DryRun) {
    Write-Host "dry-run: Copy-Item $src $dst"
    return
  }
  Copy-Item $src $dst -Force
  Say "Installed to $dst"
  & $dst version 2>$null | Write-Host
  Set-Content -Path (Join-Path $HomeRoot 'env.ps1') -Value "`$env:Path = '$BinDir;' + `$env:Path" -Encoding UTF8
  $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  $line = '{"event":"install","at":"' + (JsonEscape $ts) + '","bindir":"' + (JsonEscape $BinDir) + '","source":"' + (JsonEscape $sourceLabel) + '","os":"windows","arch":"' + $arch + '"}'
  Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Install-FromArchive([string]$source) {
  $archivePath = Join-Path $tmp (Split-Path $source -Leaf)
  Copy-OrDownload $source $archivePath
  Verify-Checksum $archivePath
  $extract = Join-Path $tmp 'extract'
  Expand-InstallerArchive $archivePath $extract
  $wv = Find-WvBinary $extract
  Install-Binary $wv "archive:$source"
  return $true
}

function Resolve-Tag() {
  if ($Version -ne 'latest') { return $Version }
  try {
    $r = Invoke-RestMethod -UseBasicParsing -Headers @{ 'User-Agent' = 'weaverssh-install' } `
      -Uri "https://api.github.com/repos/$Repo/releases/latest"
    if ($r.tag_name) { return $r.tag_name }
  } catch { }
  throw "could not resolve latest version; set WEAVERSSH_VERSION=vX.Y.Z"
}

function Install-FromRelease() {
  if ($FromSource -or $ArchiveSource) { return $false }
  $tag  = Resolve-Tag
  $ver  = $tag.TrimStart('v')
  $base = "https://github.com/$Repo/releases/download/$tag"
  if (-not $ChecksumSource) { $script:ChecksumSource = "$base/checksums.txt" }
  Say "Installing weaverssh $tag"
  try {
    Install-FromArchive "$base/weaverssh_${ver}_windows_${arch}.zip" | Out-Null
    return $true
  } catch {
    Warn $_.Exception.Message
    return $false
  }
}

function Install-FromSource() {
  if (-not ($FromSource -or $AllowSource)) {
    throw "prebuilt archive unavailable. Set WEAVERSSH_ARCHIVE=C:\path\archive or WEAVERSSH_ALLOW_SOURCE=1 to build from source."
  }
  if (-not (Have go)) { throw "Go toolchain required to build from source (https://go.dev/dl/)" }
  Say "Building $Repo@$Ref from source"
  $src = Join-Path $tmp 'src'
  if (Have gh) { gh repo clone $Repo $src -- --depth 1 --branch $Ref 2>$null }
  if (-not (Test-Path $src)) {
    if (-not (Have git)) { throw "git or gh required to fetch source" }
    git clone --depth 1 --branch $Ref "https://github.com/$Repo.git" $src
  }
  Push-Location $src
  try {
    $built = Join-Path $tmp 'wv.exe'
    go build -o $built './cmd/wv'
    Install-Binary $built "source:$Repo@$Ref"
  } finally {
    Pop-Location
  }
}

try {
  if ($ArchiveSource) {
    Say "Installing from archive: $ArchiveSource"
    Install-FromArchive $ArchiveSource | Out-Null
  } elseif (-not (Install-FromRelease)) {
    Warn "no usable prebuilt release for windows/$arch (version=$Version)"
    Install-FromSource
  }
} finally {
  if (-not $DryRun -and (Test-Path $tmp)) { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
}

$userPath = [Environment]::GetEnvironmentVariable('Path','User')
if ($userPath -notlike "*$BinDir*") {
  if (-not $DryRun) { [Environment]::SetEnvironmentVariable('Path', "$userPath;$BinDir", 'User') }
  Warn "Add $BinDir to your user PATH, or restart the shell if the installer updated it."
}
Say "Install log: $LogFile"
Say "Done. Try: wv help"
