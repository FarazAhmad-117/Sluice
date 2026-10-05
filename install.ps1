# Installs the Sluice CLI on Windows.
#
#   irm https://raw.githubusercontent.com/FarazAhmad-117/Sluice/HEAD/install.ps1 | iex
#
# Downloads the standalone sluice.exe from the project's GitHub releases,
# checks it against the release's SHA256SUMS, puts it in
# %USERPROFILE%\.sluice\bin and adds that folder to your user PATH.
#
# Settings, all optional:
#   $env:SLUICE_VERSION   a release such as 0.1.0 (default: the latest)
#   $env:SLUICE_INSTALL   where to install (default: %USERPROFILE%\.sluice)
#   $env:SLUICE_DOWNLOAD_BASE  a mirror of the release files (https:// or file://)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = 'FarazAhmad-117/Sluice'
$InstallDir = if ($env:SLUICE_INSTALL) { $env:SLUICE_INSTALL } else { Join-Path $env:USERPROFILE '.sluice' }
$BinDir = Join-Path $InstallDir 'bin'
$Archive = 'sluice-windows-x64.zip'

function Say($Message) { Write-Host "sluice-install: $Message" }

if ($env:SLUICE_DOWNLOAD_BASE) {
  if ($env:SLUICE_DOWNLOAD_BASE -notmatch '^(https|file)://') { throw 'SLUICE_DOWNLOAD_BASE must start with https:// or file://' }
  $Base = $env:SLUICE_DOWNLOAD_BASE.TrimEnd('/')
} elseif ($env:SLUICE_VERSION) {
  $Base = "https://github.com/$Repo/releases/download/cli-v$($env:SLUICE_VERSION.TrimStart('v'))"
} else {
  $Base = "https://github.com/$Repo/releases/latest/download"
}

$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sluice-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  # PowerShell 7's Invoke-WebRequest refuses file:// URLs, so a local mirror
  # is copied instead.
  function Fetch($Name) {
    $Out = Join-Path $Tmp $Name
    if ($Base -like 'file://*') { Copy-Item -LiteralPath ([Uri]"$Base/$Name").LocalPath -Destination $Out }
    else { Invoke-WebRequest -UseBasicParsing -Uri "$Base/$Name" -OutFile $Out }
  }
  Say "downloading $Archive"
  Fetch $Archive
  Fetch 'SHA256SUMS'

  $Line = Get-Content (Join-Path $Tmp 'SHA256SUMS') | Where-Object { $_ -match "\s$([regex]::Escape($Archive))$" } | Select-Object -First 1
  if (-not $Line) { throw "SHA256SUMS has no entry for $Archive" }
  $Expected = ($Line -split '\s+')[0].ToLowerInvariant()
  $Actual = (Get-FileHash -Algorithm SHA256 (Join-Path $Tmp $Archive)).Hash.ToLowerInvariant()
  if ($Expected -ne $Actual) { throw "checksum mismatch for $Archive; nothing was installed" }

  Expand-Archive -Path (Join-Path $Tmp $Archive) -DestinationPath $Tmp -Force
  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
  Move-Item -Force (Join-Path $Tmp 'sluice.exe') (Join-Path $BinDir 'sluice.exe')
} finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

$Version = & (Join-Path $BinDir 'sluice.exe') --version
Say "installed $Version to $BinDir\sluice.exe"

$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$Entries = if ($UserPath) { $UserPath -split ';' } else { @() }
if ($Entries -notcontains $BinDir) {
  $NewPath = if ($UserPath) { "$UserPath;$BinDir" } else { $BinDir }
  [Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
  $env:Path = "$env:Path;$BinDir"
  Say "added $BinDir to your user PATH. Open a new terminal to use 'sluice' everywhere."
}
Say "next: create a token for this machine in the Sluice dashboard (Environments, then Connect)."
