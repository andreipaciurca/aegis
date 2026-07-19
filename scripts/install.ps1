param(
  [string]$Version = $env:AEGIS_VERSION,
  [string]$Repo = $(if ($env:AEGIS_REPO) { $env:AEGIS_REPO } else { "andreipaciurca/aegis" }),
  [string]$InstallDir = "",
  [switch]$System,
  [switch]$NoPath
)

$ErrorActionPreference = "Stop"

function Info($Message) {
  Write-Host $Message -ForegroundColor Cyan
}

function Is-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $Version) {
  $Version = "latest"
}

if (-not $InstallDir) {
  if ($System) {
    $InstallDir = Join-Path $env:ProgramFiles "Aegis"
  } else {
    $InstallDir = Join-Path $env:LOCALAPPDATA "Aegis"
  }
}

if ($System -and -not (Is-Admin)) {
  throw "System install needs an elevated PowerShell. Re-run as Administrator, or omit -System for a user install."
}

$arch = $env:PROCESSOR_ARCHITECTURE
switch -Regex ($arch) {
  "AMD64|x64" { $releaseArch = "amd64"; break }
  default { throw "Unsupported Windows architecture: $arch. Current releases publish windows-amd64." }
}

if ($Version -eq "latest") {
  $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "aegis-installer" }
  $Version = $latest.tag_name
}

$plainVersion = $Version.TrimStart("v")
$zipName = "aegis-$plainVersion-windows-$releaseArch.zip"
$baseUrl = "https://github.com/$Repo/releases/download/$Version"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("aegis-install-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
  Info "Installing aegis $Version for windows/$releaseArch"
  $zipPath = Join-Path $tmp $zipName
  $sumsPath = Join-Path $tmp "SHA256SUMS"
  Invoke-WebRequest -Uri "$baseUrl/$zipName" -OutFile $zipPath
  Invoke-WebRequest -Uri "$baseUrl/SHA256SUMS" -OutFile $sumsPath

  $escapedZipName = [regex]::Escape($zipName)
  $expectedLine = Get-Content $sumsPath | Where-Object { $_ -match $escapedZipName } | Select-Object -First 1
  if (-not $expectedLine) {
    throw "SHA256SUMS does not contain $zipName"
  }
  $expected = ($expectedLine -split "\s+")[0].ToLowerInvariant()
  $actual = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLowerInvariant()
  if ($actual -ne $expected) {
    throw "Checksum mismatch for $zipName"
  }

  Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
  $src = Join-Path $tmp "aegis-$plainVersion-windows-$releaseArch\aegis.exe"
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  Copy-Item $src (Join-Path $InstallDir "aegis.exe") -Force

  if (-not $NoPath) {
    if ($System) {
      $target = "Machine"
    } else {
      $target = "User"
    }
    $pathValue = [Environment]::GetEnvironmentVariable("Path", $target)
    $parts = $pathValue -split ";" | Where-Object { $_ }
    if ($parts -notcontains $InstallDir) {
      [Environment]::SetEnvironmentVariable("Path", (($parts + $InstallDir) -join ";"), $target)
      Info "Added $InstallDir to the $target PATH. Open a new terminal to use aegis."
    }
  }

  Info "aegis installed to $(Join-Path $InstallDir 'aegis.exe')"
  & (Join-Path $InstallDir "aegis.exe") version
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
