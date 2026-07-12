# reaper installer (Windows) — latest GitHub release, on your PATH.
#   irm https://raw.githubusercontent.com/benelser/reaper/main/install.ps1 | iex
#
# Env overrides: REAPER_INSTALL_DIR, REAPER_ARTIFACT (local .zip — used by
# CI to validate this script without a network release).
$ErrorActionPreference = "Stop"

$repo = "benelser/reaper"
$target = "x86_64-pc-windows-msvc"
$installDir = if ($env:REAPER_INSTALL_DIR) { $env:REAPER_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "reaper\bin" }

$tmp = Join-Path $env:TEMP "reaper-install-$PID"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp "reaper.zip"
    if ($env:REAPER_ARTIFACT) {
        Copy-Item $env:REAPER_ARTIFACT $zip
    } else {
        Write-Host "downloading reaper ($target)..."
        Invoke-WebRequest -Uri "https://github.com/$repo/releases/latest/download/reaper-$target.zip" -OutFile $zip
    }
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Copy-Item (Join-Path $tmp "reaper.exe") (Join-Path $installDir "reaper.exe") -Force
} finally {
    Remove-Item -Recurse -Force $tmp
}

$exe = Join-Path $installDir "reaper.exe"
Write-Host "installed: $(& $exe --version) -> $exe"

# Put it on the user PATH, persistently.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($userPath -split ";" | Where-Object { $_ -eq $installDir })) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
    $env:Path = "$env:Path;$installDir"
    Write-Host "PATH: added $installDir (new terminals will see it)"
}

Write-Host ""
Write-Host "  reaper              # TUI on the current directory - nothing is deleted until you confirm"
Write-Host "  reaper scan $HOME   # classify your home dir, zero mutation"
Write-Host "  reaper update       # stay current - updates itself in place"
