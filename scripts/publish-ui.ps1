# Publish Viso UI to Freenet via fdev
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

# Ensure rustup cargo bin is in PATH
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

$KeyName = if ($env:VISO_SITE_KEY) { $env:VISO_SITE_KEY } else { "viso" }
$SiteDir = Join-Path $RepoRoot "target\dx\viso-ui\release\web\public"

Write-Host "Building Viso UI with Dioxus..." -ForegroundColor Cyan
Set-Location (Join-Path $RepoRoot "ui")
& dx build --release --base-path "."
$buildStatus = $LASTEXITCODE
Set-Location $RepoRoot
if ($buildStatus -ne 0) {
    throw "dx build failed with code $buildStatus"
}

# Normalize paths for Freenet web sandbox
Write-Host "Normalizing relative paths for Freenet..." -ForegroundColor Cyan
(Get-Content "$SiteDir\index.html") -replace '/\./assets/', './assets/' | Set-Content "$SiteDir\index.html"
Get-ChildItem "$SiteDir\assets\*.js" | ForEach-Object {
    (Get-Content $_.FullName) -replace '/\./assets/', './assets/' | Set-Content $_.FullName
}

# Check if key exists
$keyList = & fdev website list 2>&1
$keyExists = $false
foreach ($line in ($keyList -split "`n")) {
    $parts = $line.Trim() -split "\s+"
    if ($parts[0] -eq $KeyName) {
        $keyExists = $true
        break
    }
}

if ($keyExists) {
    Write-Host "Updating existing website contract for '$KeyName'..." -ForegroundColor Green
    & fdev website update --key $KeyName $SiteDir
} else {
    Write-Host "Initializing new key '$KeyName'..." -ForegroundColor Green
    & fdev website init $KeyName
    Write-Host "Publishing website contract for '$KeyName'..." -ForegroundColor Green
    & fdev website publish --key $KeyName $SiteDir
}
