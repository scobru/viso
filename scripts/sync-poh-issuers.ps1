# Sync Viso PoH issuer SPKI public keys into both viso-core (common/src/poh.rs)
# and Radica (ui/src/viso.ts) from gatekeeper/issuers.json (or a running /keys endpoint).
[CmdletBinding()]
param(
    [string]$IssuersConfig = "",
    [string]$FromUrl = "",
    [string]$RadicaPath = "",
    [switch]$Build
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

if (-not $IssuersConfig) {
    $IssuersConfig = Join-Path $RepoRoot "gatekeeper\issuers.json"
}
if (-not $RadicaPath) {
    $RadicaPath = Join-Path (Split-Path -Parent $RepoRoot) "radica"
}

function Resolve-SpkiPath([string]$Pkcs8Path, [string]$ConfigDir) {
    $spkiRel = if ($Pkcs8Path -match '\.pkcs8\.der$') {
        $Pkcs8Path -replace '\.pkcs8\.der$', '.spki.der'
    } else {
        "$Pkcs8Path.spki.der"
    }
    if ([System.IO.Path]::IsPathRooted($spkiRel)) {
        return $spkiRel
    }
    $fromRoot = Join-Path $RepoRoot $spkiRel
    if (Test-Path $fromRoot) { return $fromRoot }
    $fromCfg = Join-Path $ConfigDir $spkiRel
    if (Test-Path $fromCfg) { return $fromCfg }
    throw "Could not find SPKI DER file for '$Pkcs8Path' (checked '$fromRoot' and '$fromCfg'). Run keygen first."
}

$entries = @()
if ($FromUrl) {
    $keysUrl = ($FromUrl.TrimEnd("/")) + "/keys"
    Write-Host "Fetching issuers from $keysUrl ..." -ForegroundColor Cyan
    $resp = Invoke-RestMethod -Uri $keysUrl -Method Get
    foreach ($item in @($resp)) {
        $entries += [pscustomobject]@{
            key_id   = [string]$item.key_id
            provider = [string]$item.provider
            tier     = [string]$item.tier
            epoch    = [string]$item.epoch
            spki     = [Convert]::FromBase64String([string]$item.spki_b64)
        }
    }
} else {
    if (-not (Test-Path $IssuersConfig)) {
        throw "Issuers config not found: $IssuersConfig"
    }
    $cfgDir = Split-Path -Parent (Resolve-Path $IssuersConfig)
    $rawJson = Get-Content -Raw -Path $IssuersConfig | ConvertFrom-Json
    foreach ($item in @($rawJson)) {
        $spkiPath = Resolve-SpkiPath -Pkcs8Path ([string]$item.pkcs8_path) -ConfigDir $cfgDir
        $spkiBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $spkiPath))
        $entries += [pscustomobject]@{
            key_id   = [string]$item.key_id
            provider = [string]$item.provider
            tier     = [string]$item.tier
            epoch    = [string]$item.epoch
            spki     = $spkiBytes
        }
    }
}

if ($entries.Count -eq 0) {
    throw "No issuers found to sync."
}

# 1. Update d:\viso\common\src\poh.rs
$pohRsPath = Join-Path $RepoRoot "common\src\poh.rs"
$pohRs = [System.IO.File]::ReadAllText($pohRsPath, $Utf8NoBom)

$rustItems = foreach ($e in $entries) {
    $byteList = ($e.spki | ForEach-Object { $_.ToString() }) -join ", "
@"
    PohIssuer {
        key_id: "$($e.key_id)",
        provider: "$($e.provider)",
        tier: "$($e.tier)",
        epoch: "$($e.epoch)",
        spki_der: &[$byteList],
    },
"@
}
$rustReplacement = "// BEGIN POH_ISSUERS`npub const POH_ISSUERS: &[PohIssuer<'static>] = &[`n$($rustItems -join "`n")`n];`n// END POH_ISSUERS"
$rustPattern = '(?s)// BEGIN POH_ISSUERS\r?\n.*?// END POH_ISSUERS'
if ($pohRs -notmatch $rustPattern) {
    throw "Markers // BEGIN POH_ISSUERS ... // END POH_ISSUERS not found in $pohRsPath"
}
$rustBlock = $rustReplacement.Replace("`n", "`r`n")
$updatedPohRs = [regex]::Replace($pohRs, $rustPattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $rustBlock })
[System.IO.File]::WriteAllText($pohRsPath, $updatedPohRs, $Utf8NoBom)
Write-Host "Updated $($entries.Count) issuer(s) in $pohRsPath" -ForegroundColor Green

# 2. Update d:\radica\ui\src\viso.ts
$radicaVisoPath = Join-Path $RadicaPath "ui\src\viso.ts"
if (Test-Path $radicaVisoPath) {
    $visoTs = [System.IO.File]::ReadAllText($radicaVisoPath, $Utf8NoBom)
    $tsItems = foreach ($e in $entries) {
        $hex = ([System.BitConverter]::ToString($e.spki)).Replace("-", "").ToLowerInvariant()
        "  { keyId: `"$($e.key_id)`", provider: `"$($e.provider)`", tier: `"$($e.tier)`", epoch: `"$($e.epoch)`", spkiDerHex: `"$hex`" },"
    }
    $tsReplacement = "// BEGIN VISO_POH_ISSUERS`nexport const VISO_POH_ISSUERS: readonly PohIssuer[] = [`n$($tsItems -join "`n")`n];`n// END VISO_POH_ISSUERS"
    $tsPattern = '(?s)// BEGIN VISO_POH_ISSUERS\r?\n.*?// END VISO_POH_ISSUERS'
    if ($visoTs -notmatch $tsPattern) {
        throw "Markers // BEGIN VISO_POH_ISSUERS ... // END VISO_POH_ISSUERS not found in $radicaVisoPath"
    }
    $tsBlock = $tsReplacement.Replace("`n", "`r`n")
    $updatedVisoTs = [regex]::Replace($visoTs, $tsPattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $tsBlock })
    [System.IO.File]::WriteAllText($radicaVisoPath, $updatedVisoTs, $Utf8NoBom)
    Write-Host "Updated $($entries.Count) issuer(s) in $radicaVisoPath" -ForegroundColor Green
} else {
    Write-Warning "Radica viso.ts not found at $radicaVisoPath (skipped)."
}

if ($Build) {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    Write-Host "`nRunning cargo check / tests in Viso..." -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        & cargo test -p viso-core --all-features
        if ($LASTEXITCODE -ne 0) { throw "viso-core tests failed" }
        & cargo check -p viso-ui --target wasm32-unknown-unknown
        if ($LASTEXITCODE -ne 0) { throw "viso-ui wasm check failed" }
    } finally {
        Pop-Location
    }

    if (Test-Path (Join-Path $RadicaPath "ui\package.json")) {
        Write-Host "`nRunning npm test & npm run build in Radica UI..." -ForegroundColor Cyan
        Push-Location (Join-Path $RadicaPath "ui")
        try {
            & npm test
            if ($LASTEXITCODE -ne 0) { throw "radica npm test failed" }
            & npm run build
            if ($LASTEXITCODE -ne 0) { throw "radica npm run build failed" }
        } finally {
            Pop-Location
        }
    }
}
