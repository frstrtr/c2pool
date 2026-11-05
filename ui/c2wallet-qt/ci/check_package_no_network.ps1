# ===========================================================================
# check_package_no_network.ps1 - the PowerShell twin of
# check_package_no_network.sh, for the Windows runner (no bash there).
#
# Fails (non-zero exit) if the staged package tree contains a QtNetwork /
# QtWebEngine / QtWebChannel library, a plugins\tls or
# plugins\networkinformation directory, or libcurl / libssl / libcrypto.
# windeployqt adds the TLS and network-information plugins by default; the
# release job passes --skip-plugin-types tls,networkinformation and this scan
# proves it held.
#
# Usage:  powershell -ExecutionPolicy Bypass -File check_package_no_network.ps1 -Package <dir>
# ===========================================================================
param(
    [Parameter(Mandatory = $true)][string]$Package
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Package -PathType Container)) {
    Write-Host "FAIL: package directory not found: $Package"
    exit 2
}
$root = (Resolve-Path -LiteralPath $Package).Path
Write-Host "== c2wallet-qt-signer package scan (no network library or plugin) =="
Write-Host "package: $root"
$items = @(Get-ChildItem -LiteralPath $root -Recurse -Force)
$files = @($items | Where-Object { -not $_.PSIsContainer })
Write-Host "files:   $($files.Count)"
if ($files.Count -eq 0) { Write-Host "FAIL: the package is empty"; exit 2 }

$nameRe = '(?i)(Qt6?Network|Qt6?WebEngine|Qt6?WebChannel|^libcurl|^libssl|^libcrypto)'
$pathRe = '(?i)[\\/]plugins[\\/](tls|networkinformation)([\\/]|$)'
$hits = @($items | Where-Object {
        $rel = $_.FullName.Substring($root.Length)
        ($_.Name -match $nameRe) -or ($rel -match $pathRe)
    } | ForEach-Object { $_.FullName.Substring($root.Length) } | Sort-Object)

if ($hits.Count -gt 0) {
    Write-Host "FAIL: the package ships networking code:"
    $hits | ForEach-Object { Write-Host "   >>> $_" }
    Write-Host "RESULT: PACKAGE SCAN FAILED."
    exit 1
}
Write-Host "RESULT: PASS - no QtNetwork, TLS / network-information plugin, curl or OpenSSL in the package."
exit 0
