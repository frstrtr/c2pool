# ===========================================================================
# check_no_network_pe.ps1 - the network-incapable link-guard for the Windows
# (PE) c2wallet-qt-signer.exe: the sibling of check_no_network.sh (ELF), run
# by the release job on the PACKAGED exe after windeployqt.
#
# It fails (non-zero exit) if the exe:
#   (1) imports from a networking DLL (dumpbin /dependents): Qt6Network,
#       Qt6WebEngine*, Qt6WebChannel, ws2_32, wsock32, mswsock, wininet,
#       winhttp, dnsapi, libcurl*, libssl*, libcrypto*; or
#   (2) imports a network function by name (dumpbin /imports): connect,
#       socket, bind, listen, accept, getaddrinfo, freeaddrinfo, getnameinfo,
#       gethostbyname, gethostbyaddr, sendto, recvfrom, getpeername, and the
#       families WSA*, GetAddrInfo*, InternetOpen*, WinHttp*.
# Names are matched EXACTLY on the unmangled import name, so a C++ import such
# as ?connect@QObject@@... never matches.
#
# Usage:  powershell -ExecutionPolicy Bypass -File check_no_network_pe.ps1 `
#             -Binary <path\to\c2wallet-qt-signer.exe> [-Dumpbin <path\to\dumpbin.exe>]
# Without -Dumpbin it uses dumpbin.exe from PATH, else finds it with vswhere.
#
# Honest limit, as for the ELF guard: this inspects the exe's OWN imports.
# On Windows Qt6Core.dll itself imports ws2_32.dll (for gethostname); that is
# out of scope at this layer. check_package_no_network.ps1 proves the package
# ships no Qt6Network.dll and no TLS / network-information plugin.
# ===========================================================================
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [string]$Dumpbin = ""
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    Write-Host "FAIL: binary not found: $Binary"
    exit 2
}

if (-not $Dumpbin) {
    $cmd = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($cmd) { $Dumpbin = $cmd.Source }
}
if (-not $Dumpbin) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vs) {
            $cand = Get-ChildItem -Path (Join-Path $vs 'VC\Tools\MSVC') -Recurse -Filter dumpbin.exe -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\Hostx64\\x64\\' } | Select-Object -First 1
            if ($cand) { $Dumpbin = $cand.FullName }
        }
    }
}
if (-not $Dumpbin) {
    Write-Host "FAIL: dumpbin.exe not found (PATH or vswhere)"
    exit 2
}

Write-Host "== c2wallet-qt-signer network-incapable link-guard (PE) =="
Write-Host "target:  $Binary"
Write-Host "dumpbin: $Dumpbin"
$fail = $false

# -- (1) imported DLLs -------------------------------------------------------
$depOut = & $Dumpbin /nologo /dependents $Binary
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: dumpbin /dependents exited $LASTEXITCODE"; exit 2 }
$dlls = @($depOut | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[^\s]+\.dll$' } | Sort-Object -Unique)
Write-Host "-- imported DLLs --"
$dlls | ForEach-Object { Write-Host "   $_" }
if ($dlls.Count -eq 0) { Write-Host "FAIL: no imported DLL read (not a PE image?)"; exit 2 }
$forbiddenDll = '^(Qt6Network|Qt6WebEngine\w*|Qt6WebChannel|ws2_32|wsock32|mswsock|wininet|winhttp|dnsapi|libcurl[\w\-\.]*|libssl[\w\-\.]*|libcrypto[\w\-\.]*)\.dll$'
$badDlls = @($dlls | Where-Object { $_ -match $forbiddenDll })
if ($badDlls.Count -gt 0) {
    Write-Host "FAIL: the exe imports a networking DLL:"
    $badDlls | ForEach-Object { Write-Host "   >>> $_" }
    $fail = $true
} else {
    Write-Host "OK: no networking DLL imported."
}

# -- (2) imported functions --------------------------------------------------
# dumpbin /imports lists each function as "<hint> <name>" (hex hint) under its
# DLL; ordinal-only imports carry no name (the DLL check above covers them).
$impOut = & $Dumpbin /nologo /imports $Binary
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: dumpbin /imports exited $LASTEXITCODE"; exit 2 }
$names = @($impOut | ForEach-Object {
        if ($_ -match '^\s+[0-9A-Fa-f]+\s+(\S+)\s*$') { $Matches[1] }
    } | Sort-Object -Unique)
Write-Host "-- $($names.Count) imported function names --"
$exact = @('connect', 'socket', 'bind', 'listen', 'accept', 'getaddrinfo', 'freeaddrinfo', 'getnameinfo',
    'gethostbyname', 'gethostbyaddr', 'sendto', 'recvfrom', 'getpeername')
$prefix = '^(WSA|GetAddrInfo|FreeAddrInfo|GetNameInfo|InternetOpen|InternetConnect|WinHttp)'
$badNames = @($names | Where-Object { ($exact -ccontains $_) -or ($_ -cmatch $prefix) })
if ($badNames.Count -gt 0) {
    Write-Host "FAIL: the exe imports network function(s):"
    $badNames | ForEach-Object { Write-Host "   >>> $_" }
    $fail = $true
} else {
    Write-Host "OK: no network function imported."
}

if ($fail) {
    Write-Host "RESULT: NETWORK-INCAPABLE GUARD FAILED - this exe can touch the network."
    exit 1
}
Write-Host "RESULT: PASS - c2wallet-qt-signer.exe is network-incapable (no net DLLs, no net imports)."
exit 0
