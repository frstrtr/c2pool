# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Windows counterpart of dash_bls_linked_guard.sh: POSITIVE assertion that a
# c2pool-dash.exe really uses the dashbls (BLS12-381) backend.
#
# On Windows the backend is not inside the .exe. dashbls is built with mingw-w64
# exactly as dashd builds it and linked into c2pool_dashbls.dll, which the MSVC
# exe reaches through a C ABI (src/impl/dash/coin/vendor/dashbls_abi). A stub
# build includes none of that and imports nothing from the DLL. So the proof
# has three legs, all required, all on the ARTEFACTS:
#
#   1. imports: the exe's import table names c2pool_dashbls.dll and the verify
#      entry points bls_verify.cpp reaches (import names are NUL-terminated
#      ASCII in the PE, so this survives any stripping);
#   2. rodata: the DLL carries the BLS12-381 ciphersuite ID dashbls'
#      BasicSchemeMPL signs under, the same marker the Linux guard uses;
#   3. load: the DLL loads in this process and reports what it was built from
#      (c2dbls_build_info): the pinned dash tag and the GMP backend.
#
#   usage: dash_bls_linked_guard.ps1 -Exe <c2pool-dash.exe> [-Dll <c2pool_dashbls.dll>] [-Pin <dash tag>]
#          (-Dll defaults to the DLL next to the exe, which is where it must ship)
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [string]$Dll = '',
    [string]$Pin = ''
)
$ErrorActionPreference = 'Stop'

if (-not $Dll) { $Dll = Join-Path (Split-Path -Parent $Exe) 'c2pool_dashbls.dll' }
Write-Host "dash_bls_linked_guard: target = $Exe"
Write-Host "dash_bls_linked_guard: backend = $Dll"

$fail = $false
foreach ($f in @($Exe, $Dll)) {
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) {
        Write-Host "  FAIL missing $f"
        $fail = $true
    }
}
if ($fail) {
    Write-Host "::error::c2pool-dash BLS backend files are missing -- the package would be BLS-dark or would not start"
    exit 1
}

# Byte-exact text view of a binary (ISO-8859-1 maps every byte to one char).
function Read-Bytes([string]$path) {
    [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $path).Path))
}
$nul = [char]0
$exeText = Read-Bytes $Exe
$dllText = Read-Bytes $Dll

# Leg 1: imports.
if ($exeText.Contains("c2pool_dashbls.dll$nul")) {
    Write-Host "  ok   exe imports c2pool_dashbls.dll"
} else {
    Write-Host "  FAIL exe does not import c2pool_dashbls.dll -- dash_bls_verify compiled the stub"
    $fail = $true
}
foreach ($fn in @('c2dbls_basic_verify_secure', 'c2dbls_basic_verify', 'c2dbls_g1_from_bytes', 'c2dbls_g2_from_bytes')) {
    if ($exeText.Contains("$fn$nul")) {
        Write-Host "  ok   exe imports $fn"
    } else {
        Write-Host "  FAIL exe does not import $fn"
        $fail = $true
    }
}

# Leg 2: rodata.
if ($dllText -match 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_(NUL|AUG|POP)_') {
    Write-Host "  ok   dashbls BLS12-381 ciphersuite ID present in the DLL"
} else {
    Write-Host "  FAIL no BLS12-381 ciphersuite ID in $Dll"
    $fail = $true
}

# Leg 3: load.
try {
    $full = (Resolve-Path -LiteralPath $Dll).Path
    $type = 'C2DblsGuardProbe' + [Guid]::NewGuid().ToString('N')
    Add-Type -TypeDefinition ('using System; using System.Runtime.InteropServices; public static class ' + $type +
        ' { [DllImport(@"' + $full + '", CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr c2dbls_build_info(); }')
    $info = [Runtime.InteropServices.Marshal]::PtrToStringAnsi(([type]$type)::c2dbls_build_info())
    $want = if ($Pin) { "dashbls $Pin ARITH=GMP *" } else { 'dashbls * ARITH=GMP *' }
    if ($info -like $want) {
        Write-Host "  ok   DLL loads: $info"
    } else {
        Write-Host "  FAIL DLL reports '$info' (expected '$want')"
        $fail = $true
    }
} catch {
    Write-Host "  FAIL could not load $Dll : $($_.Exception.Message)"
    $fail = $true
}

if ($fail) {
    Write-Host "::error::$Exe does NOT carry a working dashbls backend. Build c2pool_dashbls.dll with scripts/build_dashbls_win64.sh, configure with -DC2POOL_DASH_BLS=ON -DDASHBLS_ROOT=<prefix>, and ship the DLL next to the exe."
    exit 1
}
Write-Host "dash_bls_linked_guard: PASS -- real BLS verification is linked in (via c2pool_dashbls.dll)"
