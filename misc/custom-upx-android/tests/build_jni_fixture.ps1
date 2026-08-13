param(
    [Parameter(Mandatory = $true)]
    [string]$Ndk,

    [Parameter(Mandatory = $true)]
    [string]$Output
)

$ErrorActionPreference = 'Stop'
$clang = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android21-clang.cmd'
if (-not (Test-Path -LiteralPath $clang)) {
    throw "AArch64 Android clang was not found: $clang"
}

$source = Join-Path $PSScriptRoot 'jni_fixture.c'
$payload = Join-Path $PSScriptRoot 'jni_fixture_payload.S'
$outputDirectory = Split-Path -Parent $Output
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

& $clang -fPIC -shared -O2 -fuse-ld=lld `
    '-Wl,--hash-style=both' `
    '-Wl,-soname,libjni-fixture.so' `
    '-Wl,-z,relro,-z,now' `
    '-o' $Output $source $payload -ldl
if ($LASTEXITCODE -ne 0) {
    throw "fixture compilation failed with exit code $LASTEXITCODE"
}
