param(
    [string] $Api = "34",
    [string] $TargetConfig = "target.h"
)

$ErrorActionPreference = "Stop"

$NDK = "C:\Users\abc\android-ndk-r26d"
$CC  = "$NDK\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
$TGT = "aarch64-linux-android${Api}"

if (-not (Test-Path $CC)) { Write-Error "Compiler not found: $CC"; exit 1 }

$cmd = "$CC --target=$TGT -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -Isrc -Isrc/cJSON -Isrc/kernels -DTARGET_CONFIG_H=^<$TargetConfig^> -fPIE -pie -pthread src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c src/cJSON/cJSON.c -o cve2026_43499_ghostlock"

cmd /c $cmd
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed!"; exit 1 }

Write-Host "[OK] cve2026_43499_ghostlock"
