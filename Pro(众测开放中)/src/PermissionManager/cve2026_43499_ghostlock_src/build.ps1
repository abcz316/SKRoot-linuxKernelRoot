param(
    [string] $Api = "34",
    [string] $TargetConfig = "target.h"
)

$ErrorActionPreference = "Stop"

$NDK = "D:\android-ndk-r26c"
$CC  = "$NDK\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
$TGT = "aarch64-linux-android${Api}"

if (-not (Test-Path $CC)) { Write-Error "Compiler not found: $CC"; exit 1 }

$cmd = "$CC --target=$TGT -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -Isrc/core -Isrc/core/cJSON -Isrc/kernels -DTARGET_CONFIG_H=^<$TargetConfig^> -fPIE -pie -pthread src/core/main.c src/core/cpu.c src/core/util.c src/core/fops.c src/core/target.c src/core/cJSON/cJSON.c -o ghostlock"

cmd /c $cmd
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed!"; exit 1 }

Write-Host "[OK] ghostlock"
