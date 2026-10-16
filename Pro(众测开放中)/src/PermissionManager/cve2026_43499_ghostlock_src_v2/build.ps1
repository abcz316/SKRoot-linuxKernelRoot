param(
    [string] $Api = "34",
    [string] $TargetConfig = "target.h"
)

$ErrorActionPreference = "Stop"

$NDK = "C:\Users\abc\android-ndk-r26d"
$BIN = "$NDK\toolchains\llvm\prebuilt\windows-x86_64\bin"
$CC  = "$BIN\clang.exe"
$CXX = "$BIN\clang++.exe"
$TGT = "aarch64-linux-android${Api}"

if (-not (Test-Path $CC)) { Write-Error "Compiler not found: $CC"; exit 1 }
if (-not (Test-Path $CXX)) { Write-Error "C++ compiler not found: $CXX"; exit 1 }

$KitRoot = Join-Path $PSScriptRoot "..\..\testModule\kernel_module_kit"
$KitInc  = Join-Path $KitRoot "include"
$KitLib  = Join-Path $KitRoot "lib\libkernel_module_kit_static.a"

if (-not (Test-Path $KitLib)) { Write-Error "Static lib not found: $KitLib"; exit 1 }

Set-Location $PSScriptRoot

$CommonArgs = @(
    "--target=$TGT",
    "-O2", "-Wall",
    "-Wno-unused-parameter", "-Wno-sign-compare", "-Wno-unused-function",
    "-Isrc", "-Isrc\cJSON", "-Isrc\kernels", "-I$KitInc",
    "-DTARGET_CONFIG_H=<$TargetConfig>",
    "-fPIE", "-pie", "-pthread"
)

$cSources = @(
    "src\main.c", "src\target.c", "src\util.c", "src\slide.c",
    "src\fops.c", "src\pipe.c", "src\root.c", "src\cJSON\cJSON.c"
)
& $CC @CommonArgs -c $cSources
if ($LASTEXITCODE -ne 0) { Write-Error "C compile failed!"; exit 1 }

& $CXX @CommonArgs -c src\oneplus_bypass_bridge.cpp -o oneplus_bypass_bridge.o
if ($LASTEXITCODE -ne 0) { Write-Error "bridge compile failed!"; exit 1 }

$objs = @(
    "main.o", "target.o", "util.o", "slide.o", "fops.o",
    "pipe.o", "root.o", "cJSON.o", "oneplus_bypass_bridge.o"
)
& $CXX @CommonArgs $objs $KitLib -static-libstdc++ -lz -ldl -o cve2026_43499_ghostlock
if ($LASTEXITCODE -ne 0) { Write-Error "Link failed!"; exit 1 }

Remove-Item -ErrorAction SilentlyContinue $objs

Write-Host "[OK] cve2026_43499_ghostlock"
