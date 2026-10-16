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
    "-Isrc\core", "-Isrc\core\cJSON", "-Isrc\kernels", "-I$KitInc",
    "-DTARGET_CONFIG_H=<$TargetConfig>",
    "-fPIE", "-pie", "-pthread"
)

$cSources = @(
    "src\core\main.c", "src\core\cpu.c", "src\core\util.c",
    "src\core\fops.c", "src\core\target.c", "src\core\cJSON\cJSON.c"
)
& $CC @CommonArgs -c $cSources
if ($LASTEXITCODE -ne 0) { Write-Error "C compile failed!"; exit 1 }

& $CXX @CommonArgs -c src\core\oneplus_bypass_bridge.cpp -o oneplus_bypass_bridge.o
if ($LASTEXITCODE -ne 0) { Write-Error "bridge compile failed!"; exit 1 }

$objs = @(
    "main.o", "cpu.o", "util.o", "fops.o", "target.o",
    "cJSON.o", "oneplus_bypass_bridge.o"
)
& $CXX @CommonArgs $objs $KitLib -static-libstdc++ -lz -ldl -o ghostlock_v1
if ($LASTEXITCODE -ne 0) { Write-Error "Link failed!"; exit 1 }

Remove-Item -ErrorAction SilentlyContinue $objs

Write-Host "[OK] ghostlock_v1"
