param(
    [string]$NdkRoot  = "C:\Users\abc\android-ndk-r26d",
    [string]$ApiLevel = "31",                       # matches app/build.gradle.kts minSdk
    [string]$Target   = "aarch64-linux-android",    # project is arm64-v8a only
    [string]$Output   = "cve98260",
    [string]$KitRoot  = "",                         # kernel_module_kit 根目录
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcDir    = Join-Path $scriptDir "src"
$prebuilt  = Join-Path $NdkRoot "toolchains\llvm\prebuilt\windows-x86_64"
$clang     = Join-Path $prebuilt "bin\clang.exe"
$clangxx   = Join-Path $prebuilt "bin\clang++.exe"
$sysroot   = Join-Path $prebuilt "sysroot"
$targetTriple = "${Target}${ApiLevel}"

if (-not (Test-Path $clang)) {
    Write-Error "NDK clang not found: $clang`nSpecify the correct NDK root with -NdkRoot (current: $NdkRoot)"
}
if (-not (Test-Path $clangxx)) {
    Write-Error "NDK clang++ not found: $clangxx`nSpecify the correct NDK root with -NdkRoot (current: $NdkRoot)"
}

# ---- kernel_module_kit（C++ 桥接依赖）----
if (-not $KitRoot) {
    $candidates = @(
        (Join-Path $scriptDir "kernel_module_kit"),
        # PermissionManager\cve2026_98260_ghostkey_src_v1 -> Pro_version\testModule\kernel_module_kit
        (Join-Path $scriptDir "..\..\testModule\kernel_module_kit"),
        (Join-Path $scriptDir "..\..\..\testModule\kernel_module_kit")
    )
    foreach ($cand in $candidates) {
        if (Test-Path (Join-Path $cand "include\module_err_def.h")) {
            $KitRoot = (Resolve-Path $cand).Path
            break
        }
    }
}

$kitInc = $null
$kitLib = $null
if ($KitRoot) {
    $kitInc = Join-Path $KitRoot "include"
    $kitLib = Join-Path $KitRoot "lib\libkernel_module_kit_static.a"
}
if (-not $kitInc -or -not (Test-Path (Join-Path $kitInc "module_err_def.h"))) {
    Write-Error ("module_err_def.h not found.`n" +
        "oneplus_bypass_bridge.cpp 需要 kernel_module_kit 的 include 目录。`n" +
        "用 -KitRoot <kit 根目录> 指定，或把 kit 放到 $scriptDir\kernel_module_kit\。")
}
if (-not (Test-Path $kitLib)) {
    Write-Error "kernel_module_kit static lib not found: $kitLib"
}

$objDir = Join-Path $scriptDir "obj"

if ($Clean) {
    Write-Host "Cleaning obj/$Output and old out\ ..."
    Remove-Item -Recurse -Force $objDir -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force (Join-Path $scriptDir "out") -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $scriptDir $Output) -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Force -Path $objDir | Out-Null

# C sources: everything that is plain C
$sources = @(
    "main.c",
    "uaf_plant.c",
    "timer_probe.c",
    "kernel_table.c",
    "kernel_offsets.c",
    "patch_json.c",
    "cJSON/cJSON.c",
    "calib_core.c",
    "calib.c",
    "kprobe.c"
)

# C++ sources: SELinux 关掉后的 OnePlus/OPPO 设备绕过桥接
$cxxSources = @(
    "oneplus_bypass_bridge.cpp"
)

# 公共编译选项（C/C++ 共用；标准版本分开指定）
$commonFlags = @(
    "--target=$targetTriple",
    "--sysroot=$sysroot",
    "-O2",
    "-Wall",
    "-Wno-unused-parameter",
    "-Wno-sign-compare",
    "-Wno-unused-function",
    "-fPIE",
    "-pthread",
    "-I$srcDir"
)

$cFlags   = $commonFlags + @("-std=gnu11")
$cxxFlags = $commonFlags + @("-std=gnu++17", "-I$kitInc")

$objects = New-Object System.Collections.Generic.List[string]

foreach ($src in $sources) {
    $srcPath = Join-Path $srcDir $src
    if (-not (Test-Path $srcPath)) {
        Write-Error "Missing source file: $srcPath"
    }
    $objName = ($src -replace '[\\/]', '_') + ".o"
    $objPath = Join-Path $objDir $objName
    $objects.Add($objPath)
    Write-Host "CC  $src"
    & $clang @cFlags -c $srcPath -o $objPath
    if ($LASTEXITCODE -ne 0) { throw "Compile failed: $src" }
}

foreach ($src in $cxxSources) {
    $srcPath = Join-Path $srcDir $src
    if (-not (Test-Path $srcPath)) {
        Write-Error "Missing source file: $srcPath"
    }
    $objName = ($src -replace '[\\/]', '_') + ".o"
    $objPath = Join-Path $objDir $objName
    $objects.Add($objPath)
    Write-Host "CXX $src"
    & $clangxx @cxxFlags -c $srcPath -o $objPath
    if ($LASTEXITCODE -ne 0) { throw "Compile failed: $src" }
}

# 产物直接落在 build.ps1 同级目录
$outputPath = Join-Path $scriptDir $Output
Write-Host "LD  $outputPath"

$ldFlags = @(
    "--target=$targetTriple",
    "--sysroot=$sysroot",
    "-pie",
    "-rdynamic",
    "-pthread",
    # Android 15+ 16KB-page devices require 16KB-aligned ELF LOAD segments
    "-Wl,-z,max-page-size=16384",
    "-Wl,-z,common-page-size=16384"
)

# 必须用 clang++ 链接：C++ 桥接会带进 libc++ 符号。
# -static-libstdc++ 让驱动用 -Bstatic 去链 libc++_static.a + libc++abi.a + libunwind.a，
# 把这些静态版直接并进二进制；产物不依赖 libc++_shared.so
# （部分机型系统里没有这个动态库，动态链接的话一跑就报 dlopen/找不到库）。
& $clangxx @ldFlags $objects.ToArray() $kitLib -static-libstdc++ -lz -ldl -o $outputPath
if ($LASTEXITCODE -ne 0) { throw "Link failed" }

# 自检：DT_NEEDED 里不允许出现 libc++_shared.so，出现就说明静态链接没生效
$readelf = Join-Path $prebuilt "bin\llvm-readelf.exe"
if (Test-Path $readelf) {
    $dyn = & $readelf -d $outputPath
    if ($LASTEXITCODE -ne 0) { throw "llvm-readelf failed on $outputPath" }
    $needed = @($dyn | Select-String -Pattern "NEEDED" | ForEach-Object { $_.Line.Trim() })
    foreach ($line in $needed) { Write-Host "  $line" }
    if ($needed -match "libc\+\+_shared") {
        throw "libc++_shared.so is still a DT_NEEDED entry: static libc++ did not take effect"
    }
} else {
    Write-Host "[warn] llvm-readelf.exe not found, skipped the libc++_shared.so check"
}

Write-Host ""
Write-Host "Build OK: $outputPath"
Write-Host "  Arch: $Target (API $ApiLevel)"
Write-Host "  C++ runtime: static (no libc++_shared.so)"
