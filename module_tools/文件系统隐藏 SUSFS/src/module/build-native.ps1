#Requires -Version 5.1
[CmdletBinding()]
param(
    [string] $NdkBuild = "$env:LOCALAPPDATA/Android/Sdk/ndk/26.3.11579264/ndk-build.cmd",
    [string] $SdkRoot = '',
    [string] $OutputDirectory = '',
    [string] $PrebuiltLibrary = '',
    [string] $JavaHome = '',
    [string] $AndroidSdk = "$env:LOCALAPPDATA/Android/Sdk"
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$module = [IO.Path]::GetFullPath($PSScriptRoot)
if (-not $SdkRoot) { $SdkRoot = Join-Path $PSScriptRoot '../../dependencies/SKRoot-linuxKernelRoot/Pro(众测开放中)/src/testModule/kernel_module_kit' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot '../../build/susfs-standalone' }
$SdkRoot = [IO.Path]::GetFullPath($SdkRoot)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$identity = Get-Content -LiteralPath (Join-Path $module 'identity.h') -Raw
$id = [regex]::Match($identity, 'SUSFS_STANDALONE_MODULE_ID\s+"([0-9A-Za-z]{32})"').Groups[1].Value
$version = [regex]::Match($identity, 'SUSFS_STANDALONE_VERSION\s+"([0-9A-Za-z][0-9A-Za-z.+_-]{0,63})"').Groups[1].Value
if ($id -ne 'fa362333cf458e832cd032fda9a9f3c6') { throw 'Standalone module ID changed; use the fixed assigned ID.' }
if (-not $version) { throw 'Standalone module version missing.' }
foreach ($required in @($SdkRoot, (Join-Path $SdkRoot 'include/kernel_module_kit_umbrella.h'), (Join-Path $SdkRoot 'lib/libkernel_module_kit_static.a'))) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Missing SDK dependency: $required" }
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
if (-not $JavaHome) {
    $properties = @(& java -XshowSettings:properties -version 2>&1 | ForEach-Object { "$_" })
    $homeLine = $properties | Where-Object { $_ -match '^\s*java.home\s*=\s*(.+)$' } | Select-Object -First 1
    if ($homeLine -and $homeLine -match '^\s*java.home\s*=\s*(.+)$') { $JavaHome = $Matches[1].Trim() }
}
& (Join-Path $module 'tools/app-metadata/build.ps1') -JavaHome $JavaHome -AndroidSdk $AndroidSdk -OutputDirectory (Join-Path $OutputDirectory 'app-metadata')
if (-not (Test-Path -LiteralPath (Join-Path $OutputDirectory 'app-metadata/app-metadata.dex') -PathType Leaf)) { throw 'Missing application metadata DEX.' }
$library = if ($PrebuiltLibrary) { [IO.Path]::GetFullPath($PrebuiltLibrary) } else { $null }
if ($library) {
    if (-not (Test-Path -LiteralPath $library -PathType Leaf)) { throw "Missing prebuilt library: $library" }
} else {
    $obj = Join-Path $OutputDirectory 'obj'
    $libs = Join-Path $OutputDirectory 'libs'
    $sdkArg = $SdkRoot.Replace('\', '/')
    $lkmArg = $repo.Replace('\', '/')
    & $NdkBuild -C $module "NDK_PROJECT_PATH=$($module.Replace('\','/'))" "APP_BUILD_SCRIPT=$($module.Replace('\','/') + '/Android.mk')" "KERNEL_MODULE_KIT=$sdkArg" "LKM_ROOT=$lkmArg" "NDK_OUT=$($obj.Replace('\','/'))" "NDK_LIBS_OUT=$($libs.Replace('\','/'))" APP_ABI=arm64-v8a APP_PLATFORM=android-26 APP_STL=c++_static -j4
    if ($LASTEXITCODE -ne 0) { throw "NDK build failed: $LASTEXITCODE" }
    $library = Join-Path $libs 'arm64-v8a/libsusfs4skp_standalone.so'
}
$bytes = [IO.File]::ReadAllBytes($library)
if ($bytes.Length -lt 20 -or $bytes[0] -ne 127 -or $bytes[1] -ne 69 -or $bytes[2] -ne 76 -or $bytes[3] -ne 70 -or
    $bytes[4] -ne 2 -or $bytes[5] -ne 1 -or $bytes[18] -ne 183 -or $bytes[19] -ne 0) { throw 'Expected ELF64 little-endian AArch64 library.' }
$destination = Join-Path $OutputDirectory 'libsusfs4skp.so'
Copy-Item -LiteralPath $library -Destination $destination -Force
function Sha256([string] $path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
$sourceRoots = @($module, (Join-Path $repo 'management'), (Join-Path $repo 'kernel'))
$extensions = @('.cpp','.c','.h','.hpp','.mk','.ps1','.py','.js','.css','.html','.java','.a')
$sourceFiles = @()
foreach ($root in $sourceRoots) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
    foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File) {
        if ($extensions -contains $file.Extension.ToLowerInvariant()) {
            $relative = $file.FullName.Substring($repo.Length + 1).Replace('\','/')
            $sourceFiles += [ordered]@{ path=$relative; bytes=$file.Length; sha256=(Sha256 $file.FullName) }
        }
    }
}
$sourceFiles = @($sourceFiles | Sort-Object path)
$manifest = [ordered]@{
    schema_version = 1
    project = 'susfs4skp-standalone'
    module = [ordered]@{ id32=$id; version=$version }
    target = [ordered]@{ abi='arm64-v8a'; android_min_api=26 }
    private_directory = $true
    cross_module_transport = $false
    output = [ordered]@{ path='libsusfs4skp.so'; bytes=(Get-Item $destination).Length; sha256=(Sha256 $destination) }
    metadata_dex = [ordered]@{ path='app-metadata/app-metadata.dex'; bytes=(Get-Item (Join-Path $OutputDirectory 'app-metadata/app-metadata.dex')).Length; sha256=(Sha256 (Join-Path $OutputDirectory 'app-metadata/app-metadata.dex')) }
    source_files = $sourceFiles
}
$manifestPath = Join-Path $OutputDirectory 'build-manifest.json'
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Output "BUILD_DIRECTORY=$OutputDirectory"
Write-Output "MANIFEST=$manifestPath"
Write-Output "LIBRARY_SHA256=$($manifest.output.sha256)"
