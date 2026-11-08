# SPDX-License-Identifier: GPL-2.0
<#
.SYNOPSIS
Build the offline SUSFS guide using installed Android SDK/JDK tools only.
.DESCRIPTION
Run interactive/build.py first. No Gradle, dependency downloads, device access or
module build is involved. Keep SigningDirectory private and preserve it for
future app updates. Passwords are passed through files, never command arguments.
#>
[CmdletBinding()]
param(
    [string]$SdkRoot = (Join-Path $env:LOCALAPPDATA 'Android/Sdk'),
    [string]$JdkRoot = 'C:/Program Files/Java/jdk-17',
    [string]$BuildToolsVersion = '36.0.0',
    [string]$Platform = 'android-35',
    [string]$OutputDirectory,
    [string]$SigningDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (!$OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot '../../../../build/susfs-guide-interactive-042-20261022' }
if (!$SigningDirectory) { $SigningDirectory = Join-Path $PSScriptRoot '../../../../build/signing/susfs-guide-android' }

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    # Windows PowerShell 5.1 treats successful compiler stderr as ErrorRecord.
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $messages = @(& $Executable @Arguments 2>&1)
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousErrorAction }
    if ($code -ne 0) {
        foreach ($message in $messages) { Write-Warning "$message" }
        throw "Tool failed with exit=$code : $Executable"
    }
    return $messages
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-RelativeName {
    param([string]$Root, [string]$Path)
    return $Path.Substring($Root.TrimEnd('\', '/').Length + 1).Replace('\', '/')
}

$sdkPath = (Resolve-Path -LiteralPath $SdkRoot).Path
$jdkPath = (Resolve-Path -LiteralPath $JdkRoot).Path
$sourcePath = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
$signingPath = [System.IO.Path]::GetFullPath($SigningDirectory)
$exeSuffix = if ($env:OS -eq 'Windows_NT') { '.exe' } else { '' }
$buildTools = Join-Path $sdkPath "build-tools/$BuildToolsVersion"
$androidJar = Join-Path $sdkPath "platforms/$Platform/android.jar"
$java = Join-Path $jdkPath "bin/java$exeSuffix"
$javac = Join-Path $jdkPath "bin/javac$exeSuffix"
$keytool = Join-Path $jdkPath "bin/keytool$exeSuffix"
$aapt2 = Join-Path $buildTools "aapt2$exeSuffix"
$aapt = Join-Path $buildTools "aapt$exeSuffix"
$zipalign = Join-Path $buildTools "zipalign$exeSuffix"
$d8Jar = Join-Path $buildTools 'lib/d8.jar'
$signerJar = Join-Path $buildTools 'lib/apksigner.jar'
$manifest = Join-Path $sourcePath 'AndroidManifest.xml'
$resources = Join-Path $sourcePath 'res'
$javaSources = Join-Path $sourcePath 'src'
$assetRoot = Join-Path $outputPath 'assets'
$guideRoot = Join-Path $assetRoot 'guide'
foreach ($required in @($androidJar, $java, $javac, $keytool, $aapt2, $aapt,
                       $zipalign, $d8Jar, $signerJar, $manifest,
                       (Join-Path $guideRoot 'index.html'))) {
    if (!(Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required local input missing (nothing downloaded): $required"
    }
}
if (!(Test-Path -LiteralPath $resources -PathType Container)) { throw 'Missing Android resources' }
if (!(Test-Path -LiteralPath $javaSources -PathType Container)) { throw 'Missing Android Java sources' }
$inputs = @($manifest) + @(
    Get-ChildItem -LiteralPath $sourcePath -File |
        Where-Object { $_.Extension -in @('.ps1', '.py', '.js') } |
        Sort-Object FullName | ForEach-Object FullName
) + @(
    Get-ChildItem -LiteralPath $resources, $javaSources -File -Recurse |
        Sort-Object FullName | ForEach-Object FullName
)
$sourceHashes = [ordered]@{}
foreach ($inputFile in $inputs) {
    $sourceHashes[(Get-RelativeName $sourcePath $inputFile)] = Get-Sha256 $inputFile
}
$assetHashes = [ordered]@{}
$assetFiles = @(Get-ChildItem -LiteralPath $assetRoot -File -Recurse | Sort-Object FullName)
foreach ($file in $assetFiles) {
    $assetHashes['assets/' + (Get-RelativeName $assetRoot $file.FullName)] = Get-Sha256 $file.FullName
}
$svgCount = @($assetHashes.Keys | Where-Object { $_ -match '^assets/guide/reference/svg/.+\.svg$' }).Count
$screenshotCount = @($assetHashes.Keys | Where-Object { $_ -match '^assets/guide/reference/screenshots/.+\.png$' }).Count
$metadataPath = Join-Path $guideRoot 'app-metadata.json'
if (!(Test-Path -LiteralPath $metadataPath -PathType Leaf)) { throw 'Missing prepared guide metadata' }
$metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($metadata.format -ne 'susfs-guide-interactive-v1' -or
    $metadata.package -ne 'org.susfs4skp.guide' -or $metadata.version -ne '0.4.2' -or
    $metadata.versionCode -ne 5 -or $metadata.manual_version -ne '0.3.0' -or
    $metadata.offline -ne $true -or $metadata.lessons -isnot [int] -or $metadata.lessons -lt 1 -or
    $metadata.svg -isnot [int] -or $metadata.svg -lt 1 -or
    $metadata.screenshots -isnot [int] -or $metadata.screenshots -lt 1) {
    throw 'Invalid prepared guide metadata'
}
if ($svgCount -ne $metadata.svg -or $screenshotCount -ne $metadata.screenshots) {
    throw "Guide assets differ from metadata: SVG=$svgCount, screenshots=$screenshotCount"
}
$webuiSourceRoot = (Resolve-Path -LiteralPath (Join-Path $sourcePath '../../../module/webroot')).Path
$webuiSourceHashes = [ordered]@{}
$webuiPackagedHashes = [ordered]@{}
$sourceProperties = @($metadata.webui_source_sha256.PSObject.Properties)
$packagedProperties = @($metadata.webui_packaged_sha256.PSObject.Properties)
if (!$sourceProperties.Count -or $sourceProperties.Count -ne $packagedProperties.Count) {
    throw 'Missing or inconsistent production WebUI provenance'
}
foreach ($property in $sourceProperties) {
    $name = $property.Name
    if (!$name -or $name.StartsWith('/') -or $name.Contains('\') -or
        @($name.Split('/') | Where-Object { $_ -eq '..' -or $_ -eq '.' -or $_ -eq '' }).Count -or
        $property.Value -notmatch '^[0-9a-f]{64}$') {
        throw 'Unsafe production WebUI source metadata'
    }
    $file = Join-Path $webuiSourceRoot $name
    if (!(Test-Path -LiteralPath $file -PathType Leaf) -or (Get-Sha256 $file) -ne $property.Value) {
        throw "Production WebUI source differs from prepared metadata: $name"
    }
    $packagedProperty = $metadata.webui_packaged_sha256.PSObject.Properties[$name]
    $assetName = 'assets/guide/simulator/' + $name
    if ($null -eq $packagedProperty -or $packagedProperty.Value -notmatch '^[0-9a-f]{64}$' -or
        !$assetHashes.Contains($assetName) -or $assetHashes[$assetName] -ne $packagedProperty.Value) {
        throw "Packaged WebUI source differs from prepared metadata: $name"
    }
    if ($name -ne 'index.html' -and $property.Value -ne $packagedProperty.Value) {
        throw "Production WebUI must remain byte-identical except injected index.html: $name"
    }
    $webuiSourceHashes[$name] = $property.Value
    $webuiPackagedHashes[$name] = $packagedProperty.Value
}
$webuiFiles = @(Get-ChildItem -LiteralPath $webuiSourceRoot -File -Recurse)
$webuiAssets = @($assetHashes.Keys | Where-Object { $_.StartsWith('assets/guide/simulator/') })
if (!$webuiSourceHashes.Contains('index.html') -or $webuiFiles.Count -ne $sourceProperties.Count -or
    $webuiAssets.Count -ne $sourceProperties.Count) {
    throw 'Production WebUI provenance does not cover the complete webroot'
}
foreach ($requiredAsset in @('index.html', 'interactive.css', 'interactive.js', 'lessons.js',
                             'app-perspective.js', 'app-perspective.css',
                             'simulator.js', 'simulator/index.html', 'reference/index.html')) {
    if (!$assetHashes.Contains('assets/guide/' + $requiredAsset)) {
        throw "Missing interactive tutorial asset: $requiredAsset"
    }
}

$null = New-Item -ItemType Directory -Path $outputPath -Force
$intermediate = Join-Path $outputPath ('intermediate/' + [Guid]::NewGuid().ToString('N'))
$classes = Join-Path $intermediate 'classes'
$dex = Join-Path $intermediate 'dex'
$generated = Join-Path $intermediate 'generated'
$null = New-Item -ItemType Directory -Path $classes, $dex, $generated -Force
$compiledResources = Join-Path $intermediate 'resources.zip'
$baseApk = Join-Path $intermediate 'base.apk'
$unsignedApk = Join-Path $intermediate 'unsigned.apk'
$alignedApk = Join-Path $intermediate 'aligned.apk'
$signedApk = Join-Path $outputPath 'susfs-guide-0.4.2.apk'
$null = Invoke-Checked $aapt2 @('compile', '--dir', $resources, '-o', $compiledResources)
$null = Invoke-Checked $aapt2 @(
    'link', '-o', $baseApk, '-I', $androidJar, '--manifest', $manifest,
    '--min-sdk-version', '26', '--target-sdk-version', '35',
    '--version-code', '5', '--version-name', '0.4.2',
    '--java', $generated, $compiledResources
)
$sources = @(Get-ChildItem -LiteralPath $javaSources, $generated -Filter '*.java' -File -Recurse |
    Sort-Object FullName | ForEach-Object FullName)
if (!$sources.Count) { throw 'No Java sources' }
$null = Invoke-Checked $javac (@(
    '--release', '8', '-encoding', 'UTF-8', '-classpath', $androidJar, '-d', $classes
) + $sources)
$classFiles = @(Get-ChildItem -LiteralPath $classes -Filter '*.class' -File -Recurse |
    Sort-Object FullName | ForEach-Object FullName)
if (!$classFiles.Count) { throw 'Java compilation produced no classes' }
$null = Invoke-Checked $java (@(
    '-cp', $d8Jar, 'com.android.tools.r8.D8', '--min-api', '26',
    '--lib', $androidJar, '--output', $dex
) + $classFiles)
$dexFiles = @(Get-ChildItem -LiteralPath $dex -Filter 'classes*.dex' -File | Sort-Object Name)
if (!$dexFiles.Count) { throw 'D8 produced no dex files' }
Copy-Item -LiteralPath $baseApk -Destination $unsignedApk -Force
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::Open($unsignedApk, [System.IO.Compression.ZipArchiveMode]::Update)
try {
    # Windows aapt2 -A emits backslashes in raw ZIP asset paths. Android
    # AssetManager uses exact '/' paths; append canonical entries ourselves.
    foreach ($file in $assetFiles) {
        $name = 'assets/' + (Get-RelativeName $assetRoot $file.FullName)
        if ($name.Contains('\') -or $name.StartsWith('/') -or $name.Contains('../')) {
            throw "Invalid packaged asset path: $name"
        }
        $entry = $archive.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
        $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
        $destination = $entry.Open()
        $source = [System.IO.File]::OpenRead($file.FullName)
        try { $source.CopyTo($destination) }
        finally { $source.Dispose(); $destination.Dispose() }
    }
    foreach ($file in $dexFiles) {
        $entry = $archive.CreateEntry($file.Name, [System.IO.Compression.CompressionLevel]::Optimal)
        $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
        $destination = $entry.Open()
        $source = [System.IO.File]::OpenRead($file.FullName)
        try { $source.CopyTo($destination) }
        finally { $source.Dispose(); $destination.Dispose() }
    }
} finally { $archive.Dispose() }
$inspection = [System.IO.Compression.ZipFile]::OpenRead($unsignedApk)
try {
    foreach ($entry in $inspection.Entries) {
        if ($entry.FullName.Contains('\')) { throw "Noncanonical raw ZIP path: $($entry.FullName)" }
    }
    if ($null -eq $inspection.GetEntry('assets/guide/index.html')) {
        throw 'Android AssetManager cannot resolve the packaged guide homepage'
    }
} finally { $inspection.Dispose() }
$null = Invoke-Checked $zipalign @('-f', '4', $unsignedApk, $alignedApk)

$null = New-Item -ItemType Directory -Path $signingPath -Force
$keystore = Join-Path $signingPath 'susfs-guide-key.p12'
$passwordFile = Join-Path $signingPath 'signing-password.txt'
$hasKey = Test-Path -LiteralPath $keystore -PathType Leaf
$hasPassword = Test-Path -LiteralPath $passwordFile -PathType Leaf
if ($hasKey -ne $hasPassword) { throw 'Incomplete signing material: restore the original key/password pair' }
if (!$hasKey) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [System.IO.File]::WriteAllText($passwordFile, [Convert]::ToBase64String($bytes),
        [System.Text.UTF8Encoding]::new($false))
    $null = Invoke-Checked $keytool @(
        '-genkeypair', '-storetype', 'PKCS12', '-keystore', $keystore,
        '-alias', 'susfs-guide', '-storepass:file', $passwordFile,
        '-keypass:file', $passwordFile, '-keyalg', 'RSA', '-keysize', '3072',
        '-validity', '10000', '-dname', 'CN=SUSFS Offline Guide, O=SUSFS4SKP, C=CN', '-noprompt'
    )
}
$null = Invoke-Checked $java @(
    '-jar', $signerJar, 'sign', '--ks', $keystore, '--ks-key-alias', 'susfs-guide',
    '--ks-pass', "file:$passwordFile",
    '--min-sdk-version', '26', '--v1-signing-enabled', 'true',
    '--v2-signing-enabled', 'true', '--v3-signing-enabled', 'true',
    '--v4-signing-enabled', 'false', '--out', $signedApk, $alignedApk
)
$verification = Invoke-Checked $java @('-jar', $signerJar, 'verify', '--verbose', '--print-certs', $signedApk)
$verificationText = $verification -join [Environment]::NewLine
if ($verificationText -notmatch '(?m)^Verified using v2 scheme .*: true\s*$' -or
    $verificationText -notmatch '(?m)^Verified using v3 scheme .*: true\s*$' -or
    $verificationText -notmatch '(?m)^Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]{64})\s*$') {
    throw 'APK signature v2/v3 or certificate verification failed'
}
$certificateDigest = $Matches[1].ToLowerInvariant()
$null = Invoke-Checked $zipalign @('-c', '4', $signedApk)
$badging = Invoke-Checked $aapt @('dump', 'badging', $signedApk)
$badgingText = $badging -join [Environment]::NewLine
if ($badgingText -notmatch "package: name='org\.susfs4skp\.guide' versionCode='5' versionName='0\.4\.2'" -or
    $badgingText -notmatch "(?m)^sdkVersion:'26'\s*$" -or
    $badgingText -notmatch "(?m)^targetSdkVersion:'35'\s*$" -or
    $badgingText -match '(?m)^(uses-permission|native-code):') {
    throw 'APK identity, SDK, no-permissions or no-native-libraries contract failed'
}
foreach ($inputFile in $inputs) {
    if ((Get-Sha256 $inputFile) -ne $sourceHashes[(Get-RelativeName $sourcePath $inputFile)]) {
        throw 'Android source changed during build; rebuild the app'
    }
}
foreach ($file in $assetFiles) {
    if ((Get-Sha256 $file.FullName) -ne $assetHashes['assets/' + (Get-RelativeName $assetRoot $file.FullName)]) {
        throw 'Prepared guide assets changed during build; rebuild the app'
    }
}
foreach ($name in $webuiSourceHashes.Keys) {
    if ((Get-Sha256 (Join-Path $webuiSourceRoot $name)) -ne $webuiSourceHashes[$name]) {
        throw 'Production WebUI source changed during build; regenerate assets and rebuild the app'
    }
}
$javaVersion = Invoke-Checked $java @('-version')
$aaptVersion = Invoke-Checked $aapt2 @('version')
$d8Version = Invoke-Checked $java @('-cp', $d8Jar, 'com.android.tools.r8.D8', '--version')
$signerVersion = Invoke-Checked $java @('-jar', $signerJar, 'version')
$receipt = [ordered]@{
    format = 'susfs-guide-apk-build-v1'
    apk = [System.IO.Path]::GetFileName($signedApk)
    sha256 = Get-Sha256 $signedApk
    package = 'org.susfs4skp.guide'
    version_name = '0.4.2'
    version_code = 5
    manual_version = '0.3.0'
    min_sdk = 26
    target_sdk = 35
    sdk_platform = $Platform
    build_tools = $BuildToolsVersion
    tools = [ordered]@{
        java = "$($javaVersion[0])"
        aapt2 = "$($aaptVersion[0])"
        d8 = "$($d8Version[0])"
        apksigner = "$($signerVersion[0])"
    }
    certificate_sha256 = $certificateDigest
    signing_schemes = @('v1', 'v2', 'v3')
    permissions = @()
    native_libraries = @()
    source_sha256 = $sourceHashes
    assets_sha256 = $assetHashes
    standalone_svg_count = $svgCount
    screenshot_count = $screenshotCount
    interactive_lesson_count = $metadata.lessons
    webui_source_sha256 = $webuiSourceHashes
    webui_packaged_sha256 = $webuiPackagedHashes
    device_installed = $false
}
$receiptPath = Join-Path $outputPath 'build-receipt.json'
[System.IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 8),
    [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText(($signedApk + '.sha256'),
    "$($receipt.sha256)  $([System.IO.Path]::GetFileName($signedApk))`n",
    [System.Text.UTF8Encoding]::new($false))
[pscustomobject]@{ Apk = $signedApk; Sha256 = $receipt.sha256; Receipt = $receiptPath }
