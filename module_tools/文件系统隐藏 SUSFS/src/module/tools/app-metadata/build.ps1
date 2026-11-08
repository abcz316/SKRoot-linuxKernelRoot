[CmdletBinding()]
param(
    [string] $AndroidSdk = "$env:LOCALAPPDATA/Android/Sdk",
    [string] $JavaHome = 'C:/Program Files/Java/jdk-17',
    [string] $OutputDirectory = (Join-Path $PSScriptRoot '../../../build/app-metadata')
)
$ErrorActionPreference = 'Stop'
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$platform = Get-ChildItem -LiteralPath (Join-Path $AndroidSdk 'platforms') -Directory |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'android.jar') } |
    Sort-Object { [version](($_.Name -replace '^android-', '') + '.0') } -Descending | Select-Object -First 1
$tools = Get-ChildItem -LiteralPath (Join-Path $AndroidSdk 'build-tools') -Directory |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'd8.bat') } |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $platform -or -not $tools) { throw 'Android SDK platform and d8 are required.' }
$javac = Join-Path $JavaHome 'bin/javac.exe'
if (-not (Test-Path -LiteralPath $javac)) { throw "Missing javac: $javac" }
$classes = Join-Path $OutputDirectory 'classes'
$dex = Join-Path $OutputDirectory 'dex'
New-Item -ItemType Directory -Force -Path $classes,$dex | Out-Null
& $javac -encoding UTF-8 --release 8 -cp (Join-Path $platform.FullName 'android.jar') -d $classes (Join-Path $PSScriptRoot 'PlusAppMetadata.java')
if ($LASTEXITCODE -ne 0) { throw 'Application metadata javac failed.' }
$classFiles = @(Get-ChildItem -LiteralPath $classes -Filter '*.class' -File | ForEach-Object FullName)
$savedJavaHome = $env:JAVA_HOME
try {
    $env:JAVA_HOME = $JavaHome
    & (Join-Path $tools.FullName 'd8.bat') --min-api 21 --lib (Join-Path $platform.FullName 'android.jar') --output $dex $classFiles
    if ($LASTEXITCODE -ne 0) { throw 'Application metadata d8 failed.' }
} finally { $env:JAVA_HOME = $savedJavaHome }
$output = Join-Path $OutputDirectory 'app-metadata.dex'
Copy-Item -LiteralPath (Join-Path $dex 'classes.dex') -Destination $output -Force
Write-Output "DEX=$output"
Write-Output "SHA256=$((Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash)"
