param(
    [string]$SrcDir = "src",
    [string]$OutHeader = "parasite_web_assets_bundle.generated.h",
    [string]$TempZip = "parasite_web_assets.bundle.zip",
    [switch]$KeepZip
)

Add-Type -AssemblyName System.IO.Compression.FileSystem

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

function Resolve-ScriptRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    return [System.IO.Path]::GetFullPath((Join-Path $ScriptDir $Path))
}

$SrcDirAbs    = Resolve-ScriptRelativePath $SrcDir
$OutHeaderAbs = Resolve-ScriptRelativePath $OutHeader
$TempZipAbs   = Resolve-ScriptRelativePath $TempZip

if (-not (Test-Path -LiteralPath $SrcDirAbs -PathType Container)) {
    Write-Error "Source directory not found: $SrcDirAbs"
    exit 1
}

try {
    if (Test-Path -LiteralPath $TempZipAbs) {
        Remove-Item -LiteralPath $TempZipAbs -Force
    }

    # 只打包 src 里面的内容，不包含 src 目录本身
    Compress-Archive -Path (Join-Path $SrcDirAbs '*') -DestinationPath $TempZipAbs -Force

    # 读取 zip 二进制
    [byte[]]$bytes = [System.IO.File]::ReadAllBytes($TempZipAbs)
    $rawByteSize = $bytes.Length

    # 补齐到 8 字节
    $pad = $rawByteSize % 8
    if ($pad -gt 0) {
        $pad = 8 - $pad
        $newBytes = New-Object byte[] ($rawByteSize + $pad)
        [Array]::Copy($bytes, $newBytes, $rawByteSize)
        $bytes = $newBytes
    }

    $qwordCount = [int]($bytes.Length / 8)

    $sb = New-Object System.Text.StringBuilder

    for ($i = 0; $i -lt $qwordCount; $i++) {
        $offset = $i * 8
        [UInt64]$val = [System.BitConverter]::ToUInt64($bytes, $offset)

        if ($i -gt 0) {
            [void]$sb.Append(", ")
            if (($i % 3) -eq 0) {
                [void]$sb.Append("`n    ")
            }
        } else {
            [void]$sb.Append("    ")
        }

        [void]$sb.Append(("0x{0:x}" -f $val))
    }

    $content = @"
/*
 * Auto-generated file. Do not edit manually.
 *
 * This header embeds the packaged web assets used by the parasite web server.
 * Source assets are collected from the "src/" directory and bundled into a
 * ZIP payload, then converted into a static C++ data array for direct linking.
 *
 * Notes:
 * - The "src/" directory itself is not stored as a top-level folder in the bundle.
 * - kBundleData contains the raw ZIP file bytes, padded to 8-byte alignment.
 * - kBundleByteSize is the original ZIP payload size before padding.
 *
 * Typical usage:
 * - Read bundle_bytes() / bundle_size()
 * - Decompress the ZIP payload at runtime
 * - Serve the extracted web resources through the embedded web server
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace skroot::parasite_app::web_assets {

inline constexpr char kBundleName[] = "parasite_web_assets";
inline constexpr char kBundleFormat[] = "zip";

inline constexpr std::size_t kBundleByteSize = $rawByteSize;
inline constexpr std::size_t kBundleQwordCount = $qwordCount;

alignas(8) inline constexpr std::uint64_t kBundleData[kBundleQwordCount] = {
$($sb.ToString())
};

inline const std::uint8_t* bundle_bytes() noexcept {
    return reinterpret_cast<const std::uint8_t*>(kBundleData);
}

inline constexpr std::size_t bundle_size() noexcept {
    return kBundleByteSize;
}

} // namespace skroot::parasite_app::web_assets
"@

    [System.IO.File]::WriteAllText(
        $OutHeaderAbs,
        $content,
        [System.Text.Encoding]::ASCII
    )

    if (-not $KeepZip -and (Test-Path -LiteralPath $TempZipAbs)) {
        Remove-Item -LiteralPath $TempZipAbs -Force
    }

    Write-Host "Generated header: $OutHeaderAbs"
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}