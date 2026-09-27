param(
    [Parameter(Mandatory = $true)]
    [string]$InFile,

    [string]$OutFile = "res.h"
)

if (-not (Test-Path -LiteralPath $InFile)) {
    Write-Error "输入文件不存在: $InFile"
    exit 1
}

try {
    # 读取原始二进制
    [byte[]]$bytes = [System.IO.File]::ReadAllBytes($InFile)
    $fileSize = $bytes.Length

    # 补齐到 8 字节
    $pad = $fileSize % 8
    if ($pad -gt 0) {
        $pad = 8 - $pad
    }

    if ($pad -gt 0) {
        $newBytes = New-Object byte[] ($fileSize + $pad)
        [Array]::Copy($bytes, $newBytes, $fileSize)
        $bytes = $newBytes
    }

    $count = $bytes.Length / 8

    # 拼接 data 数组内容
    $sb = New-Object System.Text.StringBuilder

    for ($i = 0; $i -lt $count; $i++) {
        $offset = $i * 8

        # 在 Windows/x64 上相当于按小端读取
        [UInt64]$val = [System.BitConverter]::ToUInt64($bytes, $offset)

        if ($i -gt 0) {
            [void]$sb.Append(", ")
				if (($i % 3) -eq 0) {
					[void]$sb.Append("`n")
				}
        }

        [void]$sb.Append(("0x{0:x}" -f $val))
    }

    # 输出 res.h
    $content = @"
namespace {
static int fileSize = $fileSize;
static uint64_t data[$count] = {
$($sb.ToString())
};
}
"@

    [System.IO.File]::WriteAllText($OutFile, $content, [System.Text.Encoding]::ASCII)
    Write-Host "Output file generated: $OutFile"
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}