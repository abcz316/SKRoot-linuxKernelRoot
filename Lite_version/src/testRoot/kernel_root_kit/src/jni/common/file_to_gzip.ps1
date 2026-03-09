param(
  [Parameter(Mandatory=$true)][string]$InFile
)

$outFile = Join-Path (Split-Path $InFile) (([IO.Path]::GetFileNameWithoutExtension($InFile)) + ".gz.bin")

$fsIn  = [IO.File]::OpenRead($InFile)
$fsOut = [IO.File]::Create($outFile)

try {
  $gzip = New-Object IO.Compression.GZipStream($fsOut, [IO.Compression.CompressionLevel]::Optimal)
  try {
    $fsIn.CopyTo($gzip)
  } finally {
    $gzip.Dispose()
  }
} finally {
  $fsIn.Dispose()
  $fsOut.Dispose()
}

"Compressed file saved to: $outFile"