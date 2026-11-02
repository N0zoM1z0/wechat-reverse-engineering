# Synthetic Windows self-process fixture: no WeChat process or real key needed.
$ErrorActionPreference = 'Stop'
$directory = Join-Path ([IO.Path]::GetTempPath()) ('wcdb-fixture-' + [Guid]::NewGuid().ToString('N'))
$output = Join-Path $directory 'key-candidates.json'
$allocations = [Collections.Generic.List[IntPtr]]::new()
function Allocate-Bytes([byte[]]$Bytes) {
    $pointer = [Runtime.InteropServices.Marshal]::AllocHGlobal($Bytes.Length)
    [Runtime.InteropServices.Marshal]::Copy($Bytes,0,$pointer,$Bytes.Length)
    $allocations.Add($pointer)
    return $pointer
}
try {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $key = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('synthetic Config.Cipher fixture'))) -replace '-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $literal = [Text.Encoding]::ASCII.GetBytes("x'$key'")
    [byte[]]$mask = @(0xd2,0xc7,0x44,0x24,0x58,0x02,0x00,0x00,0x00,0x48,0x89,0x44,0x24,0x50,0x48,0x8b,0x45,0x00,0x48,0x84,0x4c,0x24,0x48,0x48,0x89,0x44,0x25,0x40,0x48,0x58,0x4c,0x24)
    for ($i=0; $i -lt $literal.Length; $i++) { $literal[$i] = $literal[$i] -bxor $mask[$i % $mask.Length] }
    $blob = Allocate-Bytes $literal
    $nameBytes = [Text.Encoding]::ASCII.GetBytes('com.Tencent.WCDB.Config.Cipher')
    $name = Allocate-Bytes $nameBytes
    $configBytes = [byte[]]::new(0xB0)
    [Array]::Copy([BitConverter]::GetBytes($blob.ToInt64()),0,$configBytes,0x90,8)
    [Array]::Copy([BitConverter]::GetBytes([long]$literal.Length),0,$configBytes,0x98,8)
    $config = Allocate-Bytes $configBytes
    $nodeBytes = [byte[]]::new(0x50)
    [Array]::Copy([BitConverter]::GetBytes($name.ToInt64()),0,$nodeBytes,0x10,8)
    [Array]::Copy([BitConverter]::GetBytes([long]$nameBytes.Length),0,$nodeBytes,0x18,8)
    [Array]::Copy([BitConverter]::GetBytes($config.ToInt64()),0,$nodeBytes,0x28,8)
    $node = Allocate-Bytes $nodeBytes
    $script = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/Get-WeChat4ConfigKeys.ps1'
    $console = (& $script -ProcessId $PID -OutFile $output -TimeoutSeconds 60) | Out-String
    if ($console.Contains($key)) { throw 'Capture leaked the synthetic key to stdout' }
    $payload = [IO.File]::ReadAllText($output) | ConvertFrom-Json
    if (@($payload.candidates | Where-Object { $_.key_hex -eq $key }).Count -eq 0) { throw 'Synthetic key was not recovered' }
    @{test='Config.Cipher self-process capture';passed=$true;summary_only_stdout=$true} | ConvertTo-Json
} finally {
    foreach ($pointer in $allocations) { [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer) }
    if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
}
