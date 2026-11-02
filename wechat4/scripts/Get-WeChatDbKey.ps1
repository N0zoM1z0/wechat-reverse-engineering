[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabasePath,

    [int]$ProcessId,
    [string]$ProcessName = 'Weixin',
    [int]$MaxMatches = 8,
    [int]$ChunkSizeMb = 1,
    [int]$ThrottleMs = 5,
    [int]$MaxScanSeconds = 60,
    [switch]$Diagnostics,
    [switch]$ShowKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('WeChatDbKeyMemoryScanner' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class WeChatDbKeyMemoryScanner
{
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint MEM_COMMIT = 0x1000;
    public const uint PAGE_GUARD = 0x100;
    public const uint PAGE_NOACCESS = 0x01;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadProcessMemory(
        IntPtr process,
        IntPtr baseAddress,
        [Out] byte[] buffer,
        UIntPtr size,
        out UIntPtr bytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern UIntPtr VirtualQueryEx(
        IntPtr process,
        IntPtr address,
        out MEMORY_BASIC_INFORMATION buffer,
        UIntPtr length);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);

    public static int[] FindPattern(byte[] buffer, int length, byte[] pattern)
    {
        var hits = new List<int>();
        int limit = length - pattern.Length;
        for (int i = 0; i <= limit; i++)
        {
            if (buffer[i] != pattern[0]) continue;
            int j = 1;
            for (; j < pattern.Length; j++)
            {
                if (buffer[i + j] != pattern[j]) break;
            }
            if (j == pattern.Length) hits.Add(i);
        }
        return hits.ToArray();
    }
}
'@
}

function Convert-BytesToHexLower {
    param([byte[]]$Bytes)
    return ([BitConverter]::ToString($Bytes) -replace '-', '').ToLowerInvariant()
}

function Convert-StringToSha256Hex {
    param([string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return Convert-BytesToHexLower $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($Value))
    } finally {
        $sha.Dispose()
    }
}

function Get-MainProcess {
    if ($ProcessId) {
        return Get-Process -Id $ProcessId -ErrorAction Stop
    }

    $candidates = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
    if ($candidates.Count -eq 0) {
        throw "No process named '$ProcessName' is running. Start and log in to WeChat, then run this script again."
    }

    foreach ($candidate in $candidates) {
        try {
            if ($candidate.MainModule.FileName -match '\\Weixin\.exe$') {
                return $candidate
            }
        } catch {
            continue
        }
    }

    return $candidates | Sort-Object StartTime -Descending | Select-Object -First 1
}

function Read-DatabaseSalt {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "DatabasePath does not exist: $Path"
    }

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $salt = [byte[]]::new(16)
        $read = $stream.Read($salt, 0, $salt.Length)
        if ($read -ne 16) {
            throw "Database is too small to contain a SQLCipher salt: $Path"
        }
        return $salt
    } finally {
        $stream.Dispose()
    }
}

$databaseFullPath = [IO.Path]::GetFullPath($DatabasePath)
$saltBytes = Read-DatabaseSalt $databaseFullPath
$saltHex = Convert-BytesToHexLower $saltBytes
$saltPatterns = @(
    [Text.Encoding]::ASCII.GetBytes($saltHex),
    [Text.Encoding]::ASCII.GetBytes($saltHex.ToUpperInvariant())
)

$targetProcess = Get-MainProcess
$access = [WeChatDbKeyMemoryScanner]::PROCESS_QUERY_INFORMATION -bor [WeChatDbKeyMemoryScanner]::PROCESS_VM_READ
$handle = [WeChatDbKeyMemoryScanner]::OpenProcess($access, $false, $targetProcess.Id)
if ($handle -eq [IntPtr]::Zero) {
    throw "OpenProcess failed for PID $($targetProcess.Id): $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

$results = [System.Collections.Generic.List[object]]::new()
$seenAddresses = [System.Collections.Generic.HashSet[string]]::new()
$ascii = [Text.Encoding]::ASCII
$recordRegex = [regex]::new("^x'[0-9A-Fa-f]{64}$([regex]::Escape($saltHex))'$", [Text.RegularExpressions.RegexOptions]::IgnoreCase)

$scanStart = [long]0x10000
$scanEnd = [long]0x00007FFFFFFFFFFF
$mbiSize = [Runtime.InteropServices.Marshal]::SizeOf([type][WeChatDbKeyMemoryScanner+MEMORY_BASIC_INFORMATION])
$chunkSize = [Math]::Max(1024 * 1024, $ChunkSizeMb * 1024 * 1024)
$overlap = 256
$address = $scanStart
$stopwatch = [Diagnostics.Stopwatch]::StartNew()
$readChunks = 0
$bytesReadTotal = [int64]0
$saltMarkers = 0
$validCandidates = 0

try {
    while ($address -lt $scanEnd -and $results.Count -lt $MaxMatches -and $stopwatch.Elapsed.TotalSeconds -lt $MaxScanSeconds) {
        $mbi = [WeChatDbKeyMemoryScanner+MEMORY_BASIC_INFORMATION]::new()
        $queried = [WeChatDbKeyMemoryScanner]::VirtualQueryEx(
            $handle,
            [IntPtr]$address,
            [ref]$mbi,
            [UIntPtr]::new([uint64]$mbiSize))
        if ($queried -eq [UIntPtr]::Zero) { break }

        $regionStart = $mbi.BaseAddress.ToInt64()
        $regionSize = [long]$mbi.RegionSize.ToUInt64()
        $regionEnd = $regionStart + $regionSize
        $readable = ($mbi.State -eq [WeChatDbKeyMemoryScanner]::MEM_COMMIT) -and
            (($mbi.Protect -band [WeChatDbKeyMemoryScanner]::PAGE_GUARD) -eq 0) -and
            (($mbi.Protect -band [WeChatDbKeyMemoryScanner]::PAGE_NOACCESS) -eq 0)

        if ($readable) {
            $cursor = $regionStart
            while ($cursor -lt $regionEnd -and $results.Count -lt $MaxMatches -and $stopwatch.Elapsed.TotalSeconds -lt $MaxScanSeconds) {
                $requested = [int][Math]::Min($chunkSize, $regionEnd - $cursor)
                if ($requested -le 0) { break }

                $buffer = [byte[]]::new($requested)
                $bytesRead = [UIntPtr]::Zero
                if ([WeChatDbKeyMemoryScanner]::ReadProcessMemory(
                    $handle,
                    [IntPtr]$cursor,
                    $buffer,
                    [UIntPtr]::new([uint64]$requested),
                    [ref]$bytesRead)) {
                    $actual = [int]$bytesRead.ToUInt64()
                    $readChunks++
                    $bytesReadTotal += $actual
                    foreach ($pattern in $saltPatterns) {
                        foreach ($hit in [WeChatDbKeyMemoryScanner]::FindPattern($buffer, $actual, $pattern)) {
                            $saltMarkers++
                            $candidateStart = $hit - 66
                            $candidateEnd = $candidateStart + 99
                            if ($candidateStart -lt 0 -or $candidateEnd -gt $actual) { continue }

                            $record = $ascii.GetString($buffer, $candidateStart, 99)
                            if (-not $recordRegex.IsMatch($record)) { continue }
                            $validCandidates++

                            $recordAddress = $cursor + $candidateStart
                            $recordAddressText = '0x{0:X}' -f $recordAddress
                            if (-not $seenAddresses.Add($recordAddressText)) { continue }

                            $keyHex = $record.Substring(2, 64).ToLowerInvariant()
                            $entry = [ordered]@{
                                process_id = $targetProcess.Id
                                process_name = $targetProcess.ProcessName
                                database_path = $databaseFullPath
                                database_salt_hex = $saltHex
                                record_address = $recordAddressText
                                region_base = '0x{0:X}' -f $regionStart
                                region_size = $regionSize
                                protection = '0x{0:X}' -f $mbi.Protect
                                key_sha256 = Convert-StringToSha256Hex $keyHex
                            }
                            if ($ShowKey) {
                                $entry.key_hex = $keyHex
                                $entry.sqlcipher_key = "x'$keyHex'"
                            } else {
                                $entry.key_hex_redacted = "$($keyHex.Substring(0, 8))...$($keyHex.Substring(56, 8))"
                            }
                            $results.Add([PSCustomObject]$entry)
                            if ($results.Count -ge $MaxMatches) { break }
                        }
                        if ($results.Count -ge $MaxMatches) { break }
                    }
                }

                if ($cursor + $requested -ge $regionEnd) { break }
                $cursor += [Math]::Max(1, $requested - $overlap)
                if ($ThrottleMs -gt 0) {
                    Start-Sleep -Milliseconds $ThrottleMs
                }
            }
        }

        if ($regionEnd -le $address) { break }
        $address = $regionEnd
    }
} finally {
    [void][WeChatDbKeyMemoryScanner]::CloseHandle($handle)
}

if ($results.Count -eq 0) {
    $diag = [PSCustomObject]@{
        ok = $false
        process_id = $targetProcess.Id
        process_name = $targetProcess.ProcessName
        database_path = $databaseFullPath
        database_salt_hex = $saltHex
        read_chunks = $readChunks
        bytes_read = $bytesReadTotal
        salt_markers = $saltMarkers
        valid_candidates = $validCandidates
        elapsed_ms = [int]$stopwatch.ElapsedMilliseconds
        timed_out = $stopwatch.Elapsed.TotalSeconds -ge $MaxScanSeconds
        throttle_ms = $ThrottleMs
        chunk_size_mb = $ChunkSizeMb
    }
    if ($Diagnostics) {
        $diag | ConvertTo-Json -Depth 4
        exit 2
    }
    throw "No WCDB raw-key record was found for salt $saltHex in PID $($targetProcess.Id). read_chunks=$readChunks bytes_read=$bytesReadTotal salt_markers=$saltMarkers valid_candidates=$validCandidates elapsed_ms=$([int]$stopwatch.ElapsedMilliseconds). Make sure WeChat is running, logged in, and has opened this account's chat database."
}

$results | ConvertTo-Json -Depth 4
