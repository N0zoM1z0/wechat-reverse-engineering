[CmdletBinding(DefaultParameterSetName = 'Hex')]
param(
    [Parameter(Mandatory = $true)]
    [int]$ProcessId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Hex')]
    [ValidatePattern('^(?:[0-9A-Fa-f]{2})+$')]
    [string]$HexPattern,

    [Parameter(Mandatory = $true, ParameterSetName = 'Text')]
    [string]$TextPattern,

    [Parameter(ParameterSetName = 'Text')]
    [ValidateSet('ASCII', 'UTF8', 'Unicode')]
    [string]$TextEncoding = 'UTF8',

    [string]$Module,
    [int]$ContextBytes = 64,
    [int]$MaxMatches = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('NativeMemoryScanner' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class NativeMemoryScanner
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
    public static extern IntPtr OpenProcess(
        uint processAccess,
        bool inheritHandle,
        int processId);

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

function Convert-HexToBytes([string]$Value) {
    $result = [byte[]]::new($Value.Length / 2)
    for ($i = 0; $i -lt $result.Length; $i++) {
        $result[$i] = [Convert]::ToByte($Value.Substring($i * 2, 2), 16)
    }
    return $result
}

if ($PSCmdlet.ParameterSetName -eq 'Hex') {
    [byte[]]$pattern = Convert-HexToBytes $HexPattern
} else {
    $encoding = switch ($TextEncoding) {
        'ASCII' { [Text.Encoding]::ASCII }
        'Unicode' { [Text.Encoding]::Unicode }
        default { [Text.UTF8Encoding]::new($false) }
    }
    [byte[]]$pattern = $encoding.GetBytes($TextPattern)
}

$process = Get-Process -Id $ProcessId
$scanStart = [long]0x10000
$scanEnd = [long]0x00007FFFFFFFFFFF
if ($Module) {
    $selectedModule = $process.Modules | Where-Object { $_.ModuleName -ieq $Module } | Select-Object -First 1
    if (-not $selectedModule) { throw "Module '$Module' is not loaded in PID $ProcessId" }
    $scanStart = $selectedModule.BaseAddress.ToInt64()
    $scanEnd = $scanStart + $selectedModule.ModuleMemorySize
}

$access = [NativeMemoryScanner]::PROCESS_QUERY_INFORMATION -bor [NativeMemoryScanner]::PROCESS_VM_READ
$handle = [NativeMemoryScanner]::OpenProcess($access, $false, $ProcessId)
if ($handle -eq [IntPtr]::Zero) {
    throw "OpenProcess failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

$results = [System.Collections.Generic.List[object]]::new()
$mbiSize = [Runtime.InteropServices.Marshal]::SizeOf([type][NativeMemoryScanner+MEMORY_BASIC_INFORMATION])
$chunkSize = 1024 * 1024
$address = $scanStart

try {
    while ($address -lt $scanEnd -and $results.Count -lt $MaxMatches) {
        $mbi = [NativeMemoryScanner+MEMORY_BASIC_INFORMATION]::new()
        $queried = [NativeMemoryScanner]::VirtualQueryEx(
            $handle,
            [IntPtr]$address,
            [ref]$mbi,
            [UIntPtr]::new([uint64]$mbiSize))
        if ($queried -eq [UIntPtr]::Zero) { break }

        $regionStart = $mbi.BaseAddress.ToInt64()
        $regionSize = [long]$mbi.RegionSize.ToUInt64()
        $regionEnd = $regionStart + $regionSize
        $readable = ($mbi.State -eq [NativeMemoryScanner]::MEM_COMMIT) -and
            (($mbi.Protect -band [NativeMemoryScanner]::PAGE_GUARD) -eq 0) -and
            (($mbi.Protect -band [NativeMemoryScanner]::PAGE_NOACCESS) -eq 0)

        if ($readable -and $regionEnd -gt $scanStart -and $regionStart -lt $scanEnd) {
            $cursor = [Math]::Max($regionStart, $scanStart)
            $effectiveEnd = [Math]::Min($regionEnd, $scanEnd)
            $overlap = [Math]::Max(0, $pattern.Length - 1)
            while ($cursor -lt $effectiveEnd -and $results.Count -lt $MaxMatches) {
                $requested = [int][Math]::Min($chunkSize, $effectiveEnd - $cursor)
                $buffer = [byte[]]::new($requested)
                $bytesRead = [UIntPtr]::Zero
                if ([NativeMemoryScanner]::ReadProcessMemory(
                    $handle,
                    [IntPtr]$cursor,
                    $buffer,
                    [UIntPtr]::new([uint64]$requested),
                    [ref]$bytesRead)) {
                    $actual = [int]$bytesRead.ToUInt64()
                    foreach ($offset in [NativeMemoryScanner]::FindPattern($buffer, $actual, $pattern)) {
                        $matchAddress = $cursor + $offset
                        $contextStart = [Math]::Max(0, $offset - $ContextBytes)
                        $contextLength = [Math]::Min(
                            $actual - $contextStart,
                            $pattern.Length + ($ContextBytes * 2))
                        $context = [byte[]]::new($contextLength)
                        [Array]::Copy($buffer, $contextStart, $context, 0, $contextLength)
                        $ascii = -join ($context | ForEach-Object {
                            if ($_ -ge 0x20 -and $_ -le 0x7e) { [char]$_ } else { '.' }
                        })
                        $results.Add([PSCustomObject]@{
                            address = ('0x{0:X}' -f $matchAddress)
                            region_base = ('0x{0:X}' -f $regionStart)
                            region_size = $regionSize
                            protection = ('0x{0:X}' -f $mbi.Protect)
                            context_address = ('0x{0:X}' -f ($cursor + $contextStart))
                            context_hex = ([BitConverter]::ToString($context) -replace '-', '')
                            context_ascii = $ascii
                        })
                        if ($results.Count -ge $MaxMatches) { break }
                    }
                }
                $advance = [Math]::Max(1, $requested - $overlap)
                $cursor += $advance
            }
        }

        if ($regionEnd -le $address) { break }
        $address = $regionEnd
    }
} finally {
    [void][NativeMemoryScanner]::CloseHandle($handle)
}

$results | ConvertTo-Json -Depth 4
