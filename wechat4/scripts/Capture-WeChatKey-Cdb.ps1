[CmdletBinding(DefaultParameterSetName = 'Attach')]
param(
    [Parameter(ParameterSetName = 'Attach')]
    [int]$ProcessId,

    [Parameter(ParameterSetName = 'Launch', Mandatory = $true)]
    [string]$WeChatExe,

    [string]$CdbPath = 'C:\Program Files\Debugging Tools for Windows (x64)\cdb.exe',
    [string]$WeixinDllName = 'Weixin.dll',
    [UInt64]$SetCipherKeyOffset = 0x5D79A0,
    [string]$RuntimeAddress,
    [int]$DumpBytes = 128,
    [string]$OutDir = (Join-Path $env:TEMP 'wechat-key-capture'),
    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-WeixinMainProcess {
    $items = Get-CimInstance Win32_Process -Filter "Name='Weixin.exe'" |
        Where-Object { ($_.CommandLine -notmatch '--type=') -and $_.ExecutablePath }
    $item = $items | Sort-Object ProcessId | Select-Object -First 1
    if (-not $item) {
        throw 'No main Weixin.exe process found.'
    }
    return [int]$item.ProcessId
}

function Get-ModuleBase {
    param([int]$Pid, [string]$ModuleName)
    $proc = [Diagnostics.Process]::GetProcessById($Pid)
    foreach ($module in $proc.Modules) {
        if ($module.ModuleName -ieq $ModuleName) {
            return [UInt64]$module.BaseAddress.ToInt64()
        }
    }
    throw "Module $ModuleName not found in PID $Pid"
}

function Convert-CdbDumpToKeyHex {
    param([string]$Text)
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -notmatch '^[0-9a-fA-F`]+\\s+') { continue }
        $parts = ($line -replace '^[0-9a-fA-F`]+\\s+', '').Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
        foreach ($part in $parts) {
            if ($part -match '^[0-9A-Fa-f]{2}$') {
                $bytes.Add([Convert]::ToByte($part, 16))
            }
        }
    }
    if ($bytes.Count -eq 0) { return $null }
    $raw = $bytes.ToArray()
    $ascii = [Text.Encoding]::ASCII.GetString($raw)
    $record = [regex]::Match($ascii, "x'([0-9A-Fa-f]{64})(?:[0-9A-Fa-f]{32})?'")
    if ($record.Success) {
        return $record.Groups[1].Value.ToLowerInvariant()
    }
    $hexText = ($ascii -replace '[^0-9A-Fa-f]', '')
    if ($hexText.Length -ge 64) {
        return $hexText.Substring(0, 64).ToLowerInvariant()
    }
    if ($raw.Length -ge 32) {
        return ([BitConverter]::ToString($raw[0..31]) -replace '-', '').ToLowerInvariant()
    }
    return $null
}

if (-not (Test-Path -LiteralPath $CdbPath -PathType Leaf)) {
    throw "cdb.exe not found: $CdbPath"
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Join-Path $OutDir "cdb-$timestamp.log"
$cmdPath = Join-Path $OutDir "cdb-$timestamp.cmd"

if ($PSCmdlet.ParameterSetName -eq 'Attach') {
    if (-not $ProcessId) {
        $ProcessId = Get-WeixinMainProcess
    }
    if ($RuntimeAddress) {
        $target = [Convert]::ToUInt64(($RuntimeAddress -replace '^0x', ''), 16)
    } else {
        $base = Get-ModuleBase -Pid $ProcessId -ModuleName $WeixinDllName
        $target = $base + $SetCipherKeyOffset
    }
    $mode = 'attach'
} else {
    if (-not (Test-Path -LiteralPath $WeChatExe -PathType Leaf)) {
        throw "WeChatExe not found: $WeChatExe"
    }
    $target = 0
    $mode = 'launch'
}

$breakCommand = if ($mode -eq 'attach') {
    ('bp 0x{0:X} ".echo CIPHER_KEY_HIT; .printf \"page=0x%x version=0x%x data=%p ptr=%p len=0x%I64x\\n\", @r8d, @r9d, @rdx, poi(@rdx+8), poi(@rdx+10); db poi(@rdx+8) L{1}; .echo CIPHER_KEY_END; qd"' -f $target, $DumpBytes)
} else {
    # In launch mode the exact ASLR base is unknown until module load. This assumes cdb resolves
    # the Weixin module name to Weixin.dll; attach mode is preferred when possible.
    ('bu Weixin+0x{0:X} ".echo CIPHER_KEY_HIT; .printf \"page=0x%x version=0x%x data=%p ptr=%p len=0x%I64x\\n\", @r8d, @r9d, @rdx, poi(@rdx+8), poi(@rdx+10); db poi(@rdx+8) L{1}; .echo CIPHER_KEY_END; qd"' -f $SetCipherKeyOffset, $DumpBytes)
}

@"
.logopen /u "$logPath"
.echo CIPHER_CAPTURE_READY
$breakCommand
g
"@ | Set-Content -LiteralPath $cmdPath -Encoding ASCII

if ($mode -eq 'attach') {
    & $CdbPath -p $ProcessId -cf $cmdPath | Out-Host
} else {
    & $CdbPath -cf $cmdPath $WeChatExe | Out-Host
}

$logText = Get-Content -LiteralPath $logPath -Raw -ErrorAction SilentlyContinue
$keyHex = Convert-CdbDumpToKeyHex $logText

$fullResult = [PSCustomObject]@{
    ok = [bool]$keyHex
    key_hex = $keyHex
    mode = $mode
    process_id = if ($mode -eq 'attach') { $ProcessId } else { $null }
    target_address = if ($mode -eq 'attach') { ('0x{0:X}' -f $target) } else { $null }
    log_path = $logPath
    command_path = $cmdPath
}

if ($OutFile) {
    $parent = Split-Path -Parent $OutFile
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $fullResult | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutFile -Encoding UTF8
}

[PSCustomObject]@{
    ok = $fullResult.ok
    mode = $fullResult.mode
    process_id = $fullResult.process_id
    target_address = $fullResult.target_address
    key_hex_redacted = if ($keyHex) { "$($keyHex.Substring(0, 8))...$($keyHex.Substring(56, 8))" } else { $null }
    sensitive_out_file = $OutFile
    log_path = $logPath
    command_path = $cmdPath
} | ConvertTo-Json -Depth 4
