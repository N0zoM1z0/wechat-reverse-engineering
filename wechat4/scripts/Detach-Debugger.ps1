[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [int]$ProcessId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('DebugDetachApi' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class DebugDetachApi
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DebugActiveProcessStop(int processId);
}
'@
}

$ok = [DebugDetachApi]::DebugActiveProcessStop($ProcessId)
$err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

[PSCustomObject]@{
    ok = $ok
    win32_error = $err
    process_id = $ProcessId
} | ConvertTo-Json -Compress
