[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WeChatExe,
    [UInt64]$SetCipherKeyOffset = 0x5D79A0,
    [int]$TimeoutSeconds = 180,
    [int]$MaxCaptures = 8,
    [int]$PostFirstIdleSeconds = 15,
    [int]$DumpBytes = 128,
    [Parameter(Mandatory = $true)]
    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('WeChatKeyDebugApiCapture' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

public static class WeChatKeyDebugApiCapture
{
    const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
    const uint DBG_CONTINUE = 0x00010002;
    const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
    const uint EXCEPTION_DEBUG_EVENT = 1;
    const uint CREATE_PROCESS_DEBUG_EVENT = 3;
    const uint EXIT_PROCESS_DEBUG_EVENT = 5;
    const uint LOAD_DLL_DEBUG_EVENT = 6;
    const uint EXCEPTION_BREAKPOINT = 0x80000003;
    const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    const uint THREAD_GET_CONTEXT = 0x0008;
    const uint THREAD_SET_CONTEXT = 0x0010;
    const uint CONTEXT_CONTROL_INTEGER = 0x00100003;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_RECORD64
    {
        public uint ExceptionCode;
        public uint ExceptionFlags;
        public IntPtr ExceptionRecord;
        public IntPtr ExceptionAddress;
        public uint NumberParameters;
        public UIntPtr ExceptionInformation0;
        public UIntPtr ExceptionInformation1;
        public UIntPtr ExceptionInformation2;
        public UIntPtr ExceptionInformation3;
        public UIntPtr ExceptionInformation4;
        public UIntPtr ExceptionInformation5;
        public UIntPtr ExceptionInformation6;
        public UIntPtr ExceptionInformation7;
        public UIntPtr ExceptionInformation8;
        public UIntPtr ExceptionInformation9;
        public UIntPtr ExceptionInformation10;
        public UIntPtr ExceptionInformation11;
        public UIntPtr ExceptionInformation12;
        public UIntPtr ExceptionInformation13;
        public UIntPtr ExceptionInformation14;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_DEBUG_INFO
    {
        public EXCEPTION_RECORD64 ExceptionRecord;
        public uint dwFirstChance;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LOAD_DLL_DEBUG_INFO
    {
        public IntPtr hFile;
        public IntPtr lpBaseOfDll;
        public uint dwDebugInfoFileOffset;
        public uint nDebugInfoSize;
        public IntPtr lpImageName;
        public ushort fUnicode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CREATE_PROCESS_DEBUG_INFO
    {
        public IntPtr hFile;
        public IntPtr hProcess;
        public IntPtr hThread;
        public IntPtr lpBaseOfImage;
        public uint dwDebugInfoFileOffset;
        public uint nDebugInfoSize;
        public IntPtr lpThreadLocalBase;
        public IntPtr lpStartAddress;
        public IntPtr lpImageName;
        public ushort fUnicode;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct DEBUG_EVENT_UNION
    {
        [FieldOffset(0)] public EXCEPTION_DEBUG_INFO Exception;
        [FieldOffset(0)] public LOAD_DLL_DEBUG_INFO LoadDll;
        [FieldOffset(0)] public CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DEBUG_EVENT
    {
        public uint dwDebugEventCode;
        public uint dwProcessId;
        public uint dwThreadId;
        public DEBUG_EVENT_UNION u;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct CONTEXT64
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] FltSave;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 416)]
        public byte[] VectorRegister;
        public ulong VectorControl;
        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }

    public class KeyCaptureEvent
    {
        public int HitIndex;
        public int PageSize;
        public int CipherVersion;
        public string DataAddress;
        public string BufferAddress;
        public ulong BufferLength;
        public string BufferHex;
        public string BufferAscii;
        public string KeyHex;
        public int ElapsedMs;
    }

    public class CaptureResult
    {
        public bool Ok;
        public string Error;
        public int ProcessId;
        public string DllBase;
        public string BreakpointAddress;
        public int PageSize;
        public int CipherVersion;
        public string DataAddress;
        public string BufferAddress;
        public ulong BufferLength;
        public string BufferHex;
        public string BufferAscii;
        public string KeyHex;
        public KeyCaptureEvent[] Captures;
        public int LoadDllEvents;
        public int BreakpointEvents;
        public int ElapsedMs;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcess(
        string lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DebugSetProcessKillOnExit(bool KillOnExit);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DebugActiveProcessStop(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandle(IntPtr hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    static string LastError(string what)
    {
        return what + " failed: " + Marshal.GetLastWin32Error();
    }

    static ulong ToUInt64(IntPtr value)
    {
        return unchecked((ulong)value.ToInt64());
    }

    static string HexAddress(ulong value)
    {
        return "0x" + value.ToString("X");
    }

    static string HandlePath(IntPtr hFile)
    {
        if (hFile == IntPtr.Zero || hFile == new IntPtr(-1)) return "";
        var sb = new StringBuilder(1024);
        uint len = GetFinalPathNameByHandle(hFile, sb, (uint)sb.Capacity, 0);
        if (len == 0) return "";
        return sb.ToString();
    }

    static bool ReadBytes(IntPtr hProcess, ulong address, int count, out byte[] bytes)
    {
        bytes = new byte[count];
        UIntPtr read;
        if (!ReadProcessMemory(hProcess, new IntPtr(unchecked((long)address)), bytes, new UIntPtr((uint)count), out read)) return false;
        int actual = (int)read.ToUInt64();
        if (actual == bytes.Length) return true;
        Array.Resize(ref bytes, actual);
        return actual > 0;
    }

    static ulong ReadU64(IntPtr hProcess, ulong address)
    {
        byte[] bytes;
        if (!ReadBytes(hProcess, address, 8, out bytes) || bytes.Length < 8) throw new Exception("ReadU64 failed at " + HexAddress(address));
        return BitConverter.ToUInt64(bytes, 0);
    }

    static string ToHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    static string ToAscii(byte[] bytes)
    {
        var chars = new char[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
            chars[i] = bytes[i] >= 0x20 && bytes[i] <= 0x7e ? (char)bytes[i] : '.';
        return new string(chars);
    }

    static string ExtractKey(byte[] bytes, ulong length)
    {
        int n = (int)Math.Min((ulong)bytes.Length, length);
        if (n <= 0) n = bytes.Length;
        string ascii = Encoding.ASCII.GetString(bytes, 0, n);
        Match record = Regex.Match(ascii, "x'([0-9A-Fa-f]{64})(?:[0-9A-Fa-f]{32})?'");
        if (record.Success) return record.Groups[1].Value.ToLowerInvariant();
        Match hex64 = Regex.Match(ascii, "(?<![0-9A-Fa-f])([0-9A-Fa-f]{64})(?![0-9A-Fa-f])");
        if (hex64.Success) return hex64.Groups[1].Value.ToLowerInvariant();
        if (n >= 32) {
            var key = new byte[32];
            Array.Copy(bytes, 0, key, 0, 32);
            return ToHex(key);
        }
        return null;
    }

    static void RestoreBreakpoint(IntPtr hProcess, ulong address, byte original)
    {
        UIntPtr written;
        byte[] one = new byte[] { original };
        WriteProcessMemory(hProcess, new IntPtr(unchecked((long)address)), one, new UIntPtr(1), out written);
        FlushInstructionCache(hProcess, new IntPtr(unchecked((long)address)), new UIntPtr(1));
    }

    static void InsertBreakpoint(IntPtr hProcess, ulong address)
    {
        UIntPtr written;
        if (!WriteProcessMemory(hProcess, new IntPtr(unchecked((long)address)), new byte[] { 0xCC }, new UIntPtr(1), out written) || written.ToUInt64() != 1)
            throw new Exception(LastError("WriteProcessMemory breakpoint"));
        FlushInstructionCache(hProcess, new IntPtr(unchecked((long)address)), new UIntPtr(1));
    }

    static KeyCaptureEvent CaptureFromContext(IntPtr hProcess, CONTEXT64 ctx, int hitIndex, int dumpBytes, int elapsedMs)
    {
        ulong dataAddress = ctx.Rdx;
        ulong ptr = ReadU64(hProcess, dataAddress + 8);
        ulong len = ReadU64(hProcess, dataAddress + 16);
        int toRead = (int)Math.Min((ulong)Math.Max(1, dumpBytes), len > 0 ? len : (ulong)dumpBytes);
        byte[] buffer;
        if (!ReadBytes(hProcess, ptr, toRead, out buffer)) throw new Exception("failed to read key buffer at " + HexAddress(ptr));

        return new KeyCaptureEvent {
            HitIndex = hitIndex,
            PageSize = (int)ctx.R8,
            CipherVersion = (int)ctx.R9,
            DataAddress = HexAddress(dataAddress),
            BufferAddress = HexAddress(ptr),
            BufferLength = len,
            BufferHex = ToHex(buffer),
            BufferAscii = ToAscii(buffer),
            KeyHex = ExtractKey(buffer, len),
            ElapsedMs = elapsedMs
        };
    }

    public static CaptureResult LaunchAndCapture(string exePath, ulong setCipherKeyOffset, int timeoutSeconds, int maxCaptures, int postFirstIdleSeconds, int dumpBytes)
    {
        var result = new CaptureResult();
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var captures = new List<KeyCaptureEvent>();
        STARTUPINFO si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
        PROCESS_INFORMATION pi;
        string cwd = Path.GetDirectoryName(exePath);
        var cmd = new StringBuilder("\"" + exePath + "\"");

        if (!CreateProcess(exePath, cmd, IntPtr.Zero, IntPtr.Zero, false, DEBUG_ONLY_THIS_PROCESS, IntPtr.Zero, cwd, ref si, out pi))
        {
            result.Error = LastError("CreateProcess");
            return result;
        }

        result.ProcessId = (int)pi.dwProcessId;
        DebugSetProcessKillOnExit(false);

        bool targetSet = false;
        bool breakpointInserted = false;
        bool awaitingSingleStep = false;
        ulong target = 0;
        byte original = 0;
        DateTime deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        DateTime lastCapture = DateTime.MinValue;

        try
        {
            while (DateTime.UtcNow < deadline)
            {
                if (captures.Count > 0 && DateTime.UtcNow.Subtract(lastCapture).TotalSeconds >= postFirstIdleSeconds && !awaitingSingleStep)
                {
                    if (breakpointInserted) {
                        RestoreBreakpoint(pi.hProcess, target, original);
                        breakpointInserted = false;
                    }
                    result.Ok = true;
                    result.Captures = captures.ToArray();
                    KeyCaptureEvent last = captures[captures.Count - 1];
                    result.PageSize = last.PageSize;
                    result.CipherVersion = last.CipherVersion;
                    result.DataAddress = last.DataAddress;
                    result.BufferAddress = last.BufferAddress;
                    result.BufferLength = last.BufferLength;
                    result.BufferHex = last.BufferHex;
                    result.BufferAscii = last.BufferAscii;
                    result.KeyHex = last.KeyHex;
                    result.ElapsedMs = (int)watch.ElapsedMilliseconds;
                    DebugActiveProcessStop(pi.dwProcessId);
                    return result;
                }

                DEBUG_EVENT ev;
                if (!WaitForDebugEvent(out ev, 500))
                {
                    continue;
                }

                uint continueStatus = DBG_CONTINUE;
                try
                {
                    if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
                    {
                        if (ev.u.CreateProcessInfo.hFile != IntPtr.Zero) CloseHandle(ev.u.CreateProcessInfo.hFile);
                    }
                    else if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
                    {
                        result.LoadDllEvents++;
                        string path = HandlePath(ev.u.LoadDll.hFile);
                        if (ev.u.LoadDll.hFile != IntPtr.Zero) CloseHandle(ev.u.LoadDll.hFile);
                        if (!targetSet && path.EndsWith("\\Weixin.dll", StringComparison.OrdinalIgnoreCase))
                        {
                            ulong dllBase = ToUInt64(ev.u.LoadDll.lpBaseOfDll);
                            target = dllBase + setCipherKeyOffset;
                            result.DllBase = HexAddress(dllBase);
                            result.BreakpointAddress = HexAddress(target);

                            byte[] oldByte;
                            if (!ReadBytes(pi.hProcess, target, 1, out oldByte) || oldByte.Length != 1)
                                throw new Exception("failed to read original breakpoint byte at " + HexAddress(target));
                            original = oldByte[0];

                            InsertBreakpoint(pi.hProcess, target);
                            targetSet = true;
                            breakpointInserted = true;
                        }
                    }
                    else if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
                    {
                        uint code = ev.u.Exception.ExceptionRecord.ExceptionCode;
                        ulong address = ToUInt64(ev.u.Exception.ExceptionRecord.ExceptionAddress);
                        bool handledSingleStep = false;
                        if (code == EXCEPTION_BREAKPOINT && targetSet && address == target)
                        {
                            result.BreakpointEvents++;
                            IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, ev.dwThreadId);
                            if (hThread == IntPtr.Zero) throw new Exception(LastError("OpenThread"));
                            try
                            {
                                CONTEXT64 ctx = new CONTEXT64();
                                ctx.ContextFlags = CONTEXT_CONTROL_INTEGER;
                                ctx.FltSave = new byte[512];
                                ctx.VectorRegister = new byte[416];
                                if (!GetThreadContext(hThread, ref ctx)) throw new Exception(LastError("GetThreadContext"));

                                KeyCaptureEvent item = CaptureFromContext(pi.hProcess, ctx, captures.Count + 1, dumpBytes, (int)watch.ElapsedMilliseconds);
                                captures.Add(item);
                                lastCapture = DateTime.UtcNow;

                                RestoreBreakpoint(pi.hProcess, target, original);
                                breakpointInserted = false;
                                ctx.Rip = target;
                                ctx.EFlags |= 0x100;
                                if (!SetThreadContext(hThread, ref ctx)) throw new Exception(LastError("SetThreadContext"));
                                awaitingSingleStep = true;
                            }
                            finally
                            {
                                CloseHandle(hThread);
                            }
                        }
                        else if (code == EXCEPTION_SINGLE_STEP && awaitingSingleStep)
                        {
                            IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, ev.dwThreadId);
                            if (hThread != IntPtr.Zero)
                            {
                                try
                                {
                                    CONTEXT64 ctx = new CONTEXT64();
                                    ctx.ContextFlags = CONTEXT_CONTROL_INTEGER;
                                    ctx.FltSave = new byte[512];
                                    ctx.VectorRegister = new byte[416];
                                    if (GetThreadContext(hThread, ref ctx))
                                    {
                                        ctx.EFlags &= unchecked((uint)~0x100);
                                        SetThreadContext(hThread, ref ctx);
                                    }
                                }
                                finally { CloseHandle(hThread); }
                            }

                            awaitingSingleStep = false;
                            handledSingleStep = true;
                            if (captures.Count >= Math.Max(1, maxCaptures))
                            {
                                result.Ok = true;
                                result.Captures = captures.ToArray();
                                KeyCaptureEvent last = captures[captures.Count - 1];
                                result.PageSize = last.PageSize;
                                result.CipherVersion = last.CipherVersion;
                                result.DataAddress = last.DataAddress;
                                result.BufferAddress = last.BufferAddress;
                                result.BufferLength = last.BufferLength;
                                result.BufferHex = last.BufferHex;
                                result.BufferAscii = last.BufferAscii;
                                result.KeyHex = last.KeyHex;
                                result.ElapsedMs = (int)watch.ElapsedMilliseconds;
                                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                                DebugActiveProcessStop(pi.dwProcessId);
                                return result;
                            }

                            InsertBreakpoint(pi.hProcess, target);
                            breakpointInserted = true;
                        }

                        if (code != EXCEPTION_BREAKPOINT && !handledSingleStep)
                        {
                            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    }
                    else if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
                    {
                        result.Error = "WeChat exited before key capture";
                        result.ElapsedMs = (int)watch.ElapsedMilliseconds;
                        return result;
                    }
                }
                catch (Exception ex)
                {
                    result.Error = ex.Message;
                    result.ElapsedMs = (int)watch.ElapsedMilliseconds;
                    try { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_EXCEPTION_NOT_HANDLED); } catch {}
                    try { DebugActiveProcessStop(pi.dwProcessId); } catch {}
                    return result;
                }

                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus);
            }

            result.Error = "timeout waiting for WCDB_Database_setCipherKey";
            result.ElapsedMs = (int)watch.ElapsedMilliseconds;
            if (breakpointInserted) RestoreBreakpoint(pi.hProcess, target, original);
            if (captures.Count > 0) {
                result.Ok = true;
                result.Error = null;
                result.Captures = captures.ToArray();
                KeyCaptureEvent last = captures[captures.Count - 1];
                result.PageSize = last.PageSize;
                result.CipherVersion = last.CipherVersion;
                result.DataAddress = last.DataAddress;
                result.BufferAddress = last.BufferAddress;
                result.BufferLength = last.BufferLength;
                result.BufferHex = last.BufferHex;
                result.BufferAscii = last.BufferAscii;
                result.KeyHex = last.KeyHex;
            }
            DebugActiveProcessStop(pi.dwProcessId);
            return result;
        }
        finally
        {
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
        }
    }
}
'@
}

if (-not (Test-Path -LiteralPath $WeChatExe -PathType Leaf)) {
    throw "WeChatExe not found: $WeChatExe"
}

$result = [WeChatKeyDebugApiCapture]::LaunchAndCapture($WeChatExe, $SetCipherKeyOffset, $TimeoutSeconds, $MaxCaptures, $PostFirstIdleSeconds, $DumpBytes)
$json = $result | ConvertTo-Json -Depth 4
$parent = Split-Path -Parent $OutFile
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}
Set-Content -LiteralPath $OutFile -Value $json -Encoding UTF8
[pscustomobject]@{
    Ok = $result.Ok
    Error = $result.Error
    ProcessId = $result.ProcessId
    DllBase = $result.DllBase
    BreakpointAddress = $result.BreakpointAddress
    CaptureCount = @($result.Captures).Count
    LoadDllEvents = $result.LoadDllEvents
    BreakpointEvents = $result.BreakpointEvents
    ElapsedMs = $result.ElapsedMs
    OutFile = $OutFile
} | ConvertTo-Json -Depth 3
