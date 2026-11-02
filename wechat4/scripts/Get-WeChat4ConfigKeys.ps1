# WCDB Config.Cipher extraction adapted from fanyuantaier/wechatauto-replica,
# commit bc2e6f2461330eb1a53996d2f2afc18416376b52, wechatauto/db.py (Apache-2.0).
# Adapted to PowerShell/C# with bounded scanning and summary-only console output.
# See the repository's third_party/wechatauto-replica/LICENSE and notices.
[CmdletBinding()]
param(
    [ValidateRange(0, 2147483647)][int]$ProcessId = 0,
    [Parameter(Mandatory = $true)][string]$OutFile,
    [ValidateRange(1, 3600)][int]$TimeoutSeconds = 60,
    [ValidateRange(1, 4096)][int]$MaxCandidates = 256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell to inspect 64-bit WeChat.' }
if (-not ('WeChatConfigKeys' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
public static class WeChatConfigKeys {
    [StructLayout(LayoutKind.Sequential)] public struct MBI {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State, Protect, Type;
    }
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MBI mbi, UIntPtr length);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] data, UIntPtr size, out UIntPtr read);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public static int NameHits, NodeHits, BlobHits;
    public static long BytesRead;
    public static int TimeoutSeconds=60, MaxCandidates=256;
    static System.Diagnostics.Stopwatch timer;
    public static void Reset() {
        NameHits=NodeHits=BlobHits=0;BytesRead=0;
        timer=System.Diagnostics.Stopwatch.StartNew();
    }
    static void CheckDeadline() {
        if(timer.Elapsed.TotalSeconds>=TimeoutSeconds) throw new TimeoutException("Config.Cipher scan timed out; specify the main process with -ProcessId or increase -TimeoutSeconds.");
    }
    static byte[] Read(IntPtr process, long address, int length) {
        if(address<0x10000 || address>=0x800000000000) return null;
        byte[] b=new byte[length]; UIntPtr read;
        if(!ReadProcessMemory(process,new IntPtr(address),b,new UIntPtr((uint)length),out read) || read.ToUInt64()!=(ulong)length) return null;
        return b;
    }
    static List<long> Find(IntPtr process, List<byte[]> patterns) {
        var hits=new List<long>(); long address=0x10000;
        var buffer=new byte[1024*1024]; MBI mbi;
        while(address<0x7fffffffffff && VirtualQueryEx(process,new IntPtr(address),out mbi,new UIntPtr((uint)Marshal.SizeOf(typeof(MBI))))!=UIntPtr.Zero) {
            CheckDeadline();
            long start=mbi.BaseAddress.ToInt64(), end=start+(long)mbi.RegionSize.ToUInt64();
            if(end<=address) break;
            if(mbi.State==0x1000 && (mbi.Protect&0x101)==0) {
                for(long cursor=start;cursor<end;) {
                    CheckDeadline();
                    int size=(int)Math.Min(buffer.Length,end-cursor); UIntPtr read;
                    ReadProcessMemory(process,new IntPtr(cursor),buffer,new UIntPtr((uint)size),out read);
                    int length=(int)read.ToUInt64(); BytesRead+=length;
                    foreach(byte[] pattern in patterns) {
                        for(int i=0;i+pattern.Length<=length;i++) {
                            if(buffer[i]!=pattern[0]) continue;
                            int j=1;for(;j<pattern.Length && buffer[i+j]==pattern[j];j++){}
                            if(j==pattern.Length) {
                                hits.Add(cursor+i);
                                if(hits.Count>4096) throw new InvalidOperationException("Too many Config.Cipher references; layout may have changed.");
                            }
                        }
                    }
                    if(cursor+size>=end) break;
                    cursor+=Math.Max(1,size-64);
                }
            }
            address=end;
        }
        return hits;
    }
    public static string[] Scan(int pid) {
        IntPtr process=OpenProcess(0x410,false,pid);
        if(process==IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        var literals=new HashSet<string>();
        try {
            byte[] name=Encoding.ASCII.GetBytes("com.Tencent.WCDB.Config.Cipher");
            var names=Find(process,new List<byte[]>{name});NameHits+=names.Count;
            if(names.Count>32) throw new InvalidOperationException("Too many cipher-name copies; layout may have changed.");
            var pairs=new List<byte[]>();
            foreach(long address in names) {
                byte[] pair=new byte[16];Array.Copy(BitConverter.GetBytes(address),0,pair,0,8);Array.Copy(BitConverter.GetBytes((long)name.Length),0,pair,8,8);pairs.Add(pair);
            }
            if(pairs.Count==0) return new string[0];
            var nodes=Find(process,pairs);NodeHits+=nodes.Count;
            byte[] mask=new byte[]{0xd2,0xc7,0x44,0x24,0x58,0x02,0x00,0x00,0x00,0x48,0x89,0x44,0x24,0x50,0x48,0x8b,0x45,0x00,0x48,0x84,0x4c,0x24,0x48,0x48,0x89,0x44,0x25,0x40,0x48,0x58,0x4c,0x24};
            foreach(long address in nodes) {
                byte[] node=Read(process,address-0x10,0x50);if(node==null)continue;
                long config=BitConverter.ToInt64(node,0x28);
                byte[] obj=Read(process,config+0x88,0x28);if(obj==null)continue;
                long pointer=BitConverter.ToInt64(obj,8),length=BitConverter.ToInt64(obj,16);
                if(length<=0 || length>1024)continue;
                byte[] blob=Read(process,pointer,(int)length);if(blob==null)continue;BlobHits++;
                for(int i=0;i<blob.Length;i++)blob[i]^=mask[i%mask.Length];
                foreach(Match m in Regex.Matches(Encoding.ASCII.GetString(blob),"[xX]'([0-9a-fA-F]{64}(?:[0-9a-fA-F]{32})?)'")) {
                    literals.Add(m.Groups[1].Value.ToLowerInvariant());
                    if(literals.Count>MaxCandidates) throw new InvalidOperationException("Candidate limit exceeded; layout may have changed.");
                }
            }
        } finally { CloseHandle(process); }
        var result=new string[literals.Count];literals.CopyTo(result);return result;
    }
}
'@
}
[WeChatConfigKeys]::TimeoutSeconds = $TimeoutSeconds
[WeChatConfigKeys]::MaxCandidates = $MaxCandidates
[WeChatConfigKeys]::Reset()
if ($ProcessId) {
    $processIds = @($ProcessId)
} else {
    $processes = @(Get-Process -Name Weixin -ErrorAction SilentlyContinue)
    if ($processes.Count -eq 0) { throw 'Start WeChat and log in before capturing keys.' }
    $main = @($processes | Where-Object { $_.MainWindowHandle -ne [IntPtr]::Zero })
    if ($main.Count -eq 0) { $main = @($processes | Sort-Object WorkingSet64 -Descending | Select-Object -First 1) }
    $processIds = @($main | ForEach-Object { $_.Id })
}
$literals = @($processIds | ForEach-Object { [WeChatConfigKeys]::Scan($_) } | Sort-Object -Unique)
if ($literals.Count -eq 0) { throw 'No Config.Cipher key candidates found. Check login/process access; this build may need new layout or XOR-mask analysis.' }
if ($literals.Count -gt $MaxCandidates) { throw 'Combined candidate limit exceeded.' }
$records = @($literals | ForEach-Object { @{key_hex = $_.Substring(0,64)} })
$outputPath = [IO.Path]::GetFullPath($OutFile)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($outputPath)) | Out-Null
$payload = @{format='wcdb-config-cipher-v1';candidates=$records}
$encoded = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $payload -Depth 4))
$stream = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $stream.Write($encoded,0,$encoded.Length) } finally { $stream.Dispose() }
@{candidates=$literals.Count;name_hits=[WeChatConfigKeys]::NameHits;nodes=[WeChatConfigKeys]::NodeHits;blobs=[WeChatConfigKeys]::BlobHits;bytes_read=[WeChatConfigKeys]::BytesRead} | ConvertTo-Json
