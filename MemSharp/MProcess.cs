using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace MemSharp
{
    public class MProcess
    {
        public Process process;

        const int PROCESS_WM_READ = 0x0010;
        private bool _isOpen = false;
        private IntPtr _processHandle;


        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        public MProcess(string name)
        {
            if (name.EndsWith(".exe"))
            {
                name = name.Substring(0, name.Length - 4);
            }

            process = Process.GetProcessesByName(name).First();
        }

        public bool IsOpen()
        {
            return _isOpen;
        }

        public void Open()
        {
            if (!_isOpen)
            {
                _processHandle = OpenProcess(PROCESS_WM_READ, false, process.Id);
                _isOpen = true;
            }
        }

        public void Close()
        {
            if (_isOpen)
            {
                CloseHandle(_processHandle);
                _processHandle = IntPtr.Zero;
                _isOpen = false;
            }
        }

        public float ReadFloat(IntPtr address)
        {
            if (!_isOpen)
            {
                throw new Exception("Tried to read from closed process.");
            }

            float result = 0.0f;
            byte[] buff = new byte[Marshal.SizeOf(result)];
            IntPtr bytesRead;

            if (!ReadProcessMemory(_processHandle, address, buff, sizeof(float), out bytesRead))
            {
                throw new Exception("Failed to read memory.");
            }

            result = BitConverter.ToSingle(buff, 0);

            return result;
        }
    }
}
