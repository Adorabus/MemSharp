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

        private bool _isOpen = false;
        private IntPtr _processHandle;


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId
        );
        public static IntPtr OpenProcess(Process proc, ProcessAccessFlags flags)
        {
            return OpenProcess(flags, false, proc.Id);
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

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

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        public MProcess(string name)
        {
            if (name.EndsWith(".exe"))
            {
                name = name.Substring(0, name.Length - 4);
            }

            var processes = Process.GetProcessesByName(name);

            if (processes.Length == 0)
            {
                throw new Exception($"Process {name} not found.");
            }

            process = processes.First();
        }

        public bool IsOpen()
        {
            return _isOpen;
        }

        public void Open(ProcessAccessFlags flags)
        {
            if (!_isOpen)
            {
                _processHandle = OpenProcess(flags, false, process.Id);
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

        public ProcessModule GetModuleByName(string name)
        {
            foreach (ProcessModule processModule in process.Modules)
            {
                if (processModule.ModuleName.Equals(name))
                {
                    return processModule;
                }
            }

            return null;
        }

        public IntPtr GetPointerAddress(string moduleName, int[] offsets)
        {
            ProcessModule module = GetModuleByName(moduleName);

            if (module == null)
            {
                throw new Exception("Module not found.");
            }

            IntPtr address = module.BaseAddress;

            foreach (var offset in offsets)
            {
                address += offset;

                // don't read the last one, we are at the address
                if (!offset.Equals(offsets.Last()))
                {
                    address = ReadAddress(address);
                }
            }

            return address;
        }

        public byte[] ReadBytes(IntPtr address, int length)
        {
            if (!_isOpen)
            {
                throw new Exception("Tried to read from closed process.");
            }

            byte[] buff = new byte[length];
            IntPtr bytesRead;

            if (!ReadProcessMemory(_processHandle, address, buff, length, out bytesRead))
            {
                throw new Exception("Failed to read memory.");
            }

            return buff;
        }

        public void WriteBytes(IntPtr address, byte[] bytes)
        {
            if (!_isOpen)
            {
                throw new Exception("Tried to write to closed process.");
            }

            IntPtr bytesWritten;

            if (!WriteProcessMemory(_processHandle, address, bytes, bytes.Length, out bytesWritten))
            {
                throw new Exception("Failed to write memory.");
            }
        }

        public IntPtr ReadAddress(IntPtr address)
        {
            byte[] buff = ReadBytes(address, IntPtr.Size);

#if WIN64
            return (IntPtr)BitConverter.ToInt64(buff, 0);
#else
            return (IntPtr)BitConverter.ToInt32(buff, 0);
#endif
        }

        public int ReadInt(IntPtr address)
        {
            return BitConverter.ToInt32(ReadBytes(address, sizeof(int)), 0);
        }

        public void WriteInt(IntPtr address, int value)
        {
            WriteBytes(address, BitConverter.GetBytes(value));
        }

        public long ReadLong(IntPtr address)
        {
            return BitConverter.ToInt64(ReadBytes(address, sizeof(long)), 0);
        }

        public void WriteLong(IntPtr address, long value)
        {
            WriteBytes(address, BitConverter.GetBytes(value));
        }

        public float ReadFloat(IntPtr address)
        {
            return BitConverter.ToSingle(ReadBytes(address, sizeof(float)), 0);
        }

        public void WriteFloat(IntPtr address, float value)
        {
            WriteBytes(address, BitConverter.GetBytes(value));
        }

        public double ReadDouble(IntPtr address)
        {
            return BitConverter.ToDouble(ReadBytes(address, sizeof(double)), 0);
        }

        public void WriteDouble(IntPtr address, double value)
        {
            WriteBytes(address, BitConverter.GetBytes(value));
        }

        public uint ReadUInt(IntPtr address)
        {
            return BitConverter.ToUInt32(ReadBytes(address, sizeof(uint)), 0);
        }

        public void WriteUInt(IntPtr address, uint value)
        {
            WriteBytes(address, BitConverter.GetBytes(value));
        }

        public ulong ReadULong(IntPtr address)
        {
            return BitConverter.ToUInt64(ReadBytes(address, sizeof(ulong)), 0);
        }

        public void WriteULong(IntPtr address, ulong value)
        {
            WriteBytes(address, BitConverter.GetBytes(value));
        }

        public ushort ReadUShort(IntPtr address)
        {
            return BitConverter.ToUInt16(ReadBytes(address, sizeof(ushort)), 0);
        }

        public void WriteUShort(IntPtr address, ushort value)
        {
            WriteBytes(address, BitConverter.GetBytes(value));
        }

        public byte ReadByte(IntPtr address)
        {
            return ReadBytes(address, sizeof(byte))[0];
        }

        public void WriteByte(IntPtr address, byte value)
        {
            WriteBytes(address, BitConverter.GetBytes(value));
        }

        public string ReadString(IntPtr address, int length)
        {
            return Encoding.UTF8.GetString(ReadBytes(address, length));
        }

        public void WriteString(IntPtr address, string value, int length)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value.PadRight(length).Substring(0, length));

            WriteBytes(address, bytes);
        }

        public void WriteString(IntPtr address, string value, int length, Encoding encoding)
        {
            byte[] bytes = encoding.GetBytes(value.Substring(0, length));

            WriteBytes(address, bytes);
        }
    }
}
