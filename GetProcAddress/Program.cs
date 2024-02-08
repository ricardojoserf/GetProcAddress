using System;
using System.Text;
using System.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace GetProcAddress
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)] static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
        // [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);
        // [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        
        /*
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_OPTIONAL_HEADER32 { public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode; public UInt32 BaseOfData; public UInt32 ImageBase; public UInt32 SectionAlignment; public UInt32 FileAlignment; public UInt16 MajorOperatingSystemVersion; public UInt16 MinorOperatingSystemVersion; public UInt16 MajorImageVersion; public UInt16 MinorImageVersion; public UInt16 MajorSubsystemVersion; public UInt16 MinorSubsystemVersion; public UInt32 Win32VersionValue; public UInt32 SizeOfImage; public UInt32 SizeOfHeaders; public UInt32 CheckSum; public UInt16 Subsystem; public UInt16 DllCharacteristics; public UInt32 SizeOfStackReserve; public UInt32 SizeOfStackCommit; public UInt32 SizeOfHeapReserve; public UInt32 SizeOfHeapCommit; public UInt32 LoaderFlags; public UInt32 NumberOfRvaAndSizes; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory; }
        private struct PROCESS_BASIC_INFORMATION { public uint ExitStatus; public IntPtr PebBaseAddress; public UIntPtr AffinityMask; public int BasePriority; public UIntPtr UniqueProcessId; public UIntPtr InheritedFromUniqueProcessId; }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public UInt16 e_magic;
            public UInt16 e_cblp;
            public UInt16 e_cp;
            public UInt16 e_crlc;
            public UInt16 e_cparhdr;
            public UInt16 e_minalloc;
            public UInt16 e_maxalloc;
            public UInt16 e_ss;
            public UInt16 e_sp;
            public UInt16 e_csum;
            public UInt16 e_ip;
            public UInt16 e_cs;
            public UInt16 e_lfarlc;
            public UInt16 e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public UInt16[] e_res1;
            public UInt16 e_oemid;
            public UInt16 e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)] public UInt16[] e_res2;
            public UInt32 e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS
        {
            public UInt32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader64;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }


        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_DATA_DIRECTORY { 
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions;
            public UInt32 AddressOfNames;
            public UInt32 AddressOfNameOrdinals;
        }
        */


        private static T MarshalBytesTo<T>(byte[] bytes)
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return theStructure;
        }


        static IntPtr CustomGetProcAddress(IntPtr pDosHdr, String func_name)
        {
            // Current process handle
            IntPtr hProcess = Process.GetCurrentProcess().Handle;

            /*
            // DOS header -> e_lfanew
            int dos_header_size = 64;
            byte[] data = new byte[dos_header_size];
            ReadProcessMemory(hProcess, pDosHdr, data, data.Length, out _);
            IMAGE_DOS_HEADER _dosHeader = MarshalBytesTo<IMAGE_DOS_HEADER>(data);
            uint e_lfanew_offset = _dosHeader.e_lfanew;
            Console.WriteLine("e_lfanew:\t\t\t\t\t0x" + _dosHeader.e_lfanew.ToString("X"));
            Console.WriteLine("e_magic:\t\t\t\t\t0x" + _dosHeader.e_magic.ToString("X"));
            */

            // NEW: DOS header -> e_lfanew
            IntPtr e_lfanew_addr = pDosHdr + (int)0x3C;
            byte[] e_lfanew_bytearr = new byte[4];
            ReadProcessMemory(hProcess, e_lfanew_addr, e_lfanew_bytearr, e_lfanew_bytearr.Length, out _);
            ulong e_lfanew_value = BitConverter.ToUInt32(e_lfanew_bytearr, 0);
            Console.WriteLine("[*] e_lfanew: \t\t\t\t\t0x" + (e_lfanew_value).ToString("X"));

            /*
            // NT_HEADER
            IntPtr nthdr = pDosHdr + (int)e_lfanew_offset;
            byte[] data2 = new byte[Marshal.SizeOf(typeof(IMAGE_NT_HEADERS))];
            ReadProcessMemory(hProcess, nthdr, data2, data2.Length, out _);
            IMAGE_NT_HEADERS _ntHeader = MarshalBytesTo<IMAGE_NT_HEADERS>(data2);
            
            // IMAGE_FILE_HEADER
            IMAGE_FILE_HEADER _fileHeader = _ntHeader.FileHeader;
            Console.WriteLine("SizeOfOptionalHeader: \t\t\t\t" + _fileHeader.SizeOfOptionalHeader.ToString("X"));
            // int numberDataDirectory = (_fileHeader.SizeOfOptionalHeader / 16) - 1;
            */

            // NEW: SizeOfOptionalHeader
            IntPtr sizeopthdr_addr = pDosHdr + (int)e_lfanew_value + 20;
            byte[] sizeopthdr_bytearr = new byte[2];
            ReadProcessMemory(hProcess, sizeopthdr_addr, sizeopthdr_bytearr, sizeopthdr_bytearr.Length, out _);
            ulong sizeopthdr_value = BitConverter.ToUInt16(sizeopthdr_bytearr, 0);
            Console.WriteLine("[*] SizeOfOptionalHeader: \t\t\t0x" + (sizeopthdr_value).ToString("X"));
            int numberDataDirectory = ((int)sizeopthdr_value / 16) - 1;

            /*
            // OPTIONAL_HEADER
            IntPtr optionalhdr = pDosHdr + (int)e_lfanew_offset + 24; // IntPtr.Add(nthdr, 24);
            byte[] data3 = new byte[Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER64))];
            ReadProcessMemory(hProcess, optionalhdr, data3, data3.Length, out _);
            IMAGE_OPTIONAL_HEADER64 _optionalHeader = MarshalBytesTo<IMAGE_OPTIONAL_HEADER64>(data3);

            IMAGE_DATA_DIRECTORY[] optionalHeaderDataDirectory = _optionalHeader.DataDirectory;
            uint exportTableRVA = optionalHeaderDataDirectory[0].VirtualAddress;
            Console.WriteLine("optionalHeaderDataDirectory[0].VirtualAddress:\t" + optionalHeaderDataDirectory[0].VirtualAddress.ToString("X"));
            */

            // NEW: exportTableRVA
            IntPtr exportTableRVA_addr = pDosHdr + (int)e_lfanew_value + 24 + 112; // IMAGE_OPTIONAL_HEADER64 size: 240; IMAGE_DATA_DIRECTORY size: 8; 240 - (16 * 8) = 224
            byte[] exportTableRVA_bytearr = new byte[4];
            ReadProcessMemory(hProcess, exportTableRVA_addr, exportTableRVA_bytearr, exportTableRVA_bytearr.Length, out _);
            ulong exportTableRVA_value = BitConverter.ToUInt32(exportTableRVA_bytearr, 0);
            Console.WriteLine("[*] exportTableRVA: \t\t\t\t0x" + (exportTableRVA_value).ToString("X"));

            /*
            Console.WriteLine("IMAGE_DOS_HEADER size: " + Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)));
            Console.WriteLine("IMAGE_NT_HEADERS size: " + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS)));
            Console.WriteLine("IMAGE_OPTIONAL_HEADER64 size: " + Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER64)));

            unsafe {
                fixed (byte* ptr_data2 = &data2[0])
                {
                    IMAGE_DOS_HEADER* ptr_dosHeader = &_dosHeader;
                    uint* ptr_dosHeader_elfanew = &_dosHeader.e_lfanew;

                    Console.WriteLine("[-] pDosHdr:               \t0x" + pDosHdr.ToString("X"));
                    // Console.WriteLine("[-] data address:          \t0x" + ((IntPtr)ptr_data).ToString("X"));
                    Console.WriteLine("[-] _dosHeader address: \t0x" + ((IntPtr)ptr_dosHeader).ToString("X"));
                    Console.WriteLine("[-] _dosHeader address: \t0x" + ((IntPtr)ptr_dosHeader_elfanew).ToString("X"));

                    Console.WriteLine("[-] nthdr:               \t0x" + nthdr.ToString("X"));
                    Console.WriteLine("[-] data2 address:          \t0x" + ((IntPtr)ptr_data2).ToString("X"));

                    /// Console.WriteLine(Marshal.ReadIntPtr(pDosHdr).ToString("X"));
                }
            }
            */


            /*
            // FOR DEBUGGING
            Console.WriteLine("DOS Header: \t\t\t0x{0}", pDosHdr.ToString("X"));
            Console.WriteLine("DOS Signature: \t\t\t0x{0}", dos_header_signature);
            Console.WriteLine("SizeOfOptionalHeader: \t\t{0}", _fileHeader.SizeOfOptionalHeader);
            Console.WriteLine("SizeOfOptionalHeader: \t\t0x{0}", _fileHeader.SizeOfOptionalHeader.ToString("X"));
            Console.WriteLine("Optional Header Magic Number: \t0x{0}", _optionalHeader.Magic.ToString("X"));
            Console.WriteLine("DataDirectory size: \t\t{0}\n", numberDataDirectory);

            foreach (IMAGE_DATA_DIRECTORY idd in optionalHeaderDataDirectory)
            {
                Console.WriteLine("VirtualAddress/Size: \t0x{0}     \t0x{1}", idd.VirtualAddress.ToString("X"), idd.Size.ToString("X"));
            }
            */

            if (exportTableRVA_value != 0)
            {
                /*
                IntPtr exportTableAddress = IntPtr.Add(pDosHdr, (int)exportTableRVA);
                byte[] data4 = new byte[Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY))];
                ReadProcessMemory(hProcess, exportTableAddress, data4, data4.Length, out _);
                IMAGE_EXPORT_DIRECTORY exportTable = MarshalBytesTo<IMAGE_EXPORT_DIRECTORY>(data4);

                // UInt32 base_value = exportTable.Base;
                UInt32 numberOfNames = exportTable.NumberOfNames;
                UInt32 addressOfFunctionsVRA = exportTable.AddressOfFunctions;
                UInt32 addressOfNamesVRA = exportTable.AddressOfNames;
                UInt32 addressOfNameOrdinalsVRA = exportTable.AddressOfNameOrdinals;
                Console.WriteLine("numberOfNames: \t\t\t\t\t" + numberOfNames.ToString("X"));
                Console.WriteLine("addressOfFunctionsVRA: \t\t\t\t" + addressOfFunctionsVRA.ToString("X"));
                Console.WriteLine("addressOfNamesVRA: \t\t\t\t" + addressOfNamesVRA.ToString("X"));
                Console.WriteLine("addressOfNameOrdinalsVRA: \t\t\t" + addressOfNameOrdinalsVRA.ToString("X"));
                */

                // NEW - Values
                // numberOfNames
                IntPtr numberOfNames_addr = pDosHdr + (int)exportTableRVA_value + 0x18;
                byte[] numberOfNames_bytearr = new byte[4];
                ReadProcessMemory(hProcess, numberOfNames_addr, numberOfNames_bytearr, numberOfNames_bytearr.Length, out _);
                int numberOfNames_value = (int)BitConverter.ToUInt32(numberOfNames_bytearr, 0);
                Console.WriteLine("[*] numberOfNames: \t\t\t\t0x" + (numberOfNames_value).ToString("X"));

                // addressOfFunctions
                IntPtr addressOfFunctionsVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x1C;
                byte[] addressOfFunctionsVRA_bytearr = new byte[4];
                ReadProcessMemory(hProcess, addressOfFunctionsVRA_addr, addressOfFunctionsVRA_bytearr, addressOfFunctionsVRA_bytearr.Length, out _);
                ulong addressOfFunctionsVRA_value = BitConverter.ToUInt32(addressOfFunctionsVRA_bytearr, 0);
                Console.WriteLine("[*] addressOfFunctionsVRA: \t\t\t0x" + (addressOfFunctionsVRA_value).ToString("X"));

                // addressOfNamesVRA
                IntPtr addressOfNamesVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x20;
                byte[] addressOfNamesVRA_bytearr = new byte[4];
                ReadProcessMemory(hProcess, addressOfNamesVRA_addr, addressOfNamesVRA_bytearr, addressOfNamesVRA_bytearr.Length, out _);
                ulong addressOfNamesVRA_value = BitConverter.ToUInt32(addressOfNamesVRA_bytearr, 0);
                Console.WriteLine("[*] addressOfNamesVRA: \t\t\t\t0x" + (addressOfNamesVRA_value).ToString("X"));

                // addressOfNameOrdinalsVRA
                IntPtr addressOfNameOrdinalsVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x24;
                byte[] addressOfNameOrdinalsVRA_bytearr = new byte[4];
                ReadProcessMemory(hProcess, addressOfNameOrdinalsVRA_addr, addressOfNameOrdinalsVRA_bytearr, addressOfNameOrdinalsVRA_bytearr.Length, out _);
                ulong addressOfNameOrdinalsVRA_value = BitConverter.ToUInt32(addressOfNameOrdinalsVRA_bytearr, 0);
                Console.WriteLine("[*] addressOfNameOrdinalsVRA: \t\t\t0x" + (addressOfNameOrdinalsVRA_value).ToString("X"));

                IntPtr addressOfFunctionsRA = IntPtr.Add(pDosHdr, (int)addressOfFunctionsVRA_value);
                IntPtr addressOfNamesRA = IntPtr.Add(pDosHdr, (int)addressOfNamesVRA_value);
                IntPtr addressOfNameOrdinalsRA = IntPtr.Add(pDosHdr, (int)addressOfNameOrdinalsVRA_value);

                /*
                // FOR DEBUGGING
                Console.WriteLine("\nExport Table (RVA):\t\t0x{0}", exportTableRVA.ToString("X"));
                Console.WriteLine("Export Table (RA):\t\t0x{0}\n", exportTableAddress.ToString("X"));
                
                Console.WriteLine("Number Of Names (Functions)\t{0}", numberOfNames);
                Console.WriteLine("Base \t\t\t\t{0}\n", base_value);

                Console.WriteLine("AddressOfFunctions (VRA)\t0x{0}", addressOfFunctionsVRA.ToString("X"));
                Console.WriteLine("AddressOfFunctions (RA) \t0x{0}", addressOfFunctionsRA.ToString("X"));
                Console.WriteLine("AddressOfNames (VRA)\t\t0x{0}", addressOfNamesVRA.ToString("X"));
                Console.WriteLine("AddressOfNames (RA)\t\t0x{0}", addressOfNamesRA.ToString("X"));
                Console.WriteLine("AddressOfNameOrdinals (VRA)\t0x{0}", addressOfNameOrdinalsVRA.ToString("X"));
                Console.WriteLine("AddressOfNameOrdinals (RA)\t0x{0}\n", addressOfNameOrdinalsRA.ToString("X"));
                */

                IntPtr auxaddressOfNamesRA = addressOfNamesRA;
                IntPtr auxaddressOfNameOrdinalsRA = addressOfNameOrdinalsRA;
                IntPtr auxaddressOfFunctionsRA = addressOfFunctionsRA;

                for (int i = 0; i < numberOfNames_value; i++)
                {
                    byte[] data5 = new byte[Marshal.SizeOf(typeof(UInt32))];
                    ReadProcessMemory(hProcess, auxaddressOfNamesRA, data5, data5.Length, out _);
                    UInt32 functionAddressVRA = MarshalBytesTo<UInt32>(data5);
                    IntPtr functionAddressRA = IntPtr.Add(pDosHdr, (int)functionAddressVRA);
                    byte[] data6 = new byte[func_name.Length];
                    ReadProcessMemory(hProcess, functionAddressRA, data6, data6.Length, out _);
                    //String functionName = Encoding.ASCII.GetString(data6.TakeWhile(b => !b.Equals(0)).ToArray());
                    String functionName = Encoding.ASCII.GetString(data6);
                    // FOR DEBUGGING
                    /*
                    Console.WriteLine("Function: {0} ({1})", functionName, functionAddressRA.ToString("X"));
                    */
                    if (functionName == func_name)
                    {
                        // AdddressofNames --> AddressOfNamesOrdinals
                        byte[] data7 = new byte[Marshal.SizeOf(typeof(UInt16))];
                        ReadProcessMemory(hProcess, auxaddressOfNameOrdinalsRA, data7, data7.Length, out _);
                        UInt16 ordinal = MarshalBytesTo<UInt16>(data7);
                        // AddressOfNamesOrdinals --> AddressOfFunctions
                        auxaddressOfFunctionsRA += 4 * ordinal;
                        byte[] data8 = new byte[Marshal.SizeOf(typeof(UInt32))];
                        ReadProcessMemory(hProcess, auxaddressOfFunctionsRA, data8, data8.Length, out _);
                        UInt32 auxaddressOfFunctionsRAVal = MarshalBytesTo<UInt32>(data8);
                        IntPtr functionAddress = IntPtr.Add(pDosHdr, (int)auxaddressOfFunctionsRAVal);
                        return functionAddress;
                    }
                    auxaddressOfNamesRA += 4;
                    auxaddressOfNameOrdinalsRA += 2;
                }
            }
            return IntPtr.Zero;
        }


        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("[-] Usage: GetProcAddress.exe DLL_NAME FUNCTION_NAME");
                System.Environment.Exit(0);
            }
            string dll_name = args[0];
            string func_name = args[1];

            IntPtr dll_handle = LoadLibrary(dll_name); // Alternative: IntPtr dll_handle = GetModuleHandle(dll_name);
            // IntPtr dll_handle = GetModuleHandle(dll_name);
            IntPtr func_address = CustomGetProcAddress(dll_handle, func_name);

            if (func_address == IntPtr.Zero)
            {
                Console.WriteLine("[-] Function name or DLL not found");
            }
            else
            {
                Console.WriteLine("[+] Address of {0} ({1}): 0x{2}", func_name, dll_name, func_address.ToString("X"));
                // Console.WriteLine("[+] Address of {0} ({1}): 0x{2} [GetProcAddress]", func_name, dll_name, GetProcAddress(LoadLibrary(dll_name), func_name).ToString("X"));
            }
        }
    }
}