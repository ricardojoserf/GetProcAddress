using System;
using System.Text;
using System.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace test
{
    internal class test
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_DOS_HEADER { public UInt16 e_magic; public UInt16 e_cblp; public UInt16 e_cp; public UInt16 e_crlc; public UInt16 e_cparhdr; public UInt16 e_minalloc; public UInt16 e_maxalloc; public UInt16 e_ss; public UInt16 e_sp; public UInt16 e_csum; public UInt16 e_ip; public UInt16 e_cs; public UInt16 e_lfarlc; public UInt16 e_ovno; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public UInt16[] e_res1; public UInt16 e_oemid; public UInt16 e_oeminfo; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)] public UInt16[] e_res2; public UInt32 e_lfanew; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_NT_HEADERS { public UInt32 Signature; public IMAGE_FILE_HEADER FileHeader; public IMAGE_OPTIONAL_HEADER32 OptionalHeader32; public IMAGE_OPTIONAL_HEADER64 OptionalHeader64; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_FILE_HEADER { public UInt16 Machine; public UInt16 NumberOfSections; public UInt32 TimeDateStamp; public UInt32 PointerToSymbolTable; public UInt32 NumberOfSymbols; public UInt16 SizeOfOptionalHeader; public UInt16 Characteristics; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_OPTIONAL_HEADER32 { public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode; public UInt32 BaseOfData; public UInt32 ImageBase; public UInt32 SectionAlignment; public UInt32 FileAlignment; public UInt16 MajorOperatingSystemVersion; public UInt16 MinorOperatingSystemVersion; public UInt16 MajorImageVersion; public UInt16 MinorImageVersion; public UInt16 MajorSubsystemVersion; public UInt16 MinorSubsystemVersion; public UInt32 Win32VersionValue; public UInt32 SizeOfImage; public UInt32 SizeOfHeaders; public UInt32 CheckSum; public UInt16 Subsystem; public UInt16 DllCharacteristics; public UInt32 SizeOfStackReserve; public UInt32 SizeOfStackCommit; public UInt32 SizeOfHeapReserve; public UInt32 SizeOfHeapCommit; public UInt32 LoaderFlags; public UInt32 NumberOfRvaAndSizes; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_OPTIONAL_HEADER64 { public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode; public UInt64 ImageBase; public UInt32 SectionAlignment; public UInt32 FileAlignment; public UInt16 MajorOperatingSystemVersion; public UInt16 MinorOperatingSystemVersion; public UInt16 MajorImageVersion; public UInt16 MinorImageVersion; public UInt16 MajorSubsystemVersion; public UInt16 MinorSubsystemVersion; public UInt32 Win32VersionValue; public UInt32 SizeOfImage; public UInt32 SizeOfHeaders; public UInt32 CheckSum; public UInt16 Subsystem; public UInt16 DllCharacteristics; public UInt64 SizeOfStackReserve; public UInt64 SizeOfStackCommit; public UInt64 SizeOfHeapReserve; public UInt64 SizeOfHeapCommit; public UInt32 LoaderFlags; public UInt32 NumberOfRvaAndSizes; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_DATA_DIRECTORY { public UInt32 VirtualAddress; public UInt32 Size; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_EXPORT_DIRECTORY { public UInt32 Characteristics; public UInt32 TimeDateStamp; public UInt16 MajorVersion; public UInt16 MinorVersion; public UInt32 Name; public UInt32 Base; public UInt32 NumberOfFunctions; public UInt32 NumberOfNames; public UInt32 AddressOfFunctions; public UInt32 AddressOfNames; public UInt32 AddressOfNameOrdinals; }


        private static T MarshalBytesTo<T>(byte[] bytes)
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return theStructure;
        }


        static IntPtr AuxGetProcAddress(String dll_name, String func_name) {
            IntPtr nread = IntPtr.Zero;
            
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            IntPtr pDosHdr = GetModuleHandle(dll_name);
            Console.WriteLine("DOS Header: \t\t\t0x{0}", pDosHdr.ToString("X"));

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, pDosHdr, data, data.Length, out nread);

            IMAGE_DOS_HEADER _dosHeader = MarshalBytesTo<IMAGE_DOS_HEADER>(data);
            String dos_header_signature = _dosHeader.e_magic.ToString("X");
            Console.WriteLine("DOS Signature: \t\t\t0x{0}", dos_header_signature);
            uint e_lfanew_offset = _dosHeader.e_lfanew; // BitConverter.ToUInt32(data, 0x3c);
            IntPtr nthdr = IntPtr.Add(pDosHdr, Convert.ToInt32(e_lfanew_offset));

            byte[] data2 = new byte[0x200];
            ReadProcessMemory(hProcess, nthdr, data2, data2.Length, out nread);
            IMAGE_NT_HEADERS _ntHeader = MarshalBytesTo<IMAGE_NT_HEADERS>(data2);
            IMAGE_FILE_HEADER _fileHeader = _ntHeader.FileHeader;
            Console.WriteLine("SizeOfOptionalHeader: \t\t{0}", _fileHeader.SizeOfOptionalHeader);
            Console.WriteLine("SizeOfOptionalHeader: \t\t0x{0}", _fileHeader.SizeOfOptionalHeader.ToString("X"));

            IntPtr optionalhdr = IntPtr.Add(nthdr, 24);
            byte[] data3 = new byte[0x200];
            ReadProcessMemory(hProcess, optionalhdr, data3, data3.Length, out nread);
            IMAGE_OPTIONAL_HEADER64 _optionalHeader = MarshalBytesTo<IMAGE_OPTIONAL_HEADER64>(data3);
            Console.WriteLine("Optional Header Magic Number: \t0x{0}", _optionalHeader.Magic.ToString("X"));

            int numberDataDirectory = (_fileHeader.SizeOfOptionalHeader / 16) - 1;
            Console.WriteLine("DataDirectory size: \t\t{0}\n", numberDataDirectory);
            IMAGE_DATA_DIRECTORY[] optionalHeaderDataDirectory = _optionalHeader.DataDirectory;

            foreach (IMAGE_DATA_DIRECTORY idd in optionalHeaderDataDirectory)
            {
                Console.WriteLine("VirtualAddress/Size: \t0x{0}     \t0x{1}", idd.VirtualAddress.ToString("X"), idd.Size.ToString("X"));
            }

            uint exportTableRVA = optionalHeaderDataDirectory[0].VirtualAddress;

            if (exportTableRVA != 0)
            {
                Console.WriteLine("\nExport Table (RVA):\t\t0x{0}", exportTableRVA.ToString("X"));
                IntPtr exportTableAddress = IntPtr.Add(pDosHdr, (int)exportTableRVA);
                Console.WriteLine("Export Table (RA):\t\t0x{0}\n", exportTableAddress.ToString("X"));
                byte[] data4 = new byte[0x200];
                ReadProcessMemory(hProcess, exportTableAddress, data4, data4.Length, out nread);
                IMAGE_EXPORT_DIRECTORY exportTable = MarshalBytesTo<IMAGE_EXPORT_DIRECTORY>(data4);

                UInt32 numberOfNames = exportTable.NumberOfNames;
                UInt32 addressOfFunctionsVRA = exportTable.AddressOfFunctions;
                UInt32 addressOfNamesVRA = exportTable.AddressOfNames;
                UInt32 addressOfNameOrdinalsVRA = exportTable.AddressOfNameOrdinals;
                IntPtr addressOfFunctionsRA = IntPtr.Add(pDosHdr, (int)addressOfFunctionsVRA);
                IntPtr addressOfNamesRA = IntPtr.Add(pDosHdr, (int)addressOfNamesVRA);
                IntPtr addressOfNameOrdinalsRA = IntPtr.Add(pDosHdr, (int)addressOfFunctionsVRA);

                Console.WriteLine("Number Of Names (Functions)\t{0}\n", numberOfNames);
                Console.WriteLine("AddressOfFunctions (VRA)\t0x{0}", addressOfFunctionsVRA.ToString("X"));
                Console.WriteLine("AddressOfFunctions (RA) \t0x{0}", addressOfFunctionsRA.ToString("X"));
                Console.WriteLine("AddressOfNames (VRA)\t\t0x{0}", addressOfNamesVRA.ToString("X"));
                Console.WriteLine("AddressOfNames (RA)\t\t0x{0}", addressOfNamesRA.ToString("X"));
                Console.WriteLine("AddressOfNameOrdinals (VRA)\t0x{0}", addressOfNameOrdinalsVRA.ToString("X"));
                Console.WriteLine("AddressOfNameOrdinals (RA)\t0x{0}\n", addressOfNameOrdinalsRA.ToString("X"));

                IntPtr auxaddressOfNamesRA = addressOfNamesRA;
                for (int i = 0; i < numberOfNames; i++)
                {
                    byte[] data5 = new byte[4];
                    ReadProcessMemory(hProcess, auxaddressOfNamesRA, data5, data5.Length, out nread);
                    UInt32 functionAddressVRA = MarshalBytesTo<UInt32>(data5);
                    IntPtr functionAddressRA = IntPtr.Add(pDosHdr, (int)functionAddressVRA);                    
                    byte[] data6 = new byte[50];
                    ReadProcessMemory(hProcess, functionAddressRA, data6, data6.Length, out nread);
                    String functionName = Encoding.ASCII.GetString(data6.TakeWhile(b => !b.Equals(0)).ToArray());
                    // Console.WriteLine("Function: {0} ({1})", functionName, functionAddressRA.ToString("X"));
                    if (functionName == func_name) {
                        return functionAddressRA;
                    }
                    auxaddressOfNamesRA += 4;
                }
            }
            return IntPtr.Zero;
        }


        static void Main(string[] args)
        {
            string dll_name = args[0];
            string func_name = args[1];
            IntPtr func_address = AuxGetProcAddress(dll_name, func_name);
            Console.WriteLine("[+] Address of {0} ({1}): \t0x{2}", func_name, dll_name, func_address.ToString("X"));
        }
    }
}
