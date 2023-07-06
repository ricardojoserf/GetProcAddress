using System;
using System.Text;
using System.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace test
{
    internal class test
    {
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)] private static extern NTSTATUS ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        public enum NTSTATUS : uint { Success = 0x00000000, Wait0 = 0x00000000, Wait1 = 0x00000001, Wait2 = 0x00000002, Wait3 = 0x00000003, Wait63 = 0x0000003f, Abandoned = 0x00000080, AbandonedWait0 = 0x00000080, AbandonedWait1 = 0x00000081, AbandonedWait2 = 0x00000082, AbandonedWait3 = 0x00000083, AbandonedWait63 = 0x000000bf, UserApc = 0x000000c0, KernelApc = 0x00000100, Alerted = 0x00000101, Timeout = 0x00000102, Pending = 0x00000103, Reparse = 0x00000104, MoreEntries = 0x00000105, NotAllAssigned = 0x00000106, SomeNotMapped = 0x00000107, OpLockBreakInProgress = 0x00000108, VolumeMounted = 0x00000109, RxActCommitted = 0x0000010a, NotifyCleanup = 0x0000010b, NotifyEnumDir = 0x0000010c, NoQuotasForAccount = 0x0000010d, PrimaryTransportConnectFailed = 0x0000010e, PageFaultTransition = 0x00000110, PageFaultDemandZero = 0x00000111, PageFaultCopyOnWrite = 0x00000112, PageFaultGuardPage = 0x00000113, PageFaultPagingFile = 0x00000114, CrashDump = 0x00000116, ReparseObject = 0x00000118, NothingToTerminate = 0x00000122, ProcessNotInJob = 0x00000123, ProcessInJob = 0x00000124, ProcessCloned = 0x00000129, FileLockedWithOnlyReaders = 0x0000012a, FileLockedWithWriters = 0x0000012b, Informational = 0x40000000, ObjectNameExists = 0x40000000, ThreadWasSuspended = 0x40000001, WorkingSetLimitRange = 0x40000002, ImageNotAtBase = 0x40000003, RegistryRecovered = 0x40000009, Warning = 0x80000000, GuardPageViolation = 0x80000001, DatatypeMisalignment = 0x80000002, Breakpoint = 0x80000003, SingleStep = 0x80000004, BufferOverflow = 0x80000005, NoMoreFiles = 0x80000006, HandlesClosed = 0x8000000a, PartialCopy = 0x8000000d, DeviceBusy = 0x80000011, InvalidEaName = 0x80000013, EaListInconsistent = 0x80000014, NoMoreEntries = 0x8000001a, LongJump = 0x80000026, DllMightBeInsecure = 0x8000002b, Error = 0xc0000000, Unsuccessful = 0xc0000001, NotImplemented = 0xc0000002, InvalidInfoClass = 0xc0000003, InfoLengthMismatch = 0xc0000004, AccessViolation = 0xc0000005, InPageError = 0xc0000006, PagefileQuota = 0xc0000007, InvalidHandle = 0xc0000008, BadInitialStack = 0xc0000009, BadInitialPc = 0xc000000a, InvalidCid = 0xc000000b, TimerNotCanceled = 0xc000000c, InvalidParameter = 0xc000000d, NoSuchDevice = 0xc000000e, NoSuchFile = 0xc000000f, InvalidDeviceRequest = 0xc0000010, EndOfFile = 0xc0000011, WrongVolume = 0xc0000012, NoMediaInDevice = 0xc0000013, NoMemory = 0xc0000017, ConflictingAddresses = 0xc0000018, NotMappedView = 0xc0000019, UnableToFreeVm = 0xc000001a, UnableToDeleteSection = 0xc000001b, IllegalInstruction = 0xc000001d, AlreadyCommitted = 0xc0000021, AccessDenied = 0xc0000022, BufferTooSmall = 0xc0000023, ObjectTypeMismatch = 0xc0000024, NonContinuableException = 0xc0000025, BadStack = 0xc0000028, NotLocked = 0xc000002a, NotCommitted = 0xc000002d, InvalidParameterMix = 0xc0000030, ObjectNameInvalid = 0xc0000033, ObjectNameNotFound = 0xc0000034, ObjectNameCollision = 0xc0000035, ObjectPathInvalid = 0xc0000039, ObjectPathNotFound = 0xc000003a, ObjectPathSyntaxBad = 0xc000003b, DataOverrun = 0xc000003c, DataLate = 0xc000003d, DataError = 0xc000003e, CrcError = 0xc000003f, SectionTooBig = 0xc0000040, PortConnectionRefused = 0xc0000041, InvalidPortHandle = 0xc0000042, SharingViolation = 0xc0000043, QuotaExceeded = 0xc0000044, InvalidPageProtection = 0xc0000045, MutantNotOwned = 0xc0000046, SemaphoreLimitExceeded = 0xc0000047, PortAlreadySet = 0xc0000048, SectionNotImage = 0xc0000049, SuspendCountExceeded = 0xc000004a, ThreadIsTerminating = 0xc000004b, BadWorkingSetLimit = 0xc000004c, IncompatibleFileMap = 0xc000004d, SectionProtection = 0xc000004e, EasNotSupported = 0xc000004f, EaTooLarge = 0xc0000050, NonExistentEaEntry = 0xc0000051, NoEasOnFile = 0xc0000052, EaCorruptError = 0xc0000053, FileLockConflict = 0xc0000054, LockNotGranted = 0xc0000055, DeletePending = 0xc0000056, CtlFileNotSupported = 0xc0000057, UnknownRevision = 0xc0000058, RevisionMismatch = 0xc0000059, InvalidOwner = 0xc000005a, InvalidPrimaryGroup = 0xc000005b, NoImpersonationToken = 0xc000005c, CantDisableMandatory = 0xc000005d, NoLogonServers = 0xc000005e, NoSuchLogonSession = 0xc000005f, NoSuchPrivilege = 0xc0000060, PrivilegeNotHeld = 0xc0000061, InvalidAccountName = 0xc0000062, UserExists = 0xc0000063, NoSuchUser = 0xc0000064, GroupExists = 0xc0000065, NoSuchGroup = 0xc0000066, MemberInGroup = 0xc0000067, MemberNotInGroup = 0xc0000068, LastAdmin = 0xc0000069, WrongPassword = 0xc000006a, IllFormedPassword = 0xc000006b, PasswordRestriction = 0xc000006c, LogonFailure = 0xc000006d, AccountRestriction = 0xc000006e, InvalidLogonHours = 0xc000006f, InvalidWorkstation = 0xc0000070, PasswordExpired = 0xc0000071, AccountDisabled = 0xc0000072, NoneMapped = 0xc0000073, TooManyLuidsRequested = 0xc0000074, LuidsExhausted = 0xc0000075, InvalidSubAuthority = 0xc0000076, InvalidAcl = 0xc0000077, InvalidSid = 0xc0000078, InvalidSecurityDescr = 0xc0000079, ProcedureNotFound = 0xc000007a, InvalidImageFormat = 0xc000007b, NoToken = 0xc000007c, BadInheritanceAcl = 0xc000007d, RangeNotLocked = 0xc000007e, DiskFull = 0xc000007f, ServerDisabled = 0xc0000080, ServerNotDisabled = 0xc0000081, TooManyGuidsRequested = 0xc0000082, GuidsExhausted = 0xc0000083, InvalidIdAuthority = 0xc0000084, AgentsExhausted = 0xc0000085, InvalidVolumeLabel = 0xc0000086, SectionNotExtended = 0xc0000087, NotMappedData = 0xc0000088, ResourceDataNotFound = 0xc0000089, ResourceTypeNotFound = 0xc000008a, ResourceNameNotFound = 0xc000008b, ArrayBoundsExceeded = 0xc000008c, FloatDenormalOperand = 0xc000008d, FloatDivideByZero = 0xc000008e, FloatInexactResult = 0xc000008f, FloatInvalidOperation = 0xc0000090, FloatOverflow = 0xc0000091, FloatStackCheck = 0xc0000092, FloatUnderflow = 0xc0000093, IntegerDivideByZero = 0xc0000094, IntegerOverflow = 0xc0000095, PrivilegedInstruction = 0xc0000096, TooManyPagingFiles = 0xc0000097, FileInvalid = 0xc0000098, InsufficientResources = 0xc000009a, InstanceNotAvailable = 0xc00000ab, PipeNotAvailable = 0xc00000ac, InvalidPipeState = 0xc00000ad, PipeBusy = 0xc00000ae, IllegalFunction = 0xc00000af, PipeDisconnected = 0xc00000b0, PipeClosing = 0xc00000b1, PipeConnected = 0xc00000b2, PipeListening = 0xc00000b3, InvalidReadMode = 0xc00000b4, IoTimeout = 0xc00000b5, FileForcedClosed = 0xc00000b6, ProfilingNotStarted = 0xc00000b7, ProfilingNotStopped = 0xc00000b8, NotSameDevice = 0xc00000d4, FileRenamed = 0xc00000d5, CantWait = 0xc00000d8, PipeEmpty = 0xc00000d9, CantTerminateSelf = 0xc00000db, InternalError = 0xc00000e5, InvalidParameter1 = 0xc00000ef, InvalidParameter2 = 0xc00000f0, InvalidParameter3 = 0xc00000f1, InvalidParameter4 = 0xc00000f2, InvalidParameter5 = 0xc00000f3, InvalidParameter6 = 0xc00000f4, InvalidParameter7 = 0xc00000f5, InvalidParameter8 = 0xc00000f6, InvalidParameter9 = 0xc00000f7, InvalidParameter10 = 0xc00000f8, InvalidParameter11 = 0xc00000f9, InvalidParameter12 = 0xc00000fa, ProcessIsTerminating = 0xc000010a, MappedFileSizeZero = 0xc000011e, TooManyOpenedFiles = 0xc000011f, Cancelled = 0xc0000120, CannotDelete = 0xc0000121, InvalidComputerName = 0xc0000122, FileDeleted = 0xc0000123, SpecialAccount = 0xc0000124, SpecialGroup = 0xc0000125, SpecialUser = 0xc0000126, MembersPrimaryGroup = 0xc0000127, FileClosed = 0xc0000128, TooManyThreads = 0xc0000129, ThreadNotInProcess = 0xc000012a, TokenAlreadyInUse = 0xc000012b, PagefileQuotaExceeded = 0xc000012c, CommitmentLimit = 0xc000012d, InvalidImageLeFormat = 0xc000012e, InvalidImageNotMz = 0xc000012f, InvalidImageProtect = 0xc0000130, InvalidImageWin16 = 0xc0000131, LogonServer = 0xc0000132, DifferenceAtDc = 0xc0000133, SynchronizationRequired = 0xc0000134, DllNotFound = 0xc0000135, IoPrivilegeFailed = 0xc0000137, OrdinalNotFound = 0xc0000138, EntryPointNotFound = 0xc0000139, ControlCExit = 0xc000013a, InvalidAddress = 0xc0000141, PortNotSet = 0xc0000353, DebuggerInactive = 0xc0000354, CallbackBypass = 0xc0000503, PortClosed = 0xc0000700, MessageLost = 0xc0000701, InvalidMessage = 0xc0000702, RequestCanceled = 0xc0000703, RecursiveDispatch = 0xc0000704, LpcReceiveBufferExpected = 0xc0000705, LpcInvalidConnectionUsage = 0xc0000706, LpcRequestsNotAllowed = 0xc0000707, ResourceInUse = 0xc0000708, ProcessIsProtected = 0xc0000712, VolumeDirty = 0xc0000806, FileCheckedOut = 0xc0000901, CheckOutRequired = 0xc0000902, BadFileType = 0xc0000903, FileTooLarge = 0xc0000904, FormsAuthRequired = 0xc0000905, VirusInfected = 0xc0000906, VirusDeleted = 0xc0000907, TransactionalConflict = 0xc0190001, InvalidTransaction = 0xc0190002, TransactionNotActive = 0xc0190003, TmInitializationFailed = 0xc0190004, RmNotActive = 0xc0190005, RmMetadataCorrupt = 0xc0190006, TransactionNotJoined = 0xc0190007, DirectoryNotRm = 0xc0190008, CouldNotResizeLog = 0xc0190009, TransactionsUnsupportedRemote = 0xc019000a, LogResizeInvalidSize = 0xc019000b, RemoteFileVersionMismatch = 0xc019000c, CrmProtocolAlreadyExists = 0xc019000f, TransactionPropagationFailed = 0xc0190010, CrmProtocolNotFound = 0xc0190011, TransactionSuperiorExists = 0xc0190012, TransactionRequestNotValid = 0xc0190013, TransactionNotRequested = 0xc0190014, TransactionAlreadyAborted = 0xc0190015, TransactionAlreadyCommitted = 0xc0190016, TransactionInvalidMarshallBuffer = 0xc0190017, CurrentTransactionNotValid = 0xc0190018, LogGrowthFailed = 0xc0190019, ObjectNoLongerExists = 0xc0190021, StreamMiniversionNotFound = 0xc0190022, StreamMiniversionNotValid = 0xc0190023, MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024, CantOpenMiniversionWithModifyIntent = 0xc0190025, CantCreateMoreStreamMiniversions = 0xc0190026, HandleNoLongerValid = 0xc0190028, NoTxfMetadata = 0xc0190029, LogCorruptionDetected = 0xc0190030, CantRecoverWithHandleOpen = 0xc0190031, RmDisconnected = 0xc0190032, EnlistmentNotSuperior = 0xc0190033, RecoveryNotNeeded = 0xc0190034, RmAlreadyStarted = 0xc0190035, FileIdentityNotPersistent = 0xc0190036, CantBreakTransactionalDependency = 0xc0190037, CantCrossRmBoundary = 0xc0190038, TxfDirNotEmpty = 0xc0190039, IndoubtTransactionsExist = 0xc019003a, TmVolatile = 0xc019003b, RollbackTimerExpired = 0xc019003c, TxfAttributeCorrupt = 0xc019003d, EfsNotAllowedInTransaction = 0xc019003e, TransactionalOpenNotAllowed = 0xc019003f, TransactedMappingUnsupportedRemote = 0xc0190040, TxfMetadataAlreadyPresent = 0xc0190041, TransactionScopeCallbacksNotSet = 0xc0190042, TransactionRequiredPromotion = 0xc0190043, CannotExecuteFileInTransaction = 0xc0190044, TransactionsNotFrozen = 0xc0190045, MaximumNtStatus = 0xffffffff }
        public struct PROCESS_BASIC_INFORMATION { public NTSTATUS ExitStatus; public IntPtr PebBaseAddress; public UIntPtr AffinityMask; public int BasePriority; public UIntPtr UniqueProcessId; public UIntPtr InheritedFromUniqueProcessId; }
        // Source: https://sergeyakopov.com/reading-pe-format-using-data-marshaling-in-net/
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


        static void Main(string[] args)
        {
            /*
            // 1
            IntPtr hProcess = GetModuleHandle("kernel32.dll");
            */
            /*
            // 2
            IntPtr k32 = GetModuleHandle("kernel32.dll");
            IntPtr addrOpenProcess = GetProcAddress(k32, "OpenProcess");
            OpenProcessDelegate auxOpenProcess = (OpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(addrOpenProcess, typeof(OpenProcessDelegate));
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            */
            // 3
            // IntPtr hProcess = Process.GetCurrentProcess().Handle;

            string process_str = args[0];
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, uint.Parse(process_str));

            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            uint temp = 0;

            Console.WriteLine("\nHandle value: \t\t\t{0}", hProcess);
            NTSTATUS success = ZwQueryInformationProcess(hProcess, 0x0, ref pbi, (uint)(IntPtr.Size * 6), ref temp);
            Console.WriteLine("\nNTSTATUS response: \t\t{0}\n", success);

            IntPtr ptrToBaseImage = (IntPtr)((Int64)pbi.PebBaseAddress + 0x10);
            //Console.WriteLine("ptrToBaseImage " + ptrToBaseImage);
            //Console.WriteLine("ptrToBaseImage 0x" + ptrToBaseImage.ToString("X"));

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nread = IntPtr.Zero;

            bool succ = ReadProcessMemory(hProcess, ptrToBaseImage, addrBuf, addrBuf.Length, out nread);
            if (succ)
            {
                Console.WriteLine("[+] Process correctly read\n");
            }
            IntPtr pDosHdr = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

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
                    // Console.WriteLine(IntPtr.Size);
                    ReadProcessMemory(hProcess, auxaddressOfNamesRA, data5, data5.Length, out nread);
                    UInt32 functionAddressVRA = MarshalBytesTo<UInt32>(data5);
                    IntPtr functionAddressRA = IntPtr.Add(pDosHdr, (int)functionAddressVRA);
                    //Console.WriteLine("addressOfNames1VRA: \t0x" + functionAddress1VRA.ToString("X"));
                    Console.WriteLine("Function address (RA): \t\t0x" + functionAddressRA.ToString("X"));
                    byte[] data6 = new byte[50];
                    ReadProcessMemory(hProcess, functionAddressRA, data6, data6.Length, out nread);
                    String functionName = Encoding.ASCII.GetString(data6.TakeWhile(b => !b.Equals(0)).ToArray());
                    Console.WriteLine("Function name: \t\t\t" + functionName);
                    auxaddressOfNamesRA += 4;
                }
            }
        }
    }
}
