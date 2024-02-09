# GetProcAddress - C# implementation

It works like the [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) WinAPI: it takes a DLL handle and a function name or ordinal, walks the PEB structure and returns the function address. 

It only uses the [NtReadVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtFreeVirtualMemory.html) native API call, without using structs.

It works in both 32-bit and 64-bit processes. You can test this using the binaries in the Releases section:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/getProcAddress/Screenshot_2.png)


---------------------------------

### Sources

- Sektor7's Malware Intermediate course by [reenz0h](https://twitter.com/reenz0h) implements this code in C++

- PE File Format Offsets: [http://www.sunshine2k.de/reversing/tuts/tut_pe.htm](http://www.sunshine2k.de/reversing/tuts/tut_pe.htm)
