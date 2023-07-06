# GetProcAddress - C# implementation

This function takes a DLL handle and a function name, walks the PEB and returns the function address. 

It works works like the funtion [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) so it is useful if you want to avoid using it - this implementation uses only ReadProcessMemory.

It is the same idea than Sektor7's Malware Intermediate course by [reenz0h](https://twitter.com/reenz0h), but in that course the code is C++ and I wanted a implementation like this in C#, I could not find it so maybe this is useful for someone else.

There is a binary to test the functionality: 


![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/getProcAddress/Screenshot_1.png)
