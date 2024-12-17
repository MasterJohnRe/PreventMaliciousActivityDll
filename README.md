# PreventMaliciousActivityDll

Simple minhook use to hook CreateFileW and check for it's use.
prevents the use of this function on important system dlls e.g ntdll.dll, kernel32.dll.
malicious softwares usually use this techniqe to map a syscall stub to the process virtual memory and use direct syscalls.

## How to Build/Compile

- Visual studio 2022 and its workload Desktop development with C++ are requiere
- https://github.com/TsudaKageyu/minhook I recommend installing it via vcpkg
