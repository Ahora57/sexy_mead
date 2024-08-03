#ifndef NTAPI_DEF
#define NTAPI_DEF
#include "struct.h"

NTSTATUS
NTAPI
NtQueryInformationProcess
(
    HANDLE              ProcessHandle,
    PROCESSINFOCLASS    ProcessInformationClass,
    PVOID               ProcessInformation,
    ULONG               ProcessInformationLength,
    PULONG              ReturnLength
);

NTSTATUS
NTAPI
NtQueryInformationThread
(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength,
    PULONG          ReturnLength
);

NTSTATUS
NTAPI
NtSetInformationThread
(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength
);

NTSTATUS
NTAPI
NtGetContextThread
(
    HANDLE              ThreadHandle,
    PCONTEXT            ThreadContext
);

NTSTATUS
NTAPI
Wow64QueryInformationProcess64
(
    HANDLE hProcess,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

NTSTATUS 
NTAPI 
NtWow64ReadVirtualMemory64
(
    HANDLE ProcessHandle, 
    PVOID64 BaseAddress, 
    PVOID Buffer, 
    ULONGLONG BufferSize, 
    PULONGLONG NumberOfBytesRead
);

NTSTATUS WINAPI NtWow64WriteVirtualMemory64
(
    HANDLE ProcessHandle, 
    PVOID64 BaseAddress, 
    LPCVOID Buffer, 
    ULONGLONG BufferSize, 
    PULONGLONG NumberOfBytesWritten
);


#endif // !NTAPI_DEF
