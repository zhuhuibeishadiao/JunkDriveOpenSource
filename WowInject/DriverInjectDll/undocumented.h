#ifndef _UNDOCUMENTED_H
#define _UNDOCUMENTED_H

#include "_global.h"

//structures
typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfHandles;
    ULONG TotalNumberOfObjects;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION
{
    ULONG NumberOfObjects;
    OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

/*
//enums
typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectTypeInformation = 2,
    ObjectTypesInformation = 3
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;
*/

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemProcessInformation = 5,
    SystemModuleInformation = 11,
    SystemKernelDebuggerInformation = 35
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _SYSDBG_COMMAND
{
    SysDbgGetTriageDump = 29,
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

class Undocumented
{
public:
    static NTSTATUS NTAPI ZwQueryInformationProcess(
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID ProcessInformation,
        IN ULONG ProcessInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI ZwQueryInformationThread(
        IN HANDLE ThreadHandle,
        IN THREADINFOCLASS ThreadInformationClass,
        IN OUT PVOID ThreadInformation,
        IN ULONG ThreadInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI NtQueryObject(
        IN HANDLE Handle OPTIONAL,
        IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
        OUT PVOID ObjectInformation OPTIONAL,
        IN ULONG ObjectInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI ZwQuerySystemInformation(
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI NtQuerySystemInformation(
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI NtClose(
        IN HANDLE Handle);

    static NTSTATUS NTAPI NtSetContextThread(
        IN HANDLE ThreadHandle,
        IN PCONTEXT Context);

    static NTSTATUS NTAPI NtContinue(
        IN PCONTEXT Context,
        BOOLEAN RaiseAlert);

    static NTSTATUS NTAPI NtDuplicateObject(
        IN HANDLE SourceProcessHandle,
        IN HANDLE SourceHandle,
        IN HANDLE TargetProcessHandle,
        OUT PHANDLE TargetHandle,
        IN ACCESS_MASK DesiredAccess OPTIONAL,
        IN ULONG HandleAttributes,
        IN ULONG Options);

    static NTSTATUS NTAPI KeRaiseUserException(
        IN NTSTATUS ExceptionCode);

    static NTSTATUS NTAPI NtSetInformationThread(
        IN HANDLE ThreadHandle,
        IN THREADINFOCLASS ThreadInformationClass,
        IN PVOID ThreadInformation,
        IN ULONG ThreadInformationLength);

    static NTSTATUS NTAPI NtSetInformationProcess(
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        IN PVOID ProcessInformation,
        IN ULONG ProcessInformationLength);

    static NTSTATUS NTAPI NtQueryInformationProcess(
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID ProcessInformation,
        IN ULONG ProcessInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI NtSystemDebugControl(
        IN SYSDBG_COMMAND Command,
        IN PVOID InputBuffer OPTIONAL,
        IN ULONG InputBufferLength OPTIONAL,
        OUT PVOID OutputBuffer,
        IN ULONG OutputBufferLength,
        OUT PULONG ReturnLength OPTIONAL);

    static bool UndocumentedInit();
    static PVOID GetKernelBase(PULONG pImageSize = NULL);
};

#endif
