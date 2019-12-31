/*
*	Module Name:
*		infinityhook.cpp
*
*	Abstract:
*		The implementation details of infinity hook.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#include "stdafx.h"
#include "infinityhook.h"
#include "img.h"
#include "mm.h"

//
// Used internally for IfhpModifyTraceSettings.
//
enum CKCL_TRACE_OPERATION
{
	CKCL_TRACE_START,
	CKCL_TRACE_SYSCALL,
	CKCL_TRACE_END
};

//
// To enable/disable tracing on the circular kernel context logger.
//
typedef struct _CKCL_TRACE_PROPERIES: EVENT_TRACE_PROPERTIES
{
	ULONG64					Unknown[3];
	UNICODE_STRING			ProviderName;
} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

static BOOLEAN IfhpResolveSymbols();

static NTSTATUS IfhpModifyTraceSettings(
	_In_ CKCL_TRACE_OPERATION Operation);

static ULONG64 IfhpInternalGetCpuClock();

//
// Works from Windows 7+. You can backport this to Vista if you
// include an OS check and add the Vista appropriate signature.
//
UCHAR EtwpDebuggerDataPattern[] = 
{ 
	0x2c, 
	0x08, 
	0x04, 
	0x38, 
	0x0c 
};

//
// _WMI_LOGGER_CONTEXT.GetCpuClock.
//
#define OFFSET_WMI_LOGGER_CONTEXT_CPU_CYCLE_CLOCK 0x28

//
// _KPCR.Prcb.RspBase.
//
#define OFFSET_KPCR_RSP_BASE 0x1A8

//
// _KPCR.Prcb.CurrentThread.
//
#define OFFSET_KPCR_CURRENT_THREAD 0x188

//
// _KTHREAD.SystemCallNumber.
//
#define OFFSET_KTHREAD_SYSTEM_CALL_NUMBER 0x80

//
// EtwpDebuggerData silos.
//
#define OFFSET_ETW_DEBUGGER_DATA_SILO 0x10

//
// The index of the circular kernel context logger.
//
#define INDEX_CKCL_LOGGER 2

//
// Magic values on the stack. We use this to filter out system call 
// exit events.
//
#define INFINITYHOOK_MAGIC_1 ((ULONG)0x501802)
#define INFINITYHOOK_MAGIC_2 ((USHORT)0xF33)

#define kprintf(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)

struct _infinityhook_offset
{
	ULONG offset_wmi_logger_context_cpu_cycle_clock;
	ULONG offset_kthread_system_call_number;
};

_infinityhook_offset g_offset;

static bool IfhpInitialized = false;
static INFINITYHOOKCALLBACK IfhpCallback = NULL;

static const void* EtwpDebuggerData = NULL;
static PVOID CkclWmiLoggerContext = NULL;
static PVOID SystemCallEntryPage = NULL;
using NtTraceControlType = decltype(&NtTraceControl);
static NtTraceControlType g_pfnNtTraceControl = NULL;
PVOID g_pSystemCallReturnAddress = NULL;

void IfhInitAntiUserStopUpdateTrack()
{
	UNICODE_STRING usName = RTL_CONSTANT_STRING(L"NtTraceControl");

	g_pfnNtTraceControl = (NtTraceControlType)MmGetSystemRoutineAddress(&usName);

}
/*
*	Initialize infinity hook: executes your user defined callback on 
*	each syscall. You can extend this functionality to do other things
*	like trap on page faults, context switches, and more... This demo
*	only does syscalls.
*/
NTSTATUS IfhInitialize(_In_ 
	INFINITYHOOKCALLBACK InfinityHookCallback)
{
	if (IfhpInitialized)
	{
		return STATUS_ACCESS_DENIED;
	}

	IfhInitAntiUserStopUpdateTrack();

	RtlZeroMemory(&g_offset, sizeof(_infinityhook_offset));

	if (*NtBuildNumber < 8600)
	{
		g_offset.offset_kthread_system_call_number = 0x1f8;
		g_offset.offset_wmi_logger_context_cpu_cycle_clock = 0x18;
	}
	else
	{
		g_offset.offset_kthread_system_call_number = 0x80;
		g_offset.offset_wmi_logger_context_cpu_cycle_clock = 0x28;
	}

	//REGHANDLE handle = NULL;
	/*
	MS_Kernel_BootDiagnostics_SystemProxy_Provider PerfDiagpBootSystemProxyCallback 3
	MS_Kernel_BootDiagnostics_UserProxy_Provider PerfDiagpBootUserProxyCallback 4
	MS_Kernel_ShutdownDiagnostics_Proxy_Provider PerfDiagpShutdownProxyCallback 5

	INIT:000000014058A3F0                               PerfDiagInitialize proc near            ; CODE XREF: WdiInitialize+9p
	INIT:000000014058A3F0 48 83 EC 28                                   sub     rsp, 28h
	INIT:000000014058A3F4 48 83 25 DC BC C9 FF 00                       and     cs:qword_1402260D8, 0
	INIT:000000014058A3FC 83 25 DD BC C9 FF 00                          and     cs:dword_1402260E0, 0
	INIT:000000014058A403 4C 8D 0D B6 BC C9 FF                          lea     r9, PerfDiagGlobals
	INIT:000000014058A40A 48 8D 15 BF 00 EF FF                          lea     rdx, PerfDiagpBootSystemProxyCallback
	INIT:000000014058A411 48 8D 0D 30 86 C6 FF                          lea     rcx, MS_Kernel_BootDiagnostics_SystemProxy_Provider
	INIT:000000014058A418 45 33 C0                                      xor     r8d, r8d
	INIT:000000014058A41B E8 30 8B EC FF                                call    EtwRegister
	INIT:000000014058A420 4C 8D 0D A1 BC C9 FF                          lea     r9, unk_1402260C8
	INIT:000000014058A427 48 8D 15 72 00 EF FF                          lea     rdx, PerfDiagpBootUserProxyCallback
	INIT:000000014058A42E 48 8D 0D 23 86 C6 FF                          lea     rcx, MS_Kernel_BootDiagnostics_UserProxy_Provider
	INIT:000000014058A435 45 33 C0                                      xor     r8d, r8d
	INIT:000000014058A438 E8 13 8B EC FF                                call    EtwRegister
	INIT:000000014058A43D 4C 8D 0D 8C BC C9 FF                          lea     r9, unk_1402260D0
	INIT:000000014058A444 48 8D 15 25 00 EF FF                          lea     rdx, PerfDiagpShutdownProxyCallback
	INIT:000000014058A44B 48 8D 0D 16 86 C6 FF                          lea     rcx, MS_Kernel_ShutdownDiagnostics_Proxy_Provider ; "\x10z\\"
	INIT:000000014058A452 45 33 C0                                      xor     r8d, r8d
	INIT:000000014058A455 48 83 C4 28                                   add     rsp, 28h
	INIT:000000014058A459 E9 F2 8A EC FF                                jmp     EtwRegister
	INIT:000000014058A459                               ; ---------------------------------------------------------------------------
	INIT:000000014058A45E 90 90 90 90 90 90 90 90 90 90+                db 12h dup(90h)
	INIT:000000014058A45E 90 90 90 90 90 90 90 90       PerfDiagInitialize endp
	*/

	//
	// Let's assume CKCL session is already started (which is the 
	// default scenario) and try to update it for system calls only.
	//
	NTSTATUS Status = IfhpModifyTraceSettings(CKCL_TRACE_START);
	if (!NT_SUCCESS(Status))
	{
		//
		// Failed... let's try to turn it on.
		//
		Status = IfhpModifyTraceSettings(CKCL_TRACE_END);

		//
		// Failed again... We exit here, but it's possible to setup
		// a custom logger instead and use SystemTraceProvider instead
		// of hijacking the circular kernel context logger.
		//
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}

		Status = IfhpModifyTraceSettings(CKCL_TRACE_START);
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}
	}	

	//
	// We need to resolve certain unexported symbols.
	//
	if (!IfhpResolveSymbols())
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	IfhpCallback = InfinityHookCallback;

	//
	// CkclWmiLoggerContext is a WMI_LOGGER_CONTEXT structure:
	//
	/*
		0: kd> dt nt!_WMI_LOGGER_CONTEXT
			   +0x000 LoggerId         : Uint4B
			   +0x004 BufferSize       : Uint4B
			   +0x008 MaximumEventSize : Uint4B
			   +0x00c LoggerMode       : Uint4B
			   +0x010 AcceptNewEvents  : Int4B
			   +0x014 EventMarker      : [2] Uint4B
			   +0x01c ErrorMarker      : Uint4B
			   +0x020 SizeMask         : Uint4B
			   +0x028 GetCpuClock      : Ptr64     int64
			   +0x030 LoggerThread     : Ptr64 _ETHREAD
			   +0x038 LoggerStatus     : Int4B
			   +0x03c FailureReason    : Uint4B
			   +0x040 BufferQueue      : _ETW_BUFFER_QUEUE
			   +0x050 OverflowQueue    : _ETW_BUFFER_QUEUE
			   +0x060 GlobalList       : _LIST_ENTRY
			   +0x070 DebugIdTrackingList : _LIST_ENTRY
			   +0x080 DecodeControlList : Ptr64 _ETW_DECODE_CONTROL_ENTRY
			   +0x088 DecodeControlCount : Uint4B
			   +0x090 BatchedBufferList : Ptr64 _WMI_BUFFER_HEADER
			   +0x090 CurrentBuffer    : _EX_FAST_REF
			   +0x098 LoggerName       : _UNICODE_STRING
			   +0x0a8 LogFileName      : _UNICODE_STRING
			   +0x0b8 LogFilePattern   : _UNICODE_STRING
			   +0x0c8 NewLogFileName   : _UNICODE_STRING
			   +0x0d8 ClockType        : Uint4B
			   +0x0dc LastFlushedBuffer : Uint4B
			   +0x0e0 FlushTimer       : Uint4B
			   +0x0e4 FlushThreshold   : Uint4B
			   +0x0e8 ByteOffset       : _LARGE_INTEGER
			   +0x0f0 MinimumBuffers   : Uint4B
			   +0x0f4 BuffersAvailable : Int4B
			   +0x0f8 NumberOfBuffers  : Int4B
			   +0x0fc MaximumBuffers   : Uint4B
			   +0x100 EventsLost       : Uint4B
			   +0x104 PeakBuffersCount : Int4B
			   +0x108 BuffersWritten   : Uint4B
			   +0x10c LogBuffersLost   : Uint4B
			   +0x110 RealTimeBuffersDelivered : Uint4B
			   +0x114 RealTimeBuffersLost : Uint4B
			   +0x118 SequencePtr      : Ptr64 Int4B
			   +0x120 LocalSequence    : Uint4B
			   +0x124 InstanceGuid     : _GUID
			   +0x134 MaximumFileSize  : Uint4B
			   +0x138 FileCounter      : Int4B
			   +0x13c PoolType         : _POOL_TYPE
			   +0x140 ReferenceTime    : _ETW_REF_CLOCK
			   +0x150 CollectionOn     : Int4B
			   +0x154 ProviderInfoSize : Uint4B
			   +0x158 Consumers        : _LIST_ENTRY
			   +0x168 NumConsumers     : Uint4B
			   +0x170 TransitionConsumer : Ptr64 _ETW_REALTIME_CONSUMER
			   +0x178 RealtimeLogfileHandle : Ptr64 Void
			   +0x180 RealtimeLogfileName : _UNICODE_STRING
			   +0x190 RealtimeWriteOffset : _LARGE_INTEGER
			   +0x198 RealtimeReadOffset : _LARGE_INTEGER
			   +0x1a0 RealtimeLogfileSize : _LARGE_INTEGER
			   +0x1a8 RealtimeLogfileUsage : Uint8B
			   +0x1b0 RealtimeMaximumFileSize : Uint8B
			   +0x1b8 RealtimeBuffersSaved : Uint4B
			   +0x1c0 RealtimeReferenceTime : _ETW_REF_CLOCK
			   +0x1d0 NewRTEventsLost  : _ETW_RT_EVENT_LOSS
			   +0x1d8 LoggerEvent      : _KEVENT
			   +0x1f0 FlushEvent       : _KEVENT
			   +0x208 FlushTimeOutTimer : _KTIMER
			   +0x248 LoggerDpc        : _KDPC
			   +0x288 LoggerMutex      : _KMUTANT
			   +0x2c0 LoggerLock       : _EX_PUSH_LOCK
			   +0x2c8 BufferListSpinLock : Uint8B
			   +0x2c8 BufferListPushLock : _EX_PUSH_LOCK
			   +0x2d0 ClientSecurityContext : _SECURITY_CLIENT_CONTEXT
			   +0x318 TokenAccessInformation : Ptr64 _TOKEN_ACCESS_INFORMATION
			   +0x320 SecurityDescriptor : _EX_FAST_REF
			   +0x328 StartTime        : _LARGE_INTEGER
			   +0x330 LogFileHandle    : Ptr64 Void
			   +0x338 BufferSequenceNumber : Int8B
			   +0x340 Flags            : Uint4B
			   +0x340 Persistent       : Pos 0, 1 Bit
			   +0x340 AutoLogger       : Pos 1, 1 Bit
			   +0x340 FsReady          : Pos 2, 1 Bit
			   +0x340 RealTime         : Pos 3, 1 Bit
			   +0x340 Wow              : Pos 4, 1 Bit
			   +0x340 KernelTrace      : Pos 5, 1 Bit
			   +0x340 NoMoreEnable     : Pos 6, 1 Bit
			   +0x340 StackTracing     : Pos 7, 1 Bit
			   +0x340 ErrorLogged      : Pos 8, 1 Bit
			   +0x340 RealtimeLoggerContextFreed : Pos 9, 1 Bit
			   +0x340 PebsTracing      : Pos 10, 1 Bit
			   +0x340 PmcCounters      : Pos 11, 1 Bit
			   +0x340 PageAlignBuffers : Pos 12, 1 Bit
			   +0x340 StackLookasideListAllocated : Pos 13, 1 Bit
			   +0x340 SecurityTrace    : Pos 14, 1 Bit
			   +0x340 LastBranchTracing : Pos 15, 1 Bit
			   +0x340 SystemLoggerIndex : Pos 16, 8 Bits
			   +0x340 StackCaching     : Pos 24, 1 Bit
			   +0x340 ProviderTracking : Pos 25, 1 Bit
			   +0x340 ProcessorTrace   : Pos 26, 1 Bit
			   +0x340 QpcDeltaTracking : Pos 27, 1 Bit
			   +0x340 MarkerBufferSaved : Pos 28, 1 Bit
			   +0x340 SpareFlags2      : Pos 29, 3 Bits
			   +0x344 RequestFlag      : Uint4B
			   +0x344 DbgRequestNewFile : Pos 0, 1 Bit
			   +0x344 DbgRequestUpdateFile : Pos 1, 1 Bit
			   +0x344 DbgRequestFlush  : Pos 2, 1 Bit
			   +0x344 DbgRequestDisableRealtime : Pos 3, 1 Bit
			   +0x344 DbgRequestDisconnectConsumer : Pos 4, 1 Bit
			   +0x344 DbgRequestConnectConsumer : Pos 5, 1 Bit
			   +0x344 DbgRequestNotifyConsumer : Pos 6, 1 Bit
			   +0x344 DbgRequestUpdateHeader : Pos 7, 1 Bit
			   +0x344 DbgRequestDeferredFlush : Pos 8, 1 Bit
			   +0x344 DbgRequestDeferredFlushTimer : Pos 9, 1 Bit
			   +0x344 DbgRequestFlushTimer : Pos 10, 1 Bit
			   +0x344 DbgRequestUpdateDebugger : Pos 11, 1 Bit
			   +0x344 DbgSpareRequestFlags : Pos 12, 20 Bits
			   +0x350 StackTraceBlock  : _ETW_STACK_TRACE_BLOCK
			   +0x3d0 HookIdMap        : _RTL_BITMAP
			   +0x3e0 StackCache       : Ptr64 _ETW_STACK_CACHE
			   +0x3e8 PmcData          : Ptr64 _ETW_PMC_SUPPORT
			   +0x3f0 LbrData          : Ptr64 _ETW_LBR_SUPPORT
			   +0x3f8 IptData          : Ptr64 _ETW_IPT_SUPPORT
			   +0x400 BinaryTrackingList : _LIST_ENTRY
			   +0x410 ScratchArray     : Ptr64 Ptr64 _WMI_BUFFER_HEADER
			   +0x418 DisallowedGuids  : _DISALLOWED_GUIDS
			   +0x428 RelativeTimerDueTime : Int8B
			   +0x430 PeriodicCaptureStateGuids : _PERIODIC_CAPTURE_STATE_GUIDS
			   +0x440 PeriodicCaptureStateTimer : Ptr64 _EX_TIMER
			   +0x448 PeriodicCaptureStateTimerState : _ETW_PERIODIC_TIMER_STATE
			   +0x450 SoftRestartContext : Ptr64 _ETW_SOFT_RESTART_CONTEXT
			   +0x458 SiloState        : Ptr64 _ETW_SILODRIVERSTATE
			   +0x460 CompressionWorkItem : _WORK_QUEUE_ITEM
			   +0x480 CompressionWorkItemState : Int4B
			   +0x488 CompressionLock  : _EX_PUSH_LOCK
			   +0x490 CompressionTarget : Ptr64 _WMI_BUFFER_HEADER
			   +0x498 CompressionWorkspace : Ptr64 Void
			   +0x4a0 CompressionOn    : Int4B
			   +0x4a4 CompressionRatioGuess : Uint4B
			   +0x4a8 PartialBufferCompressionLevel : Uint4B
			   +0x4ac CompressionResumptionMode : ETW_COMPRESSION_RESUMPTION_MODE
			   +0x4b0 PlaceholderList  : _SINGLE_LIST_ENTRY
			   +0x4b8 CompressionDpc   : _KDPC
			   +0x4f8 LastBufferSwitchTime : _LARGE_INTEGER
			   +0x500 BufferWriteDuration : _LARGE_INTEGER
			   +0x508 BufferCompressDuration : _LARGE_INTEGER
			   +0x510 ReferenceQpcDelta : Int8B
			   +0x518 CallbackContext  : Ptr64 _ETW_EVENT_CALLBACK_CONTEXT
			   +0x520 LastDroppedTime  : Ptr64 _LARGE_INTEGER
			   +0x528 FlushingLastDroppedTime : Ptr64 _LARGE_INTEGER
			   +0x530 FlushingSequenceNumber : Int8B
	*/

	//
	// We care about overwriting the GetCpuClock (+0x28) pointer in 
	// this structure.
	//
	PVOID* AddressOfEtwpGetCycleCount = (PVOID*)((uintptr_t)CkclWmiLoggerContext + g_offset.offset_wmi_logger_context_cpu_cycle_clock);
	
	//
	// Replace this function pointer with our own. Each time syscall
	// is logged by ETW, it will invoke our new timing function.
	//
	*AddressOfEtwpGetCycleCount = IfhpInternalGetCpuClock;

	IfhpInitialized = true;

	return STATUS_SUCCESS;
}

/*
*	Disables and then re-enables the circular kernel context logger,
*	clearing the system of the infinity hook pointer override.
*/
void IfhRelease()
{
	if (!IfhpInitialized)
	{
		return;
	}

	IfhpModifyTraceSettings(CKCL_TRACE_END);

	IfhpInitialized = false;
}

/*
*	Resolves necessary unexported symbols.
*/
static BOOLEAN IfhpResolveSymbols()
{
	//
	// We need to resolve nt!EtwpDebuggerData to get the current ETW
	// sessions WMI_LOGGER_CONTEXTS, find the CKCL, and overwrite its
	// GetCpuClock function pointer.
	//
	PVOID NtBaseAddress = NULL;
	ULONG SizeOfNt = 0;
	NtBaseAddress = ImgGetBaseAddress(NULL, &SizeOfNt);
	if (!NtBaseAddress)
	{
		return FALSE;
	}

	ULONG SizeOfSection;
	PVOID SectionBase = ImgGetImageSection(NtBaseAddress, ".data", &SizeOfSection);
	if (!SectionBase)
	{
		return FALSE;
	}

	//
	// Look for the EtwpDebuggerData global using the signature. This 
	// should be the same for Windows 7+.
	//
	EtwpDebuggerData = MmSearchMemory(SectionBase, SizeOfSection, EtwpDebuggerDataPattern, RTL_NUMBER_OF(EtwpDebuggerDataPattern));
	if (!EtwpDebuggerData)
	{
		//
		// Check inside of .rdata too... this is true for Windows 7.
		// Thanks to @ivanpos2015 for reporting.
		//
		SectionBase = ImgGetImageSection(NtBaseAddress, ".rdata", &SizeOfSection);
		if (!SectionBase)
		{
            // Windows 7 6.1.7601.24441
            SectionBase = ImgGetImageSection(NtBaseAddress, ".text", &SizeOfSection);
            if (!SectionBase)
            {
                return FALSE;
            }
		}

		EtwpDebuggerData = MmSearchMemory(SectionBase, SizeOfSection, EtwpDebuggerDataPattern, RTL_NUMBER_OF(EtwpDebuggerDataPattern));
		if (!EtwpDebuggerData)
		{
			return FALSE;
		}
	}

	// 
	// This is offset by 2 bytes due to where the signature starts.
	//
	EtwpDebuggerData = (PVOID)((uintptr_t)EtwpDebuggerData - 2);
	
	//
	// Get the silos of EtwpDebuggerData.
	//
	PVOID* EtwpDebuggerDataSilo = *(PVOID**)((uintptr_t)EtwpDebuggerData + OFFSET_ETW_DEBUGGER_DATA_SILO);

	kprintf("EtwpDebuggerData:0x%p\n", EtwpDebuggerData);
	kprintf("EtwpDebuggerDataSilo:0x%p\n", EtwpDebuggerDataSilo);
	//
	// Pull out the circular kernel context logger.
	//
	CkclWmiLoggerContext = EtwpDebuggerDataSilo[0];//EtwpDebuggerDataSilo[INDEX_CKCL_LOGGER];
	kprintf("CkclWmiLoggerContext:0x%p\n", CkclWmiLoggerContext);
	//DbgBreakPoint();
	//
	// Grab the system call entry value.
	//
	SystemCallEntryPage = PAGE_ALIGN(ImgGetSyscallEntry());
	if (!SystemCallEntryPage)
	{
		return FALSE;
	}

	return TRUE;
}

/*
*	Modify the trace settings for the circular kernel context logger.
*/
static NTSTATUS IfhpModifyTraceSettings(
	_In_ CKCL_TRACE_OPERATION Operation)
{
	PCKCL_TRACE_PROPERTIES Property = (PCKCL_TRACE_PROPERTIES)ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (!Property)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	auto szlen = wcslen(L"NT Kernel Logger");
	WCHAR* szProvider = (WCHAR*)ExAllocatePool(NonPagedPool, (szlen + 1) * sizeof(WCHAR));

	if (szProvider == NULL)
		return STATUS_MEMORY_NOT_ALLOCATED;

	RtlZeroMemory(szProvider, (szlen + 1) * sizeof(WCHAR));

	RtlCopyMemory(szProvider, L"NT Kernel Logger", szlen * 2);

	// WmipLoggerContext

	memset(Property, 0, PAGE_SIZE);

	Property->Wnode.BufferSize = PAGE_SIZE;
	Property->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	Property->ProviderName.Buffer = szProvider;
	Property->ProviderName.Length = szlen * sizeof(WCHAR);
	Property->ProviderName.MaximumLength = (szlen + 1) * sizeof(WCHAR);
	Property->Wnode.Guid = SystemTraceControlGuid;
	Property->Wnode.ClientContext = 1;
	Property->BufferSize = 4;
	Property->MinimumBuffers = 2;
	Property->MaximumFileSize = 5;
	Property->LogFileMode = EVENT_TRACE_BUFFERING_MODE;
	Property->FlushTimer = 1;
	Property->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
	Property->NumberOfBuffers = 1;

	NTSTATUS Status = STATUS_ACCESS_DENIED;
	ULONG ReturnLength = 0;

	//
	// Might be wise to actually hook ZwTraceControl so folks don't 
	// disable your infinity hook ;).
	//
	switch (Operation)
	{
		case CKCL_TRACE_START:
		{
			Status = NtTraceControl(EtwpStartTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
			break;
		}
		case CKCL_TRACE_END:
		{
			Status = NtTraceControl(EtwpStopTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
			break;
		}
		//case CKCL_TRACE_SYSCALL:
		//{
		//	//
		//	// Add more flags here to trap on more events!
		//	//
		//	Property->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;

		//	Status = NtTraceControl(EtwpUpdateTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
		//	break;
		//}
	}

	ExFreePool(Property->ProviderName.Buffer);
	ExFreePool(Property);

	return Status;
}

NTSTATUS
NTAPI
AntiUserCallNtTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
)
{
	if (FunctionCode == EtwpStartTrace || FunctionCode == EtwpStopTrace || FunctionCode == EtwpUpdateTrace)
	{
		PCKCL_TRACE_PROPERTIES p = (PCKCL_TRACE_PROPERTIES)InBuffer;

		if (InBufferLen >= sizeof(_CKCL_TRACE_PROPERIES))
		{
			if (IsEqualGUID(p->Wnode.Guid, SystemTraceControlGuid))
			{
				kprintf("anti user call NtTraceControl: %d, pid:%d, TraceInfo:0x%p.\n", FunctionCode, PsGetCurrentProcessId(), p);
				//DbgBreakPoint();
				return STATUS_ACCESS_DENIED;
			}
		}
	}

	return g_pfnNtTraceControl(FunctionCode, InBuffer, InBufferLen, OutBuffer, OutBufferLen, ReturnLength);
}

/*
*	We replaced the GetCpuClock pointer to this one here which 
*	implements stack walking logic. We use this to determine whether 
*	a syscall occurred. It also provides you a way to alter the 
*	address on the stack to redirect execution to your detoured
*	function.
*	
*/
static ULONG64 IfhpInternalGetCpuClock()
{
	if (ExGetPreviousMode() == KernelMode)
	{
		return __rdtsc();
	}

	//
	// Extract the system call index (if you so desire).
	//
	PKTHREAD CurrentThread = (PKTHREAD)__readgsqword(OFFSET_KPCR_CURRENT_THREAD);
	unsigned int SystemCallIndex = *(unsigned int*)((uintptr_t)CurrentThread + g_offset.offset_kthread_system_call_number);

	PVOID* StackMax = (PVOID*)__readgsqword(OFFSET_KPCR_RSP_BASE);
	PVOID* StackFrame = (PVOID*)_AddressOfReturnAddress();

	//
	// First walk backwards on the stack to find the 2 magic values.
	//
	for (PVOID* StackCurrent = StackMax; 
		StackCurrent > StackFrame;
		--StackCurrent)
	{
		// 
		// This is intentionally being read as 4-byte magic on an 8
		// byte aligned boundary.
		//
		PULONG AsUlong = (PULONG)StackCurrent;
		if (*AsUlong != INFINITYHOOK_MAGIC_1)
		{
			continue;
		}

		// 
		// If the first magic is set, check for the second magic.
		//
		--StackCurrent;

		PUSHORT AsShort = (PUSHORT)StackCurrent;
		if (*AsShort != INFINITYHOOK_MAGIC_2)
		{
			continue;
		}

		if (g_pSystemCallReturnAddress == NULL)
		{
			PVOID pCall = ExAllocatePoolWithTag(NonPagedPool, 200 * sizeof(PVOID), 'call');

			if (pCall == NULL)
				DbgBreakPoint();

			RtlZeroMemory(pCall, 200 * sizeof(PVOID));
			auto StackCount = RtlWalkFrameChain((PVOID*)pCall, 200, 0);

			kprintf("StackCount=%ld\n", StackCount);
			for (ULONG i = 0; i < StackCount; i++)
			{
				ULONGLONG call = (ULONGLONG)((PVOID*)(pCall))[i];

				kprintf("Stack[%d]=%p\n", i, call);
				if (PAGE_ALIGN(call) >= SystemCallEntryPage &&
					PAGE_ALIGN(call) < (PVOID)((uintptr_t)SystemCallEntryPage + (PAGE_SIZE * 2)))
				{
					g_pSystemCallReturnAddress = (PVOID)call;
					kprintf("SystemCallReturnAddress:0x%p, SystemCallEntryPage:0x%p\n", g_pSystemCallReturnAddress, SystemCallEntryPage);
					break;
					//DbgBreakPoint();
				}
			}

			ExFreePoolWithTag(pCall, 'call');

		}

		if (g_pSystemCallReturnAddress == NULL)
			break;

		for (; StackCurrent < StackMax; ++StackCurrent)
		{
			PULONGLONG AsUlonglong = (PULONGLONG)StackCurrent;
			if (*AsUlonglong != (ULONGLONG)g_pSystemCallReturnAddress)
				continue;

			void** SystemCallFunction = &StackCurrent[9];

			/*if(SystemCallIndex == 7)
				kprintf("index:%d, SystemcCallAddress:0x%p, stack:0x%p\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);*/

			if (*SystemCallFunction == g_pfnNtTraceControl)
			{
				*SystemCallFunction = AntiUserCallNtTraceControl;
				break;
			}

			if (IfhpCallback)
			{
				IfhpCallback(SystemCallIndex, SystemCallFunction);
			}

			break;
		}
		
		break;
	}

		//
		// Now we reverse the direction of the stack walk.
		//
		//for (;
		//	StackCurrent < StackMax;
		//	++StackCurrent)
		//{
		//	PULONGLONG AsUlonglong = (PULONGLONG)StackCurrent;

		//	if (!(PAGE_ALIGN(*AsUlonglong) >= SystemCallEntryPage && 
		//		PAGE_ALIGN(*AsUlonglong) < (PVOID)((uintptr_t)SystemCallEntryPage + (PAGE_SIZE * 2))))
		//	{
		//		continue;
		//	}

		//	//
		//	// If you want to "hook" this function, replace this stack memory 
		//	// with a pointer to your own function.
		//	//

		//	void** SystemCallFunction = &StackCurrent[9];

		//	if (*SystemCallFunction == g_pfnNtTraceControl)
		//	{
		//		*SystemCallFunction = AntiUserCallNtTraceControl;
		//		break;
		//	}

		//	if (IfhpCallback)
		//	{
		//		IfhpCallback(SystemCallIndex, SystemCallFunction);
		//	}

		//	break;
		//}

		//break;
	//}

	return __rdtsc();
}