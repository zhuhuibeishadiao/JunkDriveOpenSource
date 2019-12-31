/*
*	Module Name:
*		entry.cpp
*
*	Abstract:
*		Sample driver that implements infinity hook to detour
*		system calls.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#include "stdafx.h"
#include "entry.h"
#include "infinityhook.h"

static wchar_t IfhMagicFileName[] = L"ifh--";

static UNICODE_STRING StringNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
static NtCreateFile_t OriginalNtCreateFile = NULL;

typedef NTSTATUS (*NtDeviceIoControlFileType)(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN ULONG                IoControlCode,
	IN PVOID                InputBuffer OPTIONAL,
	IN ULONG                InputBufferLength,
	OUT PVOID               OutputBuffer OPTIONAL,
	IN ULONG                OutputBufferLength);

extern "C" PSHORT NtBuildNumber;

typedef struct _DATA {
	ULONG IoControlIndex;
	LONG BuildNumber;
	NtDeviceIoControlFileType OriginalNtDeviceIoControlFile;
}DATA, *PDATA;

DATA g_dyData;

#define IOCONTROL_FILEHANDLE 10010
#define IOCODE_READ 1
#define IOCODE_WRITE 2
#define IOCODE_GETBASE 3

#define IOCODE_MAX 5


// 废除 使用 NtDeviceIoControlFile进行通信

NTSTATUS InitData()
{
	/*
	SP0(7600)SP1(7601)					 1507(10240) 1511(10586) 1607(14393) 1703(15063) 1709(16299) 1803(17134) 1809(17763) 1903(18362)
	0x0004 	 0x0004 					 0x0007 	 0x0007 	 0x0007 	 0x0007 	 0x0007 	 0x0007 	 0x0007 	 0x0007  NtDeviceIoControlFile
	*/

	RtlZeroMemory(&g_dyData, sizeof(DATA));

	g_dyData.BuildNumber = *NtBuildNumber;

	g_dyData.BuildNumber < 8600 ? g_dyData.IoControlIndex = 0x4 : g_dyData.IoControlIndex = 0x7;

	UNICODE_STRING StringNtDeviceIoControlFile = RTL_CONSTANT_STRING(L"NtDeviceIoControlFile");

	g_dyData.OriginalNtDeviceIoControlFile = (NtDeviceIoControlFileType)MmGetSystemRoutineAddress(&StringNtDeviceIoControlFile);

	if (g_dyData.OriginalNtDeviceIoControlFile == NULL)
		return STATUS_UNSUCCESSFUL;
	else
		return STATUS_SUCCESS;
}

/*
*	The entry point of the driver. Initializes infinity hook and
*	sets up the driver's unload routine so that it can be gracefully 
*	turned off.
*/
extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	kprintf("[+] infinityhook: Loaded.\n");

	DriverObject->DriverUnload = DriverUnload;

	NTSTATUS status = InitData();

	if (!NT_SUCCESS(status))
	{
		kprintf("[-] infinityhook: Failed to initialize with InitData.\n");
		return status;
	}

	status = IfhInitialize(SyscallStub);
	if (!NT_SUCCESS(status))
	{
		kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", status);
	}

	return status;
}

/*
*	Turns off infinity hook.
*/
void DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	//
	// Unload infinity hook gracefully.
	//
	IfhRelease();

	kprintf("\n[!] infinityhook: Unloading... BYE!\n");
}

/*
*	For each usermode syscall, this stub will be invoked.
*/
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

	UNREFERENCED_PARAMETER(SystemCallIndex);

	//
	// In our demo, we care only about nt!NtCreateFile calls.
	//
	if (*SystemCallFunction == g_dyData.OriginalNtDeviceIoControlFile)
	{
		//
		// We can overwrite the return address on the stack to our detoured
		// NtCreateFile.
		//
		DbgBreakPoint();
		*SystemCallFunction = DetourNtDeviceIoControlFile;
	}
}

NTSTATUS DetourNtDeviceIoControlFile(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN ULONG                IoControlCode,
	IN PVOID                InputBuffer OPTIONAL,
	IN ULONG                InputBufferLength,
	OUT PVOID               OutputBuffer OPTIONAL,
	IN ULONG                OutputBufferLength)
{

	if (FileHandle == (HANDLE)IOCONTROL_FILEHANDLE && IoControlCode < IOCODE_MAX)
	{
		kprintf("[+] infinityhook called.\n");
		return STATUS_SUCCESS;
	}

	return g_dyData.OriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}
