#ifndef _PCH_H_
#define _PCH_H_

#include <ntifs.h>
#include <ntddk.h>
#include "HideDriver.h"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define IOCTL_BASE  0x800
#define MY_CTL_CODE(i) CTL_CODE(FILE_DEVICE_NULL, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_TEST MY_CTL_CODE(0) 
#define IOCTL_HIDE_DRIVER MY_CTL_CODE(1)

#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

NTSYSAPI
NTSTATUS
NTAPI
IoCreateDriver(
    IN PUNICODE_STRING DriverName    OPTIONAL,
    IN PDRIVER_INITIALIZE InitializationFunction
);

NTSYSAPI
VOID
NTAPI
IoDeleteDriver(
    IN PDRIVER_OBJECT DriverObject
);

extern PSHORT NtBuildNumber;

NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    __in PUNICODE_STRING ObjectName,
    __in ULONG Attributes,
    __in_opt PACCESS_STATE AccessState,
    __in_opt ACCESS_MASK DesiredAccess,
    __in POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __inout_opt PVOID ParseContext,
    __out PVOID* Object
);

extern POBJECT_TYPE *IoDriverObjectType;


#endif



