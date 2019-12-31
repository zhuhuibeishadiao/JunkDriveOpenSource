#include "pch.h"

NTSTATUS DispatchIoctl(
    PDEVICE_OBJECT pDevObj,
    PIRP pIrp
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION pIrpStack;
    WCHAR* szDrvName = NULL;
    ULONG uIoControlCode;
    PVOID pIoBuffer;
    ULONG uInSize;
    ULONG uOutSize;

    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
    pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
    uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
    uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (uIoControlCode)
    {
        case IOCTL_TEST:
        {
            DPRINT("DrvEnjoy Hello.\n");
            status = STATUS_SUCCESS;
        }
        break;
        case IOCTL_HIDE_DRIVER:
        {
            if (uInSize > MAX_PATH * 2)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            szDrvName = ExAllocatePoolWithTag(NonPagedPool, MAX_PATH * 2, 'hide');

            if (szDrvName == NULL)
            {
                status = STATUS_NO_MEMORY;
                break;
            }

            RtlZeroMemory(szDrvName, MAX_PATH * 2);

            RtlCopyMemory(szDrvName, pIoBuffer, uInSize);

            status = HideDriver(szDrvName, FALSE);
            
            ExFreePoolWithTag(szDrvName, 'hide');
        }
        break;
    }

    if (status == STATUS_SUCCESS)
        pIrp->IoStatus.Information = uOutSize;
    else
        pIrp->IoStatus.Information = 0;

    /////////////////////////////////////  
    pIrp->IoStatus.Status = status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS DispatchOK(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DrvUnload(PDRIVER_OBJECT pDriverObject)
{
    UNICODE_STRING strLink;
    RtlInitUnicodeString(&strLink, L"\\DosDevices\\BLCheers");

    IoDeleteSymbolicLink(&strLink);
    IoDeleteDevice(pDriverObject->DeviceObject);
    DPRINT("DrvEnjoy Unload.\n");
}

NTSTATUS DriverInit(PDRIVER_OBJECT DriverObject, PDRIVER_DISPATCH pControl)
{
    NTSTATUS        status;
    UNICODE_STRING  SymLink, DevName;
    PDEVICE_OBJECT  devobj;
    ULONG           t;

    RtlInitUnicodeString(&DevName, L"\\Device\\BLCheers");
    status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_NULL, FILE_DEVICE_SECURE_OPEN, FALSE, &devobj);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&SymLink, L"\\DosDevices\\BLCheers");
    status = IoCreateSymbolicLink(&SymLink, &DevName);

    devobj->Flags |= DO_BUFFERED_IO;

    for (t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
        DriverObject->MajorFunction[t] = &DispatchOK;

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = pControl;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = &DispatchOK;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = &DispatchOK;
    DriverObject->DriverUnload = DrvUnload;

    devobj->Flags &= ~DO_DEVICE_INITIALIZING;

    return status;
}

VOID Reinitialize(
    _In_     PDRIVER_OBJECT        pDriverObject,
    _In_opt_ PVOID                 Context,
    _In_     ULONG                 Count
)
{
    WCHAR* szDrv = NULL;

    szDrv = ExAllocatePoolWithTag(NonPagedPool, pDriverObject->DriverName.MaximumLength, 'xxxx');

    if (szDrv == NULL)
        return;

    RtlZeroMemory(szDrv, pDriverObject->DriverName.MaximumLength);

    RtlCopyMemory(szDrv, pDriverObject->DriverName.Buffer, pDriverObject->DriverName.Length);

    if (!NT_SUCCESS(HideDriver(szDrv, TRUE)))
        DPRINT("hide driver faild.\n");
    else
        DPRINT("hide driver success.\n");

    ExFreePoolWithTag(szDrv, 'xxxx');
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegisterPath)
{
    DPRINT("DrvEnjoy.\n");

    DriverInit(pDriverObject, DispatchIoctl);

    IoRegisterDriverReinitialization(pDriverObject, Reinitialize, NULL);
    return STATUS_SUCCESS;
}