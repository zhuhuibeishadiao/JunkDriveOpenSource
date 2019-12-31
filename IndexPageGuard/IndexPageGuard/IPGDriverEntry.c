#include "pch.h"

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	IndexGuardEnableCloseProtect(TRUE);
}

NTSTATUS RegSetValueKey(LPWSTR KeyName, LPWSTR ValueName, DWORD DataType, PVOID DataBuffer, DWORD DataLength)
{
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING usKeyName, usValueName;
    NTSTATUS ntStatus;
    HANDLE hRegister;

    RtlInitUnicodeString(&usKeyName, KeyName);
    RtlInitUnicodeString(&usValueName, ValueName);
    InitializeObjectAttributes(&objectAttributes,
        &usKeyName,
        OBJ_CASE_INSENSITIVE,//对大小写敏感
        NULL,
        NULL);

    ntStatus = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);

    if (NT_SUCCESS(ntStatus))
    {
        ntStatus = ZwSetValueKey(hRegister, &usValueName, 0, DataType, DataBuffer, DataLength);
        ZwFlushKey(hRegister);
        ZwClose(hRegister);
    }

    return ntStatus;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pUsRegPath)
{
	NTSTATUS status = STATUS_SUCCESS;

    WCHAR* szBuff = NULL;

    DWORD dwStart = 2;

    szBuff = ExAllocatePoolWithTag(NonPagedPool, pUsRegPath->MaximumLength, 'xxxx');

    if (szBuff)
    {
        RtlZeroMemory(szBuff, pUsRegPath->MaximumLength);

        RtlCopyMemory(szBuff, pUsRegPath->Buffer, pUsRegPath->Length);

        if (!NT_SUCCESS(RegSetValueKey(szBuff, L"Start", REG_DWORD, &dwStart, 4)))
        {
            DbgPrint("SetValue faild....\n");
            RtlZeroMemory(szBuff, pUsRegPath->Length);
            RtlCopyMemory(szBuff, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\services\\", wcslen(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\services\\") * 2);
            __try {
                RtlCopyMemory(szBuff + wcslen(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\services\\"), pDriverObject->DriverExtension->ServiceKeyName.Buffer, pDriverObject->DriverExtension->ServiceKeyName.Length);
                if (!(NT_SUCCESS(RegSetValueKey(szBuff, L"Start", REG_DWORD, &dwStart, 4))))
                {
                    DbgPrint("SetValue faild 3....\n");
                }
            }
            __except (1)
            {
                DbgPrint("SetValue faild 2....\n");
            }
        }

        ExFreePoolWithTag(szBuff, 'xxxx');
    }

    pDriverObject->DriverUnload = NULL;//DriverUnload;

	status = IndexGuardEnableCloseProtect(FALSE);

	if (NT_SUCCESS(status))
	{
		MinifilterSetProtectedFile(L"xxx.dll", L"xxxx.exe");
		status = InitializeMiniFilter(pDriverObject, pUsRegPath);
	}

#ifdef _DEBUG_
	if (NT_SUCCESS(status))
		DbgPrint("Initlize Success....\n");
	else
		DbgPrint("Initlize faild....\n");
#endif // _DEBUG_
	return status;
}