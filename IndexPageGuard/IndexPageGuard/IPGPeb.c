#include "pch.h"

USHORT PebGetCommandLineLen(PPEB32 Peb)
{
	if (Peb == NULL || !MmIsAddressValid(Peb))
		return 0;

	__try {
		return Peb->ProcessParameters->CommandLine.Length;
	}
	__except (1)
	{
		return 0;
	}
}

USHORT PebGetCommandLineMaxWriteLen(PPEB32 Peb)
{
	if (Peb == NULL || !MmIsAddressValid(Peb))
		return 0;
	
	__try {
		return Peb->ProcessParameters->CommandLine.MaximumLength + Peb->ProcessParameters->WindowTitle.Length - Peb->ProcessParameters->ImagePathName.Length - 6;
	}
	__except (1)
	{
		return 0;
	}
}



WCHAR* PebGetCommandLinePoint(PPEB32 Peb)
{
	if (Peb == NULL || !MmIsAddressValid(Peb))
		return NULL;

	__try {
		return (WCHAR*)Peb->ProcessParameters->CommandLine.Buffer;
	}
	__except (1)
	{
		return NULL;
	}
}

BOOLEAN PebSetCommandLine(PPEB32 Peb, WCHAR* szCommandLine, PVOID pNewPoint, BOOLEAN bNewPoint)
{
	if (Peb == NULL || szCommandLine == NULL)
		return FALSE;

	if (bNewPoint)
	{
		if (pNewPoint == NULL)
			return FALSE;

		__try {
			RtlCopyMemory(pNewPoint, szCommandLine, wcslen(szCommandLine) * 2);
			Peb->ProcessParameters->MaximumLength = (ULONG32)((ULONG_PTR)pNewPoint - (ULONG_PTR)Peb->ProcessParameters + wcslen(szCommandLine) * 2 + 10);
			return TRUE;
		}
		__except (1)
		{
			return FALSE;
		}
	}

	__try {
		RtlZeroMemory((PVOID)Peb->ProcessParameters->CommandLine.Buffer, Peb->ProcessParameters->CommandLine.MaximumLength);
		RtlCopyMemory((PVOID)Peb->ProcessParameters->CommandLine.Buffer, szCommandLine, wcslen(szCommandLine) * 2);
		return TRUE;	
	}
	__except (1)
	{
		return FALSE;
	}
}

PVOID PebGetNewCommandLinePoint(PPEB32 Peb)
{
	if (Peb == NULL || !MmIsAddressValid(Peb))
		return NULL;
	
	__try {
#ifdef _AMD64_
		return (PVOID)(Peb->ProcessParameters->MaximumLength + (ULONG_PTR)Peb->ProcessParameters + 0x10);
#else
		return (PVOID)((ULONG_PTR)Peb->ProcessParameters + 0x1500);
#endif
	}
	__except (1)
	{
		return NULL;
	}
}

WCHAR* PebGetParameterPoint(PPEB32 Peb)
{
	if (Peb == NULL || !MmIsAddressValid(Peb))
		return NULL;

	__try {
		// 6 = peb->ProcessParameters->CommandLine.Length - peb->ProcessParameters->ImagePathName.Length
		return (WCHAR*)(Peb->ProcessParameters->CommandLine.Buffer + Peb->ProcessParameters->ImagePathName.Length + 6);
	}
	__except (1)
	{
		return NULL;
	}
}

USHORT PebGetParmeterLen(PPEB32 Peb)
{
	UNICODE_STRING usParmeter = { 0 };
	WCHAR* szParmeter = NULL;

	if (Peb == NULL || !MmIsAddressValid(Peb))
		return 0;

	szParmeter = PebGetParameterPoint(Peb);

	if (szParmeter == NULL)
		return 0;

	RtlInitUnicodeString(&usParmeter, szParmeter);

	return Peb->ProcessParameters->CommandLine.Length - usParmeter.Length;
}