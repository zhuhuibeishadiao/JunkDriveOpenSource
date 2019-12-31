#ifndef _NT_API_H_
#define _NT_API_H_ 1

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
	__in HANDLE ulProcId,
	__out PEPROCESS * Process
);

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PRKPROCESS   Process,
    _Out_   PRKAPC_STATE ApcState
);

NTKERNELAPI
VOID KeUnstackDetachProcess(
    _In_ PRKAPC_STATE ApcState
);


NTKERNELAPI
PPEB
PsGetProcessPeb(
	PEPROCESS Process
);

NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
	__in PEPROCESS Process
);

NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(
	PEPROCESS Process
);

#endif // !_NT_API_H_

