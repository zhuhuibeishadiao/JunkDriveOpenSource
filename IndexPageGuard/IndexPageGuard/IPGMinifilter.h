#ifndef _IPG_MINIFILTER_H_
#define _IPG_MINIFILTER_H_ 1

NTSTATUS InitializeMiniFilter(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);

NTSTATUS FinalizeMiniFilterCallback(IN FLT_FILTER_UNLOAD_FLAGS Flags);

VOID MinifilterSetProtectedFile(WCHAR* szFileName, WCHAR* szProcessName);

#endif // !_IPG_MINIFILTER_H_
