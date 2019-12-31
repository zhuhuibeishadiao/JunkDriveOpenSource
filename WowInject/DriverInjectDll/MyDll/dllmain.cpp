// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include <Shlwapi.h>
#include <winsock2.h>

#pragma comment(lib, "WS2_32.lib")  

#pragma comment(lib,"Shlwapi.lib")

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

typedef NTSTATUS(NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

EXTERN_C NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserThread(
    _In_ HANDLE Process,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_opt_ ULONG ZeroBits,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ SIZE_T CommittedStackSize,
    _In_ PUSER_THREAD_START_ROUTINE StartAddress,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PHANDLE Thread,
    _Out_opt_ PCLIENT_ID ClientId
);

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT * Buffer;
#else // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ReservedFlags5 : 2;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef NTSTATUS(NTAPI* pfnLdrFindEntryForAddress)(HMODULE hMod, LDR_DATA_TABLE_ENTRY** ppLdrData);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

void PrintfToFile(const char* s)
{
    if (s == NULL)
        return;

    freopen("c:\\output.txt", "a+", stdout);
    printf("%s\n", s);
    freopen("CON", "w", stdout);
}

void TcpTest()
{
    WSADATA wsaData;
    WORD sockVersion = MAKEWORD(2, 2);
    SOCKET sock = 0;

    if (WSAStartup(sockVersion, &wsaData) != 0)
    {
        PrintfToFile("initlization failed!");
        return;
    }

    sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock == INVALID_SOCKET)
    {
        PrintfToFile("failed socket!");
        return;
    }

    sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(4567);
    sin.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

    if (connect(sock, (sockaddr*)&sin, sizeof(sockaddr)) == -1)
    {
        PrintfToFile("connect failed!");
        return;
    }

    char buffer[256] = "\0";
    int  nRecv = 0;

    nRecv = recv(sock, buffer, 256, 0);

    if (nRecv > 0)
    {
        buffer[nRecv] = '\0';
        freopen("c:\\output.txt", "a+", stdout);
        printf("reveive data:%s\n", buffer);
        freopen("CON", "w", stdout);
    }

    closesocket(sock);

    WSACleanup();
}

DWORD __stdcall WorkThread(LPVOID lpram)
{
	TCHAR modulePtah[MAX_PATH];
	TCHAR exeName[MAX_PATH];

	GetModuleFileName(NULL, modulePtah, MAX_PATH);
	_tcscat(modulePtah, _T(" -> Inject OK!"));
	MessageBox(NULL, modulePtah, _T("Info"), MB_ICONINFORMATION);
	_tcscpy(exeName, modulePtah);

    DWORD dwCount = 0;

    while (true)
    {
        dwCount++;

        // 注意：这个函数 很多exe是会直接崩溃的 这里只是测试
        freopen("c:\\output.txt", "a+", stdout);

        printf("ThreadRoutine:0x%p, Tid:%d, Count:%d\n", WorkThread, GetCurrentThreadId(), dwCount);

        freopen("CON", "w", stdout);

        Sleep(5000);

        TcpTest();
    }

	return 0;
}

void AntiAntiThread()
{
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    pfnLdrFindEntryForAddress LdrFindEntryForAddress = (pfnLdrFindEntryForAddress)GetProcAddress(hNtdll, "LdrFindEntryForAddress");
    LDR_DATA_TABLE_ENTRY* pEntry = NULL;

    if (NT_SUCCESS(LdrFindEntryForAddress(GetModuleHandle(NULL), &pEntry)))
    {
        pEntry->TlsIndex = 0;
    }
    else
    {
        freopen("c:\\output.txt", "a+", stdout);
        printf("0x%p\n", AntiAntiThread);
        freopen("CON", "w", stdout);
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{   
        HANDLE hTread = NULL;

#ifdef _AMD64_
        AntiAntiThread();
        RtlCreateUserThread((HANDLE)-1, NULL, FALSE, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)WorkThread, NULL, &hTread, NULL);
#else
        RtlCreateUserThread((HANDLE)-1, NULL, FALSE, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)WorkThread, NULL, &hTread, NULL);
#endif
		if (hTread)
		{
			CloseHandle(hTread);
		}
		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

