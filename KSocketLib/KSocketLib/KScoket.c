#include "KSocket.h"

#pragma warning(disable:4267)
#pragma warning(disable:4242)
#pragma warning(disable:4244)
#pragma warning(disable:4018)
#pragma warning(disable:4389)

typedef unsigned char   u_char;
typedef unsigned short  u_short;
typedef unsigned int    u_int;
typedef unsigned long   u_long;

static WSK_REGISTRATION         g_WskRegistration;
static WSK_PROVIDER_NPI         g_WskProvider;
static WSK_CLIENT_DISPATCH      g_WskDispatch = { MAKE_WSK_VERSION(1,0), 0, NULL };

enum
{
    DEINITIALIZED,
    DEINITIALIZING,
    INITIALIZING,
    INITIALIZED
};

static LONG     g_SocketsState = DEINITIALIZED;

static int inet_aton(const char *name, struct in_addr *addr)
{
    u_int dots, digits;
    u_long byte;

    if (!name || !addr)
    {
        return 0;
    }

    for (dots = 0, digits = 0, byte = 0, addr->s_addr = 0; *name; name++)
    {
        if (*name == '.')
        {
            addr->s_addr += byte << (8 * dots);
            if (++dots > 3 || digits == 0)
            {
                return 0;
            }
            digits = 0;
            byte = 0;
        }
        else
        {
            byte = byte * 10 + (*name - '0');
            if (++digits > 3 || *name < '0' || *name > '9' || byte > 255)
            {
                return 0;
            }
        }
    }

    if (dots != 3 || digits == 0)
    {
        return 0;
    }

    addr->s_addr += byte << (8 * dots);

    return 1;
}

static u_long inet_addr(const char *name)
{
    struct in_addr addr;

    if (inet_aton(name, &addr))
    {
        return addr.s_addr;
    }
    return INADDR_NONE;
}


static u_short htons(u_short hostshort)
{
    return RtlUshortByteSwap(hostshort);
}

static
NTSTATUS
NTAPI
CompletionRoutine(
    __in PDEVICE_OBJECT 		DeviceObject,
    __in PIRP                   Irp,
    __in PKEVENT                CompletionEvent
)
{
    ASSERT(CompletionEvent);

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(DeviceObject);

    KeSetEvent(CompletionEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static
NTSTATUS
InitWskData(
    __out PIRP*             pIrp,
    __out PKEVENT   CompletionEvent
)
{
    ASSERT(pIrp);
    ASSERT(CompletionEvent);

    *pIrp = IoAllocateIrp(1, FALSE);
    if (!*pIrp) {
        KdPrint(("InitWskData(): IoAllocateIrp() failed\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(CompletionEvent, SynchronizationEvent, FALSE);
    IoSetCompletionRoutine(*pIrp, CompletionRoutine, CompletionEvent, TRUE, TRUE, TRUE);
    return STATUS_SUCCESS;
}

static
NTSTATUS
InitWskBuffer(
    __in  PVOID             Buffer,
    __in  ULONG             BufferSize,
    __out PWSK_BUF  WskBuffer
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    ASSERT(Buffer);
    ASSERT(BufferSize);
    ASSERT(WskBuffer);

    WskBuffer->Offset = 0;
    WskBuffer->Length = BufferSize;

    WskBuffer->Mdl = IoAllocateMdl(Buffer, BufferSize, FALSE, FALSE, NULL);
    if (!WskBuffer->Mdl) {
        KdPrint(("InitWskBuffer(): IoAllocateMdl() failed\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("InitWskBuffer(): MmProbeAndLockPages(%p) failed\n", Buffer));
        IoFreeMdl(WskBuffer->Mdl);
        Status = STATUS_ACCESS_VIOLATION;
    }

    return Status;
}

static
VOID
FreeWskBuffer(
    __in PWSK_BUF WskBuffer
)
{
    ASSERT(WskBuffer);


    MmUnlockPages(WskBuffer->Mdl);
    IoFreeMdl(WskBuffer->Mdl);
}

//
// Library initialization routine
//

NTSTATUS NTAPI WSKStartup()
{
    WSK_CLIENT_NPI  WskClient = { 0 };
    NTSTATUS                Status = STATUS_UNSUCCESSFUL;

    if (InterlockedCompareExchange(&g_SocketsState, INITIALIZING, DEINITIALIZED) != DEINITIALIZED)
        return STATUS_ALREADY_REGISTERED;

    WskClient.ClientContext = NULL;
    WskClient.Dispatch = &g_WskDispatch;

    Status = WskRegister(&WskClient, &g_WskRegistration);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("WskRegister() failed with status 0x%08X\n", Status));
        InterlockedExchange(&g_SocketsState, DEINITIALIZED);
        return Status;
    }

    Status = WskCaptureProviderNPI(&g_WskRegistration, WSK_NO_WAIT, &g_WskProvider);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("WskCaptureProviderNPI() failed with status 0x%08X\n", Status));
        WskDeregister(&g_WskRegistration);
        InterlockedExchange(&g_SocketsState, DEINITIALIZED);
        return Status;
    }

    InterlockedExchange(&g_SocketsState, INITIALIZED);
    return STATUS_SUCCESS;
}

//
// Library deinitialization routine
//

VOID NTAPI WSKCleanup()
{
    if (InterlockedCompareExchange(&g_SocketsState, INITIALIZED, DEINITIALIZING) != INITIALIZED)
        return;

    WskReleaseProviderNPI(&g_WskRegistration);
    WskDeregister(&g_WskRegistration);

    InterlockedExchange(&g_SocketsState, DEINITIALIZED);
}



PWSK_SOCKET
NTAPI
CreateSocket(
    __in ADDRESS_FAMILY AddressFamily,
    __in USHORT                 SocketType,
    __in ULONG                  Protocol,
    __in ULONG                  Flags
)
{
    KEVENT                  CompletionEvent = { 0 };
    PIRP                    Irp = NULL;
    PWSK_SOCKET             WskSocket = NULL;
    NTSTATUS                Status = STATUS_UNSUCCESSFUL;

    if (g_SocketsState != INITIALIZED)
        return NULL;

    Status = InitWskData(&Irp, &CompletionEvent);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("CreateSocket(): InitWskData() failed with status 0x%08X\n", Status));
        return NULL;
    }

    Status = g_WskProvider.Dispatch->WskSocket(
        g_WskProvider.Client,
        AddressFamily,
        SocketType,
        Protocol,
        Flags,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    WskSocket = NT_SUCCESS(Status) ? (PWSK_SOCKET)Irp->IoStatus.Information : NULL;

    IoFreeIrp(Irp);
    return (PWSK_SOCKET)WskSocket;
}

NTSTATUS
NTAPI
CloseSocket(
    __in PWSK_SOCKET WskSocket
)
{
    KEVENT          CompletionEvent = { 0 };
    PIRP            Irp = NULL;
    NTSTATUS        Status = STATUS_UNSUCCESSFUL;

    if (g_SocketsState != INITIALIZED || !WskSocket)
        return STATUS_INVALID_PARAMETER;

    Status = InitWskData(&Irp, &CompletionEvent);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("CloseSocket(): InitWskData() failed with status 0x%08X\n", Status));
        return Status;
    }

    Status = ((PWSK_PROVIDER_BASIC_DISPATCH)WskSocket->Dispatch)->WskCloseSocket(WskSocket, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    IoFreeIrp(Irp);
    return Status;
}


NTSTATUS
NTAPI
Connect(
    __in PWSK_SOCKET        WskSocket,
    __in PSOCKADDR          RemoteAddress
)
{
    KEVENT          CompletionEvent = { 0 };
    PIRP            Irp = NULL;
    NTSTATUS        Status = STATUS_UNSUCCESSFUL;

    if (g_SocketsState != INITIALIZED || !WskSocket || !RemoteAddress)
        return STATUS_INVALID_PARAMETER;

    Status = InitWskData(&Irp, &CompletionEvent);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("Connect(): InitWskData() failed with status 0x%08X\n", Status));
        return Status;
    }

    Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskConnect(
        WskSocket,
        RemoteAddress,
        0,
        Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    IoFreeIrp(Irp);
    return Status;
}

PWSK_SOCKET
NTAPI
SocketConnect(
    __in USHORT             SocketType,
    __in ULONG              Protocol,
    __in PSOCKADDR  RemoteAddress,
    __in PSOCKADDR  LocalAddress
)
{
    KEVENT                  CompletionEvent = { 0 };
    PIRP                    Irp = NULL;
    NTSTATUS                Status = STATUS_UNSUCCESSFUL;
    PWSK_SOCKET             WskSocket = NULL;

    if (g_SocketsState != INITIALIZED || !RemoteAddress || !LocalAddress)
        return NULL;

    Status = InitWskData(&Irp, &CompletionEvent);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("InitWskData() failed with status 0x%08X\n", Status));
        return NULL;
    }

    Status = g_WskProvider.Dispatch->WskSocketConnect(
        g_WskProvider.Client,
        SocketType,
        Protocol,
        LocalAddress,
        RemoteAddress,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    WskSocket = NT_SUCCESS(Status) ? (PWSK_SOCKET)Irp->IoStatus.Information : NULL;

    IoFreeIrp(Irp);
    return WskSocket;
}


LONG
NTAPI
Send(
    __in PWSK_SOCKET        WskSocket,
    __in PVOID                      Buffer,
    __in ULONG                      BufferSize,
    __in ULONG                      Flags
)
{
    KEVENT          CompletionEvent = { 0 };
    PIRP            Irp = NULL;
    WSK_BUF         WskBuffer = { 0 };
    LONG            BytesSent = SOCKET_ERROR;
    NTSTATUS        Status = STATUS_UNSUCCESSFUL;

    if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
        return SOCKET_ERROR;

    Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("Send(): InitWskData() failed with status 0x%08X\n", Status));
        return SOCKET_ERROR;
    }

    Status = InitWskData(&Irp, &CompletionEvent);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("Send(): InitWskData() failed with status 0x%08X\n", Status));
        FreeWskBuffer(&WskBuffer);
        return SOCKET_ERROR;
    }

    Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskSend(
        WskSocket,
        &WskBuffer,
        Flags,
        Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    BytesSent = NT_SUCCESS(Status) ? (LONG)Irp->IoStatus.Information : SOCKET_ERROR;

    IoFreeIrp(Irp);
    FreeWskBuffer(&WskBuffer);
    return BytesSent;
}

LONG
NTAPI
SendTo(
    __in PWSK_SOCKET        WskSocket,
    __in PVOID              Buffer,
    __in ULONG              BufferSize,
    __in_opt PSOCKADDR      RemoteAddress
)
{
    KEVENT          CompletionEvent = { 0 };
    PIRP            Irp = NULL;
    WSK_BUF         WskBuffer = { 0 };
    LONG            BytesSent = SOCKET_ERROR;
    NTSTATUS        Status = STATUS_UNSUCCESSFUL;

    if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
        return SOCKET_ERROR;

    Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("SendTo(): InitWskData() failed with status 0x%08X\n", Status));
        return SOCKET_ERROR;
    }

    Status = InitWskData(&Irp, &CompletionEvent);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("SendTo(): InitWskData() failed with status 0x%08X\n", Status));
        FreeWskBuffer(&WskBuffer);
        return SOCKET_ERROR;
    }

    Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)WskSocket->Dispatch)->WskSendTo(
        WskSocket,
        &WskBuffer,
        0,
        RemoteAddress,
        0,
        NULL,
        Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    BytesSent = NT_SUCCESS(Status) ? (LONG)Irp->IoStatus.Information : SOCKET_ERROR;

    IoFreeIrp(Irp);
    FreeWskBuffer(&WskBuffer);
    return BytesSent;
}

LONG
NTAPI
Receive(
    __in  PWSK_SOCKET       WskSocket,
    __out PVOID                     Buffer,
    __in  ULONG                     BufferSize,
    __in  ULONG                     Flags
)
{
    KEVENT          CompletionEvent = { 0 };
    PIRP            Irp = NULL;
    WSK_BUF         WskBuffer = { 0 };
    LONG            BytesReceived = SOCKET_ERROR;
    NTSTATUS        Status = STATUS_UNSUCCESSFUL;

    if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
        return SOCKET_ERROR;

    Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("Receive(): InitWskData() failed with status 0x%08X\n", Status));
        return SOCKET_ERROR;
    }

    Status = InitWskData(&Irp, &CompletionEvent);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("Receive(): InitWskData() failed with status 0x%08X\n", Status));
        FreeWskBuffer(&WskBuffer);
        return SOCKET_ERROR;
    }

    Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskReceive(
        WskSocket,
        &WskBuffer,
        Flags,
        Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    BytesReceived = NT_SUCCESS(Status) ? (LONG)Irp->IoStatus.Information : SOCKET_ERROR;

    IoFreeIrp(Irp);
    FreeWskBuffer(&WskBuffer);
    return BytesReceived;
}

LONG
NTAPI
ReceiveFrom(
    __in  PWSK_SOCKET       WskSocket,
    __out PVOID                     Buffer,
    __in  ULONG                     BufferSize,
    __out_opt PSOCKADDR     RemoteAddress,
    __out_opt PULONG        ControlFlags
)
{
    KEVENT          CompletionEvent = { 0 };
    PIRP            Irp = NULL;
    WSK_BUF         WskBuffer = { 0 };
    LONG            BytesReceived = SOCKET_ERROR;
    NTSTATUS        Status = STATUS_UNSUCCESSFUL;

    if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
        return SOCKET_ERROR;

    Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("ReceiveFrom(): InitWskData() failed with status 0x%08X\n", Status));
        return SOCKET_ERROR;
    }

    Status = InitWskData(&Irp, &CompletionEvent);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("ReceiveFrom(): InitWskData() failed with status 0x%08X\n", Status));
        FreeWskBuffer(&WskBuffer);
        return SOCKET_ERROR;
    }

    Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)WskSocket->Dispatch)->WskReceiveFrom(
        WskSocket,
        &WskBuffer,
        0,
        RemoteAddress,
        0,
        NULL,
        ControlFlags,
        Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    BytesReceived = NT_SUCCESS(Status) ? (LONG)Irp->IoStatus.Information : SOCKET_ERROR;

    IoFreeIrp(Irp);
    FreeWskBuffer(&WskBuffer);
    return BytesReceived;
}

NTSTATUS
NTAPI
Bind(
    __in PWSK_SOCKET        WskSocket,
    __in PSOCKADDR          LocalAddress
)
{
    KEVENT          CompletionEvent = { 0 };
    PIRP            Irp = NULL;
    NTSTATUS        Status = STATUS_UNSUCCESSFUL;

    if (g_SocketsState != INITIALIZED || !WskSocket || !LocalAddress)
        return STATUS_INVALID_PARAMETER;

    Status = InitWskData(&Irp, &CompletionEvent);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("Bind(): InitWskData() failed with status 0x%08X\n", Status));
        return Status;
    }

    Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskBind(
        WskSocket,
        LocalAddress,
        0,
        Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    IoFreeIrp(Irp);
    return Status;
}


PWSK_SOCKET
NTAPI
Accept(
    __in PWSK_SOCKET        WskSocket,
    __out_opt PSOCKADDR     LocalAddress,
    __out_opt PSOCKADDR     RemoteAddress
)
{
    KEVENT                  CompletionEvent = { 0 };
    PIRP                    Irp = NULL;
    NTSTATUS                Status = STATUS_UNSUCCESSFUL;
    PWSK_SOCKET             AcceptedSocket = NULL;

    if (g_SocketsState != INITIALIZED || !WskSocket)
        return NULL;

    Status = InitWskData(&Irp, &CompletionEvent);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("Accept(): InitWskData() failed with status 0x%08X\n", Status));
        return NULL;
    }

    Status = ((PWSK_PROVIDER_LISTEN_DISPATCH)WskSocket->Dispatch)->WskAccept(
        WskSocket,
        0,
        NULL,
        NULL,
        LocalAddress,
        RemoteAddress,
        Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    AcceptedSocket = NT_SUCCESS(Status) ? (PWSK_SOCKET)Irp->IoStatus.Information : NULL;

    IoFreeIrp(Irp);
    return AcceptedSocket;
}

NTSTATUS 
NTAPI 
TcpSendAndRecvData(
    __in char *HostAddress,
    __in char *data,
    __in size_t datalen,
    __in USHORT Port,
    __out PVOID *lpRecv,
    __out size_t *lpcbRecvLen
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    BOOLEAN bStart = FALSE;
    
    PWSK_SOCKET TcpSocket = NULL;

    SOCKADDR_IN 	RemoteAddress = { 0, };
    SOCKADDR_IN 	LocalAddress = { 0, };

    LONG nSend = 0;
    LONG nRecv = 0;

    PVOID pRecvBuffer = NULL;

    SIZE_T cbRecvBuffer = 1024 * 1024;

    do
    {
        pRecvBuffer = ExAllocatePool(NonPagedPool, cbRecvBuffer);

        if (pRecvBuffer == NULL)
        {
            status = STATUS_NO_MEMORY;
            break;
        }

        status = WSKStartup();

        if (!NT_SUCCESS(status))
            break;

        bStart = TRUE;

        TcpSocket = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET);

        if (TcpSocket == NULL)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        LocalAddress.sin_family = AF_INET;
        LocalAddress.sin_addr.s_addr = INADDR_ANY;
        LocalAddress.sin_port = 0;

        status = Bind(TcpSocket, (PSOCKADDR)&LocalAddress);

        if (!NT_SUCCESS(status))
        {
            KdPrint(("bind : 0x%x\n", status));
            break;
        }

        RemoteAddress.sin_family = AF_INET;
        RemoteAddress.sin_addr.s_addr = inet_addr(HostAddress);
        RemoteAddress.sin_port = htons(Port);

        status = Connect(TcpSocket, (PSOCKADDR)&RemoteAddress);

        if (!NT_SUCCESS(status))
            break;

        nSend = Send(TcpSocket, data, datalen, 0);

        if (nSend < datalen)
        {
            KdPrint(("complete: %d < %d\n", nSend, datalen));
        }

        RtlZeroMemory(pRecvBuffer, cbRecvBuffer);

        nRecv = Receive(TcpSocket, pRecvBuffer, cbRecvBuffer, 0);

        if (nRecv == 0)
        {
            KdPrint(("recv return 0 service closed\n"));
            break;
        }

        if (nRecv == -1)
        {
            KdPrint(("recv return -1\n"));
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        if (nRecv != cbRecvBuffer)
        {
            *lpRecv = pRecvBuffer;
            *lpcbRecvLen = nRecv;
            status = STATUS_SUCCESS;
            break;
        }
        else
            DbgBreakPoint();  // 这里不支持超过1024 * 1024的数据传输

    } while (FALSE);

    if (TcpSocket)
        CloseSocket(TcpSocket);

    if (!NT_SUCCESS(status))
    {
        if (pRecvBuffer)
            ExFreePool(pRecvBuffer);
    }

    if(bStart)
        WSKCleanup();

    return status;
}