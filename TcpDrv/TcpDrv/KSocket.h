#ifndef _KSOCKET_
#define _KSOCKET_

#ifdef __cplusplus
extern "C" {
#endif

#pragma warning(push)
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // bit field types other than int

#pragma once
#include <ntddk.h>
#include <wsk.h>

#pragma warning(pop)

#define SOCKET_ERROR -1

NTSTATUS NTAPI WSKStartup();
VOID NTAPI WSKCleanup();

PWSK_SOCKET
NTAPI
CreateSocket(
    __in ADDRESS_FAMILY AddressFamily,
    __in USHORT                 SocketType,
    __in ULONG                  Protocol,
    __in ULONG                  Flags
);

NTSTATUS
NTAPI
CloseSocket(
    __in PWSK_SOCKET WskSocket
);

NTSTATUS
NTAPI
Connect(
    __in PWSK_SOCKET        WskSocket,
    __in PSOCKADDR          RemoteAddress
);

PWSK_SOCKET
NTAPI
SocketConnect(
    __in USHORT             SocketType,
    __in ULONG              Protocol,
    __in PSOCKADDR  RemoteAddress,
    __in PSOCKADDR  LocalAddress
);

LONG
NTAPI
Send(
    __in PWSK_SOCKET        WskSocket,
    __in PVOID                      Buffer,
    __in ULONG                      BufferSize,
    __in ULONG                      Flags
);

LONG
NTAPI
SendTo(
    __in PWSK_SOCKET        WskSocket,
    __in PVOID                      Buffer,
    __in ULONG                      BufferSize,
    __in_opt PSOCKADDR      RemoteAddress
);

LONG
NTAPI
Receive(
    __in  PWSK_SOCKET       WskSocket,
    __out PVOID                     Buffer,
    __in  ULONG                     BufferSize,
    __in  ULONG                     Flags
);

LONG
NTAPI
ReceiveFrom(
    __in  PWSK_SOCKET       WskSocket,
    __out PVOID                     Buffer,
    __in  ULONG                     BufferSize,
    __out_opt PSOCKADDR     RemoteAddress,
    __out_opt PULONG        ControlFlags
);

NTSTATUS
NTAPI
Bind(
    __in PWSK_SOCKET        WskSocket,
    __in PSOCKADDR          LocalAddress
);

PWSK_SOCKET
NTAPI
Accept(
    __in PWSK_SOCKET        WskSocket,
    __out_opt PSOCKADDR     LocalAddress,
    __out_opt PSOCKADDR     RemoteAddress
);

NTSTATUS
NTAPI
TcpSendAndRecvData(
    __in char *HostAddress,
    __in char *data,
    __in size_t datalen,
    __in USHORT Port,
    __out PVOID *lpRecv,
    __out size_t *lpcbRecvLen
);

#ifdef __cplusplus
}
#endif

#endif