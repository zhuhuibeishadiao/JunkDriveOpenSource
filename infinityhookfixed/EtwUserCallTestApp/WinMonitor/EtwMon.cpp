
#include "Network.h"

#include "EtwMon.h"

#include <evntcons.h>
#include <strsafe.h>
#include <psapi.h>
#include <shlwapi.h>
#include <process.h>

#pragma comment(lib,"Shlwapi.lib")

#ifndef SAF_MAX_PATH
#define SAF_MAX_PATH						(MAX_PATH + 1)
#endif

#define EVENT_TRACE_TYPE_SEND_IPV4			(EVENT_TRACE_TYPE_SEND)
#define EVENT_TRACE_TYPE_RECEIVE_IPV4		(EVENT_TRACE_TYPE_RECEIVE)
#define EVENT_TRACE_TYPE_CONNECT_IPV4		(EVENT_TRACE_TYPE_CONNECT)
#define EVENT_TRACE_TYPE_ACCEPT_IPV4		(EVENT_TRACE_TYPE_ACCEPT)
#define EVENT_TRACE_TYPE_RECONNECT_IPV4		(EVENT_TRACE_TYPE_RECONNECT)

#define EVENT_TRACE_TYPE_SEND_IPV6			(EVENT_TRACE_TYPE_SEND		+ 16)
#define EVENT_TRACE_TYPE_RECEIVE_IPV6		(EVENT_TRACE_TYPE_RECEIVE	+ 16)
#define EVENT_TRACE_TYPE_CONNECT_IPV6		(EVENT_TRACE_TYPE_CONNECT	+ 16)
#define EVENT_TRACE_TYPE_ACCEPT_IPV6		(EVENT_TRACE_TYPE_ACCEPT	+ 16)
#define EVENT_TRACE_TYPE_RECONNECT_IPV6		(EVENT_TRACE_TYPE_RECONNECT + 16)

static GUID TcpIpGuid		= { 0x9a280ac0, 0xc8e0, 0x11d1, { 0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2 } };
static GUID UdpIpGuid		= { 0xbf3a50c5, 0xa9c9, 0x4988, { 0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80 } };
static GUID ThrGuid			= { 0x3d6fa8d1, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };
static GUID ImageLoadGuid	= { 0x2cb15d1d, 0x5fc1, 0x11d2, { 0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18 } };
static GUID ProGuid			= { 0x3d6fa8d0, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };
static GUID SystemGuid = { 0xce1dbfb4,0x137e,0x4da6, {0x87,0xb0,0x3f,0x59,0xaa,0x10,0x2c,0xbc} };

std::wstring CEtwMon::ms_SessionLoggerName = KERNEL_LOGGER_NAME;

BOOL CEtwMon::ms_bRunning = FALSE;

TraceEventInfo* CEtwMon::ms_pTraceEventInfo = NULL;

CEtwMon::CEtwMon()
{
	m_SessionProperties = NULL;
	m_SessionHandle = NULL;
	m_ThreadHandle = NULL;
	m_MonFlags = 0;

	m_WaitThreadStarted = NULL;

	m_EtwEnabled = FALSE;
	m_EtwActive = FALSE;
	m_EtwStartedSession = FALSE;
}

CEtwMon::~CEtwMon()
{
	Stop();
}

DWORD CEtwMon::_InitSecssionProperties()
{
	DWORD dwError = ERROR_SUCCESS;

	do
	{
		ULONG bufferSize;
		ULONG cbLoggerNameLen;

		cbLoggerNameLen =
			(ms_SessionLoggerName.length() + 1) * sizeof(ms_SessionLoggerName[0]);
		bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + cbLoggerNameLen;
		
		if (NULL == m_SessionProperties)
		{
			m_SessionProperties = (PEVENT_TRACE_PROPERTIES)
				::malloc(bufferSize);
			if (NULL == m_SessionProperties)
			{
				dwError = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}
		}

		::ZeroMemory(m_SessionProperties, sizeof(EVENT_TRACE_PROPERTIES));

		m_SessionProperties->Wnode.BufferSize = bufferSize;
		m_SessionProperties->Wnode.Guid = SystemTraceControlGuid;
		m_SessionProperties->Wnode.ClientContext = 1;
		m_SessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;

		m_SessionProperties->MaximumBuffers = 1;
		m_SessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		m_SessionProperties->FlushTimer = 1;
		m_SessionProperties->EnableFlags = m_MonFlags;
		m_SessionProperties->MaximumFileSize = 5;
		m_SessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

	} while (0);

	return dwError;
}

DWORD CEtwMon::_StartSession()
{
	DWORD dwError = ERROR_SUCCESS;

	do
	{
		dwError = _InitSecssionProperties();
		if (ERROR_SUCCESS != dwError)
		{
			break;
		}

		DWORD dwResult =
			::StartTraceW(&m_SessionHandle,
			ms_SessionLoggerName.c_str(),
			m_SessionProperties);

		if (ERROR_SUCCESS == dwResult)
		{
			m_EtwEnabled = TRUE;
			m_EtwActive = TRUE;
			m_EtwStartedSession = TRUE;
		}
		else if (ERROR_ALREADY_EXISTS == dwResult)
		{
			m_EtwEnabled = TRUE;
			m_EtwActive = TRUE;
			m_EtwStartedSession = FALSE;
		}
		else
		{
			m_EtwActive = FALSE;
			m_EtwEnabled = FALSE;
			m_EtwStartedSession = FALSE;
		}

	} while (0);

	return dwError;
}

DWORD CEtwMon::_ReStartSession()
{
	DWORD dwError = ERROR_SUCCESS;

	do
	{
	_ReStart:
		dwError = _InitSecssionProperties();
		if (ERROR_SUCCESS != dwError)
		{
			break;
		}

		DWORD dwResult =
			::StartTraceW(&m_SessionHandle,
			ms_SessionLoggerName.c_str(),
			m_SessionProperties);

		if (ERROR_SUCCESS == dwResult)
		{
			m_EtwEnabled = TRUE;
			m_EtwActive = TRUE;
			m_EtwStartedSession = TRUE;
		}
		else if (ERROR_ALREADY_EXISTS == dwResult)
		{
			dwError = ::ControlTraceW(m_SessionHandle, ms_SessionLoggerName.c_str(),
				m_SessionProperties, EVENT_TRACE_CONTROL_STOP);
			
			if (ERROR_SUCCESS == dwError)
				goto _ReStart;
		}
		else
		{
			m_EtwActive = FALSE;
			m_EtwEnabled = FALSE;
			m_EtwStartedSession = FALSE;
		}

	} while (0);

	return dwError;
}


DWORD	CEtwMon::Start(
	_In_ DWORD dwFlags /* = MonitorAll */)
{
	DWORD dwError = ERROR_SUCCESS;

	do
	{
		if (TRUE == ms_bRunning)
		{
			break;
		}

		m_MonFlags = 0;

		/*if (IsMonitor(dwFlags, MonitorProcess))
			m_MonFlags |= EVENT_TRACE_FLAG_PROCESS;

		if (IsMonitor(dwFlags, MonitorThread))
			m_MonFlags |= EVENT_TRACE_FLAG_THREAD;

		if (IsMonitor(dwFlags, MonitorModuleLoad))
			m_MonFlags |= EVENT_TRACE_FLAG_IMAGE_LOAD;

		if (IsMonitor(dwFlags, MonitorNetWork))
			m_MonFlags |= EVENT_TRACE_FLAG_NETWORK_TCPIP;*/
		m_MonFlags = EVENT_TRACE_FLAG_SYSTEMCALL;

		dwError = _ReStartSession();
		if (ERROR_SUCCESS != dwError)
		{
			break;
		}

		ms_bRunning = TRUE;

		ms_pTraceEventInfo = new TraceEventInfo();

		m_WaitThreadStarted = ::CreateEvent(NULL, FALSE, FALSE, NULL);
		if (NULL == m_WaitThreadStarted)
		{
			dwError = ::GetLastError();
			Stop();
			break;
		}

		m_ThreadHandle = (HANDLE)_beginthreadex(NULL, 0, _ThreadFunc, this, 0, NULL);
		if (NULL == m_ThreadHandle)
		{
			dwError = _doserrno;
			Stop();
			break;
		}
		else
		{
			::WaitForSingleObject(m_WaitThreadStarted, INFINITE);
		}

	} while (0);

	return dwError;
}

VOID CEtwMon::Stop(_In_ DWORD dwWaiteTime /* = INFINITE */)
{
	if (TRUE == ms_bRunning)
	{
		ms_bRunning = FALSE;

		if (m_EtwEnabled)
		{
			if (m_EtwStartedSession)
			{
				m_SessionProperties->LogFileNameOffset = 0;
				::ControlTrace(m_SessionHandle,ms_SessionLoggerName.c_str(),
					m_SessionProperties, EVENT_TRACE_CONTROL_STOP);
				m_EtwStartedSession = FALSE;
			}
			m_EtwEnabled = FALSE;

			m_SessionHandle = NULL;
		}

		if (NULL != m_WaitThreadStarted)
		{
			::CloseHandle(m_WaitThreadStarted);
			m_WaitThreadStarted = NULL;
		}

		if (NULL != m_ThreadHandle)
		{
			DWORD dwResult = ::WaitForSingleObject(
				m_ThreadHandle, dwWaiteTime);	//1s
			if (WAIT_TIMEOUT == dwResult)
			{
				::TerminateThread(m_ThreadHandle, 1);
			}

			::CloseHandle(m_ThreadHandle);
			m_ThreadHandle = NULL;
		}

		if (NULL != ms_pTraceEventInfo)
		{
			delete ms_pTraceEventInfo;
			ms_pTraceEventInfo = NULL;
		}

		if (NULL != m_SessionProperties)
		{
			::free(m_SessionProperties);
			m_SessionProperties = NULL;
		}
	}
}

UINT CEtwMon::_ThreadFunc(_In_ LPVOID lpParameter)
{
	UINT uRet = ERROR_SUCCESS;

	ULONG result;
	EVENT_TRACE_LOGFILE logFile;
	TRACEHANDLE traceHandle;

	CEtwMon* pThis = (CEtwMon*)lpParameter;
	
	::SetEvent(pThis->m_WaitThreadStarted);

	::ZeroMemory(&logFile, sizeof(EVENT_TRACE_LOGFILE));
	logFile.LoggerName = (LPWSTR)ms_SessionLoggerName.c_str();
	logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME		| 
							   PROCESS_TRACE_MODE_EVENT_RECORD	|
							   PROCESS_TRACE_MODE_RAW_TIMESTAMP;

	logFile.BufferCallback = _BufferCallback;
	logFile.EventRecordCallback = _EventRecordCallback;

	while (TRUE)
	{
		traceHandle = ::OpenTrace(&logFile);

		if (INVALID_PROCESSTRACE_HANDLE != traceHandle)
		{
			while (ms_bRunning &&
				(result = ::ProcessTrace(&traceHandle, 1, NULL, NULL)) == ERROR_SUCCESS)
			{
				::Sleep(1000);
			}

			::CloseTrace(traceHandle);
		}

		if (FALSE == ms_bRunning)
			break;

		if (ERROR_WMI_INSTANCE_NOT_FOUND == result)
		{
			// The session was stopped by another program. Try to start it again.
			pThis->_StartSession();
		}

		// Some error occurred, so sleep for a while before trying again.
		// Don't sleep if we just successfully started a session, though.
		if (!pThis->m_EtwEnabled)
			::Sleep(250);
	}

	_endthreadex(uRet);

	return uRet;
}

ULONG CEtwMon::_BufferCallback(_In_ PEVENT_TRACE_LOGFILE Buffer)
{
	return ms_bRunning;
}

VOID CEtwMon::_EventRecordCallback(_In_ PEVENT_RECORD pEventRecord)
{
	/*BOOL bUdpIp = FALSE;

	if (::memcmp(&pEventRecord->EventHeader.ProviderId, &TcpIpGuid, sizeof(GUID)) == 0 ||
		(bUdpIp = (::memcmp(&pEventRecord->EventHeader.ProviderId, &UdpIpGuid, sizeof(GUID)) == 0)))
	{
		_NetWorkEvent(bUdpIp, pEventRecord);
	}
	else if (::memcmp(&pEventRecord->EventHeader.ProviderId, &ThrGuid, sizeof(GUID)) == 0)
	{
		_ThreadEvent(pEventRecord);
	}
	else if (::memcmp(&pEventRecord->EventHeader.ProviderId, &ImageLoadGuid, sizeof(GUID)) == 0)
	{
		_ModuleLoadEvent(pEventRecord);
	}
	else if (::memcmp(&pEventRecord->EventHeader.ProviderId, &ProGuid, sizeof(GUID)) == 0)
	{
		_ProcessEvent(pEventRecord);
	}
	else if (::memcmp(&pEventRecord->EventHeader.ProviderId, &SystemGuid, sizeof(GUID)) == 0)
	{
		if (51 == pEventRecord->EventHeader.EventDescriptor.Opcode)
		{
			DWORD dwError = ms_pTraceEventInfo->SetEvent(pEventRecord);
			if (ERROR_SUCCESS == dwError)
			{
				ULONG64 call = 0;
				ms_pTraceEventInfo->GetData<ULONG64>(call, L"SysCallAddress");
				printf("syscall:0x%llx\n", call);
				__asm int 3;
			}
		}
	}*/
}

VOID CEtwMon::_ProcessEvent(_In_ PEVENT_RECORD pEventRecord)
{
	DWORD dwError;

	if (EVENT_TRACE_TYPE_START == pEventRecord->EventHeader.EventDescriptor.Opcode)
	{
		pEventRecord->EventHeader.TimeStamp.QuadPart;

		dwError = ms_pTraceEventInfo->SetEvent(pEventRecord);
		if (ERROR_SUCCESS == dwError)
		{
			DWORD dwProcessId;
			DWORD dwParentId;
			std::string strImageFileName;
			std::wstring wstrCommandLine;
			ms_pTraceEventInfo->GetData<DWORD>(dwProcessId, L"ProcessId");
			ms_pTraceEventInfo->GetData<DWORD>(dwParentId, L"ParentId");
			ms_pTraceEventInfo->GetDataEx(strImageFileName, L"ImageFileName");
			ms_pTraceEventInfo->GetDataEx(wstrCommandLine, L"CommandLine");
		}
	}
	else if (EVENT_TRACE_TYPE_END == pEventRecord->EventHeader.EventDescriptor.Opcode)
	{
		pEventRecord->EventHeader.TimeStamp.QuadPart;

		dwError = ms_pTraceEventInfo->SetEvent(pEventRecord);
		if (ERROR_SUCCESS == dwError)
		{
			DWORD dwProcessId;
			ms_pTraceEventInfo->GetData<DWORD>(dwProcessId, L"ProcessId");

		}
	}

	return;
}

VOID CEtwMon::_ModuleLoadEvent(_In_ PEVENT_RECORD pEventRecord)
{
	DWORD dwError;
	BOOL  bResult;
	BOOL  bImageSize = FALSE;
	BOOL  bFileName = FALSE;

	if (EVENT_TRACE_TYPE_LOAD == pEventRecord->EventHeader.EventDescriptor.Opcode)
	{
		pEventRecord->EventHeader.TimeStamp.QuadPart;

		dwError = ms_pTraceEventInfo->SetEvent(pEventRecord);
		if (ERROR_SUCCESS == dwError)
		{
			DWORD dwProcessId;
			PVOID pImageBase;
			UINT uiImageSize;
			std::wstring	wstrFileName;
			ms_pTraceEventInfo->GetData<DWORD>(dwProcessId, L"ProcessId");
			ms_pTraceEventInfo->GetData<PVOID>(pImageBase, L"ImageBase");
			ms_pTraceEventInfo->GetData<UINT>(uiImageSize, L"ImageSize");
			ms_pTraceEventInfo->GetDataEx(wstrFileName, L"FileName");
		}
	}
	//................
}

VOID CEtwMon::_ThreadEvent(_In_ PEVENT_RECORD pEventRecord)
{
	DWORD dwError;
	BOOL  bResult;

	if (EVENT_TRACE_TYPE_START == pEventRecord->EventHeader.EventDescriptor.Opcode)
	{
		pEventRecord->EventHeader.TimeStamp.QuadPart;
		
		dwError = ms_pTraceEventInfo->SetEvent(pEventRecord);
		if (ERROR_SUCCESS == dwError)
		{
			DWORD dwProcessId;
			DWORD dwThreadId;
			PVOID pWin32StartAddr;
			ms_pTraceEventInfo->GetData<DWORD>(dwProcessId, L"ProcessId");
			ms_pTraceEventInfo->GetData<DWORD>(dwThreadId, L"TThreadId");
			ms_pTraceEventInfo->GetData<PVOID>(pWin32StartAddr, L"Win32StartAddr");
		}
	}
	else if (EVENT_TRACE_TYPE_END == pEventRecord->EventHeader.EventDescriptor.Opcode)
	{
		pEventRecord->EventHeader.TimeStamp.QuadPart;

		dwError = ms_pTraceEventInfo->SetEvent(pEventRecord);
		if (ERROR_SUCCESS == dwError)
		{
			DWORD dwProcessId;
			DWORD dwThreadId;
			ms_pTraceEventInfo->GetData<DWORD>(dwProcessId, L"ProcessId");
			ms_pTraceEventInfo->GetData<DWORD>(dwThreadId, L"TThreadId");
		}
	}

	return;
}

VOID CEtwMon::_NetWorkEvent(_In_ BOOL bUdpIp, _In_ PEVENT_RECORD pEventRecord)
{
	typedef struct
	{
		ULONG PID;
		ULONG size;
		ULONG daddr;
		ULONG saddr;
		USHORT dport;
		USHORT sport;
	} TcpIpOrUdpIp_IPV4_Header;

	typedef struct
	{
		ULONG PID;
		ULONG size;
		IN6_ADDR daddr;
		IN6_ADDR saddr;
		USHORT dport;
		USHORT sport;
	} TcpIpOrUdpIp_IPV6_Header;

	MonEventType EventType;
	ULONG        ProtocolType;
	BOOL		 bResult;

	switch (pEventRecord->EventHeader.EventDescriptor.Opcode)
	{
	case EVENT_TRACE_TYPE_SEND_IPV4:
		EventType = NetWorkSendEvent;
		ProtocolType = IPV4_NETWORK_TYPE;
		break;
	case EVENT_TRACE_TYPE_RECEIVE_IPV4:
		EventType = NetWorkReceiveEvent;
		ProtocolType = IPV4_NETWORK_TYPE;
		break;
	case EVENT_TRACE_TYPE_SEND_IPV6:
		EventType = NetWorkSendEvent;
		ProtocolType = IPV6_NETWORK_TYPE;
		break;
	case EVENT_TRACE_TYPE_RECEIVE_IPV6:
		EventType = NetWorkReceiveEvent;
		ProtocolType = IPV6_NETWORK_TYPE;
		break;
	case EVENT_TRACE_TYPE_CONNECT_IPV4:
		EventType = NetWorkConnectEvent;
		ProtocolType = IPV4_NETWORK_TYPE;
		break;
	case EVENT_TRACE_TYPE_ACCEPT_IPV4:
		EventType = NetWorkAcceptEvent;
		ProtocolType = IPV4_NETWORK_TYPE;
		break;
	case EVENT_TRACE_TYPE_RECONNECT_IPV4:
		EventType = NetWorkReconnectEvent;
		ProtocolType = IPV4_NETWORK_TYPE;
		break;
	case EVENT_TRACE_TYPE_CONNECT_IPV6:
		EventType = NetWorkConnectEvent;
		ProtocolType = IPV6_NETWORK_TYPE;
		break;
	case EVENT_TRACE_TYPE_ACCEPT_IPV6:
		EventType = NetWorkAcceptEvent;
		ProtocolType = IPV6_NETWORK_TYPE;
		break;
	case EVENT_TRACE_TYPE_RECONNECT_IPV6:
		EventType = NetWorkConnectEvent;
		ProtocolType = IPV6_NETWORK_TYPE;
		break;
	default:
		return;
	}

	if (FALSE == bUdpIp)
	{
		ProtocolType |= TCP_PROTOCOL_TYPE;
	}
	else
	{
		ProtocolType |= UDP_PROTOCOL_TYPE;
	}

	DWORD           dwProcessId;
	ULONG			ulTransferSize;
	IP_ENDPOINT		LocalEndpoint;
	IP_ENDPOINT		RemoteEndpoint;

	if (ProtocolType & IPV4_NETWORK_TYPE)
	{
		TcpIpOrUdpIp_IPV4_Header *data =
			(TcpIpOrUdpIp_IPV4_Header*)pEventRecord->UserData;

		dwProcessId		= data->PID;
		ulTransferSize	= data->size;

		LocalEndpoint.Address.Type = IPV4_NETWORK_TYPE;
		LocalEndpoint.Address.Ipv4 = data->saddr;
		LocalEndpoint.Port = _byteswap_ushort(data->sport);

		RemoteEndpoint.Address.Type = IPV4_NETWORK_TYPE;
		RemoteEndpoint.Address.Ipv4 = data->daddr;
		RemoteEndpoint.Port = _byteswap_ushort(data->dport);
	}
	else
	{
		TcpIpOrUdpIp_IPV6_Header *data =
			(TcpIpOrUdpIp_IPV6_Header*)pEventRecord->UserData;

		dwProcessId = data->PID;
		ulTransferSize = data->size;

		LocalEndpoint.Address.Type = IPV6_NETWORK_TYPE;
		LocalEndpoint.Address.In6Addr = data->saddr;
		LocalEndpoint.Port = _byteswap_ushort(data->sport);

		RemoteEndpoint.Address.Type = IPV6_NETWORK_TYPE;
		RemoteEndpoint.Address.In6Addr = data->daddr;
		RemoteEndpoint.Port = _byteswap_ushort(data->dport);
	}

	pEventRecord->EventHeader.TimeStamp.QuadPart;

	return;
}
