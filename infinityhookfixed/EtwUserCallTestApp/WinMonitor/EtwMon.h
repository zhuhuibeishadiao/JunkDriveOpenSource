/*
*	author: zyb
*/

#pragma once

#ifndef __ETW_MONITOR_H__
#define __ETW_MONITOR_H__

#define INITGUID

#include "TraceEventInfo.h"
#include "MonEvent.h"

#include <windows.h>
#include <evntrace.h>
#include <string>


class CEtwMon
{
public:
	CEtwMon();
	~CEtwMon();

public:
	DWORD Start(
		_In_ DWORD dwFlags = MonitorAll);

	VOID  Stop(
		_In_ DWORD dwWaiteTime = INFINITE);

private:
	DWORD _StartSession();

	DWORD _ReStartSession();

	DWORD _InitSecssionProperties();

	static UINT WINAPI _ThreadFunc(
		_In_ LPVOID lpParameter);

	static ULONG WINAPI _BufferCallback(
		_In_ PEVENT_TRACE_LOGFILE Buffer);

	static VOID WINAPI _EventRecordCallback(
		_In_ PEVENT_RECORD pEventRecord);

	static VOID _NetWorkEvent(_In_ BOOL bUdpIp, _In_ PEVENT_RECORD pEventRecord);

	static VOID _ThreadEvent(_In_ PEVENT_RECORD pEventRecord);

	static VOID _ModuleLoadEvent(_In_ PEVENT_RECORD pEventRecord);

	static VOID _ProcessEvent(_In_ PEVENT_RECORD pEventRecord);

private:

	PEVENT_TRACE_PROPERTIES			m_SessionProperties;
	TRACEHANDLE						m_SessionHandle;
	HANDLE							m_ThreadHandle;
	DWORD							m_MonFlags;

	HANDLE							m_WaitThreadStarted;

	BOOL							m_EtwEnabled;
	BOOL							m_EtwActive;
	BOOL							m_EtwStartedSession;

	static TraceEventInfo*			ms_pTraceEventInfo;

	static std::wstring				ms_SessionLoggerName;
	static BOOL						ms_bRunning;
};

#endif
