
#include "TraceEventInfo.h"

#pragma comment(lib,"Tdh.lib")

TraceEventInfo::TraceEventInfo()
{
	m_pEvent = NULL;
	m_pInfo = NULL;
	m_InfoSize = 0;
	m_strBuf = NULL;
	m_BufSize = 0;
}

TraceEventInfo::~TraceEventInfo()
{
	if (NULL != m_pInfo)
		::free(m_pInfo);
	if (NULL != m_strBuf)
		::free(m_strBuf);
}

DWORD TraceEventInfo::SetEvent(_In_ PEVENT_RECORD pEvent)
{
	DWORD  dwError = ERROR_SUCCESS;

	m_pEvent = NULL;
	ULONG uInfoSize = m_InfoSize;
	dwError = ::TdhGetEventInformation(pEvent,
		0, NULL, m_pInfo, &uInfoSize);
	if (ERROR_INSUFFICIENT_BUFFER == dwError &&
		uInfoSize > m_InfoSize)
	{
		if (m_pInfo)
			::free(m_pInfo);
		m_pInfo = (TRACE_EVENT_INFO*)::malloc(uInfoSize);
		if (NULL == m_pInfo)
		{
			dwError = ERROR_NOT_ENOUGH_MEMORY;
			m_InfoSize = 0;
			return dwError;
		}
		m_InfoSize = uInfoSize;
		dwError = ::TdhGetEventInformation(pEvent,
			0, NULL, m_pInfo, &uInfoSize);
	}
	if (ERROR_SUCCESS == dwError)
		m_pEvent = pEvent;

	return dwError;
}

DWORD TraceEventInfo::_GetData(_Out_ PBYTE pBufData, _In_ DWORD dwBufSize, _In_ PCWSTR name)
{
	DWORD dwError;
	PROPERTY_DATA_DESCRIPTOR descriptor;
	descriptor.ArrayIndex = 0;
	descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
	dwError = ::TdhGetProperty(m_pEvent, 0, NULL, 1, &descriptor, dwBufSize, pBufData);
	return dwError;
}

DWORD TraceEventInfo::GetDataSize(_Out_ DWORD& dwBufLen, _In_ PCWSTR name)
{
	DWORD dwError;
	PROPERTY_DATA_DESCRIPTOR descriptor;
	descriptor.ArrayIndex = 0;
	descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
	dwError = ::TdhGetPropertySize(m_pEvent, 0, NULL, 1, &descriptor, &dwBufLen);
	return dwError;
}

DWORD TraceEventInfo::GetDataEx(_Out_ PBYTE& strData, _In_ PCWSTR name)
{
	if (NULL == m_strBuf)
		goto _Init;

	DWORD dwError =
		_GetData(m_strBuf, m_BufSize, name);
	if (ERROR_INSUFFICIENT_BUFFER == dwError)
	{
_Init:
		DWORD dwBufLen = 0;
		dwError = GetDataSize(dwBufLen, name);
		if (ERROR_SUCCESS != dwError)
			return dwError;
		if (dwBufLen > m_BufSize)
		{
			if (m_strBuf)
				::free(m_strBuf);
			m_strBuf = (PBYTE)::malloc(dwBufLen);
			if (NULL == m_strBuf)
			{
				m_BufSize = 0;
				return ERROR_NOT_ENOUGH_MEMORY;
			}
			m_BufSize = dwBufLen;

			dwError = _GetData(m_strBuf, dwBufLen, name);
		}
	}
	if (ERROR_SUCCESS == dwError)
		strData = m_strBuf;

	return dwError;
}

DWORD TraceEventInfo::GetDataEx(_Out_ std::string& strData, _In_ PCWSTR name)
{
	PBYTE pbyte;
	DWORD dwError =
		GetDataEx(pbyte, name);
	if (ERROR_SUCCESS == dwError)
		strData = (PSTR)pbyte;

	return dwError;
}

DWORD TraceEventInfo::GetDataEx(_Out_ std::wstring& wstrData, _In_ PCWSTR name)
{
	PBYTE pbyte;
	DWORD dwError =
		GetDataEx(pbyte, name);
	if (ERROR_SUCCESS == dwError)
		wstrData = (PWSTR)pbyte;

	return dwError;
}
