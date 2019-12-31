
/*
*	author: zyb
*/

#include <windows.h>
#include <string>
#include <tdh.h>

class TraceEventInfo
{
public:
	TraceEventInfo();
	~TraceEventInfo();

	DWORD SetEvent(_In_ PEVENT_RECORD pEvent);

	DWORD GetDataSize(_Out_ DWORD& dwBufLen, _In_ PCWSTR name);

	template <typename T>
	DWORD GetData(_Out_ T& data, _In_ PCWSTR name)
	{
		T local;
		DWORD dwError =
			_GetData(reinterpret_cast<PBYTE>(&local), sizeof(local), name);
		if (ERROR_SUCCESS == dwError)
			data = local;
		return dwError;
	}

	DWORD GetDataEx(_Out_ PBYTE& strData, _In_ PCWSTR name);

	DWORD GetDataEx(_Out_ std::string& strData, _In_ PCWSTR name);

	DWORD GetDataEx(_Out_ std::wstring& wstrData, _In_ PCWSTR name);

private:
	DWORD _GetData(_Out_ PBYTE pBufData, _In_ DWORD dwBufSize, _In_ PCWSTR name);

private:
	EVENT_RECORD*	  m_pEvent;

	TRACE_EVENT_INFO* m_pInfo;
	ULONG			  m_InfoSize;

	PBYTE			  m_strBuf;
	ULONG			  m_BufSize;
};