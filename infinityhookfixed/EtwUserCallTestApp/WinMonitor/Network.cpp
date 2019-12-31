

#include "Network.h"

BOOL EqualEndPoint(_In_ IP_ENDPOINT& EndPoint1, _In_ IP_ENDPOINT& EndPoint2)
{
	BOOL bRet = FALSE;

	do 
	{
		if (EndPoint1.Port == EndPoint2.Port)
		{
			bRet = EqualIpAddress(EndPoint1.Address, EndPoint2.Address);
		}

	} while (0);

	return bRet;
}

BOOL EqualIpAddress(_In_ IP_ADDRESS& Address1, _In_ IP_ADDRESS& Address2)
{
	BOOL bRet = FALSE;

	do 
	{
		if ((Address1.Type | Address2.Type) == 0)
		{
			bRet = TRUE;
			break;
		}

		if (Address1.Type != Address2.Type)
		{
			break;
		}

		if (IPV4_NETWORK_TYPE == Address1.Type)
		{
			bRet = (Address1.Ipv4 == Address2.Ipv4);
		}
		else
		{
			bRet = (
				*(PULONG)(Address1.Ipv6) == *(PULONG)(Address2.Ipv6)		&&
				*(PULONG)(Address1.Ipv6 + 4) == *(PULONG)(Address2.Ipv6 + 4)&&
				*(PULONG)(Address1.Ipv6 + 8) == *(PULONG)(Address2.Ipv6 + 8)&&
				*(PULONG)(Address1.Ipv6 + 12) == *(PULONG)(Address2.Ipv6 + 12)
				);
		}

	} while (0);

	return bRet;
}

BOOL IsNullIpAddress(_In_ IP_ADDRESS& Address)
{
	BOOL bRet = TRUE;

	do 
	{	
		if (IPV4_NETWORK_TYPE == Address.Type)
		{
			bRet = (0 == Address.Ipv4);
			break;
		}
		else if (IPV6_NETWORK_TYPE == Address.Type)
		{
			bRet = ( 
				(*(PULONG)(Address.Ipv6)	| 
				*(PULONG)(Address.Ipv6 + 4)	|
				*(PULONG)(Address.Ipv6 + 8)	|
				*(PULONG)(Address.Ipv6 + 12)) == 0
				);
		}

	} while (0);

	return bRet;
}

/////////////////////////////////////////////////////////////////////////////////////////

#ifndef NTDLL_NAME
#define NTDLL_NAME						"ntdll.dll"
#endif
#ifndef RtlIpv4AddressToStringA_NAME
#define RtlIpv4AddressToStringA_NAME	"RtlIpv4AddressToStringA"
#endif
#ifndef RtlIpv6AddressToStringA_NAME
#define RtlIpv6AddressToStringA_NAME	"RtlIpv6AddressToStringA"
#endif

typedef
PSTR
(_stdcall* _RtlIpv4AddressToStringA)(
_In_ struct in_addr *Addr,
_Out_ PSTR S
);

typedef
PSTR
(_stdcall* _RtlIpv6AddressToStringA)(
_In_ struct in6_addr *Addr,
_Out_ PSTR S
);

HMODULE HNtDll()
{
	static HMODULE s_hNtdll = NULL;

	if (NULL == s_hNtdll)
	{
		s_hNtdll = ::LoadLibraryA(NTDLL_NAME);
	}

	return s_hNtdll;
}

PSTR RtlIpv4AddressToStringA(
	_In_ struct in_addr *Addr,
	_Out_ PSTR S
	)
{
	PSTR	pRet = NULL;

	static _RtlIpv4AddressToStringA
		s_RtlIpv4AddressToStringA = NULL;

	do
	{
		if (NULL == s_RtlIpv4AddressToStringA)
		{
			HMODULE hNtdll = HNtDll();

			s_RtlIpv4AddressToStringA = (_RtlIpv4AddressToStringA)
				::GetProcAddress(hNtdll, RtlIpv4AddressToStringA_NAME);

			if (NULL == s_RtlIpv4AddressToStringA)
			{
				break;
			}
		}

		pRet =
			s_RtlIpv4AddressToStringA(Addr, S);

	} while (0);

	return pRet;
}

PSTR RtlIpv6AddressToStringA(
	_In_ struct in6_addr *Addr,
	_Out_ PSTR S
	)
{
	PSTR	pRet = NULL;

	static _RtlIpv6AddressToStringA
		s_RtlIpv6AddressToStringA = NULL;

	do
	{
		if (NULL == s_RtlIpv6AddressToStringA)
		{
			HMODULE hNtdll = HNtDll();

			s_RtlIpv6AddressToStringA = (_RtlIpv6AddressToStringA)
				::GetProcAddress(hNtdll, RtlIpv6AddressToStringA_NAME);

			if (NULL == s_RtlIpv6AddressToStringA)
			{
				break;
			}
		}

		pRet =
			s_RtlIpv6AddressToStringA(Addr, S);

	} while (0);

	return pRet;
}

std::string IpAddressToStringA(_In_ IP_ADDRESS& Address)
{
	char ipBuffer[64];
	ipBuffer[0] = 0;

	PSTR pResult = NULL;

	if (IPV4_NETWORK_TYPE == Address.Type)
	{
		pResult = RtlIpv4AddressToStringA(&Address.InAddr, ipBuffer);
	}
	else if (IPV6_NETWORK_TYPE == Address.Type)
	{
		pResult = RtlIpv6AddressToStringA(&Address.In6Addr, ipBuffer);
	}
	
	if (NULL != pResult)
	{
		return ipBuffer;
	}
	else
	{
		return "";
	}
}

/////////////////////////////////////////////////////////////////////////////////////////

