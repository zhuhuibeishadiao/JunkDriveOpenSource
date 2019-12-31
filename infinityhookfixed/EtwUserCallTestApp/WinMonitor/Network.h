
/*
*	author: zyb
*/

#pragma once

#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <wtypes.h>
#include <inaddr.h>
#include <in6addr.h>
#include <string>

#define IPV4_NETWORK_TYPE			(0x1)
#define IPV6_NETWORK_TYPE			(0x2)
#define NETWORK_TYPE_MASK			(0x3)

#define TCP_PROTOCOL_TYPE			(0x10)
#define UDP_PROTOCOL_TYPE			(0x20)
#define PROTOCOL_TYPE_MASK			(0x30)

#define NO_NETWORK_PROTOCOL			(0x0)
#define TCP4_NETWORK_PROTOCOL		(IPV4_NETWORK_TYPE | TCP_PROTOCOL_TYPE)
#define TCP6_NETWORK_PROTOCOL		(IPV6_NETWORK_TYPE | TCP_PROTOCOL_TYPE)
#define UDP4_NETWORK_PROTOCOL		(IPV4_NETWORK_TYPE | UDP_PROTOCOL_TYPE)
#define UDP6_NETWORK_PROTOCOL		(IPV6_NETWORK_TYPE | UDP_PROTOCOL_TYPE)

typedef struct _IP_ADDRESS
{
	ULONG	Type;
	union
	{
		ULONG	Ipv4;
		struct  in_addr  InAddr;
		UCHAR	Ipv6[16];
		struct  in6_addr In6Addr;
	};

}IP_ADDRESS, *PIP_ADDRESS;

typedef struct _IP_ENDPOINT
{
	IP_ADDRESS	Address;
	ULONG		Port;
}IP_ENDPOINT, *PIP_ENDPOINT;

BOOL EqualEndPoint(
	_In_ IP_ENDPOINT& EndPoint1,
	_In_ IP_ENDPOINT& EndPoint2);

BOOL EqualIpAddress(
	_In_ IP_ADDRESS& Address1,
	_In_ IP_ADDRESS& Address2);

BOOL IsNullIpAddress(
	_In_ IP_ADDRESS& Address);

std::string IpAddressToStringA(
	_In_ IP_ADDRESS& Address);

#endif