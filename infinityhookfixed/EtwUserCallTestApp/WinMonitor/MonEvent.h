
/*
*		author: zyb
*/
#pragma once

#ifndef __MON_EVENT_H__
#define __MON_EVENT_H__

#include <wtypes.h>
#include <string>

typedef enum
{
	UnknowMonEvent = 0,
	ModuleLoadEvent,
	ProcessStartEvent,
	ProcessEndEvent,
	ThreadStartEvent,
	ThreadEndEvent,
	NetWorkSendEvent,
	NetWorkReceiveEvent,
	NetWorkConnectEvent,
	NetWorkAcceptEvent,
	NetWorkReconnectEvent,
}MonEventType;

#define MonitorProcess				(1 << 0)
#define MonitorThread				(1 << 1)
#define MonitorModuleLoad			(1 << 2)
#define MonitorNetWork				(1 << 3)

#define MonitorAll					(MonitorProcess		|					\
									 MonitorThread		|					\
									 MonitorModuleLoad	|					\
									 MonitorNetWork)

#define IsMonitor(flags,type)		((flags) & (type))


#endif