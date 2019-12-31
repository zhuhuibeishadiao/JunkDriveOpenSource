#ifndef _PCH_H_
#define _PCH_H_  1

#include <ntifs.h>
#include <ntddk.h>
#include <stdio.h>
#include <fltkernel.h>

#include "IPGPeb.h"
#include "IPGNtApi.h"
#include "IPGbrowser.h"
#include "IPGMinifilter.h"
#include "IPGIndexGuard.h"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifndef DWORD
#define DWORD ULONG
#endif


#endif