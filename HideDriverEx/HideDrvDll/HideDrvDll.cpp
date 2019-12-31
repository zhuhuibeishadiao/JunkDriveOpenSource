// HideDrvDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <Windows.h>
#include <devioctl.h>

#define IOCTL_BASE  0x800
#define MY_CTL_CODE(i) CTL_CODE(FILE_DEVICE_NULL, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_TEST MY_CTL_CODE(0) 
#define IOCTL_HIDE_DRIVER MY_CTL_CODE(1)

DWORD NTAPI HideDriver(WCHAR* szDriverName)
{
    if (szDriverName == NULL)
        return 1;

    MessageBox(NULL, szDriverName, L"xxx", MB_OK);

    HANDLE hDevice = CreateFileA("\\\\.\\BLCheers",
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        // 隐藏驱动的驱动没加载
        return 2;
    }

    DWORD dwRet = 0;
   
    auto b = DeviceIoControl(hDevice, IOCTL_HIDE_DRIVER, szDriverName, wcslen(szDriverName) * 2, NULL, 0, &dwRet, NULL);

    CloseHandle(hDevice);

    return b ? 0 : 3;
  
}

