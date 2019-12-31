// TestApp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <Windows.h>

#define IOCONTROL_FILEHANDLE 10010
#define IOCODE_READ 1
#define IOCODE_WRITE 2
#define IOCODE_GETBASE 3

#define IOCODE_DRIVER_LOADED 4

#define IOCODE_MAX 5

int main()
{
	DWORD dwRet = 0;
	DWORD dwMin = 0;
	while (true)
	{
		if (DeviceIoControl((HANDLE)IOCONTROL_FILEHANDLE, IOCODE_DRIVER_LOADED, NULL, 0, NULL, 0, &dwRet, NULL))
		{
			printf("success.\n");
		}
		else
		{
			printf("faild.\n");
		}
		dwMin++;
		printf("%d\n", dwMin);
		Sleep(1000 * 60);
	}

	getchar();
}
