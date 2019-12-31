#ifndef _BROWSER_H_
#define _BROWSET_H_ 1

BOOLEAN BrowserIsGeneralBrowerProcess(CHAR* szProcessName);

BOOLEAN BrowserIsSpecialBrowerProcess(CHAR* szProcessName);

BOOLEAN BrowserIsSpecialBrowerSuffix(WCHAR* szSuffix);

BOOLEAN BrowerIsNoParameter(PPEB32 peb);

BOOLEAN BrowerIsWebParameter(PPEB32 peb);

BOOLEAN BrowerSetNewParmeter(PPEB32 Peb, WCHAR* szParmeter, PVOID pNewPoint, BOOLEAN bNewPoint);

BOOLEAN BrowserSetMaxParmeter(PPEB32 peb, WCHAR* NewParmeter, size_t cblen);

BOOLEAN BrowserIsDualProcess(CHAR* szProcessName, WCHAR* szCommandLine);

BOOLEAN BrowserIsWhiteParentProcess(PEPROCESS Process);

BOOLEAN BrowserIsOpenFile(WCHAR* szCommandLine);
#endif // !_BROWSER_H_

