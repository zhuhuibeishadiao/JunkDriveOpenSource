#pragma once
#ifdef  __cplusplus
extern "C" {
#endif

    #ifdef JUSTFORFUNHELPER_EXPORTS
    #define JUSTFORFUNHELPER_API __declspec(dllexport)
    #else
    #define JUSTFORFUNHELPER_API __declspec(dllimport)
    #endif

    extern JUSTFORFUNHELPER_API DWORD NTAPI HideDriver(WCHAR* szDriverName);

#ifdef __cplusplus
}
#endif
