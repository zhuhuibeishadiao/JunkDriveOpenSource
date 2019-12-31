#ifndef _PEB_H_
#define _PEB_H_ 1

#pragma warning(disable: 4100)
#pragma warning(disable: 4201)
#pragma warning(disable: 4214)

typedef struct _CURDIR              // 2 elements, 0xC bytes (sizeof) 
{
	/*0x000*/     UNICODE_STRING32 DosPath; // 3 elements, 0x8 bytes (sizeof) 
	/*0x008*/     ULONG32        Handle;
}CURDIR, *PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS32                // 30 elements, 0x298 bytes (sizeof) 
{
	/*0x000*/     ULONG32      MaximumLength;
	/*0x004*/     ULONG32      Length;
	/*0x008*/     ULONG32      Flags;
	/*0x00C*/     ULONG32      DebugFlags;
	/*0x010*/     ULONG32      ConsoleHandle;
	/*0x014*/     ULONG32      ConsoleFlags;
	/*0x018*/     ULONG32      StandardInput;
	/*0x01C*/     ULONG32      StandardOutput;
	/*0x020*/     ULONG32      StandardError;
	/*0x024*/     struct _CURDIR CurrentDirectory;                       // 2 elements, 0xC bytes (sizeof)    
	/*0x030*/     STRING32 DllPath;                        // 3 elements, 0x8 bytes (sizeof)    
	/*0x038*/     STRING32 ImagePathName;                  // 3 elements, 0x8 bytes (sizeof)    
	/*0x040*/     STRING32 CommandLine;                    // 3 elements, 0x8 bytes (sizeof)    
	/*0x048*/     ULONG32        Environment;
	/*0x04C*/     ULONG32      StartingX;
	/*0x050*/     ULONG32      StartingY;
	/*0x054*/     ULONG32      CountX;
	/*0x058*/     ULONG32      CountY;
	/*0x05C*/     ULONG32      CountCharsX;
	/*0x060*/     ULONG32      CountCharsY;
	/*0x064*/     ULONG32      FillAttribute;
	/*0x068*/     ULONG32      WindowFlags;
	/*0x06C*/     ULONG32      ShowWindowFlags;
	/*0x070*/	  STRING32 WindowTitle;                    // 3 elements, 0x8 bytes (sizeof)    
	/*0x078*/     STRING32 DesktopInfo;                    // 3 elements, 0x8 bytes (sizeof)    
	/*............................................*/
}RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

typedef struct _PEB32                                      // 95 elements, 0x250 bytes (sizeof) 
{
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union                                                  // 2 elements, 0x1 bytes (sizeof)    
	{
		/*0x003*/         UINT8        BitField;
		struct                                             // 8 elements, 0x1 bytes (sizeof)    
		{
			/*0x003*/             UINT8        ImageUsesLargePages : 1;          // 0 BitPosition                     
			/*0x003*/             UINT8        IsProtectedProcess : 1;           // 1 BitPosition                     
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;  // 2 BitPosition                     
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1; // 3 BitPosition                     
			/*0x003*/             UINT8        IsPackagedProcess : 1;            // 4 BitPosition                     
			/*0x003*/             UINT8        IsAppContainer : 1;               // 5 BitPosition                     
			/*0x003*/             UINT8        IsProtectedProcessLight : 1;      // 6 BitPosition                     
			/*0x003*/             UINT8        SpareBits : 1;                    // 7 BitPosition                     
		};
	};
	/*0x004*/     ULONG32      Mutant;
	/*0x008*/     ULONG32      ImageBaseAddress;
	/*0x00C*/     ULONG32      Ldr;
	/*0x010*/	  struct _RTL_USER_PROCESS_PARAMETERS32*      ProcessParameters;
	/*0x014*/     ULONG32      SubSystemData;
	/*0x018*/     ULONG32      ProcessHeap;
	/*0x01C*/     ULONG32      FastPebLock;
	/*0x020*/     ULONG32      AtlThunkSListPtr;
}PEB32, *PPEB32;


USHORT PebGetCommandLineLen(PPEB32 Peb);

USHORT PebGetCommandLineMaxWriteLen(PPEB32 Peb);

WCHAR* PebGetCommandLinePoint(PPEB32 Peb);

BOOLEAN PebSetCommandLine(PPEB32 Peb, WCHAR* szCommandLine, PVOID pNewPoint, BOOLEAN bNewPoint);

PVOID PebGetNewCommandLinePoint(PPEB32 Peb);

WCHAR* PebGetParameterPoint(PPEB32 Peb);

USHORT PebGetParmeterLen(PPEB32 Peb);

#endif // !_PEB_H_





