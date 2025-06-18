#pragma once

#include <winternl.h>
#include <ntstatus.h>

#ifndef RTL_CONSTANT_STRING
#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), const_cast<PWSTR>(s) }
#endif

#define NtCurrentProcess		((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread			((HANDLE)(LONG_PTR)-2)
#define NtCurrentPeb()			(NtCurrentTeb()->ProcessEnvironmentBlock)
#define NtCurrentProcessId()	(NtCurrentTeb()->ClientId.UniqueProcess)
#define NtCurrentThreadId()		(NtCurrentTeb()->ClientId.UniqueThread)
#define RtlProcessHeap()		(NtCurrentPeb()->ProcessHeap)

typedef struct _PEB_CUSTOM {
	BYTE Reserved1[0x30];     // Offset to ProcessHeap (0x30 on x64)
	PVOID ProcessHeap;        // Offset 0x30
} PEB_CUSTOM, * PPEB_CUSTOM;




#ifndef RTL_CONSTANT_OBJECT_ATTRIBUTES
#define RTL_CONSTANT_OBJECT_ATTRIBUTES(p, a) { sizeof(OBJECT_ATTRIBUTES), nullptr, p, a, nullptr, nullptr }
#endif

#define NT_MACHINE					L"\\Registry\\Machine\\"
#define SVC_BASE					NT_MACHINE L"System\\CurrentControlSet\\Services\\"

#define RTL_REGISTRY_ABSOLUTE         0   // Full path from root
#define RTL_REGISTRY_SERVICES         1   // \Registry\Machine\System\CurrentControlSet\Services
#define RTL_REGISTRY_CONTROL          2   // \Registry\Machine\System\CurrentControlSet\Control
#define RTL_REGISTRY_WINDOWS_NT       3   // \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
#define RTL_REGISTRY_DEVICEMAP        4   // \Registry\Machine\Hardware\DeviceMap
#define RTL_REGISTRY_USER             5   // \Registry\User\<SID>
#define RTL_REGISTRY_HANDLE           0x40000000
#define RTL_REGISTRY_OPTIONAL         0x80000000

typedef enum _RTL_PATH_TYPE {
	RtlPathTypeUnknown = 0,
	RtlPathTypeUncAbsolute,         // \\server\share
	RtlPathTypeDriveAbsolute,       // C:\path
	RtlPathTypeDriveRelative,       // C:path (relative to current dir of drive)
	RtlPathTypeRooted,              // \path (rooted but no drive)
	RtlPathTypeRelative,            // path (relative path)
	RtlPathTypeLocalDevice,         // \\.\ or \\?\ device paths
	RtlPathTypeRootLocalDevice      // \\?\C:\path or \\?\UNC\server\share
} RTL_PATH_TYPE;

extern "C" {NTSYSAPI NTSTATUS NTAPI NtLoadDriver( PUNICODE_STRING DriverServiceName ); }

extern "C" {NTSYSAPI NTSTATUS NTAPI NtUnloadDriver( PUNICODE_STRING DriverServiceName ); }

extern "C" {NTSYSAPI NTSTATUS NTAPI RtlCreateRegistryKey( ULONG RelativeTo, PCWSTR Path ); }

extern "C" {NTSYSAPI NTSTATUS NTAPI RtlWriteRegistryValue( ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName, ULONG ValueType, PVOID ValueData, ULONG ValueLength ); }

extern "C" { NTSYSAPI NTSTATUS NTAPI RtlAdjustPrivilege( ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled ); }

extern "C" { NTSYSAPI NTSTATUS NTAPI RtlGetFullPathName_UEx( _In_ PWSTR FileName, _In_ ULONG BufferLength, _Out_writes_bytes_( BufferLength ) PWSTR Buffer, _Out_opt_ PWSTR* FilePart, _Out_opt_ RTL_PATH_TYPE* InputPathType ); }



typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef PVOID( *RtlAllocateHeap_t )( PVOID, ULONG, SIZE_T );
extern "C" {PVOID RtlAllocateHeap( PVOID HeapHandle, ULONG Flags, SIZE_T Size ); }

typedef BOOLEAN( *RtlFreeHeap_t )( PVOID, ULONG, PVOID );
extern "C" BOOLEAN RtlFreeHeap( PVOID HeapHandle, ULONG Flags, PVOID HeapBase );
