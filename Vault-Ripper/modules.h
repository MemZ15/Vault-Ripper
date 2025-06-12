#pragma once
#include "includes.h"
#include "hooks.h"
#include "helpers.h"
#include "modules.h"

namespace modules {

	uintptr_t throw_idt_exception(uintptr_t &base, size_t &base_size);

	uintptr_t find_base_from_exception( uintptr_t search_addr, size_t search_limit, uintptr_t& base, size_t& size );

	uintptr_t traverse_export_list( UINT64 hash, uintptr_t base );

	PDRIVER_OBJECT AllocateFakeDriverObject( PDRIVER_OBJECT tar, PDRIVER_OBJECT fakeDriver, func_pointer_table table_handle );

	void scan_file_sys(uintptr_t base, size_t size, func_pointer_table table_handle);

	bool check_env();

	bool LogHookDetection( UINT8* codePtr, UINT64 baseAddress );
	
	UINTN IpiBroadcastCallback( _In_ UINTN Argument );

	void* get_NTFS_driver_object( const wchar_t* device_name, PDRIVER_OBJECT& device_object, pointer_table table_handle );

	static const WCHAR* FindFilenameStart( const WCHAR* full_path, size_t length ) {
		for ( size_t i = length; i > 0; --i ) {
			if ( full_path[i - 1] == L'\\' )  return &full_path[i];
		} return full_path;
	}

}


namespace driver_information {
	struct DriverMetadata {
		PVOID OriginalDriverStart{ nullptr };
		SIZE_T OriginalDriverSize{};             
		PVOID OriginalSectionSize{ nullptr };
		PDEVICE_OBJECT OriginalObject{ nullptr };
		PUNICODE_STRING DriverName{ nullptr };
		PDRIVER_DISPATCH OriginalDeviceControl{ nullptr };

		SIZE_T OriginalImageSize{};            
		struct OriginalListPointers {
			PLIST_ENTRY Blink{ nullptr };
			PLIST_ENTRY Flink{ nullptr };
		} OriginalList{};
	};

	struct Target_DriverMetadata {
		PVOID OriginalDriverStart{ nullptr };
		SIZE_T OriginalDriverSize{};
		PVOID OriginalSectionSize{ nullptr };
		PDEVICE_OBJECT OriginalObject{ nullptr };
		PUNICODE_STRING DriverName{ nullptr };
		PDRIVER_DISPATCH OriginalDeviceControl{ nullptr };

		SIZE_T OriginalImageSize{};
		struct OriginalListPointers {
			PLIST_ENTRY Blink{ nullptr };
			PLIST_ENTRY Flink{ nullptr };
		} OriginalList{};
	};
}


namespace hash {

	constexpr UINT64 FNV_OFFSET_BASIS = 0xCBF29CE484222325;
	constexpr UINT64 FNV_PRIME = 0x100000001B3;
	constexpr UINT64 HASH_SALT = 0xA5A5A5A5A5A5A5A5;
	constexpr UINT64 XOR_KEY = 0x1337133713371337;

	constexpr UINT64 obfuscate( UINT64 hash ) {
		return hash ^ XOR_KEY;
	}
	constexpr UINT64 deobfuscate( UINT64 obf_hash ) {
	return obf_hash ^ XOR_KEY;
	}
	
	
	inline UINT64 salted_hash_string_ci( const WCHAR* str, size_t len ) {
		UINT64 hash = FNV_OFFSET_BASIS ^ HASH_SALT;
		
		for ( size_t i = 0; i < len; ++i ) {

			WCHAR c = RtlUpcaseUnicodeChar( str[i] );
			hash ^= static_cast< UINT64 >( c );
			hash *= FNV_PRIME;
		}
		return hash;
	}

	inline UINT64 salted_hash_unicode_string_ci( const UNICODE_STRING& ustr ) {
		if ( !ustr.Buffer || ustr.Length == 0 ) return 0;
			
		return salted_hash_string_ci( ustr.Buffer, ustr.Length / sizeof( 2 ) );
	}

	inline UINT64 salted_hash_lpcwstr_ci( LPCWSTR str, size_t len ) {
		return salted_hash_string_ci( str, len );
	}

	inline UINT64 salted_hash_lpcstr_ci( LPCSTR str, size_t len ) {
		UINT64 hash = FNV_OFFSET_BASIS ^ HASH_SALT;
		for ( size_t i = 0; i < len; ++i ) {
			CHAR c = str[i];
			if ( c >= 'a' && c <= 'z' ) c -= 32;
			hash ^= static_cast< UINT64 >( c );
			hash *= FNV_PRIME;
		}
		return hash;
	}

	inline UINT64 hash_bytes_ci( const BYTE* data, size_t length ) {
		UINT64 hash = FNV_OFFSET_BASIS ^ HASH_SALT;
		for ( size_t i = 0; i < length; ++i ) {
			BYTE b = data[i];
			hash ^= b;
			hash *= FNV_PRIME;
		}
		return obfuscate( hash );
	}

	#define HASH_TARGET(name_literal) \::hash::obfuscate( \::hash::salted_hash_string_ci(name_literal, sizeof(name_literal) / sizeof(2) - 1) \)
}
