#pragma once
#include "includes.h"
#include "hooks.h"

namespace modules {

	uintptr_t throw_idt_exception(uintptr_t &base, size_t &base_size);

	uintptr_t find_base_from_exception( uintptr_t search_addr, size_t search_limit, uintptr_t& base, size_t& size );

	uintptr_t traverse_export_list( const char* module_name, uintptr_t base );

	PDRIVER_OBJECT AllocateFakeDriverObject( PDRIVER_OBJECT tar, PDRIVER_OBJECT fakeDriver );

	void* get_driver_object( const wchar_t* driver_name, PDRIVER_OBJECT& obj, pointer_table& table_handle );

	void DeallocateFakeDriverObject( PDRIVER_OBJECT fakeDriver );

	void scan_file_sys(uintptr_t base, size_t size, func_pointer_table table_handle);

}


namespace driver_information {

	struct DriverMetadata {
		PVOID OriginalDriverStart = nullptr;           // Original DriverStart field
		SIZE_T OriginalDriverSize;                // Original DriverSize field
		PVOID OriginalSectionSize = nullptr;          // Original DriverSection pointer
		PDEVICE_OBJECT OriginalObject = nullptr;      // Original DeviceObject pointer
		PUNICODE_STRING DriverName = nullptr;         // Original DriverName
		PDRIVER_DISPATCH OriginalDeviceControl = nullptr; // Original IRP_MJ_DEVICE_CONTROL function

		SIZE_T OriginalImageSize;                         // Original SizeOfImage from KLDR_DATA_TABLE_ENTRY
		struct OriginalListPointers {
			PLIST_ENTRY Blink = nullptr;              // Pointer to the previous entry in the list
			PLIST_ENTRY Flink = nullptr;              // Pointer to the next entry in the list
		} OriginalList;
	};


	struct Target_DriverMetadata {
		PVOID OriginalDriverStart = nullptr;           // Original DriverStart field
		SIZE_T OriginalDriverSize;                // Original DriverSize field
		PVOID OriginalSectionSize = nullptr;          // Original DriverSection pointer
		PDEVICE_OBJECT OriginalObject = nullptr;      // Original DeviceObject pointer
		PUNICODE_STRING DriverName = nullptr;         // Original DriverName
		PDRIVER_DISPATCH OriginalDeviceControl = nullptr; // Original IRP_MJ_DEVICE_CONTROL function

		SIZE_T OriginalImageSize;                         // Original SizeOfImage from KLDR_DATA_TABLE_ENTRY
		struct OriginalListPointers {
			PLIST_ENTRY Blink = nullptr;              // Pointer to the previous entry in the list
			PLIST_ENTRY Flink = nullptr;              // Pointer to the next entry in the list
		} OriginalList;
	};

}