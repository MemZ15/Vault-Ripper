#pragma once
#include "includes.h"
#include "nt_structs.h"
#include "hooks.h"


namespace object_type_init_hooks {

	NTSTATUS __fastcall hk_process_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, 
		PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count );

	NTSTATUS __fastcall hk_thread_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, 
		PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count );

	NTSTATUS __fastcall hk_driver_parse_procedure_ex( void* ObjectType, void* Object, UNICODE_STRING* ObjectName, UNICODE_STRING* RemainingName );

	NTSTATUS __fastcall hk_file_parse_procedure_ex( void* ObjectType, void* Object, UNICODE_STRING* Remaining_Path );

	NTSTATUS __fastcall hk_directory_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, 
		PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count );

	NTSTATUS __fastcall hk_symlink_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, 
		PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count );
	
	NTSTATUS __fastcall hk_device_parse_procedure_ex( IN PVOID ParseObject, IN PVOID ObjectType, IN OUT PACCESS_STATE AccessState, 
		IN KPROCESSOR_MODE AccessMode, IN ULONG Attributes, IN OUT PUNICODE_STRING CompleteName, 
			IN OUT PUNICODE_STRING RemainingName, IN OUT PVOID Context, 
				IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL, OUT PVOID* Object );

	NTSTATUS __fastcall hk_device_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, 
		PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count );
}