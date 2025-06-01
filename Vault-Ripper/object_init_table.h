#pragma once
#include "includes.h"
#include "nt_structs.h"
#include "hooks.h"


namespace object_type_init_hooks {

	NTSTATUS __fastcall hk_process_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count );

	NTSTATUS __fastcall hk_thread_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count );

	NTSTATUS __fastcall hk_driver_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS parent_process, PEPROCESS target_process, unsigned int* granted_access, unsigned long handle_count );

	NTSTATUS __fastcall hk_driver_open_procedure2( _DRIVER_OBJECT* driver_object, _UNICODE_STRING* registry_path );
}