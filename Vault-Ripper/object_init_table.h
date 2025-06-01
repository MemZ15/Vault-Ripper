#pragma once
#include "includes.h"
#include "nt_structs.h"
#include "hooks.h"


namespace object_type_init_hooks {

	NTSTATUS __fastcall hk_process_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count );

	NTSTATUS __fastcall hk_thread_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count );

	NTSTATUS __fastcall hk_parse_procedure_ex( VOID* ObjectType, VOID* Object, ACCESS_STATE* AccessState, char AccessReason, unsigned int HandleCount, UNICODE_STRING* ObjectName, UNICODE_STRING* RemainingName, VOID* ParseContext, SECURITY_QUALITY_OF_SERVICE* SecurityQos, ob_extended_parse_parameters* ExtendedParameters, VOID** AdditionalInfo );
}