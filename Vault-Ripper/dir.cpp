#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair dir;

NTSTATUS __fastcall object_type_init_hooks::hk_directory_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count ) {
    if ( !process || !object_body || !granted_access )
        return STATUS_INVALID_PARAMETER;

    DbgPrint( "Directory Object called" );

    if ( AV::extract_directory_name( process ) )     return STATUS_SUCCESS;

    return STATUS_SUCCESS;
}


