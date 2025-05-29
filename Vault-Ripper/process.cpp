#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair process;



NTSTATUS __fastcall object_type_init_hooks::hk_process_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count )
{

    if ( !process || !object_body || !granted_access )
        return STATUS_INVALID_PARAMETER;


    if ( open_reason == e_ob_open_reason::ob_create_handle || open_reason == e_ob_open_reason::ob_duplicate_handle || open_reason == e_ob_open_reason::ob_open_handle ) {
        
        if ( AV::process_extraction( object_body, L"MBAMSerivce.exe" ) ) { // Gonna require an array of AV based processes
            return STATUS_ACCESS_VIOLATION;
        }
        
    }

    return hook_metadata.process.o_open_procedure( open_reason, access_mode, process, object_body, granted_access, handle_count );

}

