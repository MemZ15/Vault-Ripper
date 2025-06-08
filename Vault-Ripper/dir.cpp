#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair dir;

NTSTATUS __fastcall object_type_init_hooks::hk_directory_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count ) {
    
    UNREFERENCED_PARAMETER( open_reason ); UNREFERENCED_PARAMETER( access_mode );     UNREFERENCED_PARAMETER( granted_access );     UNREFERENCED_PARAMETER( handle_count );

    if ( !process || !object_body || !granted_access )
        return STATUS_SUCCESS;

    if ( AV::extract_directory_name( process ) )     
        return STATUS_SUCCESS;


    // Kills sys wide searches
    // ->  return STATUS_OBJECT_NAME_NOT_FOUND;
    return STATUS_SUCCESS;
}


