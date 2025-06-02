#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair thread;


NTSTATUS __fastcall object_type_init_hooks::hk_thread_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count ) {
    if ( !process || !object_body || !granted_access )
        return STATUS_INVALID_PARAMETER;

    auto thread = reinterpret_cast< _KTHREAD* >( object_body );

    if ( AV::extract_thread_name( thread ) ) {
        return STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT;
    }
        
    return hook_metadata.thread.o_open_procedure( open_reason, access_mode, process, object_body, granted_access, handle_count );
}