#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "log.h"
#include "nt_structs.h"

ob_type_hook_pair driver;

NTSTATUS __fastcall object_type_init_hooks::hk_driver_parse_procedure_ex( void* ObjectType, void* Object, UNICODE_STRING* ObjectName, UNICODE_STRING* RemainingName) {
    
    UNREFERENCED_PARAMETER( ObjectType );
    UNREFERENCED_PARAMETER( Object );
    UNREFERENCED_PARAMETER( RemainingName );

    if ( !ObjectType || !Object || !ObjectName || !RemainingName )
        return STATUS_OBJECT_NO_LONGER_EXISTS;

    auto* obj = static_cast< PDRIVER_OBJECT >( ObjectType );

    if ( AV::extract_driver_name( obj ) ) {
        return STATUS_POLICY_OBJECT_NOT_FOUND;
    }
  
    return STATUS_OBJECT_NAME_NOT_FOUND;

}






