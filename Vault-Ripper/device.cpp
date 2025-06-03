#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "log.h"
#include "nt_structs.h"

ob_type_hook_pair device;

NTSTATUS __fastcall object_type_init_hooks::hk_device_parse_procedure_ex( void* ObjectType, void* Object, UNICODE_STRING* ObjectName, UNICODE_STRING* RemainingName ) {

    if ( !ObjectType || !Object || !ObjectName || !RemainingName )
        return SL_READ_ACCESS_GRANTED;

    auto* obj = static_cast< PDEVICE_OBJECT >( ObjectType );

    DbgPrint( "Device Parses" );

    if ( AV::extract_device_name( obj ) ) {
        return SL_READ_ACCESS_GRANTED;
    }

    return SL_READ_ACCESS_GRANTED;

}






