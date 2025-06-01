#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "log.h"
#include "nt_structs.h"

ob_type_hook_pair driver;

NTSTATUS __fastcall object_type_init_hooks::hk_parse_procedure_ex( void* ObjectType, void* Object, UNICODE_STRING* ObjectName, UNICODE_STRING* RemainingName) {
    
    if ( !ObjectType || !Object )
        return SL_READ_ACCESS_GRANTED;

    auto* obj = reinterpret_cast< PDRIVER_OBJECT >( ObjectType );
    if ( obj )
        DbgPrint( "OBJECT_TYPE name: %wZ\n", obj->DriverName );
  

    Logger::Print( Logger::Level::Info, "Driver Parse Procedure Called" );

    return SL_READ_ACCESS_GRANTED;

}


// This is a start, need to figure out return param's then iterate on AV based drivers





