#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair file;


NTSTATUS __fastcall object_type_init_hooks::hk_file_parse_procedure_ex( void* ObjectType, void* Object, UNICODE_STRING* ObjectName, UNICODE_STRING* RemainingName ) {

    if ( !ObjectType || !Object || !ObjectName || !RemainingName )
        return STATUS_OBJECT_NO_LONGER_EXISTS;

    auto fileObj = reinterpret_cast< FILE_OBJECT* >( ObjectType );

    DbgPrint( "File Interaction called" );


    if ( AV::file_name_extraction( fileObj ) ) {
        return STATUS_BAD_FILE_TYPE;
    }

    if ( AV::protect_file_name_extraction( fileObj ) ) {
        DbgPrint( "Found our driver" );
        return SL_READ_ACCESS_GRANTED;
    }


    return SL_READ_ACCESS_GRANTED;
}
    

 

