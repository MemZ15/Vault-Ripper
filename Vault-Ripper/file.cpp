#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair file;


NTSTATUS __fastcall object_type_init_hooks::hk_file_parse_procedure_ex( void* ObjectType, void* Object, UNICODE_STRING* Remaining_Path ) {

    UNREFERENCED_PARAMETER( ObjectType );
    UNREFERENCED_PARAMETER( Object );
    UNREFERENCED_PARAMETER( Remaining_Path );

    if ( !Remaining_Path || Remaining_Path->Length == 0 ) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }


    auto fileObj = reinterpret_cast< FILE_OBJECT* >( ObjectType );

    if ( AV::extract_file_name( fileObj ) ) {
        return STATUS_SUCCESS;
    }

    //if ( AV::protect_file( fileObj ) ) {
    //    return SL_READ_ACCESS_GRANTED;
    //}

    return STATUS_OBJECT_NAME_NOT_FOUND;
}
    

 // TD: conjoin protecting our driver vs killing others

