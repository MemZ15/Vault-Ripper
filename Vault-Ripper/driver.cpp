#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair driver;

NTSTATUS __fastcall object_type_init_hooks::hk_parse_procedure_ex( VOID* ObjectType, VOID* Object ) {
    
    DbgPrint( "ParseProcedureEx Called\n" );
    if ( !ObjectType || !Object  )
        return SL_READ_ACCESS_GRANTED;

}


// This is a start, need to figure out return param's then iterate on AV based drivers





