#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair driver;

NTSTATUS __fastcall object_type_init_hooks::hk_parse_procedure_ex( VOID* ObjectType, VOID* Object, ACCESS_STATE* AccessState, char AccessReason, unsigned int HandleCount, UNICODE_STRING* ObjectName, UNICODE_STRING* RemainingName, VOID* ParseContext, SECURITY_QUALITY_OF_SERVICE* SecurityQos, ob_extended_parse_parameters* ExtendedParameters, VOID** AdditionalInfo ) {
    
    DbgPrint( "ParseProcedureEx Called\n" );

    return HandleCount;

}


// This is a start, need to figure out return param's then iterate on AV based drivers





