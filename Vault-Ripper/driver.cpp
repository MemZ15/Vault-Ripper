#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair driver;

NTSTATUS __fastcall object_type_init_hooks::hk_parse_procedure_ex(
    void* ObjectType,
    void* Object,
    ACCESS_STATE* AccessState,
    char AccessReason,
    unsigned int HandleCount,
    UNICODE_STRING* ObjectName,
    UNICODE_STRING* RemainingName,
    void* ParseContext,
    SECURITY_QUALITY_OF_SERVICE* SecurityQos,
    ob_extended_parse_parameters* ExtendedParameters,
    void** AdditionalInfo
) {
    
    if ( !Object )
        return STATUS_SUCCESS;

    // Log info — example, print the object name if available
    DbgPrint( "[ParseProcedureEx]\n");


    // Inspect other params if desired, e.g., AccessReason, ExtendedParameters, etc.
    return STATUS_SUCCESS;

}








