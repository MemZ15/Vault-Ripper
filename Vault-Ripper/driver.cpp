#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair driver;

NTSTATUS __fastcall object_type_init_hooks::hk_parse_procedure(
    void* ObjectType,
    void* Object,
    ACCESS_STATE* AccessState,
    char AccessReason,
    unsigned int HandleCount,
    UNICODE_STRING* ObjectName,
    UNICODE_STRING* RemainingName,
    void* ParseContext,
    SECURITY_QUALITY_OF_SERVICE* SecurityQos,
    void** AdditionalInfo
) {

    if ( Object != nullptr ) {
        DbgPrint( "Driver Info consulted" );
    }

    // Possibly inspect AccessState, AccessReason, HandleCount etc. here

    // Call the original parse procedure
    return STATUS_SUCCESS;


}





