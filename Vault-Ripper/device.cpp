#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair device;


NTSTATUS __fastcall object_type_init_hooks::hk_device_parse_procedure_ex( IN PVOID ParseObject,
    IN PVOID ObjectType,
    IN OUT PACCESS_STATE AccessState,
    IN KPROCESSOR_MODE AccessMode,
    IN ULONG Attributes,
    IN OUT PUNICODE_STRING CompleteName,
    IN OUT PUNICODE_STRING RemainingName,
    IN OUT PVOID Context,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
    OUT PVOID* Object )
{

    auto devObj = reinterpret_cast< PDEVICE_OBJECT* >( ObjectType );

    DbgPrint( "Invoked" );

    return STATUS_SUCCESS;
}

NTSTATUS __fastcall object_type_init_hooks::hk_device_open_procedure( e_ob_open_reason open_reason, uint8_t access_mode, PEPROCESS process, PEPROCESS object_body, unsigned int* granted_access, unsigned long handle_count ){

    DbgPrint( "Device Parse Called" );

    return NTSTATUS( STATUS_SUCCESS );
}



