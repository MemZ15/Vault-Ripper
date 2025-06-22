#include "object_init_table.h"
#include "modules.h"
#include "includes.h"
#include "nt_structs.h"

ob_type_hook_pair thread;


LONG __fastcall object_type_init_hooks::ThreadOpenProcedure( _OB_OPEN_REASON arg1, KPROCESSOR_MODE arg2, _EPROCESS* arg3, _EPROCESS* arg4, ULONG* arg5, ULONG arg6 ) {
    if ( hook_metadata.thread.o_open_procedure ) {
        DbgPrint( "[THREAD] Returning to Handler" );
        return hook_metadata.thread.o_open_procedure( arg1, arg2, arg3, arg4, arg5, arg6 );
    }
    DbgPrint( "Returning to NTSTATUS" );

    return STATUS_SUCCESS;
}