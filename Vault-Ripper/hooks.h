#pragma once
#include "includes.h"
#include "nt_structs.h"

typedef struct _PEB* ( *PsGetProcessPeb_t )( PEPROCESS Process );
typedef object_type* ( *ObGetObjectType_t )( PVOID* Object );
typedef object_type* ( *PsLookupProcessByProcessId_t )( HANDLE, PEPROCESS* );
typedef UCHAR* ( *PsGetProcessImageFileName_t )( PEPROCESS );
typedef PEPROCESS( *PsGetNextProcess_t )( PEPROCESS PROCESS );
typedef PEPROCESS( *PsInitialSystemProcess_t )( void );
typedef POBJECT_TYPE** ObTypeIndexTable_t;
typedef struct func_pointer_table {
    uintptr_t PsLoadedModuleList;
    uintptr_t PsActiveProcessHead;
    ObGetObjectType_t ObGetObjectType;
    ObTypeIndexTable_t ObTypeIndexTableInstr;
    PsGetNextProcess_t PsGetNextProcess;
    PsInitialSystemProcess_t PsInitialSystemProcess;
    PsGetProcessImageFileName_t PsGetProcessImageFileName;
    PsLookupProcessByProcessId_t PsLookupProcessByProcessID;
    PsGetProcessPeb_t PsGetProcessPeb;
    uintptr_t ObTypeIndexTable;
    PHAL_PRIVATE_DISPATCH HalTable;
} pointer_table, * _pointer_table;


namespace hooks {

    void hook_win_API( uintptr_t base, size_t size, func_pointer_table &table_handle);

    object_type* capture_initalizer_table( uintptr_t base, size_t size, pointer_table& table_handle, void* obj, bool should_hook );

    object_type* get_obj_type( void* obj );

}

namespace AV {

    bool process_extraction( PEPROCESS process, LPCWSTR target_name );



}