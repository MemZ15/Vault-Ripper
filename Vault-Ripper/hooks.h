#pragma once
#include "includes.h"
#include "nt_structs.h"

typedef struct _PEB*                            ( *PsGetProcessPeb_t )( PEPROCESS Process );
typedef _OBJECT_TYPE*                            ( *ObGetObjectType_t )( PVOID* Object );
typedef _OBJECT_TYPE*                            ( *PsLookupProcessByProcessId_t )( HANDLE, PEPROCESS* );
typedef UCHAR*                                  ( *PsGetProcessImageFileName_t )( PEPROCESS );
typedef POBJECT_TYPE                            ( *GetIoDriverObjectType_t )( void );
typedef PEPROCESS                               ( *PsGetNextProcess_t )( PEPROCESS PROCESS );
typedef PEPROCESS                               ( *PsInitialSystemProcess_t )( void );
typedef POBJECT_TYPE**                          ObTypeIndexTable_t;
typedef PVOID                                   ( *ExAllocatePoolWithTag_t )( POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag );
typedef PVOID                                   ( *ExFreePoolWithTag_t )( PVOID P, ULONG Tag );


typedef struct func_pointer_table {
    uintptr_t                           PsLoadedModuleList;
    uintptr_t                           PsActiveProcessHead;
    ObGetObjectType_t                   ObGetObjectType;
    ObTypeIndexTable_t                  ObTypeIndexTableInstr;
    PsGetNextProcess_t                  PsGetNextProcess;
    PsInitialSystemProcess_t            PsInitialSystemProcess;
    PsGetProcessImageFileName_t         PsGetProcessImageFileName;
    GetIoDriverObjectType_t             GetIoDriverObjectType;
    PsLookupProcessByProcessId_t        PsLookupProcessByProcessID;
    PsGetProcessPeb_t                   PsGetProcessPeb;
    ExAllocatePoolWithTag_t             ExAllocatePoolWithTag;
    ExFreePoolWithTag_t                 ExFreePoolWithTag;

    uintptr_t                           ObTypeIndexTable;
    PHAL_PRIVATE_DISPATCH               HalTable;

} pointer_table, * _pointer_table;


namespace hooks {

    void hook_win_API( uintptr_t base, size_t size, func_pointer_table &table_handle);

    _OBJECT_TYPE* capture_initalizer_table( uintptr_t base, size_t size, pointer_table& table_handle, void* obj, bool should_hook );

}

namespace AV {

    bool process_extraction( PEPROCESS process );

    bool thread_extraction( PETHREAD thread );

    bool driver_name_extraction( PDRIVER_OBJECT driver_object );

    bool file_name_extraction( FILE_OBJECT* file_object);

    bool protect_file_name_extraction( FILE_OBJECT* file_object );

}