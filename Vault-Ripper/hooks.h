#pragma once
#include "includes.h"
#include "nt_structs.h"

struct HookEntry {
    const char* name;
    uint64_t export_hash = 0;                 // Export hash if using export table
    uintptr_t* target_addr = nullptr;         // Where resolved address should be written
    uintptr_t* original_fn = nullptr;              // Resolved original function
    void* hook_fn = nullptr;                  // Optional detour
};

class HookManager {
public:
    HookManager( uintptr_t module_base, size_t module_size );

    void ResolveExport( HookEntry& hook );
    void ResolvePattern( HookEntry& hook, const BYTE* pattern, const char* mask );
    bool InstallHook( HookEntry& hook, void* detour );

private:
    uintptr_t base;
    size_t size;
};


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
typedef PEPROCESS                               ( *IoThreadToProcess_t )( PETHREAD Thread );


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
    IoThreadToProcess_t                 IoThreadToProcess;

} pointer_table, * _pointer_table;


namespace hooks {

    void hook_win_API( uintptr_t base, size_t size, func_pointer_table &table_handle);

    _OBJECT_TYPE* capture_initalizer_table( uintptr_t base, size_t size, pointer_table& table_handle, void* obj, bool should_hook );

    void hook_win_API2( uintptr_t base, size_t size, func_pointer_table& table );

}

namespace AV {

    bool extract_process_name( PEPROCESS process );

    bool extract_thread_name( PETHREAD thread );

    bool extract_driver_name( PDRIVER_OBJECT driver_object );

    bool extract_device_name( PDEVICE_OBJECT dev_object );

    bool extract_directory_name( PEPROCESS process );

    bool extract_file_name( FILE_OBJECT* file_object);

    bool protect_file( FILE_OBJECT* file_object );

}

