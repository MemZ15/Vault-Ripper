#pragma once
#include "includes.h"
#include "nt_structs.h"

// Constants for MSRs and VM-exit reasons
#define MSR_LSTAR                0xC0000082ULL
#define MSR_IA32_SYSENTER_EIP    0x00000176ULL

#define EXIT_REASON_MSR_READ     0x1FULL
#define EXIT_REASON_MSR_WRITE    0x20ULL
#define EXIT_REASON_EXCEPTION_OR_NMI 0x0EULL
#define VECTOR_SYSCALL           0x2E

#define CPU_BASED_ACTIVATE_SECONDARY 0x80000000ULL
#define SECONDARY_ENABLE_EPT         0x00000002ULL

// AdjustCtl: helper to combine MSR read controls and desired bits
#define AdjustCtl(msr, value) (((msr) & 0xFFFFFFFF) | ((value) & 0xFFFFFFFF00000000))


// API typedef's
typedef struct _PEB* ( *PsGetProcessPeb_t )( PEPROCESS Process );
typedef uintptr_t( *PsLoadedModuleList_t )( PEPROCESS );
typedef _OBJECT_TYPE* ( *ObGetObjectType_t )( PVOID* Object );
typedef _OBJECT_TYPE* ( *PsLookupProcessByProcessId_t )( HANDLE, PEPROCESS* );
typedef UCHAR* ( *PsGetProcessImageFileName_t )( PEPROCESS );
typedef POBJECT_TYPE( *GetIoDriverObjectType_t )( void );
typedef PEPROCESS( *PsGetNextProcess_t )( PEPROCESS PROCESS );
typedef PEPROCESS( *PsInitialSystemProcess_t )( void );
typedef POBJECT_TYPE** ObTypeIndexTable_t;
typedef PVOID( *ExAllocatePoolWithTag_t )( POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag );
typedef PVOID( *ExFreePoolWithTag_t )( PVOID P, ULONG Tag );
typedef PEPROCESS( *IoThreadToProcess_t )( PETHREAD Thread );

// API table
typedef struct func_pointer_table {
    PsLoadedModuleList_t                PsLoadedModuleList;
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
    IoThreadToProcess_t                 IoThreadToProcess;

} pointer_table, * _pointer_table;


struct HookEntry {
    unsigned char index;                // index to be looped
    uintptr_t* target_addr;             // the adr
    void* hook_fn;                      // our func
    void* original_fn;                  // og func
};

namespace test {
    _OBJECT_TYPE* capture_initalizer_table( uintptr_t* base, size_t size, pointer_table& table_handle, void* obj, bool should_hook );
}

namespace mngr {

    void hook_win_API( uintptr_t base, size_t size, func_pointer_table& table_handle );

    class HookManager {
        public:
            HookManager( uintptr_t ob_type_index_table_base );

            bool HookObjects( bool install );

        private:
            uintptr_t ob_type_index_table{ 0 };

            static const int hook_count = 2; // static # of hooks to iterate on

            HookEntry hooks[hook_count];

            _OBJECT_TYPE* GetObjectByIndex( unsigned char idx ) const;
        };
}

// process identification modules
namespace AV {
    bool extract_process_name( PEPROCESS process );

    bool extract_symlink_name( PEPROCESS process );

    bool extract_directory_name( PEPROCESS process );

    bool extract_thread_name( PETHREAD thread );

    bool extract_driver_name( PDRIVER_OBJECT driver_object );

    bool extract_file_name( FILE_OBJECT* file_object );

    bool protect_file( FILE_OBJECT* file_object );

    bool extract_device_name( PDEVICE_OBJECT dev_object );
}
