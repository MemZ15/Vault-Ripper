#include "hooks.h"
#include "includes.h"
#include "helpers.h"
#include "log.h"
#include "nt_structs.h"
#include "modules.h"
#include "object_init_table.h"

ob_type_hook_pair hook_metadata = { 0 };

void mngr::hook_win_API( uintptr_t base, size_t size, func_pointer_table& table_handle ) {
    table_handle.ObGetObjectType = ( ObGetObjectType_t )
        modules::traverse_export_list( OBGetObjectType_HASH, base );
    DbgPrint( "ObGetObjectType: 0x%p\n", table_handle.ObGetObjectType );

    table_handle.PsLoadedModuleList = ( PsLoadedModuleList_t )
        modules::traverse_export_list( PsLoadedModuleList_HASH, base );
    DbgPrint( "PsLoadedModuleList: 0x%p\n", table_handle.PsLoadedModuleList );

    table_handle.ExAllocatePoolWithTag = ( ExAllocatePoolWithTag_t )
        modules::traverse_export_list( ExAllocatePoolWithTag_HASH, base );
    DbgPrint( "ExAllocatePoolWithTag: 0x%p\n", table_handle.ExAllocatePoolWithTag );

    table_handle.ExFreePoolWithTag = ( ExFreePoolWithTag_t )
        modules::traverse_export_list( ExFreePoolWithTag_HASH, base );
    DbgPrint( "ExFreePoolWithTag: 0x%p\n", table_handle.ExFreePoolWithTag );

    table_handle.PsLookupProcessByProcessID = ( PsLookupProcessByProcessId_t )
        modules::traverse_export_list( PsLookupProcessByProcessId_HASH, base );
    DbgPrint( "PsLookupProcessByProcessId: 0x%p\n", table_handle.PsLookupProcessByProcessID );

    table_handle.PsGetProcessImageFileName = ( PsGetProcessImageFileName_t )
        modules::traverse_export_list( PsGetProcessImageFileName_HASH, base );
    DbgPrint( "PsGetProcessImageFileName: 0x%p\n", table_handle.PsGetProcessImageFileName );

    table_handle.GetIoDriverObjectType = ( GetIoDriverObjectType_t )
        modules::traverse_export_list( GetIoDriverObjectType_t_HASH, base );
    DbgPrint( "GetIoDriverObjectType: 0x%p\n", table_handle.GetIoDriverObjectType );

    table_handle.PsGetNextProcess = ( PsGetNextProcess_t )
        helpers::pattern_scan( base, size, patterns::PsGetNextProcessPattern, patterns::PsGetNextProcessMask );
    DbgPrint( "PsGetNextProcess: 0x%p\n", table_handle.PsGetNextProcess );

    table_handle.ObTypeIndexTableInstr = ( ObTypeIndexTable_t )
        helpers::pattern_scan( ( uintptr_t )table_handle.ObGetObjectType, 0x100, patterns::ObTypeIndexTablePattern, patterns::ObTypeIndexTableMask );
    DbgPrint( "ObTypeIndexTableInstr: 0x%p\n", table_handle.ObTypeIndexTableInstr );

    table_handle.ObTypeIndexTable = helpers::resolve_relative_address(
        ( uintptr_t )table_handle.ObTypeIndexTableInstr, 3, 7 );
    DbgPrint( "ObTypeIndexTable (resolved): 0x%p\n", table_handle.ObTypeIndexTable );

    table_handle.PsGetProcessPeb = ( PsGetProcessPeb_t )
        modules::traverse_export_list( PsGetProcessPeb_t_HASH, base );
    DbgPrint( "PsGetProcessPeb: 0x%p\n", table_handle.PsGetProcessPeb );

    table_handle.IoThreadToProcess = ( IoThreadToProcess_t )
        modules::traverse_export_list( IoThreadToProcess_t_HASH, base );
    DbgPrint( "IoThreadToProcess: 0x%p\n", table_handle.IoThreadToProcess );

    globals::stored_one = table_handle.ObTypeIndexTable;
    globals::stored_three = table_handle.PsGetProcessImageFileName;
    globals::stored_four = table_handle.IoThreadToProcess;

    Logger::Print( Logger::Level::Info, "Table Populated" );
}


mngr::HookManager::HookManager( uintptr_t ob_type_index_table_base ) : ob_type_index_table( ob_type_index_table_base ) {
    hooks[0] = { 8, nullptr, reinterpret_cast< void** >( object_type_init_hooks::ProcessOpenProcedure ), nullptr };
    hooks[1] = { 9, nullptr, reinterpret_cast< void** >( object_type_init_hooks::ThreadOpenProcedure ), nullptr };
    // contintue o update
}


_OBJECT_TYPE* mngr::HookManager::GetObjectByIndex( unsigned char idx ) const {
    uintptr_t object_address = ob_type_index_table + ( idx * sizeof( uintptr_t ) );

    uintptr_t** ptr_to_ptr = reinterpret_cast< uintptr_t** >( object_address );
    if ( !ptr_to_ptr || !*ptr_to_ptr ) 
        return nullptr;

    return reinterpret_cast< _OBJECT_TYPE* >( *ptr_to_ptr );
}


bool mngr::HookManager::HookObjects( bool install ) {
    for ( int i = 0; i < hook_count; i++ ) {
        _OBJECT_TYPE* obj = GetObjectByIndex( hooks[i].index );
        if ( obj == nullptr )
            continue;

        auto update_metadata = [&]( int idx, void* orig_fn ) {
            switch ( idx ) {
            case 8: hook_metadata.process.o_open_procedure = reinterpret_cast< open_procedure_ty >( orig_fn ); break;
            case 9: hook_metadata.thread.o_open_procedure = reinterpret_cast< open_procedure_ty >( orig_fn ); break;
            }
        };
        auto hook_unhook = [&]( auto* proc_ptr, void*& original_fn ) {
            if ( install ) {
                if ( original_fn == nullptr ) {
                    original_fn = reinterpret_cast< void* >( *proc_ptr );
                }
                update_metadata( hooks[i].index, original_fn );
                _InterlockedExchangePointer( reinterpret_cast< void** >( proc_ptr ), reinterpret_cast< void* >( hooks[i].hook_fn ) );
            }
            else {
                _InterlockedExchangePointer( reinterpret_cast< void** >( proc_ptr ), reinterpret_cast< void* >( original_fn ) );
            }
        };

        // Process, Thread, Symlink, Directory
        switch ( hooks[i].index ) {
        case 8: case 9: {
            open_procedure_ty* open_ptr = &obj->TypeInfo.OpenProcedure;
            hook_unhook( open_ptr, hooks[i].original_fn );
            break;
        }
        default:
            break;
        }
    } Logger::Print( Logger::Level::Info, install ? "Object Initializers Hooked" : "Object Initializers Unhooked" );
    return true;
}





// Just used to dump obj types --> will be removed
_OBJECT_TYPE* test::capture_initalizer_table( uintptr_t* base, size_t size, pointer_table& table_handle, void* obj, bool should_hook ) {
	auto ob_type_index_table_base = table_handle.ObTypeIndexTable;

	_OBJECT_HEADER* obj_header = reinterpret_cast< _OBJECT_HEADER* >( reinterpret_cast< uint8_t* >( obj ) - sizeof( _OBJECT_HEADER ) );

	auto get_object_by_index = [ob_type_index_table_base]( size_t idx ) -> _OBJECT_TYPE* {

		uintptr_t object_address = ob_type_index_table_base + ( idx * sizeof( uintptr_t ) );

		return reinterpret_cast< _OBJECT_TYPE* >( *reinterpret_cast< uintptr_t** >( object_address ) );
	};

	unsigned char index = 2;
    if ( should_hook ) {
        for ( _OBJECT_TYPE* obj = get_object_by_index( index ); obj != nullptr; obj = get_object_by_index( ++index ) ) {
            if ( obj ) {
                DbgPrint( "Object %ws, Index %d", obj->Name.Buffer, obj->Index );
            }
        }
    }
		return nullptr;
}