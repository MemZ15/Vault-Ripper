#include "hooks.h"
#include "includes.h"
#include "helpers.h"
#include "log.h"
#include "nt_structs.h"
#include "modules.h"
#include "object_init_table.h"

ob_type_hook_pair hook_metadata = { 0 };

uintptr_t globals::table{};

void hooks::hook_win_API( uintptr_t base, size_t size, func_pointer_table &table_handle ) {

	table_handle.ObGetObjectType = ( ObGetObjectType_t )
		modules::traverse_export_list( "ObGetObjectType", base );

	table_handle.PsLookupProcessByProcessID = ( PsLookupProcessByProcessId_t )
		modules::traverse_export_list( "PsLookupProcessByProcessId", base );

	table_handle.PsGetProcessImageFileName = ( PsGetProcessImageFileName_t )
		modules::traverse_export_list( "PsGetProcessImageFileName", base );

	table_handle.GetIoDriverObjectType = ( GetIoDriverObjectType_t )
		modules::traverse_export_list( "IoDriverObjectType", base );

	table_handle.PsGetNextProcess = ( PsGetNextProcess_t )
		helpers::pattern_scan( base, size, patterns::PsGetNextProcessPattern, patterns::PsGetNextProcessMask );

	table_handle.ObTypeIndexTableInstr = ( ObTypeIndexTable_t )
		helpers::pattern_scan( ( uintptr_t )table_handle.ObGetObjectType, 0x100, patterns::ObTypeIndexTablePattern, patterns::ObTypeIndexTableMask );

	table_handle.ObTypeIndexTable = helpers::resolve_relative_address
		( ( uintptr_t )table_handle.ObTypeIndexTableInstr, 3, 7 );

	table_handle.PsGetProcessPeb = ( PsGetProcessPeb_t )
		modules::traverse_export_list( "PsGetProcessPeb", base );

	globals::table = table_handle.ObTypeIndexTable;

	Logger::Print( Logger::Level::Info, "Table Populated" );
}





object_type* hooks::capture_initalizer_table( uintptr_t base, size_t size, pointer_table& table_handle, void* obj, bool should_hook ){
	auto ob_type_index_table_base = table_handle.ObTypeIndexTable;

	_OBJECT_HEADER* obj_header = reinterpret_cast< _OBJECT_HEADER* >( reinterpret_cast< uint8_t* >( obj ) - sizeof( _OBJECT_HEADER ) );

	auto get_object_by_index = [ob_type_index_table_base]( size_t idx ) -> object_type* {

		uintptr_t object_address = ob_type_index_table_base + ( idx * sizeof( uintptr_t ) );

		return reinterpret_cast< object_type* >( *reinterpret_cast< uintptr_t* >( object_address ) );
	};

	unsigned char index = 2;
	if ( should_hook ) {
		for ( object_type* obj = get_object_by_index( index ); obj != nullptr; obj = get_object_by_index( ++index ) ) {
			if ( obj ) {
				switch ( index ) {
				case 7:
					hook_metadata.process.o_open_procedure = reinterpret_cast< open_procedure_ty >( obj->type_info.open_procedure );
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->type_info.open_procedure ), reinterpret_cast< void* >( object_type_init_hooks::hk_process_open_procedure ) );
					break;
				case 8:
					hook_metadata.thread.o_open_procedure = reinterpret_cast< open_procedure_ty >( obj->type_info.open_procedure );
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->type_info.open_procedure ), reinterpret_cast< void* >( object_type_init_hooks::hk_thread_open_procedure ) );
					break;
				case 34:
					hook_metadata.driver.o_open_procedure = reinterpret_cast< open_procedure_ty >( obj->type_info.open_procedure );
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->type_info.open_procedure ), reinterpret_cast< void* >( object_type_init_hooks::hk_driver_open_procedure ) );
					break;
				}
			}
		}
		Logger::Print( Logger::Level::Info, "Object Initalizer's Hooked" );
	}
	else
	{
		for ( object_type* obj = get_object_by_index( index ); obj != nullptr; obj = get_object_by_index( ++index ) ) {
			if ( obj ) {
				switch ( index ) {
				case 7:
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->type_info.open_procedure ), reinterpret_cast< void* >( hook_metadata.process.o_open_procedure ) );
					break;
				case 8:
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->type_info.open_procedure ), reinterpret_cast< void* >( hook_metadata.thread.o_open_procedure ) );
					break;
				case 34:
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->type_info.open_procedure ), reinterpret_cast< void* >( hook_metadata.driver.o_open_procedure ) );
					break;
				}
			}
		}
		Logger::Print( Logger::Level::Info, "Object Initalizer's Unhooked" );

		// No input code - return null
		return nullptr;
	}
}

	//FILE OBJECT needs to be hooked, and parsed