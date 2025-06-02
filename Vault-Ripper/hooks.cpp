#include "hooks.h"
#include "includes.h"
#include "helpers.h"
#include "log.h"
#include "nt_structs.h"
#include "modules.h"
#include "object_init_table.h"

ob_type_hook_pair hook_metadata = { 0 };

uintptr_t globals::stored_one{ 0 };
_OBJECT_TYPE* globals::stored_two{ nullptr };
void* globals::stored_three{ nullptr };
void* globals::stored_four{ nullptr };

void hooks::hook_win_API( uintptr_t base, size_t size, func_pointer_table &table_handle ) {

	table_handle.ObGetObjectType = ( ObGetObjectType_t )
		modules::traverse_export_list( OBGetObjectType_HASH, base );

	table_handle.ExAllocatePoolWithTag = ( ExAllocatePoolWithTag_t ) 
		modules::traverse_export_list( ExAllocatePoolWithTag_HASH, base );

	table_handle.ExFreePoolWithTag = ( ExFreePoolWithTag_t ) 
		modules::traverse_export_list( ExFreePoolWithTag_HASH, base );

	table_handle.PsLookupProcessByProcessID = ( PsLookupProcessByProcessId_t ) 
		modules::traverse_export_list( PsLookupProcessByProcessId_HASH, base );

	table_handle.PsGetProcessImageFileName = ( PsGetProcessImageFileName_t ) 
		modules::traverse_export_list( PsGetProcessImageFileName_HASH, base );

	table_handle.GetIoDriverObjectType = ( GetIoDriverObjectType_t ) 
		modules::traverse_export_list( GetIoDriverObjectType_t_HASH, base );

	table_handle.PsGetNextProcess = ( PsGetNextProcess_t )
		helpers::pattern_scan( base, size, patterns::PsGetNextProcessPattern, patterns::PsGetNextProcessMask );

	table_handle.ObTypeIndexTableInstr = ( ObTypeIndexTable_t )
		helpers::pattern_scan( ( uintptr_t )table_handle.ObGetObjectType, 0x100, patterns::ObTypeIndexTablePattern, patterns::ObTypeIndexTableMask );

	table_handle.ObTypeIndexTable = helpers::resolve_relative_address
		( ( uintptr_t )table_handle.ObTypeIndexTableInstr, 3, 7 );

	table_handle.PsGetProcessPeb = ( PsGetProcessPeb_t )
		modules::traverse_export_list( PsGetProcessPeb_t_HASH, base );

	table_handle.IoThreadToProcess = ( IoThreadToProcess_t )
		modules::traverse_export_list( IoThreadToProcess_t_HASH, base );

	globals::stored_one = table_handle.ObTypeIndexTable;
	
	globals::stored_three = table_handle.PsGetProcessImageFileName;

	globals::stored_four = table_handle.IoThreadToProcess;

	Logger::Print( Logger::Level::Info, "Table Populated" );
}

_OBJECT_TYPE* hooks::capture_initalizer_table( uintptr_t base, size_t size, pointer_table& table_handle, void* obj, bool should_hook ){
	auto ob_type_index_table_base = table_handle.ObTypeIndexTable;

	_OBJECT_HEADER* obj_header = reinterpret_cast< _OBJECT_HEADER* >( reinterpret_cast< uint8_t* >( obj ) - sizeof( _OBJECT_HEADER ) );

	auto get_object_by_index = [ob_type_index_table_base]( size_t idx ) -> _OBJECT_TYPE* {

		uintptr_t object_address = ob_type_index_table_base + ( idx * sizeof( uintptr_t ) );

		return reinterpret_cast< _OBJECT_TYPE* >( *reinterpret_cast< uintptr_t* >( object_address ) );
	};

	unsigned char index = 2;
	if ( should_hook ) {
		for ( _OBJECT_TYPE* obj = get_object_by_index( index ); obj != nullptr; obj = get_object_by_index( ++index ) ) {
			if ( obj ) {
				switch ( index ) {
				case 7:
					hook_metadata.process.o_open_procedure = reinterpret_cast< open_procedure_ty >( obj->TypeInfo.open_procedure );
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->TypeInfo.open_procedure ), reinterpret_cast< void* >( object_type_init_hooks::hk_process_open_procedure ) );
					break;
				case 8:
					hook_metadata.thread.o_open_procedure = reinterpret_cast< open_procedure_ty >( obj->TypeInfo.open_procedure );
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->TypeInfo.open_procedure ), reinterpret_cast< void* >( object_type_init_hooks::hk_thread_open_procedure ) );
					break;
				case 34:
					hook_metadata.driver.o_parse_procedure_ex_detail = reinterpret_cast< parse_procedure_ex_ty >( obj->TypeInfo.parse_procedure_ex );
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->TypeInfo.parse_procedure_ex ), reinterpret_cast< void* >( object_type_init_hooks::hk_driver_parse_procedure_ex ) );
					break;
				case 37:
					hook_metadata.file.o_parse_procedure_ex_detail = reinterpret_cast< parse_procedure_ex_ty >( obj->TypeInfo.parse_procedure_ex );
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->TypeInfo.parse_procedure_ex ), reinterpret_cast< void* >( object_type_init_hooks::hk_file_parse_procedure_ex ) );
					break;
				}
			}
		}
		Logger::Print( Logger::Level::Info, "Object Initalizer's Hooked" );
	}
	else
	{
		for ( _OBJECT_TYPE* obj = get_object_by_index( index ); obj != nullptr; obj = get_object_by_index( ++index ) ) {
			if ( obj ) {
				switch ( index ) {
				case 7:
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->TypeInfo.open_procedure ), reinterpret_cast< void* >( hook_metadata.process.o_open_procedure ) );
					break;
				case 8:
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->TypeInfo.open_procedure ), reinterpret_cast< void* >( hook_metadata.thread.o_open_procedure ) );
					break;
				case 34:
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->TypeInfo.parse_procedure_ex ), reinterpret_cast< void* >( hook_metadata.driver.o_parse_procedure_ex_detail ) );
					break;
				case 37:
					_InterlockedExchangePointer( reinterpret_cast< void** >( &obj->TypeInfo.parse_procedure_ex ), reinterpret_cast< void* >( hook_metadata.file.o_parse_procedure_ex_detail ) );
					break;
				}
			}
		}
		Logger::Print( Logger::Level::Info, "Object Initalizer's Unhooked" );

		// No input code - return null
		return nullptr;
	}
}


