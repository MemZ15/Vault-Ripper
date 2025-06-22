#include "includes.h"
#include "modules.h"
#include "log.h"
#include "hooks.h"



extern "C" NTSTATUS DriverEntry() {

	auto status = STATUS_SUCCESS;

	// Driver Load
	Logger::Print( Logger::Level::Info, "Entry Called" );

	// Define runtime vars
	uintptr_t base{};

	_OBJECT_TYPE* obj{ nullptr };

	PDRIVER_OBJECT tar_obj{ nullptr };

	PDRIVER_OBJECT fakeDriver{ nullptr };

	PDRIVER_OBJECT tar_dev{ nullptr };

	size_t size{};

	UINTN arg{};

	//const wchar_t* test = L"PsLoadedModuleList";
	//auto encrpy = hash::salted_hash_string_ci( test, helpers::wcslen( test ) );
	//DbgPrint( "Hash: %llx", encrpy );

		// Init Function Pointer Table
		func_pointer_table table_handle = { 0 };

		// Check if LSTAR is hooked
		//if ( !modules::check_env() ) return status;

		// Find NTOSKRNL Base
		status = modules::throw_idt_exception( base, size );

		// Find and save pointer info for WIN-API functions
		mngr::hook_win_API( base, size, table_handle );

		//test::capture_initalizer_table( &base, size, table_handle, obj, 1 );

		// Install hooks
		mngr::HookManager manager{table_handle.ObTypeIndexTable};
		manager.HookObjects( 1 );
		
		LARGE_INTEGER delay;
		delay.QuadPart = -10LL * 1000 * 1000 * 10; // 10 seconds
		KeDelayExecutionThread( KernelMode, FALSE, &delay );

		// Unhook before unload
		manager.HookObjects( 0 );

	// Driver Unload
	Logger::Print( Logger::Level::Info, "Driver Unload" );

	return status;
	
}

// TODO port to windows 11