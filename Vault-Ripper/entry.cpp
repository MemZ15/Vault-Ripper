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

		// Init Funcion Pointer Table
		func_pointer_table table_handle = { 0 };
	
		// Find NTOSKRNL Base
		status = modules::throw_idt_exception( base, size );

		// Find and save pointer info for WIN-API functions
		mngr::hook_win_API( base, size, table_handle );

		// Create HookManager using the with index table address as constructor
		mngr::HookManager manager( table_handle.ObTypeIndexTable );

		// Find and expose a legit Windows driver to copy its metadata to our dummy : Hash this too
		modules::get_driver_object( L"\\Driver\\spaceport", tar_obj, table_handle );

		// Create the Fake Driver Object purely to be used as a decoy
		PDRIVER_OBJECT fake_obj = modules::AllocateFakeDriverObject( tar_obj, fakeDriver, table_handle );

		test::capture_initalizer_table( base, size, table_handle, obj, 1 );

		// Install hooks
		manager.HookObjects( true );

		LARGE_INTEGER delay;
		delay.QuadPart = -10LL * 1000 * 1000 * 30; // 10 seconds
		KeDelayExecutionThread( KernelMode, FALSE, &delay );

		// Unhook before unload
		manager.HookObjects( false );

		// Clean up decoy driver object
		modules::DeallocateFakeDriverObject( fake_obj, table_handle );

	// Driver Unload
	Logger::Print( Logger::Level::Info, "Driver Unload" );

	return status;
	
}