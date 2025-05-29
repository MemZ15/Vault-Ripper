#include "includes.h"
#include "modules.h"
#include "log.h"
#include "hooks.h"


extern "C" NTSTATUS DriverEntry() {


	auto status = STATUS_SUCCESS;

	// Driver Load
	Logger::Print( Logger::Level::Info, "Entry Called" );

	uintptr_t base{};

	object_type* obj = nullptr;

	size_t size{};

	// Init Funcion Pointer Table
	func_pointer_table table_handle = { 0 };

	// Find NTOSKRNL Base
	status = modules::throw_idt_exception( base, size );

	// Find and save pointer info for WIN-API functions
	hooks::hook_win_API( base, size, table_handle );

	//Hook obj initializers in preperation for AV check
	hooks::capture_initalizer_table( base, size, table_handle, obj, 1 );


	LARGE_INTEGER delay;
	delay.QuadPart = -10 * 1000 * 1000 * 10;
	KeDelayExecutionThread( KernelMode, FALSE, &delay );

	//Unook obj initializers in preperation for driver unload
	hooks::capture_initalizer_table( base, size, table_handle, obj, 0 );

	// Driver Unload
	Logger::Print( Logger::Level::Info, "Driver Unload" );

	return status;
}