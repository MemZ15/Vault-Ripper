#include "includes.h"
#include "modules.h"
#include "nt_structs.h"
#include "hooks.h"
#include "log.h"
#include "helpers.h"

driver_information::DriverMetadata d_data{};
driver_information::Target_DriverMetadata t_data{};

uintptr_t modules::throw_idt_exception( uintptr_t& base, size_t& base_size ) {

	IDTR idtr{};

	helpers::store_idr( &idtr );

	auto idt_entry = ( PSIMPLE_IDTENTRY64 )idtr.Base;

	auto isr_addr = helpers::find_isr_address( &idt_entry[0xE] );

	auto search_addr = ( isr_addr ) & ~( 0x10000 - 1 );

    modules::find_base_from_exception( search_addr, 0x1000000, base, base_size );

    return base;

}

uintptr_t modules::traverse_export_list( UINT64 hash, uintptr_t base )
{
    if ( !base ) return uintptr_t{ 0 };

    PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER )base;
    if ( dosHeader->e_magic != 0x5A4D ) return uintptr_t{ 0 };

    PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS )( ( PUCHAR )base + dosHeader->e_lfanew );
    if ( ntHeaders->Signature != 0x00004550 ) return uintptr_t{ 0 };

    DWORD exportVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if ( !exportVA ) return uintptr_t{ 0 };

    PIMAGE_EXPORT_DIRECTORY exportDir = ( PIMAGE_EXPORT_DIRECTORY )( base + exportVA );
    ULONG* nameRvas = ( ULONG* )( base + exportDir->AddressOfNames );
    USHORT* ordinals = ( USHORT* )( base + exportDir->AddressOfNameOrdinals );
    ULONG* funcRvas = ( ULONG* )( base + exportDir->AddressOfFunctions );

    for ( ULONG i = 0; i < exportDir->NumberOfNames; ++i ) {
        auto namePtr = reinterpret_cast< LPCSTR >( base + nameRvas[i] );
        
        if ( !namePtr ) continue;

        size_t nameLen = strnlen( namePtr, 256 ); 
        if ( nameLen == 0 || nameLen >= 256 ) continue;

        UINT64 exportHash = hash::salted_hash_lpcstr_ci( namePtr, nameLen );
        
        if ( exportHash == hash ) {
            ULONG funcRva = funcRvas[ordinals[i]];
            return ( uintptr_t )( ( PUCHAR )base + funcRva );
        }
    }

    return uintptr_t{ 0 };
}



PDRIVER_OBJECT modules::AllocateFakeDriverObject( PDRIVER_OBJECT targetDriver, PDRIVER_OBJECT fakeDriver, func_pointer_table table_handle )
{
    if ( !targetDriver )
        return nullptr;

    fakeDriver = static_cast< PDRIVER_OBJECT >(
        table_handle.ExAllocatePoolWithTag( NonPagedPool, sizeof( DRIVER_OBJECT ), 'DrvO' ) );

    if ( !fakeDriver )
        return nullptr;

    RtlZeroMemory( fakeDriver, sizeof( DRIVER_OBJECT ) );

    fakeDriver->Type            =        0x04;
    fakeDriver->Size            =        sizeof( DRIVER_OBJECT );
    fakeDriver->DriverInit      =        targetDriver->DriverInit;
    fakeDriver->DriverStart     =        targetDriver->DriverStart;
    fakeDriver->DriverSize      =        targetDriver->DriverSize;
    fakeDriver->DriverUnload    =        targetDriver->DriverUnload;
    fakeDriver->DriverSection   =        targetDriver->DriverSection;
    fakeDriver->FastIoDispatch  =        targetDriver->FastIoDispatch;

    // Set name : eventually hash this
    const wchar_t* name = L"\\Driver\\FileScanner";
    UNICODE_STRING driverName;

    RtlInitUnicodeString( &driverName, name );

    fakeDriver->DriverName.Length = driverName.Length;
    fakeDriver->DriverName.MaximumLength = driverName.Length + sizeof( 2 );

    fakeDriver->DriverName.Buffer = static_cast< PWCH >(
        table_handle.ExAllocatePoolWithTag( NonPagedPool, fakeDriver->DriverName.MaximumLength, 'DrvN' ) );

    if ( !fakeDriver->DriverName.Buffer )
    {
        table_handle.ExFreePoolWithTag( fakeDriver, 'DrvO' );
        return nullptr;     
    }

    RtlCopyMemory( fakeDriver->DriverName.Buffer, driverName.Buffer, driverName.MaximumLength );

    Logger::Print( Logger::Level::Info, "Allocated Fake DRIVER_OBJECT: %wZ", &fakeDriver->DriverName );

    return fakeDriver;
}

void* modules::get_driver_object( const wchar_t* driver_name, PDRIVER_OBJECT& obj, pointer_table table_handle )
{
    auto driver_type = reinterpret_cast< POBJECT_TYPE * >( table_handle.GetIoDriverObjectType);

    UNICODE_STRING driverName;
    RtlInitUnicodeString( &driverName, driver_name );

    auto status = ObReferenceObjectByName( &driverName, OBJ_CASE_INSENSITIVE, nullptr, 0, *driver_type, KernelMode, nullptr, reinterpret_cast< PVOID* >( &obj ) );

    if ( !NT_SUCCESS( status ) ) 
        return 0;
    
    Logger::Print( Logger::Level::Info, "Spaceport Driver DRIVER_OBJECT, Exposed For Copying" );

    return obj;
}


void* modules::get_NTFS_driver_object( const wchar_t* driver_name, PDRIVER_OBJECT& obj, pointer_table table_handle )
{
    auto driver_type = reinterpret_cast< POBJECT_TYPE* >( table_handle.GetIoDriverObjectType );

    UNICODE_STRING driverName;
    RtlInitUnicodeString( &driverName, driver_name );

    auto status = ObReferenceObjectByName( &driverName, OBJ_CASE_INSENSITIVE, nullptr, 0, *driver_type, KernelMode, nullptr, reinterpret_cast< PVOID* >( &obj ) );

    if ( !NT_SUCCESS( status ) )
        return 0;

    Logger::Print( Logger::Level::Info, "Partmgr Driver DRIVER_OBJECT, Exposed For Copying" );

    if ( obj )
        DbgPrint( "Device: 0x%llx", obj->DeviceObject->DeviceType );

    return obj;
}

void modules::DeallocateFakeDriverObject( PDRIVER_OBJECT fakeDriver, func_pointer_table table_handle )
{
    if ( !fakeDriver )
        return;

    Logger::Print( Logger::Level::Info, "Deallocating Fake DRIVER_OBJECT: %wZ", &fakeDriver->DriverName );

    if ( fakeDriver->DriverName.Buffer )
    {
        table_handle.ExFreePoolWithTag( fakeDriver->DriverName.Buffer, 'DrvN' );
    }

    table_handle.ExFreePoolWithTag( fakeDriver, 'DrvO' );
}


uintptr_t modules::find_base_from_exception( uintptr_t search_addr, size_t search_limit, uintptr_t& base, size_t& base_size ) {
    for ( size_t offset = 0; offset < search_limit; offset += 0x1000 ) {
        uintptr_t currentAddress = search_addr - offset;

        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast< PIMAGE_DOS_HEADER >( currentAddress );

        if ( dosHeader->e_magic == 0x5A4D ) {
            PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast< PIMAGE_NT_HEADERS64 >( currentAddress + dosHeader->e_lfanew );

            if ( ntHeaders && ntHeaders->Signature == 0x00004550 && ntHeaders->OptionalHeader.Magic == 0x20B && ntHeaders->OptionalHeader.SizeOfImage >= 0x100000 && ntHeaders->FileHeader.NumberOfSections >= 20 ) {
                base_size = ntHeaders->OptionalHeader.SizeOfImage;
                base = ntHeaders->OptionalHeader.ImageBase;
                return currentAddress;
            }
        }
    }
}

