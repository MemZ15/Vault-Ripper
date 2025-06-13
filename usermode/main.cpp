#include <Windows.h>
#include <winternl.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")


int main()
{
    HANDLE hFile = nullptr;
    IO_STATUS_BLOCK ioStatus{};
    UNICODE_STRING ntPath;
    OBJECT_ATTRIBUTES objAttr{};

    // You can change this to any known device: \\Device\\Null, \\Device\\Beep, \\Device\\ConDrv, etc.
    RtlInitUnicodeString( &ntPath, L"\\Device\\spaceport" );

    InitializeObjectAttributes(
        &objAttr,
        &ntPath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    NTSTATUS status = NtOpenFile(
        &hFile,
        GENERIC_READ | GENERIC_WRITE,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_NON_DIRECTORY_FILE
    );

    if ( NT_SUCCESS( status ) ) {
        std::wcout << L"[+] Opened handle to \\Device\\spaceport successfully!\n";
        CloseHandle( hFile );
    }
    else {
        std::wcout << L"[-] Failed to open handle: 0x" << std::hex << status << std::endl;
    }
    system( "pause" );
    return 0;
}
