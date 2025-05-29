#include "includes.h"
#include "modules.h"
#include "nt_structs.h"
#include "hooks.h"
#include "helpers.h"


uintptr_t modules::throw_idt_exception( uintptr_t& base, size_t& base_size ) {

	IDTR idtr{};

	helpers::store_idr( &idtr );

	auto idt_entry = ( PSIMPLE_IDTENTRY64 )idtr.Base;

	auto isr_addr = helpers::find_isr_address( &idt_entry[0xE] );

	auto search_addr = ( isr_addr ) & ~( 0x10000 - 1 );

    modules::find_base_from_exception( search_addr, 0x1000000, base, base_size );

    return base;

}

uintptr_t modules::traverse_export_list( const char* module_name, uintptr_t base )
{
    PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER )base;
    if ( dosHeader->e_magic != 0x5A4D )
        return NULL;

    PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS )( ( PUCHAR )base + dosHeader->e_lfanew );
    if ( ntHeaders->Signature != 0x00004550 )
        return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDir = ( PIMAGE_EXPORT_DIRECTORY )( ( PUCHAR )base +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );


    ULONG* nameRvas = ( ULONG* )( ( PUCHAR )base + exportDir->AddressOfNames );
    ULONG* funcRvas = ( ULONG* )( ( PUCHAR )base + exportDir->AddressOfFunctions );
    USHORT* ordinals = ( USHORT* )( ( PUCHAR )base + exportDir->AddressOfNameOrdinals );

    for ( ULONG i = 0; i < exportDir->NumberOfNames; i++ ) {
        LPCSTR name = ( LPCSTR )( ( PUCHAR )base + nameRvas[i] );
        if ( _stricmp( name, module_name ) == 0 ) {
            ULONG funcRva = funcRvas[ordinals[i]];
            return ( uintptr_t )( ( PUCHAR )base + funcRva );
        }
    }
    return uintptr_t( 0 );
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

