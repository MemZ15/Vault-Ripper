#include "includes.h"
#include "modules.h"
#include "nt_structs.h"
#include "hooks.h"
#include "log.h"
#include "helpers.h"

// MSR LSTAR related asm func's
extern "C" UINTN CVE_2018_1017( VOID );
extern "C" VOID FallbackHandler( VOID );
extern "C" VOID PageFaultHookHandler( VOID );

uintptr_t modules::throw_idt_exception( uintptr_t &base, size_t& base_size ) {

	IDTR idtr{};

    helpers::store_idr( &idtr );

    auto idt_entry = ( PSIMPLE_IDTENTRY64 )idtr.Base;

    auto isr_addr = helpers::find_isr_address( &idt_entry[0xE] ); 

	auto search_addr = ( isr_addr ) & ~( 0x10000 - 1 );

    modules::find_base_from_exception( search_addr, 0x1000000, base, base_size );

    return base;

}

uintptr_t modules::traverse_export_list( UINT64 hash, uintptr_t base )
{
    if ( !base ) return uintptr_t{ 0 };

    _IMAGE_DOS_HEADER* dosHeader = ( _IMAGE_DOS_HEADER* )base;
    if ( dosHeader->e_magic != 0x5A4D ) return uintptr_t{ 0 };

    _IMAGE_NT_HEADERS64* ntHeaders = ( _IMAGE_NT_HEADERS64* )( ( PUCHAR )base + dosHeader->e_lfanew );
    if ( ntHeaders->Signature != 0x00004550 ) return uintptr_t{ 0 };

    DWORD exportVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if ( !exportVA ) return uintptr_t{ 0 };

    PIMAGE_EXPORT_DIRECTORY exportDir = ( PIMAGE_EXPORT_DIRECTORY )( base + exportVA );
    ULONG* nameRvas = ( ULONG* )( base + exportDir->AddressOfNames );
    USHORT* ordinals = ( USHORT* )( base + exportDir->AddressOfNameOrdinals );
    ULONG* funcRvas = ( ULONG* )( base + exportDir->AddressOfFunctions );

    for ( ULONG i = 0; i < exportDir->NumberOfNames; ++i ) {
        auto namePtr = reinterpret_cast< LPCSTR >( base + nameRvas[i] );
        
        if ( !namePtr ) continue;

        size_t nameLen = strnlen( namePtr, 256 ); 
        if ( nameLen == 0 || nameLen >= 256 ) continue;

        UINT64 exportHash = hash::salted_hash_lpcstr_ci( namePtr, nameLen );
        
        if ( exportHash == hash ) {
            ULONG funcRva = funcRvas[ordinals[i]];
            return ( uintptr_t )( ( PUCHAR )base + funcRva );
        }
    }

    return uintptr_t{ 0 };
}


bool modules::check_env() {
    auto def = __readmsr( 0xC0000082 ); // Read default MSR_LSTAR addr
    int cpuInfo[4] = { 0 };

    Logger::Print( Logger::Level::Info, "Invoking CVE-2018-1087 syscall leak..." );
    
    KeIpiGenericCall( modules::IpiBroadcastCallback, 0 );

    if ( !globals::global_sys_caller )  return false;

    if ( def != globals::global_sys_caller ) {
        // our found handler via CVE_2018_1017
        UINT8* first_bytes_hooked = reinterpret_cast< UINT8* >( globals::global_sys_caller );
        
        // og handler
        UINT8* first_bytes_og_FN = reinterpret_cast< UINT8* >( def );
        
        if ( modules::LogHookDetection( first_bytes_hooked, globals::global_sys_caller ) || modules::LogHookDetection( first_bytes_og_FN, def ) ) 
                return false;
    }
    
    Logger::Print( Logger::Level::Info, "No patch detected � handlers are clean." );

    return true;
}
    


bool modules::LogHookDetection( UINT8* codePtr, UINT64 baseAddress ) {
    switch ( codePtr[0] ) {
        case 0xE9:                                      // JMP relative hook
            return true;
        case 0xCC:                                      // INT3 debug trap
            return true;
        case 0x48:                                      // Possible mov rax, imm64
            return codePtr[1] == 0xB8;
    default:
        return false;
    }
}


UINTN modules::IpiBroadcastCallback(_In_ UINTN Argument){
    UNREFERENCED_PARAMETER( Argument );
    
    SIMPLE_IDTENTRY64 TempIdt[19]{};
    IDTR TempIdtr{}, OriginalIdtr{};
    UINTN SyscallHandler{};

    // 0x12F
    TempIdtr.Limit = sizeof( TempIdt ) - 1; 
    TempIdtr.Base = ( UINT64 )&TempIdt[0];
    
    RtlCopyMemory( TempIdt, KeGetPcr()->IdtBase, TempIdtr.Limit + 1 );
    
    _disable();                     // Disable interrupts
    __sidt( &OriginalIdtr );        // Backup original IDT
    __lidt( &TempIdtr );            // Load our temporary hook IDT

    TempIdt[X86_TRAP_PF].OffsetLow = ( UINT16 )( UINTN )PageFaultHookHandler;
    TempIdt[X86_TRAP_PF].OffsetMiddle = ( UINT16 )( ( UINTN )PageFaultHookHandler >> 16 );
    TempIdt[X86_TRAP_PF].OffsetHigh = ( UINT32 )( ( UINTN )PageFaultHookHandler >> 32 );
   
    SyscallHandler = CVE_2018_1017();
    
    __lidt( &OriginalIdtr );        // Restore the original IDT.
    _enable();                      // Re-enable interrupts.
    
    globals::global_sys_caller = SyscallHandler;

    return SyscallHandler;
}


uintptr_t modules::find_base_from_exception( uintptr_t search_addr, size_t search_limit, uintptr_t &base, size_t& base_size ) {
    for ( size_t offset = 0; offset < search_limit; offset += 0x1000 ) {
        uintptr_t currentAddress = search_addr - offset;

        _IMAGE_DOS_HEADER* dosHeader = reinterpret_cast< _IMAGE_DOS_HEADER* >( currentAddress );

        if ( dosHeader->e_magic == 0x5A4D ) {
            PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast< PIMAGE_NT_HEADERS64 >( currentAddress + dosHeader->e_lfanew );

            if ( ntHeaders && ntHeaders->Signature == 0x00004550 && 
                ntHeaders->OptionalHeader.Magic == 0x20B 
                && ntHeaders->OptionalHeader.SizeOfImage >= 0x100000 
                && ntHeaders->FileHeader.NumberOfSections >= 20 ) {
                base_size = ntHeaders->OptionalHeader.SizeOfImage;
                base = currentAddress; 
                return currentAddress;
            }
            else
            {
                DbgPrint( "failed" );
                return { 0 };
            }
        }
    }
}

