#pragma once
#include "includes.h"
#include "nt_structs.h"

namespace helpers {

	uintptr_t store_idr( IDTR* idtr );

	uintptr_t find_isr_address( PSIMPLE_IDTENTRY64 idt_entry );

	uintptr_t pattern_scan( uintptr_t base, size_t size, const BYTE* pattern, const char* mask );

	uintptr_t resolve_relative_address( uintptr_t instruction_address, int offset_position, int instruction_size );

    inline size_t wcslen( const wchar_t* str ) {
        if ( !str ) return 0;
        size_t length = { 0 };
        while ( str[length] != L'\0' ) ++length;
        return length;
    }

    inline size_t ansi_to_wide( const char* src, wchar_t* dst, size_t dst_size ) {
        size_t i = { 0 };
            while ( src[i] && i < dst_size - 1 ) {
                dst[i] = static_cast< wchar_t >( src[i] );
                ++i;
            } dst[i] = L'\0';
       return i;
    }

}

namespace patterns {

    constexpr BYTE ObTypeIndexTablePattern[] = { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00 };
    constexpr char ObTypeIndexTableMask[] = "xxx????";


    constexpr BYTE PsGetNextProcessPattern[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x41, 0x56, 0x41, 0x57,
        0x48, 0x83, 0xEC, 0x20, 0x65, 0x48, 0x8B, 0x2C, 0x25, 0x88, 0x01, 0x00, 0x00
    };
    constexpr char PsGetNextProcessMask[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????";
}