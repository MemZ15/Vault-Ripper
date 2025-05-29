#include "helpers.h"
#include "modules.h"


uintptr_t helpers::store_idr( IDTR* idtr ) {

	_disable();
	__sidt( idtr );
	_enable();

	return uintptr_t{ 0 };
}

uintptr_t helpers::find_isr_address( PSIMPLE_IDTENTRY64 idt_entry ){
	return ( ( uintptr_t )idt_entry->OffsetHigh << 32 ) | ( ( uintptr_t )idt_entry->OffsetMiddle << 16 ) | ( uintptr_t )idt_entry->OffsetLow;

}

uintptr_t helpers::pattern_scan( uintptr_t base, size_t size, const BYTE* pattern, const char* mask ){
    size_t patternLength = strlen( mask );

    for ( size_t i = 0; i <= size - patternLength; ++i ) {
        bool found = true;
        for ( size_t j = 0; j < patternLength; ++j ) {
            if ( mask[j] != '?' && pattern[j] != *( reinterpret_cast< const BYTE* >( base + i + j ) ) ) {
                found = false;
                break;
            }
        }
        if ( found ) {
            return base + i;
        }
    }
    return uintptr_t( 0 );
}

uintptr_t helpers::resolve_relative_address( uintptr_t instruction_address, int offset_position, int instruction_size ){
    int32_t relative_offset = *reinterpret_cast< int32_t* >( instruction_address + offset_position );

    return instruction_address + instruction_size + relative_offset;
}