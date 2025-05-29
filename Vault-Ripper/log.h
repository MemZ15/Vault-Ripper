#pragma once
#include "includes.h"
#include <ntstrsafe.h>

class Logger {
public:
    enum class Level {
        Info,
        Warning,
        Error
    };

    static void Print( Level level, const char* format, ... ) {
        constexpr size_t BufferSize = 512;
        char buffer[BufferSize] = { 0 };

        const char* prefix = nullptr;
        switch ( level ) {
        case Level::Info:    
            prefix = "+ "; 
            break;
        case Level::Warning: 
            prefix = "* "; 
            break;
        case Level::Error:   
            prefix = "! "; 
            break;
        default:             
            prefix = "? "; 
            break;
        }

        const NTSTATUS Prefix = RtlStringCbPrintfA( buffer, BufferSize, "[Vault Ripper] ");
        
        if ( !NT_SUCCESS( Prefix ) ) return;
   

        const size_t written = strlen( buffer );
        const size_t remaining = BufferSize - written;

        va_list args{};
        va_start( args, format );
        const NTSTATUS Format = RtlStringCbVPrintfA( buffer + written, remaining, format, args );
        va_end( args );

        if ( !NT_SUCCESS( Format ) ) return;

        DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "%s\n", buffer );
    }
};