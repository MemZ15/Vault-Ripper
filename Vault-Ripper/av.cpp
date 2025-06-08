#include "includes.h"
#include "modules.h"
#include "nt_structs.h"
#include "log.h"
#include "hooks.h"
#include "helpers.h"

bool AV::extract_process_name( PEPROCESS process ) {
    
    wchar_t wide_buffer[260] = { 0 };
    if ( !process ) return false;

    PsGetProcessImageFileName_t fn_image_fl_name = reinterpret_cast< PsGetProcessImageFileName_t >( globals::stored_three );
    if ( !fn_image_fl_name ) return false;

    auto* image_name = fn_image_fl_name( process );
    if ( !image_name ) return false;

    auto len = helpers::ansi_to_wide( reinterpret_cast< const char* >( image_name ), wide_buffer, RTL_NUMBER_OF( wide_buffer ) );

    auto* filename_start = modules::FindFilenameStart( wide_buffer, len );
    if ( !filename_start ) return false;

    UINT64 process_hash = hash::salted_hash_string_ci( filename_start, helpers::wcslen( filename_start ) );

    DbgPrint( "[PROCESS CALLED] : %ws", filename_start );

    for ( auto hash : globals::AV_Hashes ) {
        if ( process_hash == hash ) {
            return true;
        }
    }
    return false;
}

bool AV::extract_symlink_name( PEPROCESS process ){
    wchar_t wide_buffer[260] = { 0 };
    if ( !process ) return false;

    PsGetProcessImageFileName_t fn_image_fl_name = reinterpret_cast< PsGetProcessImageFileName_t >( globals::stored_three );
    if ( !fn_image_fl_name ) return false;

    auto* image_name = fn_image_fl_name( process );
    if ( !image_name ) return false;

    auto len = helpers::ansi_to_wide( reinterpret_cast< const char* >( image_name ), wide_buffer, RTL_NUMBER_OF( wide_buffer ) );

    auto* filename_start = modules::FindFilenameStart( wide_buffer, len );
    if ( !filename_start ) return false;

    UINT64 process_hash = hash::salted_hash_string_ci( filename_start, helpers::wcslen( filename_start ) );

    DbgPrint( "[SYMLINK CALLED] : %ws", filename_start );

    for ( auto hash : globals::AV_Hashes ) {
        if ( process_hash == hash ) {
            return true;
        }
    }
    return false;
}

bool AV::extract_directory_name( PEPROCESS process ) {

    wchar_t wide_buffer[260] = { 0 };
    if ( !process ) return false;

    PsGetProcessImageFileName_t fn_image_fl_name = reinterpret_cast< PsGetProcessImageFileName_t >( globals::stored_three );
    if ( !fn_image_fl_name ) return false;

    auto* image_name = fn_image_fl_name( process );
    if ( !image_name ) return false;

    auto len = helpers::ansi_to_wide( reinterpret_cast< const char* >( image_name ), wide_buffer, RTL_NUMBER_OF( wide_buffer ) );

    auto* filename_start = modules::FindFilenameStart( wide_buffer, len );
    if ( !filename_start ) return false;
    UINT64 process_hash = hash::salted_hash_string_ci( filename_start, helpers::wcslen( filename_start ) );

    DbgPrint( "[DIRECTORY CALLED] : %ws", filename_start );


    for ( auto hash : globals::AV_Hashes ) {
        if ( process_hash == hash ) {
            return true;
        }
    }
    return false;
}

bool AV::extract_thread_name( PETHREAD thread ) {
    
    if ( !thread ) return false;
    wchar_t wide_buffer[260] = { 0 };

    // I really want to avoid win_api calls but since these are usermode orientated objects, we gotta do this gay shit, 
    // it gets the point accross (source: virus total) --> alt_syscalls soon
    IoThreadToProcess_t fn_io_thread = reinterpret_cast< IoThreadToProcess_t >( globals::stored_four );
    auto owning_process = fn_io_thread( thread );

    if ( !owning_process ) return false;

    PsGetProcessImageFileName_t fn_image_fl_name = reinterpret_cast< PsGetProcessImageFileName_t >( globals::stored_three );
    if ( !fn_image_fl_name ) return false;

    UCHAR* image_name = fn_image_fl_name( owning_process );
    if ( !image_name ) return false;

    auto len = helpers::ansi_to_wide( reinterpret_cast< const char* >( image_name ), wide_buffer, RTL_NUMBER_OF( wide_buffer ) );

    auto* filename_start = modules::FindFilenameStart( wide_buffer, len );
    if ( !filename_start ) return false;

    UINT64 thread_hash = hash::salted_hash_string_ci( filename_start, helpers::wcslen( filename_start ) );

    DbgPrint( "[THREAD CALLED] : %ws", filename_start );

    for ( auto hash : globals::AV_Hashes ) {
        if ( thread_hash == hash ) {
            return true;
        }
    }

    return false;
}


bool AV::extract_driver_name( PDRIVER_OBJECT driver_object ) {

    if ( !driver_object )
        return false;

    if ( !driver_object->DriverName.Buffer )
        return false;

    auto* full_path = driver_object->DriverName.Buffer;
    auto* filename_start = modules::FindFilenameStart( full_path, helpers::wcslen( full_path ) );

    if ( !filename_start )
        return false;

    UINT64 driver_hash = hash::salted_hash_string_ci( filename_start, helpers::wcslen( filename_start ) );

    DbgPrint( "[DRIVER CALLED] : %ws", filename_start );

    for ( auto hash : globals::AV_Hashes ) {
        if ( driver_hash == hash ) {
            return true;
        }
    }
    return false;
}



bool AV::extract_file_name( FILE_OBJECT* file_object) {
    if ( !file_object || !file_object->FileName.Buffer )
        return false;
   
    auto* full_path = file_object->FileName.Buffer;

    auto* filename_start = modules::FindFilenameStart( full_path, helpers::wcslen( full_path ) );

    if ( !filename_start ) return false;
    
    UINT64 extension_hash = hash::salted_hash_string_ci( filename_start, helpers::wcslen( filename_start ) );

    for ( auto hash : globals::AV_Hashes ) {

        if ( extension_hash == hash ) {
            return true;
        }
    }

    return false;
}

bool AV::protect_file( FILE_OBJECT* file_object ) {
    if ( !file_object || !file_object->FileName.Buffer )
        return false;

    auto* full_path = file_object->FileName.Buffer;

    auto* filename_start = modules::FindFilenameStart( full_path, helpers::wcslen( full_path ) );

    if ( !filename_start ) return false;

    UINT64 extension_hash = hash::salted_hash_string_ci( filename_start, helpers::wcslen( filename_start ) );
    for ( auto hash : globals::Hashed_Names ) {

        if ( extension_hash == hash ) {
            return true;
        }
    }

    return false;
}