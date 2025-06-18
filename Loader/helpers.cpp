#include "includes.h"
#include "win_api_defs.h"

DWORD64 helpers::FindBytes64( DWORD64 imageBase, SIZE_T imageSize, const unsigned char* pattern, SIZE_T patternLen ) {

    if ( !imageBase || !pattern || patternLen == 0 || imageSize < patternLen )
        return 0;

    const unsigned char* bytes = reinterpret_cast< const unsigned char* >( imageBase );

    for ( SIZE_T i = 0; i <= imageSize - patternLen; ++i )
    {
        if ( bytes[i] == pattern[0] &&
            !memcmp( bytes + i, pattern, patternLen ) )
        {
            return imageBase + i;
        }
    }
    return 0;
}

void* helpers::mapFileIntoMem( const char* path ) {

    HANDLE fileHandle = CreateFileA( path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if ( fileHandle == INVALID_HANDLE_VALUE ) {
        return NULL;
    }

    HANDLE fileMapping = CreateFileMapping( fileHandle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL );
    if ( fileMapping == NULL ) {
        CloseHandle( fileHandle );
        return NULL;
    }

    void* fileMap = MapViewOfFile( fileMapping, FILE_MAP_READ, 0, 0, 0 );
    if ( fileMap == NULL ) {
        CloseHandle( fileMapping );
        CloseHandle( fileHandle );
    }

    return fileMap;
}

void* helpers::signature_search( char* base, char* inSig, int length, int maxHuntLength ) {
    for ( int i = 0; i < maxHuntLength; i++ ) {
        if ( base[i] == inSig[0] ) {
            if ( memcmp( base + i, inSig, length ) == 0 ) {
                return base + i;
            }
        }
    }

    return NULL;
}

ULONG_PTR helpers::signatureSearchInSection( char* section, char* base, char* inSig, int length ) {

    IMAGE_DOS_HEADER* dosHeader = ( IMAGE_DOS_HEADER* )base;
    IMAGE_NT_HEADERS64* ntHeaders = ( IMAGE_NT_HEADERS64* )( ( char* )base + dosHeader->e_lfanew );
    IMAGE_SECTION_HEADER* sectionHeaders = ( IMAGE_SECTION_HEADER* )( ( char* )ntHeaders + sizeof( IMAGE_NT_HEADERS64 ) );
    IMAGE_SECTION_HEADER* textSection = NULL;
    ULONG_PTR gadgetSearch = NULL;

    for ( int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++ ) {
        if ( memcmp( sectionHeaders[i].Name, section, strlen( section ) ) == 0 ) {
            textSection = &sectionHeaders[i];
            break;
        }
    }

    if ( textSection == NULL ) {
        return NULL;
    }

    gadgetSearch = ( ULONG_PTR )helpers::signature_search( ( ( char* )base + textSection->VirtualAddress ), inSig, length, textSection->SizeOfRawData );

    return gadgetSearch;
}

void helpers::FileNameToServiceName( PWCHAR ServiceName, PWCHAR FileName ){
    int p = sizeof( SVC_BASE ) / sizeof( WCHAR ) - 1;
    wcscpy_s( ServiceName, sizeof( SVC_BASE ) / sizeof( WCHAR ), SVC_BASE );
    for ( PWCHAR i = FileName; *i; ++i )
    {
        if ( *i == L'\\' )
            FileName = i + 1;
    }
    while ( *FileName != L'\0' && *FileName != L'.' )
        ServiceName[p++] = *FileName++;
    ServiceName[p] = L'\0';
}

