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
            return imageBase + i + 4;
        }
    }
    return 0;
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

