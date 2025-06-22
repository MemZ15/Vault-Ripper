#pragma once
#include "includes.h"
#include "nt_structs.h"
#include "hooks.h"


namespace object_type_init_hooks {
    void __fastcall DumpProcedure( void* arg1, _OBJECT_DUMP_CONTROL* arg2 );

    void __fastcall CloseProcedure(
        _EPROCESS* arg1,
        void* arg2,
        ULONGLONG arg3,
        ULONGLONG arg4
    );

    void __fastcall DeleteProcedure( void* arg1 );

    LONG __fastcall ParseProcedure(
        void* arg1,
        void* arg2,
        _ACCESS_STATE* arg3,
        CHAR arg4,
        ULONG arg5,
        _UNICODE_STRING* arg6,
        _UNICODE_STRING* arg7,
        void* arg8,
        _SECURITY_QUALITY_OF_SERVICE* arg9,
        void** arg10
    );

    LONG __fastcall ParseProcedureEx(
        void* arg1,
        void* arg2,
        _ACCESS_STATE* arg3,
        CHAR arg4,
        ULONG arg5,
        _UNICODE_STRING* arg6,
        _UNICODE_STRING* arg7,
        void* arg8,
        _SECURITY_QUALITY_OF_SERVICE* arg9,
        _OB_EXTENDED_PARSE_PARAMETERS* arg10,
        void** arg11
    );

    LONG __fastcall SecurityProcedure(
        void* arg1,
        _SECURITY_OPERATION_CODE arg2,
        ULONG* arg3,
        void* arg4,
        ULONG* arg5,
        void** arg6,
        _POOL_TYPE arg7,
        _GENERIC_MAPPING* arg8,
        CHAR arg9
    );

    LONG __fastcall QueryNameProcedure(
        void* arg1,
        UCHAR arg2,
        _OBJECT_NAME_INFORMATION* arg3,
        ULONG arg4,
        ULONG* arg5,
        CHAR arg6
    );

    UCHAR __fastcall OkayToCloseProcedure(
        _EPROCESS* arg1,
        void* arg2,
        void* arg3,
        CHAR arg4
    );

    LONG __fastcall ProcessOpenProcedure( _OB_OPEN_REASON, KPROCESSOR_MODE, _EPROCESS*, _EPROCESS*, ULONG*, ULONG );
    LONG __fastcall ThreadOpenProcedure( _OB_OPEN_REASON, KPROCESSOR_MODE, _EPROCESS*, _EPROCESS*, ULONG*, ULONG );
}
