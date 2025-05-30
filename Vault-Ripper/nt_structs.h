#pragma once
#include "includes.h"

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0

#pragma pack(push, 1)

// DOS Header (IMAGE_DOS_HEADER)
typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;    // Magic number ("MZ")
    USHORT e_cblp;     // Bytes on last page of file
    USHORT e_cp;       // Pages in file
    USHORT e_crlc;     // Relocations
    USHORT e_cparhdr;  // Size of header in paragraphs
    USHORT e_minalloc; // Minimum extra paragraphs needed
    USHORT e_maxalloc; // Maximum extra paragraphs needed
    USHORT e_ss;       // Initial (relative) SS value
    USHORT e_sp;       // Initial SP value
    USHORT e_csum;     // Checksum
    USHORT e_ip;       // Initial IP value
    USHORT e_cs;       // Initial (relative) CS value
    USHORT e_lfarlc;   // File address of relocation table
    USHORT e_ovno;     // Overlay number
    USHORT e_res[4];   // Reserved words
    USHORT e_oemid;    // OEM identifier (for e_oeminfo)
    USHORT e_oeminfo;  // OEM information; e_oemid specific
    USHORT e_res2[10]; // Reserved words
    LONG   e_lfanew;   // File address of new exe header (offset to NT headers)
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

// NT Headers (IMAGE_NT_HEADERS64)
typedef struct _IMAGE_FILE_HEADER {
    USHORT Machine;              // Architecture type of the machine
    USHORT NumberOfSections;     // Number of sections in the file
    ULONG TimeDateStamp;         // Timestamp of creation
    ULONG PointerToSymbolTable;  // Pointer to symbol table (deprecated)
    ULONG NumberOfSymbols;       // Number of symbols (deprecated)
    USHORT SizeOfOptionalHeader; // Size of optional header
    USHORT Characteristics;      // File characteristics
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG VirtualAddress; // RVA of the table
    ULONG Size;           // Size of the table in bytes
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    USHORT Magic;                      // Magic number (PE32+ format = 0x20B)
    UCHAR MajorLinkerVersion;          // Major linker version
    UCHAR MinorLinkerVersion;          // Minor linker version
    ULONG SizeOfCode;                  // Size of code section(s)
    ULONG SizeOfInitializedData;       // Size of initialized data section(s)
    ULONG SizeOfUninitializedData;     // Size of uninitialized data section(s)
    ULONG AddressOfEntryPoint;         // Address of entry point
    ULONG BaseOfCode;                  // Base of code section
    ULONGLONG ImageBase;               // Image base address
    ULONG SectionAlignment;            // Section alignment
    ULONG FileAlignment;               // File alignment
    USHORT MajorOperatingSystemVersion;// Major OS version
    USHORT MinorOperatingSystemVersion;// Minor OS version
    USHORT MajorImageVersion;          // Major image version
    USHORT MinorImageVersion;          // Minor image version
    USHORT MajorSubsystemVersion;      // Major subsystem version
    USHORT MinorSubsystemVersion;      // Minor subsystem version
    ULONG Win32VersionValue;           // Reserved (must be zero)
    ULONG SizeOfImage;                 // Size of the image, including all headers
    ULONG SizeOfHeaders;               // Size of headers
    ULONG CheckSum;                    // Image checksum
    USHORT Subsystem;                  // Subsystem type
    USHORT DllCharacteristics;         // DLL characteristics
    ULONGLONG SizeOfStackReserve;      // Size of stack reserve
    ULONGLONG SizeOfStackCommit;       // Size of stack commit
    ULONGLONG SizeOfHeapReserve;       // Size of heap reserve
    ULONGLONG SizeOfHeapCommit;        // Size of heap commit
    ULONG LoaderFlags;                 // Loader flags
    ULONG NumberOfRvaAndSizes;         // Number of data directory entries
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; // Array of data directories
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    ULONG Signature;                   // PE Signature ("PE\0\0")
    IMAGE_FILE_HEADER FileHeader;      // File header
    IMAGE_OPTIONAL_HEADER64 OptionalHeader; // Optional header
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;         // Reserved, set to 0
    ULONG   TimeDateStamp;           // The time the export data was created
    USHORT  MajorVersion;            // Major version number
    USHORT  MinorVersion;            // Minor version number
    ULONG   Name;                    // RVA of the DLL name
    ULONG   Base;                    // Starting ordinal number
    ULONG   NumberOfFunctions;       // Number of functions in the export table
    ULONG   NumberOfNames;           // Number of names in the export table
    ULONG   AddressOfFunctions;      // RVA of the function addresses
    ULONG   AddressOfNames;          // RVA of the name pointers
    ULONG   AddressOfNameOrdinals;   // RVA of the ordinal table
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef struct _IDTR {
    USHORT Limit;
    ULONG64 Base;
} IDTR, * PIDTR;


typedef struct _SIMPLE_IDTENTRY64 {
    USHORT OffsetLow;
    USHORT Selector;
    union {
        struct {
            UCHAR Ist : 3;
            UCHAR Reserved0 : 5;
            UCHAR Type : 4;
            UCHAR Zero : 1;
            UCHAR Dpl : 2;
            UCHAR Present : 1;
        };
        UCHAR TypeAttributes;
    };
    USHORT OffsetMiddle;
    ULONG OffsetHigh;
    ULONG Reserved1;
} SIMPLE_IDTENTRY64, * PSIMPLE_IDTENTRY64;

#pragma pack(pop)


enum e_ob_open_reason : int
{
    ob_create_handle = 0x0,
    ob_open_handle = 0x1,
    ob_duplicate_handle = 0x2,
    ob_inherit_handle = 0x3,
    ob_max_reason = 0x4,
};



//0x120 bytes (sizeof)
typedef struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary : 1;                                         //0x68
            ULONG MarkedForRemoval : 1;                                       //0x68
            ULONG ImageDll : 1;                                               //0x68
            ULONG LoadNotificationsSent : 1;                                  //0x68
            ULONG TelemetryEntryProcessed : 1;                                //0x68
            ULONG ProcessStaticImport : 1;                                    //0x68
            ULONG InLegacyLists : 1;                                          //0x68
            ULONG InIndexes : 1;                                              //0x68
            ULONG ShimDll : 1;                                                //0x68
            ULONG InExceptionTable : 1;                                       //0x68
            ULONG ReservedFlags1 : 2;                                         //0x68
            ULONG LoadInProgress : 1;                                         //0x68
            ULONG LoadConfigProcessed : 1;                                    //0x68
            ULONG EntryProcessed : 1;                                         //0x68
            ULONG ProtectDelayLoad : 1;                                       //0x68
            ULONG ReservedFlags3 : 2;                                         //0x68
            ULONG DontCallForThreads : 1;                                     //0x68
            ULONG ProcessAttachCalled : 1;                                    //0x68
            ULONG ProcessAttachFailed : 1;                                    //0x68
            ULONG CorDeferredValidate : 1;                                    //0x68
            ULONG CorImage : 1;                                               //0x68
            ULONG DontRelocate : 1;                                           //0x68
            ULONG CorILOnly : 1;                                              //0x68
            ULONG ChpeImage : 1;                                              //0x68
            ULONG ReservedFlags5 : 2;                                         //0x68
            ULONG Redirected : 1;                                             //0x68
            ULONG ReservedFlags6 : 2;                                         //0x68
            ULONG CompatDatabaseProcessed : 1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


extern "C" NTSTATUS ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
);

//0xa0 bytes (sizeof)
typedef struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    VOID* ExceptionTable;                                                   //0x10
    ULONG ExceptionTableSize;                                               //0x18
    VOID* GpValue;                                                          //0x20
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    union
    {
        USHORT SignatureLevel : 4;                                            //0x6e
        USHORT SignatureType : 3;                                             //0x6e
        USHORT Unused : 9;                                                    //0x6e
        USHORT EntireField;                                                 //0x6e
    } u1;                                                                   //0x6e
    VOID* SectionPointer;                                                   //0x70
    ULONG CheckSum;                                                         //0x78
    ULONG CoverageSectionSize;                                              //0x7c
    VOID* CoverageSection;                                                  //0x80
    VOID* LoadedImports;                                                    //0x88
    VOID* Spare;                                                            //0x90
    ULONG SizeOfImageNotRounded;                                            //0x98
    ULONG TimeDateStamp;                                                    //0x9c
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


typedef struct __declspec( align( 8 ) ) _object_dump_control
{
    void* Stream;
    unsigned int Detail;
} object_dump_control, object_dump_control;

typedef struct _ob_extended_parse_paramters
{
    unsigned short length;
    unsigned int restricted_access_mask;
    _EJOB* silo;
} ob_extended_parse_parameters, * pob_extended_parse_parameters;
typedef struct _object_name_information
{
    UNICODE_STRING Name;
} object_name_information, * pobject_name_information;


using dump_procedure_ty = void( __fastcall* )( void*, object_dump_control* );
using open_procedure_ty = int( __fastcall* )( e_ob_open_reason, char, PEPROCESS, void*, unsigned int*, unsigned int );
using close_procedure_ty = void( __fastcall* )( PEPROCESS, void*, unsigned long long, unsigned long long );
using delete_procedure_ty = void( __fastcall* )( void* );
using parse_procedure_ty = int( __fastcall* )( void*, void*, ACCESS_STATE*, char, unsigned int, UNICODE_STRING*, UNICODE_STRING*, void*, SECURITY_QUALITY_OF_SERVICE*, void** );
using parse_procedure_ex_ty = int( __fastcall* )( void*, void*, ACCESS_STATE*, char, unsigned int, UNICODE_STRING*, UNICODE_STRING*, void*, SECURITY_QUALITY_OF_SERVICE*, ob_extended_parse_parameters*, void** );
using security_procedure_ty = int( __fastcall* )( void*, SECURITY_OPERATION_CODE, unsigned int*, void*, unsigned int*, void**, POOL_TYPE, GENERIC_MAPPING*, char );
using query_name_procedure_ty = int( __fastcall* )( void*, unsigned char, object_name_information*, unsigned int, unsigned int*, char );
using okay_to_close_procedure_ty = unsigned char( __fastcall* )( PEPROCESS, void*, void*, char );


union parse_procedure_detail_ty
{
    parse_procedure_ty parse_procedure;
    parse_procedure_ex_ty parse_procedure_ex;
};


struct object_type_initializer
{
    unsigned short length;
    union
    {
        unsigned short flags;
        unsigned char case_insensitive : 1;
        unsigned char unnamed_objects_only : 1;
        unsigned char use_default_object : 1;
        unsigned char security_required : 1;
        unsigned char maintain_handle_count : 1;
        unsigned char maintain_type_list : 1;
        unsigned char supports_object_callbacks : 1;
        unsigned char cache_aligned : 1;
        unsigned char use_extended_parameters : 1;
        unsigned char reserved : 7;
    } object_type_flags;
    unsigned int object_type_code;
    unsigned int invalid_attributes;
    GENERIC_MAPPING generic_mapping;
    unsigned int valid_access_mask;
    unsigned int retain_access;
    POOL_TYPE pool_type;
    unsigned int default_paged_pool_charge;
    unsigned int default_non_paged_pool_charge;
    void( __fastcall* dump_procedure )( void*, object_dump_control* );
    int( __fastcall* open_procedure )( e_ob_open_reason, char, PEPROCESS, void*, unsigned int*, unsigned int );
    void( __fastcall* close_procedure )( PEPROCESS, void*, unsigned long long, unsigned long long );
    void( __fastcall* delete_procedure )( void* );

    int( __fastcall* parse_procedure )( void*, void*, ACCESS_STATE*, char, unsigned int, UNICODE_STRING*, UNICODE_STRING*, void*, SECURITY_QUALITY_OF_SERVICE*, void** );
    int( __fastcall* parse_procedure_ex )( void*, void*, ACCESS_STATE*, char, unsigned int, UNICODE_STRING*, UNICODE_STRING*, void*, SECURITY_QUALITY_OF_SERVICE*, ob_extended_parse_parameters*, void** );

    int( __fastcall* security_procedure )( void*, SECURITY_OPERATION_CODE, unsigned int*, void*, unsigned int*, void**, POOL_TYPE, GENERIC_MAPPING*, char );
    int( __fastcall* query_name_procedure )( void*, unsigned char, object_name_information*, unsigned int, unsigned int*, char );
    unsigned char( __fastcall* okay_to_close_procedure )( PEPROCESS, void*, void*, char );
    unsigned int wait_object_flag_mask;
    unsigned short wait_object_flag_offset;
    unsigned short wait_object_pointer_offset;
};


typedef struct _ex_push_lock_flags
{
    unsigned long long Locked : 1;
    unsigned long long Waiting : 1;
    unsigned long long Waking : 1;
    unsigned long long MultipleShared : 1;
    unsigned long long Shared : 60;
} ex_push_lock_flags;
typedef struct _ex_push_lock
{
    union
    {
        ex_push_lock_flags flags;
        unsigned long long value;
        void* ptr;
    } u;
} ex_push_lock, * pex_push_lock;
typedef struct object_type
{
    LIST_ENTRY type_list;
    UNICODE_STRING name;
    void* default_object;
    unsigned char index;
    unsigned int total_number_of_objects;
    unsigned int total_number_of_handles;
    unsigned int high_water_number_of_objects;
    unsigned int high_water_number_of_handles;
    object_type_initializer type_info;
    ex_push_lock type_lock;
    unsigned int key;
    LIST_ENTRY callback_list;
} object_type, * p_object_type;


struct ob_type_hook_pair {

    struct DeviceHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_detail_ty       o_parse_procedure_detail;
        security_procedure_ty           o_security_procedure;
        parse_procedure_ty              parse_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } device;

    struct ProcessHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_detail_ty       o_parse_procedure_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } process;

    struct DriverHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_detail_ty       o_parse_procedure_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } driver;

    struct FileHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_detail_ty       o_parse_procedure_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } file;

    struct CallbackHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_detail_ty       o_parse_procedure_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } callback;

    struct ALPCHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_detail_ty       o_parse_procedure_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        parse_procedure_ty              parse_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } ALPC;

    struct ThreadObjectHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_detail_ty       o_parse_procedure_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } thread;
};

extern ob_type_hook_pair hook_metadata, debug_object, process, device, file, token, callback, thread, driver;

//0xa40 bytes (sizeof)
struct _EPROCESS
{
    struct _KPROCESS;                                                   //0x0
    struct _EX_PUSH_LOCK;                                       //0x438
    VOID* UniqueProcessId;                                                  //0x440
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x448
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x458
    union
    {
        ULONG Flags2;                                                       //0x460
        struct
        {
            ULONG JobNotReallyActive : 1;                                     //0x460
            ULONG AccountingFolded : 1;                                       //0x460
            ULONG NewProcessReported : 1;                                     //0x460
            ULONG ExitProcessReported : 1;                                    //0x460
            ULONG ReportCommitChanges : 1;                                    //0x460
            ULONG LastReportMemory : 1;                                       //0x460
            ULONG ForceWakeCharge : 1;                                        //0x460
            ULONG CrossSessionCreate : 1;                                     //0x460
            ULONG NeedsHandleRundown : 1;                                     //0x460
            ULONG RefTraceEnabled : 1;                                        //0x460
            ULONG PicoCreated : 1;                                            //0x460
            ULONG EmptyJobEvaluated : 1;                                      //0x460
            ULONG DefaultPagePriority : 3;                                    //0x460
            ULONG PrimaryTokenFrozen : 1;                                     //0x460
            ULONG ProcessVerifierTarget : 1;                                  //0x460
            ULONG RestrictSetThreadContext : 1;                               //0x460
            ULONG AffinityPermanent : 1;                                      //0x460
            ULONG AffinityUpdateEnable : 1;                                   //0x460
            ULONG PropagateNode : 1;                                          //0x460
            ULONG ExplicitAffinity : 1;                                       //0x460
            ULONG ProcessExecutionState : 2;                                  //0x460
            ULONG EnableReadVmLogging : 1;                                    //0x460
            ULONG EnableWriteVmLogging : 1;                                   //0x460
            ULONG FatalAccessTerminationRequested : 1;                        //0x460
            ULONG DisableSystemAllowedCpuSet : 1;                             //0x460
            ULONG ProcessStateChangeRequest : 2;                              //0x460
            ULONG ProcessStateChangeInProgress : 1;                           //0x460
            ULONG InPrivate : 1;                                              //0x460
        };
    };
    union
    {
        ULONG Flags;                                                        //0x464
        struct
        {
            ULONG CreateReported : 1;                                         //0x464
            ULONG NoDebugInherit : 1;                                         //0x464
            ULONG ProcessExiting : 1;                                         //0x464
            ULONG ProcessDelete : 1;                                          //0x464
            ULONG ManageExecutableMemoryWrites : 1;                           //0x464
            ULONG VmDeleted : 1;                                              //0x464
            ULONG OutswapEnabled : 1;                                         //0x464
            ULONG Outswapped : 1;                                             //0x464
            ULONG FailFastOnCommitFail : 1;                                   //0x464
            ULONG Wow64VaSpace4Gb : 1;                                        //0x464
            ULONG AddressSpaceInitialized : 2;                                //0x464
            ULONG SetTimerResolution : 1;                                     //0x464
            ULONG BreakOnTermination : 1;                                     //0x464
            ULONG DeprioritizeViews : 1;                                      //0x464
            ULONG WriteWatch : 1;                                             //0x464
            ULONG ProcessInSession : 1;                                       //0x464
            ULONG OverrideAddressSpace : 1;                                   //0x464
            ULONG HasAddressSpace : 1;                                        //0x464
            ULONG LaunchPrefetched : 1;                                       //0x464
            ULONG Background : 1;                                             //0x464
            ULONG VmTopDown : 1;                                              //0x464
            ULONG ImageNotifyDone : 1;                                        //0x464
            ULONG PdeUpdateNeeded : 1;                                        //0x464
            ULONG VdmAllowed : 1;                                             //0x464
            ULONG ProcessRundown : 1;                                         //0x464
            ULONG ProcessInserted : 1;                                        //0x464
            ULONG DefaultIoPriority : 3;                                      //0x464
            ULONG ProcessSelfDelete : 1;                                      //0x464
            ULONG SetTimerResolutionLink : 1;                                 //0x464
        };
    };
    union _LARGE_INTEGER CreateTime;                                        //0x468
    ULONGLONG ProcessQuotaUsage[2];                                         //0x470
    ULONGLONG ProcessQuotaPeak[2];                                          //0x480
    ULONGLONG PeakVirtualSize;                                              //0x490
    ULONGLONG VirtualSize;                                                  //0x498
    struct _LIST_ENTRY SessionProcessLinks;                                 //0x4a0
    union
    {
        VOID* ExceptionPortData;                                            //0x4b0
        ULONGLONG ExceptionPortValue;                                       //0x4b0
        ULONGLONG ExceptionPortState : 3;                                     //0x4b0
    };
    struct _EX_FAST_REF;                                              //0x4b8
    ULONGLONG MmReserved;                                                   //0x4c0
    struct _EX_PUSH_LOCK;                               //0x4c8
    struct _EX_PUSH_LOCK;                           //0x4d0
    struct _ETHREAD* RotateInProgress;                                      //0x4d8
    struct _ETHREAD* ForkInProgress;                                        //0x4e0
    struct _EJOB* volatile CommitChargeJob;                                 //0x4e8
    struct _RTL_AVL_TREE;                                         //0x4f0
    volatile ULONGLONG NumberOfPrivatePages;                                //0x4f8
    volatile ULONGLONG NumberOfLockedPages;                                 //0x500
    VOID* Win32Process;                                                     //0x508
    struct _EJOB* volatile Job;                                             //0x510
    VOID* SectionObject;                                                    //0x518
    VOID* SectionBaseAddress;                                               //0x520
    ULONG Cookie;                                                           //0x528
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x530
    VOID* Win32WindowStation;                                               //0x538
    VOID* InheritedFromUniqueProcessId;                                     //0x540
    volatile ULONGLONG OwnerProcessId;                                      //0x548
    struct _PEB* Peb;                                                       //0x550
    struct _MM_SESSION_SPACE* Session;                                      //0x558
    VOID* Spare1;                                                           //0x560
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x568
    struct _HANDLE_TABLE* ObjectTable;                                      //0x570
    VOID* DebugPort;                                                        //0x578
    struct _EWOW64PROCESS* WoW64Process;                                    //0x580
    VOID* DeviceMap;                                                        //0x588
    VOID* EtwDataSource;                                                    //0x590
    ULONGLONG PageDirectoryPte;                                             //0x598
    struct _FILE_OBJECT* ImageFilePointer;                                  //0x5a0
    UCHAR ImageFileName[15];                                                //0x5a8
    UCHAR PriorityClass;                                                    //0x5b7
    VOID* SecurityPort;                                                     //0x5b8
    struct _SE_AUDIT_PROCESS_CREATION_INFO;      //0x5c0
    struct _LIST_ENTRY JobLinks;                                            //0x5c8
    VOID* HighestUserAddress;                                               //0x5d8
    struct _LIST_ENTRY ThreadListHead;                                      //0x5e0
    volatile ULONG ActiveThreads;                                           //0x5f0
    ULONG ImagePathHash;                                                    //0x5f4
    ULONG DefaultHardErrorProcessing;                                       //0x5f8
    LONG LastThreadExitStatus;                                              //0x5fc
    struct _EX_FAST_REF;                                      //0x600
    VOID* LockedPagesList;                                                  //0x608
    union _LARGE_INTEGER ReadOperationCount;                                //0x610
    union _LARGE_INTEGER WriteOperationCount;                               //0x618
    union _LARGE_INTEGER OtherOperationCount;                               //0x620
    union _LARGE_INTEGER ReadTransferCount;                                 //0x628
    union _LARGE_INTEGER WriteTransferCount;                                //0x630
    union _LARGE_INTEGER OtherTransferCount;                                //0x638
    ULONGLONG CommitChargeLimit;                                            //0x640
    volatile ULONGLONG CommitCharge;                                        //0x648
    volatile ULONGLONG CommitChargePeak;                                    //0x650
    struct _MMSUPPORT_FULL;                                              //0x680
    struct _LIST_ENTRY MmProcessLinks;                                      //0x7c0
    ULONG ModifiedPageCount;                                                //0x7d0
    LONG ExitStatus;                                                        //0x7d4
    struct _RTL_AVL_TREE;                                           //0x7d8
    VOID* VadHint;                                                          //0x7e0
    ULONGLONG VadCount;                                                     //0x7e8
    volatile ULONGLONG VadPhysicalPages;                                    //0x7f0
    ULONGLONG VadPhysicalPagesLimit;                                        //0x7f8
    struct _ALPC_PROCESS_CONTEXT;                               //0x800
    struct _LIST_ENTRY TimerResolutionLink;                                 //0x820
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x830
    ULONG RequestedTimerResolution;                                         //0x838
    ULONG SmallestTimerResolution;                                          //0x83c
    union _LARGE_INTEGER ExitTime;                                          //0x840
    struct _INVERTED_FUNCTION_TABLE;                 //0x848
    struct _EX_PUSH_LOCK;                         //0x850
    ULONG ActiveThreadsHighWatermark;                                       //0x858
    ULONG LargePrivateVadCount;                                             //0x85c
    struct _EX_PUSH_LOCK;                                    //0x860
    VOID* WnfContext;                                                       //0x868
    struct _EJOB* ServerSilo;                                               //0x870
    UCHAR SignatureLevel;                                                   //0x878
    UCHAR SectionSignatureLevel;                                            //0x879
    struct _PS_PROTECTION;                                       //0x87a
    UCHAR HangCount : 3;                                                      //0x87b
    UCHAR GhostCount : 3;                                                     //0x87b
    UCHAR PrefilterException : 1;                                             //0x87b
    union
    {
        ULONG Flags3;                                                       //0x87c
        struct
        {
            ULONG Minimal : 1;                                                //0x87c
            ULONG ReplacingPageRoot : 1;                                      //0x87c
            ULONG Crashed : 1;                                                //0x87c
            ULONG JobVadsAreTracked : 1;                                      //0x87c
            ULONG VadTrackingDisabled : 1;                                    //0x87c
            ULONG AuxiliaryProcess : 1;                                       //0x87c
            ULONG SubsystemProcess : 1;                                       //0x87c
            ULONG IndirectCpuSets : 1;                                        //0x87c
            ULONG RelinquishedCommit : 1;                                     //0x87c
            ULONG HighGraphicsPriority : 1;                                   //0x87c
            ULONG CommitFailLogged : 1;                                       //0x87c
            ULONG ReserveFailLogged : 1;                                      //0x87c
            ULONG SystemProcess : 1;                                          //0x87c
            ULONG HideImageBaseAddresses : 1;                                 //0x87c
            ULONG AddressPolicyFrozen : 1;                                    //0x87c
            ULONG ProcessFirstResume : 1;                                     //0x87c
            ULONG ForegroundExternal : 1;                                     //0x87c
            ULONG ForegroundSystem : 1;                                       //0x87c
            ULONG HighMemoryPriority : 1;                                     //0x87c
            ULONG EnableProcessSuspendResumeLogging : 1;                      //0x87c
            ULONG EnableThreadSuspendResumeLogging : 1;                       //0x87c
            ULONG SecurityDomainChanged : 1;                                  //0x87c
            ULONG SecurityFreezeComplete : 1;                                 //0x87c
            ULONG VmProcessorHost : 1;                                        //0x87c
            ULONG VmProcessorHostTransition : 1;                              //0x87c
            ULONG AltSyscall : 1;                                             //0x87c
            ULONG TimerResolutionIgnore : 1;                                  //0x87c
            ULONG DisallowUserTerminate : 1;                                  //0x87c
        };
    };
    LONG DeviceAsid;                                                        //0x880
    VOID* SvmData;                                                          //0x888
    struct _EX_PUSH_LOCK;                                    //0x890
    ULONGLONG SvmLock;                                                      //0x898
    struct _LIST_ENTRY SvmProcessDeviceListHead;                            //0x8a0
    ULONGLONG LastFreezeInterruptTime;                                      //0x8b0
    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x8b8
    VOID* PicoContext;                                                      //0x8c0
    VOID* EnclaveTable;                                                     //0x8c8
    ULONGLONG EnclaveNumber;                                                //0x8d0
    struct _EX_PUSH_LOCK;                                       //0x8d8
    ULONG HighPriorityFaultsAllowed;                                        //0x8e0
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x8e8
    VOID* VmContext;                                                        //0x8f0
    ULONGLONG SequenceNumber;                                               //0x8f8
    ULONGLONG CreateInterruptTime;                                          //0x900
    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x908
    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x910
    ULONGLONG LastAppStateUpdateTime;                                       //0x918
    ULONGLONG LastAppStateUptime : 61;                                        //0x920
    ULONGLONG LastAppState : 3;                                               //0x920
    volatile ULONGLONG SharedCommitCharge;                                  //0x928
    struct _EX_PUSH_LOCK;                                  //0x930
    struct _LIST_ENTRY SharedCommitLinks;                                   //0x938
    union
    {
        struct
        {
            ULONGLONG AllowedCpuSets;                                       //0x948
            ULONGLONG DefaultCpuSets;                                       //0x950
        };
        struct
        {
            ULONGLONG* AllowedCpuSetsIndirect;                              //0x948
            ULONGLONG* DefaultCpuSetsIndirect;                              //0x950
        };
    };
    VOID* DiskIoAttribution;                                                //0x958
    VOID* DxgProcess;                                                       //0x960
    ULONG Win32KFilterSet;                                                  //0x968
    volatile ULONG KTimerSets;                                              //0x978
    volatile ULONG KTimer2Sets;                                             //0x97c
    volatile ULONG ThreadTimerSets;                                         //0x980
    ULONGLONG VirtualTimerListLock;                                         //0x988
    struct _LIST_ENTRY VirtualTimerListHead;                                //0x990
    union
    {
        struct _WNF_STATE_NAME WakeChannel;                                 //0x9a0
        struct _PS_PROCESS_WAKE_INFORMATION;                       //0x9a0
    };
    union
    {
        ULONG MitigationFlags;                                              //0x9d0
        struct
        {
            ULONG ControlFlowGuardEnabled : 1;                                //0x9d0
            ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x9d0
            ULONG ControlFlowGuardStrict : 1;                                 //0x9d0
            ULONG DisallowStrippedImages : 1;                                 //0x9d0
            ULONG ForceRelocateImages : 1;                                    //0x9d0
            ULONG HighEntropyASLREnabled : 1;                                 //0x9d0
            ULONG StackRandomizationDisabled : 1;                             //0x9d0
            ULONG ExtensionPointDisable : 1;                                  //0x9d0
            ULONG DisableDynamicCode : 1;                                     //0x9d0
            ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x9d0
            ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x9d0
            ULONG AuditDisableDynamicCode : 1;                                //0x9d0
            ULONG DisallowWin32kSystemCalls : 1;                              //0x9d0
            ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x9d0
            ULONG EnableFilteredWin32kAPIs : 1;                               //0x9d0
            ULONG AuditFilteredWin32kAPIs : 1;                                //0x9d0
            ULONG DisableNonSystemFonts : 1;                                  //0x9d0
            ULONG AuditNonSystemFontLoading : 1;                              //0x9d0
            ULONG PreferSystem32Images : 1;                                   //0x9d0
            ULONG ProhibitRemoteImageMap : 1;                                 //0x9d0
            ULONG AuditProhibitRemoteImageMap : 1;                            //0x9d0
            ULONG ProhibitLowILImageMap : 1;                                  //0x9d0
            ULONG AuditProhibitLowILImageMap : 1;                             //0x9d0
            ULONG SignatureMitigationOptIn : 1;                               //0x9d0
            ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x9d0
            ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x9d0
            ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x9d0
            ULONG AuditLoaderIntegrityContinuity : 1;                         //0x9d0
            ULONG EnableModuleTamperingProtection : 1;                        //0x9d0
            ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x9d0
            ULONG RestrictIndirectBranchPrediction : 1;                       //0x9d0
            ULONG IsolateSecurityDomain : 1;                                  //0x9d0
        } MitigationFlagsValues;                                            //0x9d0
    };
    union
    {
        ULONG MitigationFlags2;                                             //0x9d4
        struct
        {
            ULONG EnableExportAddressFilter : 1;                              //0x9d4
            ULONG AuditExportAddressFilter : 1;                               //0x9d4
            ULONG EnableExportAddressFilterPlus : 1;                          //0x9d4
            ULONG AuditExportAddressFilterPlus : 1;                           //0x9d4
            ULONG EnableRopStackPivot : 1;                                    //0x9d4
            ULONG AuditRopStackPivot : 1;                                     //0x9d4
            ULONG EnableRopCallerCheck : 1;                                   //0x9d4
            ULONG AuditRopCallerCheck : 1;                                    //0x9d4
            ULONG EnableRopSimExec : 1;                                       //0x9d4
            ULONG AuditRopSimExec : 1;                                        //0x9d4
            ULONG EnableImportAddressFilter : 1;                              //0x9d4
            ULONG AuditImportAddressFilter : 1;                               //0x9d4
            ULONG DisablePageCombine : 1;                                     //0x9d4
            ULONG SpeculativeStoreBypassDisable : 1;                          //0x9d4
            ULONG CetUserShadowStacks : 1;                                    //0x9d4
            ULONG AuditCetUserShadowStacks : 1;                               //0x9d4
            ULONG AuditCetUserShadowStacksLogged : 1;                         //0x9d4
            ULONG UserCetSetContextIpValidation : 1;                          //0x9d4
            ULONG AuditUserCetSetContextIpValidation : 1;                     //0x9d4
            ULONG AuditUserCetSetContextIpValidationLogged : 1;               //0x9d4
            ULONG CetUserShadowStacksStrictMode : 1;                          //0x9d4
            ULONG BlockNonCetBinaries : 1;                                    //0x9d4
            ULONG BlockNonCetBinariesNonEhcont : 1;                           //0x9d4
            ULONG AuditBlockNonCetBinaries : 1;                               //0x9d4
            ULONG AuditBlockNonCetBinariesLogged : 1;                         //0x9d4
            ULONG Reserved1 : 1;                                              //0x9d4
            ULONG Reserved2 : 1;                                              //0x9d4
            ULONG Reserved3 : 1;                                              //0x9d4
            ULONG Reserved4 : 1;                                              //0x9d4
            ULONG Reserved5 : 1;                                              //0x9d4
            ULONG CetDynamicApisOutOfProcOnly : 1;                            //0x9d4
            ULONG UserCetSetContextIpValidationRelaxedMode : 1;               //0x9d4
        } MitigationFlags2Values;                                           //0x9d4
    };
    VOID* PartitionObject;                                                  //0x9d8
    ULONGLONG SecurityDomain;                                               //0x9e0
    ULONGLONG ParentSecurityDomain;                                         //0x9e8
    VOID* CoverageSamplerContext;                                           //0x9f0
    VOID* MmHotPatchContext;                                                //0x9f8
    struct _RTL_AVL_TREE;                  //0xa00
    struct _EX_PUSH_LOCK;                  //0xa08
    struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES; //0xa10
    ULONG DisabledComponentFlags;                                           //0xa20
    ULONG* volatile PathRedirectionHashes;                                  //0xa28
};

typedef struct _MY_EPROCESS {
    UCHAR Reserved[0x5A8];
    UCHAR ImageFileName[15]; // ImageFileName is at offset 0x5A8
} MY_EPROCESS, * PMY_EPROCESS;

typedef struct _MMY_EPROCESS {
    UCHAR Reserved1[0x440];    // Reserved up to Process ID
    VOID* UniqueProcessId;     // Offset 0x440: Process ID
    UCHAR Reserved2[0xDC];     // Reserved space from 0x448 to 0x51F
    VOID* SectionBaseAddr;     // Offset 0x520: Section Base Address
    UCHAR Reserved3[0x30];     // Reserved space from 0x528 to 0x54F
    struct _PEB* Peb;          // Offset 0x550: Process Environment Block (PEB)
} MMY_EPROCESS, * PMMY_EPROCESS;



typedef struct _MY_KPROCESS {
    UCHAR Reserved[0x28];
    ULONG DirectoryTableBase; // CR3 or Directory Table Base
} MY_KPROCESS, * PMY_KPROCESS;



//0xe0 bytes (sizeof)
struct _KPROCESS
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x10
    ULONG64 DirectoryTableBase;                                               //0x18
    struct _LIST_ENTRY ThreadListHead;                                      //0x2c
    ULONG ProcessLock;                                                      //0x34
    ULONGLONG DeepFreezeStartTime;                                          //0x38
    struct _LIST_ENTRY ReadyListHead;                                       //0x4c
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x54
    union
    {
        struct
        {
            ULONG AutoAlignment : 1;                                          //0x64
            ULONG DisableBoost : 1;                                           //0x64
            ULONG DisableQuantum : 1;                                         //0x64
            ULONG DeepFreeze : 1;                                             //0x64
            ULONG TimerVirtualization : 1;                                    //0x64
            ULONG CheckStackExtents : 1;                                      //0x64
            ULONG CacheIsolationEnabled : 1;                                  //0x64
            ULONG PpmPolicy : 3;                                              //0x64
            ULONG VaSpaceDeleted : 1;                                         //0x64
            ULONG ReservedFlags : 21;                                         //0x64
        };
        volatile LONG ProcessFlags;                                         //0x64
    };
    CHAR BasePriority;                                                      //0x68
    CHAR QuantumReset;                                                      //0x69
    CHAR Visited;                                                           //0x6a
    USHORT ThreadSeed[1];                                                   //0x6c
    USHORT IdealProcessor[1];                                               //0x6e
    USHORT IdealNode[1];                                                    //0x70
    USHORT IdealGlobalNode;                                                 //0x72
    USHORT Spare1;                                                          //0x74
    USHORT IopmOffset;                                                      //0x76
    struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x78
    struct _LIST_ENTRY ProcessListEntry;                                    //0x80
    ULONGLONG CycleTime;                                                    //0x88
    ULONGLONG ContextSwitches;                                              //0x90
    ULONG FreezeCount;                                                      //0x98
    ULONG KernelTime;                                                       //0x9c
    ULONG UserTime;                                                         //0xa0
    ULONG ReadyTime;                                                        //0xa4
    VOID* VdmTrapcHandler;                                                  //0xa8
    ULONG ProcessTimerDelay;                                                //0xac
    ULONGLONG KernelWaitTime;                                               //0xb0
    ULONGLONG UserWaitTime;                                                 //0xb8
    ULONG EndPadding[8];                                                    //0xc0
};


struct _OBJECT_HEADER {
    uint32_t PointerCount;   // +0x000
    uint32_t HandleCount;    // +0x004
    uint32_t Lock;           // +0x008 (_EX_PUSH_LOCK Lock)
    uint32_t Reserved1;      // +0x00C Reserved or padding
    uint64_t Reserved2;      // +0x010 Reserved or padding
    uint8_t TypeIndex;       // +0x018 TypeIndex (if this is its actual location)
    uint8_t Reserved3[7];    // +0x019 Padding to align Body
    uint64_t Body;           // +0x020 Body
};



//0x4e0 bytes (sizeof)
struct _ETHREAD
{
    uint8_t Padding0[0x280];                                                // Padding to replace the Tcb field
    union _LARGE_INTEGER CreateTime;                                        //0x280
    union
    {
        union _LARGE_INTEGER ExitTime;                                      //0x288
        struct _LIST_ENTRY KeyedWaitChain;                                  //0x288
    };
    VOID* ChargeOnlySession;                                                //0x290
    union
    {
        struct _LIST_ENTRY PostBlockList;                                   //0x294
        struct
        {
            VOID* ForwardLinkShadow;                                        //0x294
            VOID* StartAddress;                                             //0x298
        };
    };
    union
    {
        struct _TERMINATION_PORT* TerminationPort;                          //0x29c
        struct _ETHREAD* ReaperLink;                                        //0x29c
        VOID* KeyedWaitValue;                                               //0x29c
    };
    ULONG ActiveTimerListLock;                                              //0x2a0
    struct _LIST_ENTRY ActiveTimerListHead;                                 //0x2a4
    struct _CLIENT_ID Cid;                                                  //0x2ac
    union
    {
        struct _KSEMAPHORE KeyedWaitSemaphore;                              //0x2b4
        struct _KSEMAPHORE AlpcWaitSemaphore;                               //0x2b4
    };
    struct _LIST_ENTRY IrpList;                                             //0x2cc
    ULONG TopLevelIrp;                                                      //0x2d4
    struct _DEVICE_OBJECT* DeviceToVerify;                                  //0x2d8
    VOID* Win32StartAddress;                                                //0x2dc
    VOID* LegacyPowerObject;                                                //0x2e0
    struct _LIST_ENTRY ThreadListEntry;                                     //0x2e4
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x2ec
    ULONG ReadClusterSize;                                                  //0x2f4
    volatile LONG MmLockOrdering;                                           //0x2f8
    union
    {
        ULONG CrossThreadFlags;                                             //0x2fc
        struct
        {
            ULONG Terminated : 1;                                             //0x2fc
            ULONG ThreadInserted : 1;                                         //0x2fc
            ULONG HideFromDebugger : 1;                                       //0x2fc
            ULONG ActiveImpersonationInfo : 1;                                //0x2fc
            ULONG HardErrorsAreDisabled : 1;                                  //0x2fc
            ULONG BreakOnTermination : 1;                                     //0x2fc
            ULONG SkipCreationMsg : 1;                                        //0x2fc
            ULONG SkipTerminationMsg : 1;                                     //0x2fc
            ULONG CopyTokenOnOpen : 1;                                        //0x2fc
            ULONG ThreadIoPriority : 3;                                       //0x2fc
            ULONG ThreadPagePriority : 3;                                     //0x2fc
            ULONG RundownFail : 1;                                            //0x2fc
            ULONG UmsForceQueueTermination : 1;                               //0x2fc
            ULONG IndirectCpuSets : 1;                                        //0x2fc
            ULONG DisableDynamicCodeOptOut : 1;                               //0x2fc
            ULONG ExplicitCaseSensitivity : 1;                                //0x2fc
            ULONG PicoNotifyExit : 1;                                         //0x2fc
            ULONG DbgWerUserReportActive : 1;                                 //0x2fc
            ULONG ForcedSelfTrimActive : 1;                                   //0x2fc
            ULONG SamplingCoverage : 1;                                       //0x2fc
            ULONG ReservedCrossThreadFlags : 8;                               //0x2fc
        };
    };
    union
    {
        ULONG SameThreadPassiveFlags;                                       //0x300
        struct
        {
            ULONG ActiveExWorker : 1;                                         //0x300
            ULONG MemoryMaker : 1;                                            //0x300
            ULONG StoreLockThread : 2;                                        //0x300
            ULONG ClonedThread : 1;                                           //0x300
            ULONG KeyedEventInUse : 1;                                        //0x300
            ULONG SelfTerminate : 1;                                          //0x300
            ULONG RespectIoPriority : 1;                                      //0x300
            ULONG ActivePageLists : 1;                                        //0x300
            ULONG SecureContext : 1;                                          //0x300
            ULONG ZeroPageThread : 1;                                         //0x300
            ULONG WorkloadClass : 1;                                          //0x300
            ULONG ReservedSameThreadPassiveFlags : 20;                        //0x300
        };
    };
    union
    {
        ULONG SameThreadApcFlags;                                           //0x304
        struct
        {
            UCHAR OwnsProcessAddressSpaceExclusive : 1;                       //0x304
            UCHAR OwnsProcessAddressSpaceShared : 1;                          //0x304
            UCHAR HardFaultBehavior : 1;                                      //0x304
            volatile UCHAR StartAddressInvalid : 1;                           //0x304
            UCHAR EtwCalloutActive : 1;                                       //0x304
            UCHAR SuppressSymbolLoad : 1;                                     //0x304
            UCHAR Prefetching : 1;                                            //0x304
            UCHAR OwnsVadExclusive : 1;                                       //0x304
            UCHAR SystemPagePriorityActive : 1;                               //0x305
            UCHAR SystemPagePriority : 3;                                     //0x305
            UCHAR AllowUserWritesToExecutableMemory : 1;                      //0x305
            UCHAR AllowKernelWritesToExecutableMemory : 1;                    //0x305
            UCHAR OwnsVadShared : 1;                                          //0x305
        };
    };
    UCHAR CacheManagerActive;                                               //0x308
    UCHAR DisablePageFaultClustering;                                       //0x309
    UCHAR ActiveFaultCount;                                                 //0x30a
    UCHAR LockOrderState;                                                   //0x30b
    ULONG PerformanceCountLowReserved;                                      //0x30c
    LONG PerformanceCountHighReserved;                                      //0x310
    ULONG AlpcMessageId;                                                    //0x314
    union
    {
        VOID* AlpcMessage;                                                  //0x318
        ULONG AlpcReceiveAttributeSet;                                      //0x318
    };
    struct _LIST_ENTRY AlpcWaitListEntry;                                   //0x31c
    LONG ExitStatus;                                                        //0x324
    ULONG CacheManagerCount;                                                //0x328
    ULONG IoBoostCount;                                                     //0x32c
    ULONG IoQoSBoostCount;                                                  //0x330
    ULONG IoQoSThrottleCount;                                               //0x334
    ULONG KernelStackReference;                                             //0x338
    struct _LIST_ENTRY BoostList;                                           //0x33c
    struct _LIST_ENTRY DeboostList;                                         //0x344
    ULONG BoostListLock;                                                    //0x34c
    ULONG IrpListLock;                                                      //0x350
    VOID* ReservedForSynchTracking;                                         //0x354
    struct _SINGLE_LIST_ENTRY CmCallbackListHead;                           //0x358
    struct _GUID* ActivityId;                                               //0x35c
    struct _SINGLE_LIST_ENTRY SeLearningModeListHead;                       //0x360
    VOID* VerifierContext;                                                  //0x364
    VOID* AdjustedClientToken;                                              //0x368
    VOID* WorkOnBehalfThread;                                               //0x36c
    VOID* PicoContext;                                                      //0x37c
    ULONG UserFsBase;                                                       //0x380
    ULONG UserGsBase;                                                       //0x384
    struct _THREAD_ENERGY_VALUES* EnergyValues;                             //0x388
    union
    {
        ULONG SelectedCpuSets;                                              //0x38c
        ULONG* SelectedCpuSetsIndirect;                                     //0x38c
    };
    struct _EJOB* Silo;                                                     //0x390
    struct _UNICODE_STRING* ThreadName;                                     //0x394
    VOID* SparePointer;                                                     //0x398
    ULONG LastExpectedRunTime;                                              //0x39c
    ULONG HeapData;                                                         //0x3a0
    struct _LIST_ENTRY OwnerEntryListHead;                                  //0x3a4
    ULONG DisownedOwnerEntryListLock;                                       //0x3ac
    struct _LIST_ENTRY DisownedOwnerEntryListHead;                          //0x3b0
    VOID* CmDbgInfo;                                                        //0x4d8
};

typedef struct _DEBUG_OBJECT {
    ULONG Flags;                   // Flags for the debug object
    LIST_ENTRY EventList;          // List of pending debug events
    KEVENT EventsAvailable;        // Event to signal that debug events are available
    ULONG EventCount;              // Number of events in the event list
    LIST_ENTRY WaitQueue;          // List of threads waiting for debug events
    LIST_ENTRY ProcessList;        // List of processes attached to this debug object
    EX_PUSH_LOCK Lock;             // Synchronization lock for access
} DEBUG_OBJECT, * PDEBUG_OBJECT;



struct _KTHREAD
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    VOID* SListFaultAddress;                                                //0x10
    ULONGLONG QuantumTarget;                                                //0x18
    VOID* InitialStack;                                                     //0x20
    VOID* volatile StackLimit;                                              //0x24
    VOID* StackBase;                                                        //0x28
    ULONG ThreadLock;                                                       //0x2c
    volatile ULONGLONG CycleTime;                                           //0x30
    volatile ULONG HighCycleTime;                                           //0x38
    VOID* ServiceTable;                                                     //0x3c
    ULONG CurrentRunTime;                                                   //0x40
    ULONG ExpectedRunTime;                                                  //0x44
    VOID* KernelStack;                                                      //0x48
    struct _XSAVE_FORMAT* StateSaveArea;                                    //0x4c
    struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x50
    uintptr_t padding[54];                                                  //0x54
    volatile UCHAR Running;                                                 //0x55
    UCHAR Alerted[2];                                                       //0x56
    union
    {
        struct
        {
            ULONG AutoBoostActive : 1;                                        //0x58
            ULONG ReadyTransition : 1;                                        //0x58
            ULONG WaitNext : 1;                                               //0x58
            ULONG SystemAffinityActive : 1;                                   //0x58
            ULONG Alertable : 1;                                              //0x58
            ULONG UserStackWalkActive : 1;                                    //0x58
            ULONG ApcInterruptRequest : 1;                                    //0x58
            ULONG QuantumEndMigrate : 1;                                      //0x58
            ULONG UmsDirectedSwitchEnable : 1;                                //0x58
            ULONG TimerActive : 1;                                            //0x58
            ULONG SystemThread : 1;                                           //0x58
            ULONG ProcessDetachActive : 1;                                    //0x58
            ULONG CalloutActive : 1;                                          //0x58
            ULONG ScbReadyQueue : 1;                                          //0x58
            ULONG ApcQueueable : 1;                                           //0x58
            ULONG ReservedStackInUse : 1;                                     //0x58
            ULONG UmsPerformingSyscall : 1;                                   //0x58
            ULONG TimerSuspended : 1;                                         //0x58
            ULONG SuspendedWaitMode : 1;                                      //0x58
            ULONG SuspendSchedulerApcWait : 1;                                //0x58
            ULONG CetUserShadowStack : 1;                                     //0x58
            ULONG BypassProcessFreeze : 1;                                    //0x58
            ULONG Reserved : 10;                                              //0x58
        };
        LONG MiscFlags;                                                     //0x58
    };
    union
    {
        struct
        {
            ULONG ThreadFlagsSpare : 2;                                       //0x5c
            ULONG AutoAlignment : 1;                                          //0x5c
            ULONG DisableBoost : 1;                                           //0x5c
            ULONG AlertedByThreadId : 1;                                      //0x5c
            ULONG QuantumDonation : 1;                                        //0x5c
            ULONG EnableStackSwap : 1;                                        //0x5c
            ULONG GuiThread : 1;                                              //0x5c
            ULONG DisableQuantum : 1;                                         //0x5c
            ULONG ChargeOnlySchedulingGroup : 1;                              //0x5c
            ULONG DeferPreemption : 1;                                        //0x5c
            ULONG QueueDeferPreemption : 1;                                   //0x5c
            ULONG ForceDeferSchedule : 1;                                     //0x5c
            ULONG SharedReadyQueueAffinity : 1;                               //0x5c
            ULONG FreezeCount : 1;                                            //0x5c
            ULONG TerminationApcRequest : 1;                                  //0x5c
            ULONG AutoBoostEntriesExhausted : 1;                              //0x5c
            ULONG KernelStackResident : 1;                                    //0x5c
            ULONG TerminateRequestReason : 2;                                 //0x5c
            ULONG ProcessStackCountDecremented : 1;                           //0x5c
            ULONG RestrictedGuiThread : 1;                                    //0x5c
            ULONG VpBackingThread : 1;                                        //0x5c
            ULONG ThreadFlagsSpare2 : 1;                                      //0x5c
            ULONG EtwStackTraceApcInserted : 8;                               //0x5c
        };
        volatile LONG ThreadFlags;                                          //0x5c
    };
    volatile UCHAR Tag;                                                     //0x60
    UCHAR SystemHeteroCpuPolicy;                                            //0x61
    UCHAR UserHeteroCpuPolicy : 7;                                            //0x62
    UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x62
    UCHAR Spare0;                                                           //0x63
    ULONG SystemCallNumber;                                                 //0x64
    VOID* FirstArgument;                                                    //0x68
    struct _KTRAP_FRAME* TrapFrame;                                         //0x6c
    union
    {
        struct _KAPC_STATE ApcState;                                        //0x70
        struct
        {
            UCHAR ApcStateFill[23];                                         //0x70
            CHAR Priority;                                                  //0x87
        };
    };
    ULONG UserIdealProcessor;                                               //0x88
    ULONG ContextSwitches;                                                  //0x8c
    volatile UCHAR State;                                                   //0x90
    CHAR Spare12;                                                           //0x91
    UCHAR WaitIrql;                                                         //0x92
    CHAR WaitMode;                                                          //0x93
    volatile LONG WaitStatus;                                               //0x94
    struct _KWAIT_BLOCK* WaitBlockList;                                     //0x98
    union
    {
        struct _LIST_ENTRY WaitListEntry;                                   //0x9c
        struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0x9c
    };
    struct _DISPATCHER_HEADER* volatile Queue;                              //0xa4
    VOID* Teb;                                                              //0xa8
    ULONGLONG RelativeTimerBias;                                            //0xb0
    struct _KTIMER Timer;                                                   //0xb8
    union
    {
        struct _KWAIT_BLOCK WaitBlock[4];                                   //0xe0
        struct
        {
            UCHAR WaitBlockFill8[20];                                       //0xe0
            struct _KTHREAD_COUNTERS* ThreadCounters;                       //0xf4
        };
        struct
        {
            UCHAR WaitBlockFill9[44];                                       //0xe0
            struct _XSTATE_SAVE* XStateSave;                                //0x10c
        };
        struct
        {
            UCHAR WaitBlockFill10[68];                                      //0xe0
            VOID* volatile Win32Thread;                                     //0x124
        };
        struct
        {
            UCHAR WaitBlockFill11[88];                                      //0xe0
            ULONG WaitTime;                                                 //0x138
            union
            {
                struct
                {
                    SHORT KernelApcDisable;                                 //0x13c
                    SHORT SpecialApcDisable;                                //0x13e
                };
                ULONG CombinedApcDisable;                                   //0x13c
            };
        };
    };
    struct _LIST_ENTRY QueueListEntry;                                      //0x140
    union
    {
        volatile ULONG NextProcessor;                                       //0x148
        struct
        {
            ULONG NextProcessorNumber : 31;                                   //0x148
            ULONG SharedReadyQueue : 1;                                       //0x148
        };
    };
    LONG QueuePriority;                                                     //0x14c
    struct _KPROCESS* Process;                                              //0x150
    union
    {
        struct _GROUP_AFFINITY UserAffinity;                                //0x154
        struct
        {
            UCHAR UserAffinityFill[6];                                      //0x154
            CHAR PreviousMode;                                              //0x15a
            CHAR BasePriority;                                              //0x15b
            union
            {
                CHAR PriorityDecrement;                                     //0x15c
                struct
                {
                    UCHAR ForegroundBoost : 4;                                //0x15c
                    UCHAR UnusualBoost : 4;                                   //0x15c
                };
            };
            UCHAR Preempted;                                                //0x15d
            UCHAR AdjustReason;                                             //0x15e
            CHAR AdjustIncrement;                                           //0x15f
        };
    };
    ULONG AffinityVersion;                                                  //0x160
    union
    {
        struct _GROUP_AFFINITY Affinity;                                    //0x164
        struct
        {
            UCHAR AffinityFill[6];                                          //0x164
            UCHAR ApcStateIndex;                                            //0x16a
            UCHAR WaitBlockCount;                                           //0x16b
            ULONG IdealProcessor;                                           //0x16c
        };
    };
    ULONG ReadyTime;                                                        //0x170
    union
    {
        struct _KAPC_STATE SavedApcState;                                   //0x174
        struct
        {
            UCHAR SavedApcStateFill[23];                                    //0x174
            UCHAR WaitReason;                                               //0x18b
        };
    };
    CHAR SuspendCount;                                                      //0x18c
    CHAR Saturation;                                                        //0x18d
    USHORT SListFaultCount;                                                 //0x18e
    union
    {
        struct _KAPC SchedulerApc;                                          //0x190
        struct
        {
            UCHAR SchedulerApcFill0[1];                                     //0x190
            UCHAR ResourceIndex;                                            //0x191
        };
        struct
        {
            UCHAR SchedulerApcFill1[3];                                     //0x190
            UCHAR QuantumReset;                                             //0x193
        };
        struct
        {
            UCHAR SchedulerApcFill2[4];                                     //0x190
            ULONG KernelTime;                                               //0x194
        };
        struct
        {
            UCHAR SchedulerApcFill3[36];                                    //0x190
            struct _KPRCB* volatile WaitPrcb;                               //0x1b4
        };
        struct
        {
            UCHAR SchedulerApcFill4[40];                                    //0x190
            VOID* LegoData;                                                 //0x1b8
        };
        struct
        {
            UCHAR SchedulerApcFill5[47];                                    //0x190
            UCHAR CallbackNestingLevel;                                     //0x1bf
        };
    };
    ULONG UserTime;                                                         //0x1c0
    struct _KEVENT SuspendEvent;                                            //0x1c4
    struct _LIST_ENTRY ThreadListEntry;                                     //0x1d4
    struct _LIST_ENTRY MutantListHead;                                      //0x1dc
    UCHAR AbEntrySummary;                                                   //0x1e4
    UCHAR AbWaitEntryCount;                                                 //0x1e5
    UCHAR AbAllocationRegionCount;                                          //0x1e6
    CHAR SystemPriority;                                                    //0x1e7
    struct _KLOCK_ENTRY* LockEntries;                                       //0x1e8
    struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x1ec
    struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x1f0
    UCHAR PriorityFloorCounts[16];                                          //0x1f4
    UCHAR PriorityFloorCountsReserved[16];                                  //0x204
    ULONG PriorityFloorSummary;                                             //0x214
    volatile LONG AbCompletedIoBoostCount;                                  //0x218
    volatile LONG AbCompletedIoQoSBoostCount;                               //0x21c
    volatile SHORT KeReferenceCount;                                        //0x220
    UCHAR AbOrphanedEntrySummary;                                           //0x222
    UCHAR AbOwnedEntryCount;                                                //0x223
    ULONG ForegroundLossTime;                                               //0x224
    union
    {
        struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x228
        struct
        {
            struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x228
            ULONG InGlobalForegroundList;                                   //0x22c
        };
    };
    struct _KSCB* QueuedScb;                                                //0x230
    ULONGLONG NpxState;                                                     //0x238
    volatile ULONG ThreadTimerDelay;                                        //0x240
    union
    {
        volatile LONG ThreadFlags3;                                         //0x244
        struct
        {
            ULONG BamQosLevel : 8;                                            //0x244
            ULONG PpmPolicy : 2;                                              //0x244
            ULONG ThreadFlags3Reserved2 : 22;                                 //0x244
        };
    };
    VOID* volatile AbWaitObject;                                            //0x248
    ULONG ReservedPreviousReadyTimeValue;                                   //0x24c
    ULONGLONG KernelWaitTime;                                               //0x250
    ULONGLONG UserWaitTime;                                                 //0x258
    ULONG Spare29[3];                                                       //0x260
    ULONG EndPadding[5];                                                    //0x26c
};


//0x58 bytes (sizeof)
typedef struct _ALPC_COMPLETION_LIST {
    struct _LIST_ENTRY Entry;                // 0x0
    struct _EPROCESS* OwnerProcess;          // 0x8
    UCHAR Padding[sizeof( void* )];            // 0xC (replaces CompletionListLock, size is platform-specific)
    struct _MDL* Mdl;                        // 0x10
    VOID* UserVa;                            // 0x14
    VOID* UserLimit;                         // 0x18
    VOID* DataUserVa;                        // 0x1C
    VOID* SystemVa;                          // 0x20
    ULONG TotalSize;                         // 0x24
    struct _ALPC_COMPLETION_LIST_HEADER* Header; // 0x28
    VOID* List;                              // 0x2C
    ULONG ListSize;                          // 0x30
    VOID* Bitmap;                            // 0x34
    ULONG BitmapSize;                        // 0x38
    VOID* Data;                              // 0x3C
    ULONG DataSize;                          // 0x40
    ULONG BitmapLimit;                       // 0x44
    ULONG BitmapNextHint;                    // 0x48
    ULONG ConcurrencyCount;                  // 0x4C
    ULONG AttributeFlags;                    // 0x50
    ULONG AttributeSize;                     // 0x54
} IO_COMPLETION_OBJECT, * PALPC_COMPLETION_LIST;


//0x8 bytes (sizeof)
struct _HARDWARE_PTE
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG Write : 1;                                                      //0x0
    ULONGLONG Owner : 1;                                                      //0x0
    ULONGLONG WriteThrough : 1;                                               //0x0
    ULONGLONG CacheDisable : 1;                                               //0x0
    ULONGLONG Accessed : 1;                                                   //0x0
    ULONGLONG Dirty : 1;                                                      //0x0
    ULONGLONG LargePage : 1;                                                  //0x0
    ULONGLONG Global : 1;                                                     //0x0
    ULONGLONG CopyOnWrite : 1;                                                //0x0
    ULONGLONG Prototype : 1;                                                  //0x0
    ULONGLONG reserved0 : 1;                                                  //0x0
    ULONGLONG PageFrameNumber : 36;                                           //0x0
    ULONGLONG reserved1 : 4;                                                  //0x0
    ULONGLONG SoftwareWsIndex : 11;                                           //0x0
    ULONGLONG NoExecute : 1;                                                  //0x0
};

typedef struct _HAL_PRIVATE_DISPATCH {
    unsigned int Version;

    // Function pointers
    void ( *HalLocateHiberRanges )( void* );
    void ( *HalSetWakeEnable )( unsigned __int8 );
    int ( *HalSetWakeAlarm )( unsigned __int64, unsigned __int64 );
    unsigned __int8 ( *HalPciTranslateBusAddress )( INTERFACE_TYPE, unsigned int, LARGE_INTEGER, unsigned int*, LARGE_INTEGER* );
    int ( *HalPciAssignSlotResources )( UNICODE_STRING*, UNICODE_STRING*, DRIVER_OBJECT*, DEVICE_OBJECT*, INTERFACE_TYPE, unsigned int, unsigned int, CM_RESOURCE_LIST** );
    void ( *HalHaltSystem )( );
    unsigned __int8 ( *HalFindBusAddressTranslation )( LARGE_INTEGER, unsigned int*, LARGE_INTEGER*, unsigned __int64*, unsigned __int8 );
    unsigned __int8 ( *HalResetDisplay )( );
    int ( *KdSetupPciDeviceForDebugging )( void*, DEBUG_DEVICE_DESCRIPTOR* );
    int ( *KdReleasePciDeviceForDebugging )( DEBUG_DEVICE_DESCRIPTOR* );
    void ( *KdCheckPowerButton )( );
    unsigned __int8 ( *HalVectorToIDTEntry )( unsigned int );
    void* ( *KdMapPhysicalMemory64 )( LARGE_INTEGER, unsigned int, unsigned __int8 );
    void ( *KdUnmapVirtualAddress )( void*, unsigned int, unsigned __int8 );
    unsigned int ( *KdGetPciDataByOffset )( unsigned int, unsigned int, void*, unsigned int, unsigned int );
    unsigned int ( *KdSetPciDataByOffset )( unsigned int, unsigned int, void*, unsigned int, unsigned int );
    unsigned int ( *HalGetInterruptVectorOverride )( INTERFACE_TYPE, unsigned int, unsigned int, unsigned int, unsigned __int8*, unsigned __int64* );
    int ( *HalLoadMicrocode )( void* );
    int ( *HalUnloadMicrocode )( );
    int ( *HalPostMicrocodeUpdate )( );
    int ( *HalAllocateMessageTargetOverride )( DEVICE_OBJECT*, GROUP_AFFINITY*, unsigned int, KINTERRUPT_MODE, unsigned __int8, unsigned int*, unsigned __int8*, unsigned int* );
    void ( *HalFreeMessageTargetOverride )( DEVICE_OBJECT*, unsigned int, GROUP_AFFINITY* );
    void ( *HalDpReplaceTarget )( void* );
    int ( *HalDpReplaceControl )( unsigned int, void* );
    void ( *HalDpReplaceEnd )( void* );
    void ( *HalPrepareForBugcheck )( unsigned int );
    unsigned __int8 ( *HalQueryWakeTime )( unsigned __int64*, unsigned __int64* );
    void ( *HalTscSynchronization )( unsigned __int8, unsigned int* );
    int ( *HalWheaInitProcessorGenericSection )( WHEA_ERROR_RECORD_SECTION_DESCRIPTOR*, WHEA_PROCESSOR_GENERIC_ERROR_SECTION* );
    void ( *HalStopLegacyUsbInterrupts )( SYSTEM_POWER_STATE );
    int ( *HalReadWheaPhysicalMemory )( LARGE_INTEGER, unsigned int, void* );
    int ( *HalWriteWheaPhysicalMemory )( LARGE_INTEGER, unsigned int, void* );
    int ( *HalDpMaskLevelTriggeredInterrupts )( );
    int ( *HalDpUnmaskLevelTriggeredInterrupts )( );
    int ( *HalDpGetInterruptReplayState )( void*, void** );
    int ( *HalDpReplayInterrupts )( void* );
    unsigned __int8 ( *HalQueryIoPortAccessSupported )( );
    int ( *KdSetupIntegratedDeviceForDebugging )( void*, DEBUG_DEVICE_DESCRIPTOR* );
    int ( *KdReleaseIntegratedDeviceForDebugging )( DEBUG_DEVICE_DESCRIPTOR* );
    void* ( *HalMapEarlyPages )( unsigned __int64, unsigned int, unsigned int );
    void* Dummy1;
    void* Dummy2;
    void ( *HalNotifyProcessorFreeze )( unsigned __int8, unsigned __int8 );
    int ( *HalPrepareProcessorForIdle )( unsigned int );
    void ( *HalResumeProcessorFromIdle )( );
    void* Dummy;
    unsigned int ( *HalVectorToIDTEntryEx )( unsigned int );
    int ( *HalMaskInterrupt )( unsigned int, unsigned int );
    int ( *HalUnmaskInterrupt )( unsigned int, unsigned int );
    unsigned __int8 ( *HalIsInterruptTypeSecondary )( unsigned int, unsigned int );
    int ( *HalAllocateGsivForSecondaryInterrupt )( char*, unsigned __int16, unsigned int* );
    void ( *HalSaveAndDisableHvEnlightenment )( );
    void ( *HalRestoreHvEnlightenment )( );
    void ( *HalFlushIoBuffersExternalCache )( MDL*, unsigned __int8 );
    void ( *HalFlushExternalCache )( unsigned __int8 );
    int ( *HalPciEarlyRestore )( _SYSTEM_POWER_STATE );
    int ( *HalGetProcessorId )( unsigned int, unsigned int*, unsigned int* );
    int ( *HalAllocatePmcCounterSet )( unsigned int, _KPROFILE_SOURCE*, unsigned int, struct _HAL_PMC_COUNTERS** );
    void ( *HalCollectPmcCounters )( struct HAL_PMC_COUNTERS*, unsigned __int64* );
    void ( *HalFreePmcCounterSet )( struct HAL_PMC_COUNTERS* );
    int ( *HalProcessorHalt )( unsigned int, void*, int ( * )( void* ) );
    unsigned __int64 ( *HalTimerQueryCycleCounter )( unsigned __int64* );
    void* Dummy3;
    void ( *HalPciMarkHiberPhase )( );
    int ( *HalQueryProcessorRestartEntryPoint )( LARGE_INTEGER* );
    int ( *HalRequestInterrupt )( unsigned int );
    void ( *HalFlushAndInvalidatePageExternalCache )( LARGE_INTEGER );
    int ( *KdEnumerateDebuggingDevices )( void*, DEBUG_DEVICE_DESCRIPTOR*, KD_CALLBACK_ACTION( * )( DEBUG_DEVICE_DESCRIPTOR* ) );
    void ( *HalFlushIoRectangleExternalCache )( _MDL*, unsigned int, unsigned int, unsigned int, unsigned int, unsigned __int8 );
    void ( *HalPowerEarlyRestore )( unsigned int );
    int ( *HalQueryCapsuleCapabilities )( void*, unsigned int, unsigned __int64*, unsigned int* );
    int ( *HalUpdateCapsule )( void*, unsigned int, LARGE_INTEGER );
    unsigned __int8 ( *HalPciMultiStageResumeCapable )( );
    void ( *HalDmaFreeCrashDumpRegisters )( unsigned int );
    unsigned __int8 ( *HalAcpiAoacCapable )( );
    void ( *HalClockTimerActivate )( unsigned __int8 );
    void ( *HalClockTimerInitialize )( );
    void ( *HalClockTimerStop )( );
    unsigned __int8 ( *HalTimerOnlyClockInterruptPending )( );
    void* ( *HalAcpiGetMultiNode )( );
    void ( *( *HalPowerSetRebootHandler )( void ( * )( unsigned int, volatile int* ) ) )( unsigned int, volatile int* );
    void ( *HalTimerWatchdogStart )( );
    void ( *HalTimerWatchdogResetCountdown )( );
    void ( *HalTimerWatchdogStop )( );
    unsigned __int8 ( *HalTimerWatchdogGeneratedLastReset )( );
    int ( *HalTimerWatchdogTriggerSystemReset )( unsigned __int8 );
    int ( *HalInterruptGetHighestPriorityInterrupt )( unsigned int*, unsigned __int8* );
    int ( *HalProcessorOn )( unsigned int );
    int ( *HalProcessorOff )( );
    int ( *HalProcessorFreeze )( );
    int ( *HalDmaLinkDeviceObjectByToken )( unsigned __int64, DEVICE_OBJECT* );
    int ( *HalDmaCheckAdapterToken )( unsigned __int64 );
    void* Dummy4;
    int ( *HalTimerConvertPerformanceCounterToAuxiliaryCounter )( unsigned __int64, unsigned __int64*, unsigned __int64* );
    int ( *HalTimerConvertAuxiliaryCounterToPerformanceCounter )( unsigned __int64, unsigned __int64*, unsigned __int64* );
    int ( *HalTimerQueryAuxiliaryCounterFrequency )( unsigned __int64* );
    unsigned __int8 ( *HalIsEFIRuntimeActive )( );
    unsigned __int8 ( *HalTimerQueryAndResetRtcErrors )( unsigned __int8 );
    void ( *HalAcpiLateRestore )( );
    int ( *KdWatchdogDelayExpiration )( unsigned __int64* );
    unsigned __int64 ( *HalTimerWatchdogQueryDueTime )( unsigned __int8 );
    void ( *HalPreprocessNmi )( unsigned int );
    int ( *HalEnumerateEnvironmentVariablesWithFilter )( unsigned int, unsigned __int8 ( * )( const _GUID*, const wchar_t* ), void*, unsigned int* );
    unsigned __int8 ( *HalClearLastBranchRecordStack )( );
    int ( *HalConfigureLastBranchRecord )( unsigned int, unsigned int );
    unsigned __int8 ( *HalGetLastBranchInformation )( unsigned int*, unsigned int* );
    void ( *HalResumeLastBranchRecord )( unsigned __int8 );
    int ( *HalStartLastBranchRecord )( unsigned int, unsigned int* );
    int ( *HalStopLastBranchRecord )( unsigned int );
    int ( *HalIommuBlockDevice )( void* );
    int ( *HalGetIommuInterface )( unsigned int, DMA_IOMMU_INTERFACE* );
    int ( *HalRequestGenericErrorRecovery )( void*, unsigned int* );
    int ( *HalTimerQueryHostPerformanceCounter )( unsigned __int64* );
    int ( *HalTopologyQueryProcessorRelationships )( unsigned int, unsigned int, unsigned __int8*, unsigned __int8*, unsigned __int8*, unsigned int*, unsigned int* );
    void ( *HalInitPlatformDebugTriggers )( );
    void ( *HalRunPlatformDebugTriggers )( unsigned __int8 );
    void* ( *HalTimerGetReferencePage )( );
    unsigned int ( *HalGetHiddenProcessorPackageId )( unsigned int );
    unsigned int ( *HalGetHiddenPackageProcessorCount )( unsigned int );
    int ( *HalGetHiddenProcessorApicIdByIndex )( unsigned int, unsigned int* );
    int ( *HalRegisterHiddenProcessorIdleState )( unsigned int, unsigned __int64 );
    void ( *HalIommuReportIommuFault )( unsigned __int64, FAULT_INFORMATION* );
} HAL_PRIVATE_DISPATCH, * PHAL_PRIVATE_DISPATCH;


//0x58 bytes (sizeof)
struct _PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
};

typedef struct _CUSTOM_EPROCESS {
    BYTE Reserved1[0x550];     // Padding up to the PEB field
    struct _PEB* Peb;          // Process Environment Block pointer at 0x550
} CUSTOM_EPROCESS, * PCUSTOM_EPROCESS;



//0x7c8 bytes (sizeof)
struct _PEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    VOID* Mutant;                                                           //0x8
    VOID* ImageBaseAddress;                                                 //0x10
    struct _PEB_LDR_DATA* Ldr;                                              //0x18
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
    VOID* SubSystemData;                                                    //0x28
    VOID* ProcessHeap;                                                      //0x30
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
    union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
    VOID* IFEOKey;                                                          //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x50
            ULONG ProcessInitializing : 1;                                    //0x50
            ULONG ProcessUsingVEH : 1;                                        //0x50
            ULONG ProcessUsingVCH : 1;                                        //0x50
            ULONG ProcessUsingFTH : 1;                                        //0x50
            ULONG ProcessPreviouslyThrottled : 1;                             //0x50
            ULONG ProcessCurrentlyThrottled : 1;                              //0x50
            ULONG ProcessImagesHotPatched : 1;                                //0x50
            ULONG ReservedBits0 : 24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        VOID* KernelCallbackTable;                                          //0x58
        VOID* UserSharedInfoPtr;                                            //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    VOID* ApiSetMap;                                                        //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    VOID* TlsBitmap;                                                        //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    VOID* ReadOnlySharedMemoryBase;                                         //0x88
    VOID* SharedData;                                                       //0x90
    VOID** ReadOnlyStaticServerData;                                        //0x98
    VOID* AnsiCodePageData;                                                 //0xa0
    VOID* OemCodePageData;                                                  //0xa8
    VOID* UnicodeCaseTableData;                                             //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    VOID** ProcessHeaps;                                                    //0xf0
    VOID* GdiSharedHandleTable;                                             //0xf8
    VOID* ProcessStarterHelper;                                             //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    VOID( *PostProcessInitRoutine )( );                                       //0x230
    VOID* TlsExpansionBitmap;                                               //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    VOID* pShimData;                                                        //0x2d8
    VOID* AppCompatInfo;                                                    //0x2e0
    struct _UNICODE_STRING CSDVersion;                                      //0x2e8
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    VOID* SparePointers[4];                                                 //0x320
    ULONG SpareUlongs[5];                                                   //0x340
    VOID* WerRegistrationData;                                              //0x358
    VOID* WerShipAssertPtr;                                                 //0x360
    VOID* pUnused;                                                          //0x368
    VOID* pImageHeaderHash;                                                 //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled : 1;                                     //0x378
            ULONG CritSecTracingEnabled : 1;                                  //0x378
            ULONG LibLoaderTracingEnabled : 1;                                //0x378
            ULONG SpareTracingBits : 29;                                      //0x378
        };
    };
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    struct _LIST_ENTRY TppWorkerpList;                                      //0x390
    VOID* WaitOnAddressHashTable[128];                                      //0x3a0
    VOID* TelemetryCoverageHeader;                                          //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
    union
    {
        ULONG LeapSecondFlags;                                              //0x7c0
        struct
        {
            ULONG SixtySecondEnabled : 1;                                     //0x7c0
            ULONG Reserved : 31;                                              //0x7c0
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x7c4
};