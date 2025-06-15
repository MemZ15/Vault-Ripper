#pragma once
#include "includes.h"

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
typedef unsigned short WORD;

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

typedef struct _NTFS_BOOT_SECTOR {
    BYTE Jump[3];                     // 0x00: Jump instruction
    BYTE OEMID[8];                    // 0x03: "NTFS    "

    WORD BytesPerSector;             // 0x0B: Usually 512
    BYTE SectorsPerCluster;          // 0x0D: E.g., 8
    WORD ReservedSectors;            // 0x0E: Always 0 for NTFS
    BYTE Zeros1[3];                  // 0x10: Always 0
    WORD NotUsed1;                   // 0x13: Always 0
    BYTE MediaDescriptor;            // 0x15: F8 = hard disk
    WORD Zeros2;                     // 0x16: Always 0
    WORD SectorsPerTrack;            // 0x18: CHS geometry (legacy)
    WORD NumberOfHeads;             // 0x1A: CHS geometry (legacy)
    DWORD HiddenSectors;            // 0x1C: Hidden sectors before this partition
    DWORD NotUsed2;                 // 0x20: Always 0

    DWORD NotUsed3;                 // 0x24: Always 0
    LONGLONG TotalSectors;          // 0x28: Total number of sectors on the volume

    LONGLONG MFTClusterNumber;      // 0x30: Starting cluster of MFT
    LONGLONG MFTMirrorClusterNumber;// 0x38: Starting cluster of MFT mirror

    CHAR ClustersPerFileRecordSegment; // 0x40: Can be negative (2^abs(n))
    BYTE Reserved1[3];                  // 0x41

    CHAR ClustersPerIndexBlock;     // 0x44
    BYTE Reserved2[3];              // 0x45

    LONGLONG VolumeSerialNumber;   // 0x48
    DWORD Checksum;                // 0x50

    BYTE BootCode[426];            // 0x54: Bootstrap code (fills rest of sector)
    WORD EndOfSectorMarker;        // 0x1FE: Always 0xAA55
} NTFS_BOOT_SECTOR, * PNTFS_BOOT_SECTOR;




typedef struct _ATTRIBUTE_HEADER {
    DWORD Type;
    DWORD Length;
    BYTE NonResident;
    BYTE NameLength;
    WORD NameOffset;
    WORD Flags;
    WORD Instance;
    struct Resident {
        DWORD ValueLength;
        WORD ValueOffset;
        BYTE ResidentFlags;
        BYTE Reserved;
    };

    struct NonResident {
        ULONGLONG StartingVCN;
        ULONGLONG LastVCN;
        WORD RunListOffset;
        WORD CompressionUnit;
        DWORD Padding;
        ULONGLONG AllocatedSize;
        ULONGLONG DataSize;
        ULONGLONG InitializedSize;
        // Optional: ULONGLONG CompressedSize; // Only if compressed and sparse
    };
} ATTRIBUTE_HEADER, * PATTRIBUTE_HEADER;

typedef struct _FILE_RECORD_HEADER {
    DWORD Type;                  // 'FILE' = 0x454C4946 (ASCII for "FILE")
    WORD UsaOffset;              // Offset to Update Sequence Array (for fixing sectors)
    WORD UsaCount;               // Size in words of Update Sequence Array (including the USN)
    ULONGLONG LSN;               // $LogFile Sequence Number
    WORD SequenceNumber;         // Sequence number (used for detecting reused file records)
    WORD LinkCount;              // Hard link count
    WORD AttrOffset;             // Offset to first attribute
    WORD Flags;                  // 0x01 = in use, 0x02 = directory
    DWORD BytesInUse;            // Real size of the FILE record
    DWORD BytesAllocated;        // Allocated size of the FILE record (usually 1024 bytes)
    ULONGLONG BaseFileRecord;    // File reference to the base FILE record (for attribute lists)
    WORD NextAttrID;             // Next available attribute ID
    WORD Align;                  // Padding/alignment
    DWORD MFTRecordNumber;       // Index of this record in the $MFT
} FILE_RECORD_HEADER, * PFILE_RECORD_HEADER;


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
using security_procedure_ty = int( __fastcall* )( void*, SECURITY_OPERATION_CODE, unsigned int*, void*, unsigned int*, void**, POOL_TYPE, GENERIC_MAPPING*, char );
using query_name_procedure_ty = int( __fastcall* )( void*, unsigned char, object_name_information*, unsigned int, unsigned int*, char );
using okay_to_close_procedure_ty = unsigned char( __fastcall* )( PEPROCESS, void*, void*, char );
using parse_procedure_ty = int( __fastcall* )( void*, void*);
using parse_procedure_ex_ty = int( __fastcall* )( void*, void*, UNICODE_STRING*, UNICODE_STRING* );


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

    int( __fastcall* parse_procedure )( void*, void*);
    int( __fastcall* parse_procedure_ex )( void*, void*, UNICODE_STRING*, UNICODE_STRING* );

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



struct _OBJECT_TYPE
{
    _LIST_ENTRY TypeList;                                            //0x0
    _UNICODE_STRING Name;                                            //0x10
    VOID* DefaultObject;                                                    //0x20
    UCHAR Index;                                                            //0x28
    ULONG TotalNumberOfObjects;                                             //0x2c
    ULONG TotalNumberOfHandles;                                             //0x30
    ULONG HighWaterNumberOfObjects;                                         //0x34
    ULONG HighWaterNumberOfHandles;                                         //0x38
    object_type_initializer TypeInfo;                               //0x40
};


struct ob_type_hook_pair {

    struct Symlink {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_ty              o_parse_procedure_detail;
        parse_procedure_ex_ty           o_parse_procedure_ex_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } symlink;

    struct DirHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_ty              o_parse_procedure_detail;
        parse_procedure_ex_ty           o_parse_procedure_ex_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } dir;

    struct ProcessHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_ty              o_parse_procedure;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } process;

    struct DriverHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_ty              o_parse_procedure_detail;
        parse_procedure_ex_ty           o_parse_procedure_ex_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } driver;

    struct FileHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_ty              o_parse_procedure_detail;
        parse_procedure_ex_ty           o_parse_procedure_ex_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } file;

    struct Device {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_ty              o_parse_procedure_detail;
        parse_procedure_ex_ty           o_parse_procedure_ex_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } device;

    struct ThreadObjectHook {
        dump_procedure_ty               o_dump_procedure;
        open_procedure_ty               o_open_procedure;
        close_procedure_ty              o_close_procedure;
        delete_procedure_ty             o_delete_procedure;
        parse_procedure_ty              o_parse_procedure_detail;
        security_procedure_ty           o_security_procedure;
        query_name_procedure_ty         o_query_name_procedure;
        okay_to_close_procedure_ty      o_okay_to_close_procedure;
    } thread;
};

extern ob_type_hook_pair hook_metadata, device, debug_object, process, device, file, token, symlink, thread, driver, dir;


struct _IOP_FILE_OBJECT_EXTENSION
{
    ULONG FoExtFlags;                                                       //0x0
    VOID* FoExtPerTypeExtension[9];                                         //0x8
    enum _IOP_PRIORITY_HINT FoIoPriorityHint;                               //0x50
};

typedef struct _EPROCESS
{
    typedef struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK;                                                   //0x438
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
    struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;                 //0x848
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
    volatile ULONGLONG Padding_970_977[8];                                  // 0x970 - 0x977
    volatile ULONG KTimerSets;                                              //0x978
    volatile ULONG KTimer2Sets;                                             //0x97c
    volatile ULONG ThreadTimerSets;                                         //0x980
    ULONGLONG VirtualTimerListLock;                                         //0x988
    struct _LIST_ENTRY VirtualTimerListHead;                                //0x990
    union
    {
        struct _WNF_STATE_NAME WakeChannel;                                 //0x9a0
        struct _PS_PROCESS_WAKE_INFORMATION;                                  //0x9a0
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


#define KeGetPcr() ((PKPCR)__readgsqword((unsigned long)FIELD_OFFSET(KPCR, Self)))


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

typedef ULONG_PTR UINTN;

// Map of BASE Address of GS (R/W). If CPUID.80000001:EDX.[29] = 1.
#define MSR_GS_BASE 0xC0000101
// Swap Target of BASE Address of GS (R/W). If CPUID.80000001:EDX.[29] = 1.
#define MSR_KERNEL_GS_BASE 0xC0000102

#define X86_TRAP_DE            0   // Divide Error (no error)
#define X86_TRAP_DB            1   // Debug trap (no error)
#define X86_TRAP_NMI           2   // Non-maskable Interrupt (no error)
#define X86_TRAP_BP            3   // Breakpoint Exception (INT3) (no error)
#define X86_TRAP_OF            4   // Overflow (INTO) (no error)
#define X86_TRAP_BR            5   // Bounds Range Exceeded (no error)
#define X86_TRAP_UD            6   // Undefined Opcode (no error)
#define X86_TRAP_NM            7   // No Math or Device not available (WAIT/FWAIT) (no error)
#define X86_TRAP_DF            8   // Double Fault (error)
#define X86_TRAP_OLD_MF        9   // 80x87 FP coprocessor operand fetch fault (no error)
#define X86_TRAP_TS            10  // Invalid TSS fault (error)
#define X86_TRAP_NP            11  // Segment Not Present (error)
#define X86_TRAP_SS            12  // Stack-segment Fault (error)
#define X86_TRAP_GP            13  // General Protection Fault (error)
#define X86_TRAP_PF            14  // Page Fault (error)
#define X86_TRAP_SPURIOUS      15  // Reserved/Spurious Interrupt
#define X86_TRAP_RESERVED      15  // Intel Reserved (error)
#define X86_TRAP_MF            16  // x87 Floating-Point Exception (no error)
#define X86_TRAP_AC            17  // Alignment check (error)
#define X86_TRAP_MC            18  // Machine Check (no error)
#define X86_TRAP_XF            19  // SIMD Floating-Point Exception (no error)
#define X86_TRAP_VE            20  // Intel Virtualization Exception (no error)
#define X86_TRAP_VC            29  // AMD VMM Communication Exception
#define X86_TRAP_SX            30  // AMD Security Exception
#define X86_TRAP_IRET          32  // IRET Exception

#define SWAPGS_LENGTH 3
#define VMX_MSR(v)                  (v - MSR_IA32_VMX_BASIC)



// Segment descriptor for segment registers
typedef struct _SEGMENT_DESCRIPTOR {
    uint16_t Selector;
    uint64_t Base;
    uint32_t Limit;
    uint32_t Attributes; // Access rights, flags
} SEGMENT_DESCRIPTOR;

// Descriptor table (GDTR, IDTR)
typedef struct _DESCRIPTOR_TABLE {
    uint16_t Limit;
    uint64_t Base;
} DESCRIPTOR_TABLE;

typedef struct _VIRTUAL_CPU {
    // General Purpose Registers
    uint64_t Rax;
    uint64_t Rbx;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t Rbp;
    uint64_t Rsp;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;

    // Instruction Pointer and Flags
    uint64_t Rip;
    uint64_t Rflags;

    // Control Registers
    uint64_t Cr0;
    uint64_t Cr2;   // Linear address for last page fault
    uint64_t Cr3;   // Page directory base
    uint64_t Cr4;

    // Debug Registers
    uint64_t Dr0;
    uint64_t Dr1;
    uint64_t Dr2;
    uint64_t Dr3;
    uint64_t Dr6;
    uint64_t Dr7;

    // Model Specific Registers (MSRs)
    uint64_t Efer;          // Extended Feature Register (SYSCALL/SYSRET enable)
    uint64_t KernelGsBase;  // MSR_KERNEL_GS_BASE
    uint64_t Star;          // MSR_STAR (syscall segment selectors)
    uint64_t LStar;         // MSR_LSTAR (syscall handler address)
    uint64_t CStar;         // MSR_CSTAR (compat syscall handler)
    uint64_t SfMask;        // MSR_SYSCALL_MASK (flags mask)

    // Segment Registers (Selectors + Bases + Limits + Attributes)
    SEGMENT_DESCRIPTOR Cs;
    SEGMENT_DESCRIPTOR Ds;
    SEGMENT_DESCRIPTOR Ss;
    SEGMENT_DESCRIPTOR Es;
    SEGMENT_DESCRIPTOR Fs;
    SEGMENT_DESCRIPTOR Gs;

    // Descriptor Tables
    DESCRIPTOR_TABLE Gdtr;
    DESCRIPTOR_TABLE Idtr;

    // Floating Point and SIMD State (XSAVE area or pointer)
    void* FpSimdState;

    // VMCS fields (for Intel VT-x) or equivalent virtualization data
    uint64_t VmcsRevisionId;
    uint64_t VmcsRegion;

    // Additional virtualization/processor state
    uint64_t ApicBase;

    // Padding or reserved fields as needed
    uint64_t Reserved[8];

    // Track the MSR being accessed on VM exit
    uint32_t MsrIndex;

    // Flag to indicate if syscall rehook is needed
    bool NeedsSyscallRehook;

    // Storage for MSR read/write value during VM exit
    uint64_t MsrValue;

    uint64_t MsrData[18];  // cache of relevant MSRs (read at init)


    uint8_t* MsrBitmap;

} VIRTUAL_CPU, * PVIRTUAL_CPU;


#define MSR_STAR        0xC0000081  // Segment selectors for syscall/sysret
#define MSR_LSTAR       0xC0000082  // Syscall target RIP (handler address)
#define MSR_CSTAR       0xC0000083  // Compatibility mode syscall handler
#define MSR_SYSCALL_MASK 0xC0000084 // Mask for RFLAGS during syscall
#define MSR_KERNEL_GS_BASE 0xC0000102 // Kernel GS base MSR
typedef enum _VMCS_ENCODING
{
    VIRTUAL_PROCESSOR_ID = 0x00000000,  // 16-Bit Control Field
    POSTED_INTERRUPT_NOTIFICATION = 0x00000002,
    EPTP_INDEX = 0x00000004,
    GUEST_ES_SELECTOR = 0x00000800,  // 16-Bit Guest-State Fields
    GUEST_CS_SELECTOR = 0x00000802,
    GUEST_SS_SELECTOR = 0x00000804,
    GUEST_DS_SELECTOR = 0x00000806,
    GUEST_FS_SELECTOR = 0x00000808,
    GUEST_GS_SELECTOR = 0x0000080a,
    GUEST_LDTR_SELECTOR = 0x0000080c,
    GUEST_TR_SELECTOR = 0x0000080e,
    GUEST_INTERRUPT_STATUS = 0x00000810,
    HOST_ES_SELECTOR = 0x00000c00,  // 16-Bit Host-State Fields
    HOST_CS_SELECTOR = 0x00000c02,
    HOST_SS_SELECTOR = 0x00000c04,
    HOST_DS_SELECTOR = 0x00000c06,
    HOST_FS_SELECTOR = 0x00000c08,
    HOST_GS_SELECTOR = 0x00000c0a,
    HOST_TR_SELECTOR = 0x00000c0c,
    IO_BITMAP_A = 0x00002000,  // 64-Bit Control Fields
    IO_BITMAP_A_HIGH = 0x00002001,
    IO_BITMAP_B = 0x00002002,
    IO_BITMAP_B_HIGH = 0x00002003,
    MSR_BITMAP = 0x00002004,
    MSR_BITMAP_HIGH = 0x00002005,
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,
    VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
    EXECUTIVE_VMCS_POINTER = 0x0000200c,
    EXECUTIVE_VMCS_POINTER_HIGH = 0x0000200d,
    TSC_OFFSET = 0x00002010,
    TSC_OFFSET_HIGH = 0x00002011,
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
    APIC_ACCESS_ADDR = 0x00002014,
    APIC_ACCESS_ADDR_HIGH = 0x00002015,
    EPT_POINTER = 0x0000201a,
    EPT_POINTER_HIGH = 0x0000201b,
    EOI_EXIT_BITMAP_0 = 0x0000201c,
    EOI_EXIT_BITMAP_0_HIGH = 0x0000201d,
    EOI_EXIT_BITMAP_1 = 0x0000201e,
    EOI_EXIT_BITMAP_1_HIGH = 0x0000201f,
    EOI_EXIT_BITMAP_2 = 0x00002020,
    EOI_EXIT_BITMAP_2_HIGH = 0x00002021,
    EOI_EXIT_BITMAP_3 = 0x00002022,
    EOI_EXIT_BITMAP_3_HIGH = 0x00002023,
    EPTP_LIST_ADDRESS = 0x00002024,
    EPTP_LIST_ADDRESS_HIGH = 0x00002025,
    VMREAD_BITMAP_ADDRESS = 0x00002026,
    VMREAD_BITMAP_ADDRESS_HIGH = 0x00002027,
    VMWRITE_BITMAP_ADDRESS = 0x00002028,
    VMWRITE_BITMAP_ADDRESS_HIGH = 0x00002029,
    VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS = 0x0000202a,
    VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS_HIGH = 0x0000202b,
    XSS_EXITING_BITMAP = 0x0000202c,
    XSS_EXITING_BITMAP_HIGH = 0x0000202d,
    GUEST_PHYSICAL_ADDRESS = 0x00002400,  // 64-Bit Read-Only Data Field
    GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
    VMCS_LINK_POINTER = 0x00002800,  // 64-Bit Guest-State Fields
    VMCS_LINK_POINTER_HIGH = 0x00002801,
    GUEST_IA32_DEBUGCTL = 0x00002802,
    GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
    GUEST_IA32_PAT = 0x00002804,
    GUEST_IA32_PAT_HIGH = 0x00002805,
    GUEST_IA32_EFER = 0x00002806,
    GUEST_IA32_EFER_HIGH = 0x00002807,
    GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,
    GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
    GUEST_PDPTR0 = 0x0000280a,
    GUEST_PDPTR0_HIGH = 0x0000280b,
    GUEST_PDPTR1 = 0x0000280c,
    GUEST_PDPTR1_HIGH = 0x0000280d,
    GUEST_PDPTR2 = 0x0000280e,
    GUEST_PDPTR2_HIGH = 0x0000280f,
    GUEST_PDPTR3 = 0x00002810,
    GUEST_PDPTR3_HIGH = 0x00002811,
    HOST_IA32_PAT = 0x00002c00,  // 64-Bit Host-State Fields
    HOST_IA32_PAT_HIGH = 0x00002c01,
    HOST_IA32_EFER = 0x00002c02,
    HOST_IA32_EFER_HIGH = 0x00002c03,
    HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,
    HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,  // 32-Bit Control Fields
    CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400a,
    VM_EXIT_CONTROLS = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
    TPR_THRESHOLD = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
    PLE_GAP = 0x00004020,
    PLE_WINDOW = 0x00004022,
    VM_INSTRUCTION_ERROR = 0x00004400,  // 32-Bit Read-Only Data Fields
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTR_INFO = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,
    IDT_VECTORING_INFO_FIELD = 0x00004408,
    IDT_VECTORING_ERROR_CODE = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
    VMX_INSTRUCTION_INFO = 0x0000440e,
    GUEST_ES_LIMIT = 0x00004800,  // 32-Bit Guest-State Fields
    GUEST_CS_LIMIT = 0x00004802,
    GUEST_SS_LIMIT = 0x00004804,
    GUEST_DS_LIMIT = 0x00004806,
    GUEST_FS_LIMIT = 0x00004808,
    GUEST_GS_LIMIT = 0x0000480a,
    GUEST_LDTR_LIMIT = 0x0000480c,
    GUEST_TR_LIMIT = 0x0000480e,
    GUEST_GDTR_LIMIT = 0x00004810,
    GUEST_IDTR_LIMIT = 0x00004812,
    GUEST_ES_AR_BYTES = 0x00004814,
    GUEST_CS_AR_BYTES = 0x00004816,
    GUEST_SS_AR_BYTES = 0x00004818,
    GUEST_DS_AR_BYTES = 0x0000481a,
    GUEST_FS_AR_BYTES = 0x0000481c,
    GUEST_GS_AR_BYTES = 0x0000481e,
    GUEST_LDTR_AR_BYTES = 0x00004820,
    GUEST_TR_AR_BYTES = 0x00004822,
    GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
    GUEST_ACTIVITY_STATE = 0x00004826,
    GUEST_SMBASE = 0x00004828,
    GUEST_SYSENTER_CS = 0x0000482a,
    VMX_PREEMPTION_TIMER_VALUE = 0x0000482e,
    HOST_IA32_SYSENTER_CS = 0x00004c00,  // 32-Bit Host-State Field
    CR0_GUEST_HOST_MASK = 0x00006000,    // Natural-Width Control Fields
    CR4_GUEST_HOST_MASK = 0x00006002,
    CR0_READ_SHADOW = 0x00006004,
    CR4_READ_SHADOW = 0x00006006,
    CR3_TARGET_VALUE0 = 0x00006008,
    CR3_TARGET_VALUE1 = 0x0000600a,
    CR3_TARGET_VALUE2 = 0x0000600c,
    CR3_TARGET_VALUE3 = 0x0000600e,
    EXIT_QUALIFICATION = 0x00006400,  // Natural-Width Read-Only Data Fields
    IO_RCX = 0x00006402,
    IO_RSI = 0x00006404,
    IO_RDI = 0x00006406,
    IO_RIP = 0x00006408,
    GUEST_LINEAR_ADDRESS = 0x0000640a,
    GUEST_CR0 = 0x00006800,  // Natural-Width Guest-State Fields
    GUEST_CR3 = 0x00006802,
    GUEST_CR4 = 0x00006804,
    GUEST_ES_BASE = 0x00006806,
    GUEST_CS_BASE = 0x00006808,
    GUEST_SS_BASE = 0x0000680a,
    GUEST_DS_BASE = 0x0000680c,
    GUEST_FS_BASE = 0x0000680e,
    GUEST_GS_BASE = 0x00006810,
    GUEST_LDTR_BASE = 0x00006812,
    GUEST_TR_BASE = 0x00006814,
    GUEST_GDTR_BASE = 0x00006816,
    GUEST_IDTR_BASE = 0x00006818,
    GUEST_DR7 = 0x0000681a,
    GUEST_RSP = 0x0000681c,
    GUEST_RIP = 0x0000681e,
    GUEST_RFLAGS = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
    GUEST_SYSENTER_ESP = 0x00006824,
    GUEST_SYSENTER_EIP = 0x00006826,
    HOST_CR0 = 0x00006c00,  // Natural-Width Host-State Fields
    HOST_CR3 = 0x00006c02,
    HOST_CR4 = 0x00006c04,
    HOST_FS_BASE = 0x00006c06,
    HOST_GS_BASE = 0x00006c08,
    HOST_TR_BASE = 0x00006c0a,
    HOST_GDTR_BASE = 0x00006c0c,
    HOST_IDTR_BASE = 0x00006c0e,
    HOST_IA32_SYSENTER_ESP = 0x00006c10,
    HOST_IA32_SYSENTER_EIP = 0x00006c12,
    HOST_RSP = 0x00006c14,
    HOST_RIP = 0x00006c16
} VMCS_ENCODING;

// ====== VMCS Control Fields ======

// --- Pin-Based Execution Controls
#define VMCS_CTRL_PIN_BASED                0x00004000

// --- Primary Processor-Based Execution Controls
#define VMCS_CTRL_PROC_BASED              0x00004002

// --- Exception Bitmap
#define VMCS_CTRL_EXCEPTION_BITMAP        0x00004004

// --- Page Fault Error Code Mask / Match (optional, if trapping #PF)
#define VMCS_CTRL_PF_ERROR_MASK           0x00004006
#define VMCS_CTRL_PF_ERROR_MATCH          0x00004008

// --- CR3 Target Count
#define VMCS_CTRL_CR3_TARGET_COUNT        0x0000400A

// --- VM Exit Controls
#define VMCS_CTRL_EXIT_CONTROLS           0x0000400C

// --- VM Exit MSR Store / Load
#define VMCS_CTRL_EXIT_MSR_STORE_COUNT    0x0000400E
#define VMCS_CTRL_EXIT_MSR_LOAD_COUNT     0x00004010
#define VMCS_CTRL_EXIT_MSR_STORE_ADDR     0x00002006
#define VMCS_CTRL_EXIT_MSR_STORE_ADDR_HIGH 0x00002007
#define VMCS_CTRL_EXIT_MSR_LOAD_ADDR      0x00002008
#define VMCS_CTRL_EXIT_MSR_LOAD_ADDR_HIGH 0x00002009

// --- VM Entry Controls
#define VMCS_CTRL_ENTRY_CONTROLS          0x00004012
#define VMCS_CTRL_ENTRY_MSR_LOAD_COUNT    0x00004014
#define VMCS_CTRL_ENTRY_INTR_INFO_FIELD   0x00004016
#define VMCS_CTRL_ENTRY_EXCEPTION_ERROR_CODE 0x00004018
#define VMCS_CTRL_ENTRY_INSTRUCTION_LEN   0x0000401A

// --- TPR Threshold
#define VMCS_CTRL_TPR_THRESHOLD           0x0000401C

// --- Secondary Processor-Based Controls
#define VMCS_CTRL_PROC_BASED2             0x0000401E

// --- Pause Loop Exiting (optional)
#define VMCS_CTRL_PLE_GAP                 0x00004020
#define VMCS_CTRL_PLE_WINDOW              0x00004022

// --- CR0/CR4 Guest/Host Masks & Shadows
#define VMCS_CTRL_CR0_MASK                0x00006000
#define VMCS_CTRL_CR4_MASK                0x00006002
#define VMCS_CTRL_CR0_READ_SHADOW         0x00006004
#define VMCS_CTRL_CR4_READ_SHADOW         0x00006006

// --- CR3 Target Values (0–3) (optional)
#define VMCS_CTRL_CR3_TARGET_VALUE0       0x00006008
#define VMCS_CTRL_CR3_TARGET_VALUE1       0x0000600A
#define VMCS_CTRL_CR3_TARGET_VALUE2       0x0000600C
#define VMCS_CTRL_CR3_TARGET_VALUE3       0x0000600E

// --- I/O Bitmaps
#define VMCS_CTRL_IO_BITMAP_A             0x00002000
#define VMCS_CTRL_IO_BITMAP_A_HIGH        0x00002001
#define VMCS_CTRL_IO_BITMAP_B             0x00002002
#define VMCS_CTRL_IO_BITMAP_B_HIGH        0x00002003

// --- MSR Bitmap
#define VMCS_CTRL_MSR_BITMAP              0x00002004
#define VMCS_CTRL_MSR_BITMAP_HIGH         0x00002005

// --- TSC Offset
#define VMCS_CTRL_TSC_OFFSET              0x00002010
#define VMCS_CTRL_TSC_OFFSET_HIGH         0x00002011

// --- Virtual-APIC Page
#define VMCS_CTRL_VIRTUAL_APIC_PAGE       0x00002012
#define VMCS_CTRL_VIRTUAL_APIC_PAGE_HIGH  0x00002013

// --- APIC Access Address
#define VMCS_CTRL_APIC_ACCESS_ADDR        0x00002014
#define VMCS_CTRL_APIC_ACCESS_ADDR_HIGH   0x00002015

// --- Posted Interrupt Descriptor
#define VMCS_CTRL_POSTED_INTERRUPT_DESC   0x00002016
#define VMCS_CTRL_POSTED_INTERRUPT_DESC_HIGH 0x00002017

// --- EPT Pointer
#define VMCS_CTRL_EPTP                    0x0000201A
#define VMCS_CTRL_EPTP_HIGH               0x0000201B

// --- EOI Exit Bitmap (Optional for APIC virtualization)
#define VMCS_CTRL_EOI_EXIT_BITMAP0        0x0000201C
#define VMCS_CTRL_EOI_EXIT_BITMAP0_HIGH   0x0000201D
#define VMCS_CTRL_EOI_EXIT_BITMAP1        0x0000201E
#define VMCS_CTRL_EOI_EXIT_BITMAP1_HIGH   0x0000201F
#define VMCS_CTRL_EOI_EXIT_BITMAP2        0x00002020
#define VMCS_CTRL_EOI_EXIT_BITMAP2_HIGH   0x00002021
#define VMCS_CTRL_EOI_EXIT_BITMAP3        0x00002022
#define VMCS_CTRL_EOI_EXIT_BITMAP3_HIGH   0x00002023

// --- VMREAD/VMWRITE Bitmaps (optional, for fine-grained trap control)
#define VMCS_CTRL_VMREAD_BITMAP_ADDR      0x00002026
#define VMCS_CTRL_VMREAD_BITMAP_ADDR_HIGH 0x00002027
#define VMCS_CTRL_VMWRITE_BITMAP_ADDR     0x00002028
#define VMCS_CTRL_VMWRITE_BITMAP_ADDR_HIGH 0x00002029

// --- XSS Exiting Bitmap (used with XSAVES/XRSTORS and IA32_XSS)
#define VMCS_CTRL_XSS_EXITING_BITMAP      0x0000202C
#define VMCS_CTRL_XSS_EXITING_BITMAP_HIGH 0x0000202D

// --- Guest Selectors
#define VMCS_GUEST_ES_SELECTOR              0x00000800
#define VMCS_GUEST_CS_SELECTOR              0x00000802
#define VMCS_GUEST_SS_SELECTOR              0x00000804
#define VMCS_GUEST_DS_SELECTOR              0x00000806
#define VMCS_GUEST_FS_SELECTOR              0x00000808
#define VMCS_GUEST_GS_SELECTOR              0x0000080A
#define VMCS_GUEST_LDTR_SELECTOR            0x0000080C
#define VMCS_GUEST_TR_SELECTOR              0x0000080E

// --- Guest Segment Bases
#define VMCS_GUEST_ES_BASE                  0x00006806
#define VMCS_GUEST_CS_BASE                  0x00006808
#define VMCS_GUEST_SS_BASE                  0x0000680A
#define VMCS_GUEST_DS_BASE                  0x0000680C
#define VMCS_GUEST_FS_BASE                  0x0000680E
#define VMCS_GUEST_GS_BASE                  0x00006810
#define VMCS_GUEST_LDTR_BASE                0x00006812
#define VMCS_GUEST_TR_BASE                  0x00006814

// --- Guest Segment Limits
#define VMCS_GUEST_ES_LIMIT                 0x00004800
#define VMCS_GUEST_CS_LIMIT                 0x00004802
#define VMCS_GUEST_SS_LIMIT                 0x00004804
#define VMCS_GUEST_DS_LIMIT                 0x00004806
#define VMCS_GUEST_FS_LIMIT                 0x00004808
#define VMCS_GUEST_GS_LIMIT                 0x0000480A
#define VMCS_GUEST_LDTR_LIMIT               0x0000480C
#define VMCS_GUEST_TR_LIMIT                 0x0000480E

// --- Guest Access Rights
#define VMCS_GUEST_ES_ACCESS_RIGHTS         0x00004810
#define VMCS_GUEST_CS_ACCESS_RIGHTS         0x00004812
#define VMCS_GUEST_SS_ACCESS_RIGHTS         0x00004814
#define VMCS_GUEST_DS_ACCESS_RIGHTS         0x00004816
#define VMCS_GUEST_FS_ACCESS_RIGHTS         0x00004818
#define VMCS_GUEST_GS_ACCESS_RIGHTS         0x0000481A
#define VMCS_GUEST_LDTR_ACCESS_RIGHTS       0x0000481C
#define VMCS_GUEST_TR_ACCESS_RIGHTS         0x0000481E

// --- Guest System State
#define VMCS_GUEST_CR0                      0x00006800
#define VMCS_GUEST_CR3                      0x00006802
#define VMCS_GUEST_CR4                      0x00006804
#define VMCS_GUEST_DR7                      0x0000681A
#define VMCS_GUEST_RSP                      0x0000681C
#define VMCS_GUEST_RIP                      0x0000681E
#define VMCS_GUEST_RFLAGS                   0x00006820

// --- Guest Debug & IDT/GDT
#define VMCS_GUEST_DEBUGCTL                 0x00002802
#define VMCS_GUEST_GDTR_BASE                0x00006816
#define VMCS_GUEST_GDTR_LIMIT               0x00004810
#define VMCS_GUEST_IDTR_BASE                0x00006818
#define VMCS_GUEST_IDTR_LIMIT               0x00004812

// --- Guest MSRs
#define VMCS_GUEST_SYSENTER_CS              0x0000482A
#define VMCS_GUEST_SYSENTER_ESP             0x00006824
#define VMCS_GUEST_SYSENTER_EIP             0x00006826
#define VMCS_GUEST_IA32_EFER                0x00002806
#define VMCS_GUEST_PAT                      0x00002804
#define VMCS_GUEST_BNDCFGS                  0x00002808
#define VMCS_GUEST_PERF_GLOBAL_CTRL         0x00002800
// --- Host Selectors
#define VMCS_HOST_ES_SELECTOR               0x00000C00
#define VMCS_HOST_CS_SELECTOR               0x00000C02
#define VMCS_HOST_SS_SELECTOR               0x00000C04
#define VMCS_HOST_DS_SELECTOR               0x00000C06
#define VMCS_HOST_FS_SELECTOR               0x00000C08
#define VMCS_HOST_GS_SELECTOR               0x00000C0A
#define VMCS_HOST_TR_SELECTOR               0x00000C0C

// --- Host Segment Bases
#define VMCS_HOST_FS_BASE                   0x00006C00
#define VMCS_HOST_GS_BASE                   0x00006C02
#define VMCS_HOST_TR_BASE                   0x00006C04
#define VMCS_HOST_GDTR_BASE                 0x00006C06
#define VMCS_HOST_IDTR_BASE                 0x00006C08

// --- Host Control Registers & Pointers
#define VMCS_HOST_CR0                       0x00006C00
#define VMCS_HOST_CR3                       0x00006C02
#define VMCS_HOST_CR4                       0x00006C04
#define VMCS_HOST_RSP                       0x00006C14
#define VMCS_HOST_RIP                       0x00006C16

// --- Host MSRs
#define VMCS_HOST_SYSENTER_CS               0x00004C00
#define VMCS_HOST_SYSENTER_ESP              0x00006C10
#define VMCS_HOST_SYSENTER_EIP              0x00006C12
#define VMCS_HOST_IA32_EFER                 0x00002C02
#define VMCS_HOST_PAT                       0x00002C00
#define VMCS_HOST_PERF_GLOBAL_CTRL          0x00002C04

//0x10 bytes (sizeof)
struct _HV_X64_HYPERVISOR_FEATURES
{
    union _HV_PARTITION_PRIVILEGE_MASK;                 //0x0
    ULONG MaxSupportedCState : 4;                                             //0x8
    ULONG HpetNeededForC3PowerState_Deprecated : 1;                           //0x8
    ULONG Reserved : 27;                                                      //0x8
    ULONG MwaitAvailable_Deprecated : 1;                                      //0xc
    ULONG GuestDebuggingAvailable : 1;                                        //0xc
    ULONG PerformanceMonitorsAvailable : 1;                                   //0xc
    ULONG CpuDynamicPartitioningAvailable : 1;                                //0xc
    ULONG XmmRegistersForFastHypercallAvailable : 1;                          //0xc
    ULONG GuestIdleAvailable : 1;                                             //0xc
    ULONG HypervisorSleepStateSupportAvailable : 1;                           //0xc
    ULONG NumaDistanceQueryAvailable : 1;                                     //0xc
    ULONG FrequencyRegsAvailable : 1;                                         //0xc
    ULONG SyntheticMachineCheckAvailable : 1;                                 //0xc
    ULONG GuestCrashRegsAvailable : 1;                                        //0xc
    ULONG DebugRegsAvailable : 1;                                             //0xc
    ULONG Npiep1Available : 1;                                                //0xc
    ULONG DisableHypervisorAvailable : 1;                                     //0xc
    ULONG ExtendedGvaRangesForFlushVirtualAddressListAvailable : 1;           //0xc
    ULONG FastHypercallOutputAvailable : 1;                                   //0xc
    ULONG SvmFeaturesAvailable : 1;                                           //0xc
    ULONG SintPollingModeAvailable : 1;                                       //0xc
    ULONG HypercallMsrLockAvailable : 1;                                      //0xc
    ULONG DirectSyntheticTimers : 1;                                          //0xc
    ULONG RegisterPatAvailable : 1;                                           //0xc
    ULONG RegisterBndcfgsAvailable : 1;                                       //0xc
    ULONG WatchdogTimerAvailable : 1;                                         //0xc
    ULONG SyntheticTimeUnhaltedTimerAvailable : 1;                            //0xc
    ULONG DeviceDomainsAvailable : 1;                                         //0xc
    ULONG S1DeviceDomainsAvailable : 1;                                       //0xc
    ULONG LbrAvailable : 1;                                                   //0xc
    ULONG IptAvailable : 1;                                                   //0xc
    ULONG CrossVtlFlushAvailable : 1;                                         //0xc
    ULONG IdleSpecCtrlAvailable : 1;                                          //0xc
    ULONG Reserved1 : 2;                                                      //0xc
};

enum _VM_EXIT_REASON
{
    EXIT_REASON_EXCEPTION_NMI = 0,    // Exception or non-maskable interrupt (NMI).
    EXIT_REASON_EXTERNAL_INTERRUPT = 1,    // External interrupt.
    EXIT_REASON_TRIPLE_FAULT = 2,    // Triple fault.
    EXIT_REASON_INIT = 3,    // INIT signal.
    EXIT_REASON_SIPI = 4,    // Start-up IPI (SIPI).
    EXIT_REASON_IO_SMI = 5,    // I/O system-management interrupt (SMI).
    EXIT_REASON_OTHER_SMI = 6,    // Other SMI.
    EXIT_REASON_PENDING_INTERRUPT = 7,    // Interrupt window exiting.
    EXIT_REASON_NMI_WINDOW = 8,    // NMI window exiting.
    EXIT_REASON_TASK_SWITCH = 9,    // Task switch.
    EXIT_REASON_CPUID = 10,   // Guest software attempted to execute CPUID.
    EXIT_REASON_GETSEC = 11,   // Guest software attempted to execute GETSEC.
    EXIT_REASON_HLT = 12,   // Guest software attempted to execute HLT.
    EXIT_REASON_INVD = 13,   // Guest software attempted to execute INVD.
    EXIT_REASON_INVLPG = 14,   // Guest software attempted to execute INVLPG.
    EXIT_REASON_RDPMC = 15,   // Guest software attempted to execute RDPMC.
    EXIT_REASON_RDTSC = 16,   // Guest software attempted to execute RDTSC.
    EXIT_REASON_RSM = 17,   // Guest software attempted to execute RSM in SMM.
    EXIT_REASON_VMCALL = 18,   // Guest software executed VMCALL.
    EXIT_REASON_VMCLEAR = 19,   // Guest software executed VMCLEAR.
    EXIT_REASON_VMLAUNCH = 20,   // Guest software executed VMLAUNCH.
    EXIT_REASON_VMPTRLD = 21,   // Guest software executed VMPTRLD.
    EXIT_REASON_VMPTRST = 22,   // Guest software executed VMPTRST.
    EXIT_REASON_VMREAD = 23,   // Guest software executed VMREAD.
    EXIT_REASON_VMRESUME = 24,   // Guest software executed VMRESUME.
    EXIT_REASON_VMWRITE = 25,   // Guest software executed VMWRITE.
    EXIT_REASON_VMXOFF = 26,   // Guest software executed VMXOFF.
    EXIT_REASON_VMXON = 27,   // Guest software executed VMXON.
    EXIT_REASON_CR_ACCESS = 28,   // Control-register accesses.
    EXIT_REASON_DR_ACCESS = 29,   // Debug-register accesses.
    EXIT_REASON_IO_INSTRUCTION = 30,   // I/O instruction.
    EXIT_REASON_MSR_READ = 31,   // RDMSR. Guest software attempted to execute RDMSR.
    EXIT_REASON_MSR_WRITE = 32,   // WRMSR. Guest software attempted to execute WRMSR.
    EXIT_REASON_INVALID_GUEST_STATE = 33,   // VM-entry failure due to invalid guest state.
    EXIT_REASON_MSR_LOADING = 34,   // VM-entry failure due to MSR loading.
    EXIT_REASON_RESERVED_35 = 35,   // Reserved
    EXIT_REASON_MWAIT_INSTRUCTION = 36,   // Guest software executed MWAIT.
    EXIT_REASOM_MTF = 37,   // VM-exit due to monitor trap flag.
    EXIT_REASON_RESERVED_38 = 38,   // Reserved
    EXIT_REASON_MONITOR_INSTRUCTION = 39,   // Guest software attempted to execute MONITOR.
    EXIT_REASON_PAUSE_INSTRUCTION = 40,   // Guest software attempted to execute PAUSE.
    EXIT_REASON_MACHINE_CHECK = 41,   // VM-entry failure due to machine-check.
    EXIT_REASON_RESERVED_42 = 42,   // Reserved
    EXIT_REASON_TPR_BELOW_THRESHOLD = 43,   // TPR below threshold. Guest software executed MOV to CR8.
    EXIT_REASON_APIC_ACCESS = 44,   // APIC access. Guest software attempted to access memory at a physical address on the APIC-access page.
    EXIT_REASON_VIRTUALIZED_EIO = 45,   // EOI virtualization was performed for a virtual interrupt whose vector indexed a bit set in the EOIexit bitmap
    EXIT_REASON_XDTR_ACCESS = 46,   // Guest software attempted to execute LGDT, LIDT, SGDT, or SIDT.
    EXIT_REASON_TR_ACCESS = 47,   // Guest software attempted to execute LLDT, LTR, SLDT, or STR.
    EXIT_REASON_EPT_VIOLATION = 48,   // An attempt to access memory with a guest-physical address was disallowed by the configuration of the EPT paging structures.
    EXIT_REASON_EPT_MISCONFIG = 49,   // An attempt to access memory with a guest-physical address encountered a misconfigured EPT paging-structure entry.
    EXIT_REASON_INVEPT = 50,   // Guest software attempted to execute INVEPT.
    EXIT_REASON_RDTSCP = 51,   // Guest software attempted to execute RDTSCP.
    EXIT_REASON_PREEMPT_TIMER = 52,   // VMX-preemption timer expired. The preemption timer counted down to zero.
    EXIT_REASON_INVVPID = 53,   // Guest software attempted to execute INVVPID.
    EXIT_REASON_WBINVD = 54,   // Guest software attempted to execute WBINVD
    EXIT_REASON_XSETBV = 55,   // Guest software attempted to execute XSETBV.
    EXIT_REASON_APIC_WRITE = 56,   // Guest completed write to virtual-APIC.
    EXIT_REASON_RDRAND = 57,   // Guest software attempted to execute RDRAND.
    EXIT_REASON_INVPCID = 58,   // Guest software attempted to execute INVPCID.
    EXIT_REASON_VMFUNC = 59,   // Guest software attempted to execute VMFUNC.
    EXIT_REASON_RESERVED_60 = 60,   // Reserved
    EXIT_REASON_RDSEED = 61,   // Guest software attempted to executed RDSEED and exiting was enabled.
    EXIT_REASON_RESERVED_62 = 62,   // Reserved
    EXIT_REASON_XSAVES = 63,   // Guest software attempted to executed XSAVES and exiting was enabled.
    EXIT_REASON_XRSTORS = 64,   // Guest software attempted to executed XRSTORS and exiting was enabled.

    VMX_MAX_GUEST_VMEXIT = 65
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
struct _PEB64
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
    ULONGLONG Mutant;                                                       //0x8
    ULONGLONG ImageBaseAddress;                                             //0x10
    ULONGLONG Ldr;                                                          //0x18
    ULONGLONG ProcessParameters;                                            //0x20
    ULONGLONG SubSystemData;                                                //0x28
    ULONGLONG ProcessHeap;                                                  //0x30
    ULONGLONG FastPebLock;                                                  //0x38
    ULONGLONG AtlThunkSListPtr;                                             //0x40
    ULONGLONG IFEOKey;                                                      //0x48
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
        ULONGLONG KernelCallbackTable;                                      //0x58
        ULONGLONG UserSharedInfoPtr;                                        //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    ULONGLONG ApiSetMap;                                                    //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    ULONGLONG TlsBitmap;                                                    //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    ULONGLONG ReadOnlySharedMemoryBase;                                     //0x88
    ULONGLONG SharedData;                                                   //0x90
    ULONGLONG ReadOnlyStaticServerData;                                     //0x98
    ULONGLONG AnsiCodePageData;                                             //0xa0
    ULONGLONG OemCodePageData;                                              //0xa8
    ULONGLONG UnicodeCaseTableData;                                         //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    ULONGLONG ProcessHeaps;                                                 //0xf0
    ULONGLONG GdiSharedHandleTable;                                         //0xf8
    ULONGLONG ProcessStarterHelper;                                         //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    ULONGLONG LoaderLock;                                                   //0x110
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
    ULONGLONG PostProcessInitRoutine;                                       //0x230
    ULONGLONG TlsExpansionBitmap;                                           //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    ULONGLONG pShimData;                                                    //0x2d8
    ULONGLONG AppCompatInfo;                                                //0x2e0
    struct _STRING64 CSDVersion;                                            //0x2e8
    ULONGLONG ActivationContextData;                                        //0x2f8
    ULONGLONG ProcessAssemblyStorageMap;                                    //0x300
    ULONGLONG SystemDefaultActivationContextData;                           //0x308
    ULONGLONG SystemAssemblyStorageMap;                                     //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    ULONGLONG SparePointers[4];                                             //0x320
    ULONG SpareUlongs[5];                                                   //0x340
    ULONGLONG WerRegistrationData;                                          //0x358
    ULONGLONG WerShipAssertPtr;                                             //0x360
    ULONGLONG pUnused;                                                      //0x368
    ULONGLONG pImageHeaderHash;                                             //0x370
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
    struct LIST_ENTRY64 TppWorkerpList;                                     //0x390
    ULONGLONG WaitOnAddressHashTable[128];                                  //0x3a0
    ULONGLONG TelemetryCoverageHeader;                                      //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    ULONGLONG LeapSecondData;                                               //0x7b8
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