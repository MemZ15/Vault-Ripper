#pragma once
#include "includes.h"
#include <ntifs.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
typedef unsigned short WORD;

#pragma pack(push, 1)

typedef struct _IMAGE_DOS_HEADER
{
    USHORT e_magic;         // 0x0
    USHORT e_cblp;          // 0x2
    USHORT e_cp;            // 0x4
    USHORT e_crlc;          // 0x6
    USHORT e_cparhdr;       // 0x8
    USHORT e_minalloc;      // 0xA
    USHORT e_maxalloc;      // 0xC
    USHORT e_ss;            // 0xE
    USHORT e_sp;            // 0x10
    USHORT e_csum;          // 0x12
    USHORT e_ip;            // 0x14
    USHORT e_cs;            // 0x16
    USHORT e_lfarlc;        // 0x18
    USHORT e_ovno;          // 0x1A
    USHORT e_res[4];        // 0x1C
    USHORT e_oemid;         // 0x24
    USHORT e_oeminfo;       // 0x26
    USHORT e_res2[10];      // 0x28
    LONG   e_lfanew;        // 0x3C
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

// 0x8 bytes
typedef struct _IMAGE_DATA_DIRECTORY
{
    DWORD VirtualAddress;   // RVA
    DWORD Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

// 0x14 bytes
typedef struct _IMAGE_FILE_HEADER
{
    USHORT Machine;
    USHORT NumberOfSections;
    DWORD  TimeDateStamp;
    DWORD  PointerToSymbolTable;
    DWORD  NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

// 0xF0 bytes
typedef struct _IMAGE_OPTIONAL_HEADER64
{
    USHORT  Magic;
    UCHAR   MajorLinkerVersion;
    UCHAR   MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    ULONGLONG ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    USHORT  MajorOperatingSystemVersion;
    USHORT  MinorOperatingSystemVersion;
    USHORT  MajorImageVersion;
    USHORT  MinorImageVersion;
    USHORT  MajorSubsystemVersion;
    USHORT  MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    USHORT  Subsystem;
    USHORT  DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; // Array of data directories
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

// 0x108 bytes
typedef struct _IMAGE_NT_HEADERS64
{
    DWORD Signature;                              // "PE\0\0" = 0x00004550
    IMAGE_FILE_HEADER FileHeader;                 // 0x4
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;       // 0x18
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

// size: 0x28 bytes
typedef struct _IMAGE_EXPORT_DIRECTORY
{
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    DWORD   Name;                  // RVA
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;   // RVA
    DWORD   AddressOfNames;       // RVA
    DWORD   AddressOfNameOrdinals; // RVA
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


enum _OB_OPEN_REASON
{
    ObCreateHandle = 0,
    ObOpenHandle = 1,
    ObDuplicateHandle = 2,
    ObInheritHandle = 3,
    ObMaxOpenReason = 4
};

typedef struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                             //0x0
            ULONGLONG Waiting : 1;                                            //0x0
            ULONGLONG Waking : 1;                                             //0x0
            ULONGLONG MultipleShared : 1;                                     //0x0
            ULONGLONG Shared : 60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};



//0x138 bytes (sizeof)
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
            ULONG VerifierProvider : 1;                                       //0x68
            ULONG ShimEngineCalloutSent : 1;                                  //0x68
            ULONG LoadInProgress : 1;                                         //0x68
            ULONG LoadConfigProcessed : 1;                                    //0x68
            ULONG EntryProcessed : 1;                                         //0x68
            ULONG ProtectDelayLoad : 1;                                       //0x68
            ULONG AuxIatCopyPrivate : 1;                                      //0x68
            ULONG ReservedFlags3 : 1;                                         //0x68
            ULONG DontCallForThreads : 1;                                     //0x68
            ULONG ProcessAttachCalled : 1;                                    //0x68
            ULONG ProcessAttachFailed : 1;                                    //0x68
            ULONG ScpInExceptionTable : 1;                                    //0x68
            ULONG CorImage : 1;                                               //0x68
            ULONG DontRelocate : 1;                                           //0x68
            ULONG CorILOnly : 1;                                              //0x68
            ULONG ChpeImage : 1;                                              //0x68
            ULONG ChpeEmulatorImage : 1;                                      //0x68
            ULONG ReservedFlags5 : 1;                                         //0x68
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
    ULONG CheckSum;                                                         //0x120
    VOID* ActivePatchImageBase;                                             //0x128
    enum _LDR_HOT_PATCH_STATE HotPatchState;                                //0x130
};

typedef struct FakeEPROCESS {
    uint8_t padding[0x338];       // Filler up to ImageFileName
    UCHAR ImageFileName[16];      // At offset 0x338
};

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
        USHORT Frozen : 2;                                                    //0x6e
        USHORT HotPatch : 1;                                                  //0x6e
        USHORT Unused : 6;                                                    //0x6e
        USHORT EntireField;                                                 //0x6e
    } u1;                                                                   //0x6e
    VOID* SectionPointer;                                                   //0x70
    ULONG CheckSum;                                                         //0x78
    ULONG CoverageSectionSize;                                              //0x7c
    VOID* CoverageSection;                                                  //0x80
    VOID* LoadedImports;                                                    //0x88
    union
    {
        VOID* Spare;                                                        //0x90
        struct _KLDR_DATA_TABLE_ENTRY* NtDataTableEntry;                    //0x90
    };
    ULONG SizeOfImageNotRounded;                                            //0x98
    ULONG TimeDateStamp;                                                    //0x9c
};


typedef struct _OBJECT_DUMP_CONTROL
{
    VOID* Stream;                                                           //0x0
    ULONG Detail;                                                           //0x8
};

//0x10 bytes (sizeof)
typedef struct _OB_EXTENDED_PARSE_PARAMETERS
{
    USHORT Length;                                                          //0x0
    ULONG RestrictedAccessMask;                                             //0x4
    struct _EJOB* Silo;                                                     //0x8
};

//0x840 bytes (sizeof)
typedef struct _EPROCESS
{
    typedef struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x1c8
    VOID* UniqueProcessId;                                                  //0x1d0
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x1d8
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x1e8
    union
    {
        ULONG Flags2;                                                       //0x1f0
        struct
        {
            ULONG JobNotReallyActive : 1;                                     //0x1f0
            ULONG AccountingFolded : 1;                                       //0x1f0
            ULONG NewProcessReported : 1;                                     //0x1f0
            ULONG ExitProcessReported : 1;                                    //0x1f0
            ULONG ReportCommitChanges : 1;                                    //0x1f0
            ULONG LastReportMemory : 1;                                       //0x1f0
            ULONG ForceWakeCharge : 1;                                        //0x1f0
            ULONG CrossSessionCreate : 1;                                     //0x1f0
            ULONG NeedsHandleRundown : 1;                                     //0x1f0
            ULONG RefTraceEnabled : 1;                                        //0x1f0
            ULONG PicoCreated : 1;                                            //0x1f0
            ULONG EmptyJobEvaluated : 1;                                      //0x1f0
            ULONG DefaultPagePriority : 3;                                    //0x1f0
            ULONG PrimaryTokenFrozen : 1;                                     //0x1f0
            ULONG ProcessVerifierTarget : 1;                                  //0x1f0
            ULONG RestrictSetThreadContext : 1;                               //0x1f0
            ULONG AffinityPermanent : 1;                                      //0x1f0
            ULONG AffinityUpdateEnable : 1;                                   //0x1f0
            ULONG PropagateNode : 1;                                          //0x1f0
            ULONG ExplicitAffinity : 1;                                       //0x1f0
            ULONG Flags2Available1 : 2;                                       //0x1f0
            ULONG EnableReadVmLogging : 1;                                    //0x1f0
            ULONG EnableWriteVmLogging : 1;                                   //0x1f0
            ULONG FatalAccessTerminationRequested : 1;                        //0x1f0
            ULONG DisableSystemAllowedCpuSet : 1;                             //0x1f0
            ULONG Flags2Available2 : 3;                                       //0x1f0
            ULONG InPrivate : 1;                                              //0x1f0
        };
    };
    union
    {
        ULONG Flags;                                                        //0x1f4
        struct
        {
            ULONG CreateReported : 1;                                         //0x1f4
            ULONG NoDebugInherit : 1;                                         //0x1f4
            ULONG ProcessExiting : 1;                                         //0x1f4
            ULONG ProcessDelete : 1;                                          //0x1f4
            ULONG ManageExecutableMemoryWrites : 1;                           //0x1f4
            ULONG VmDeleted : 1;                                              //0x1f4
            ULONG OutswapEnabled : 1;                                         //0x1f4
            ULONG Outswapped : 1;                                             //0x1f4
            ULONG FailFastOnCommitFail : 1;                                   //0x1f4
            ULONG Wow64VaSpace4Gb : 1;                                        //0x1f4
            ULONG AddressSpaceInitialized : 2;                                //0x1f4
            ULONG SetTimerResolution : 1;                                     //0x1f4
            ULONG BreakOnTermination : 1;                                     //0x1f4
            ULONG DeprioritizeViews : 1;                                      //0x1f4
            ULONG WriteWatch : 1;                                             //0x1f4
            ULONG ProcessInSession : 1;                                       //0x1f4
            ULONG OverrideAddressSpace : 1;                                   //0x1f4
            ULONG HasAddressSpace : 1;                                        //0x1f4
            ULONG LaunchPrefetched : 1;                                       //0x1f4
            ULONG Reserved : 1;                                               //0x1f4
            ULONG VmTopDown : 1;                                              //0x1f4
            ULONG ImageNotifyDone : 1;                                        //0x1f4
            ULONG PdeUpdateNeeded : 1;                                        //0x1f4
            ULONG VdmAllowed : 1;                                             //0x1f4
            ULONG ProcessRundown : 1;                                         //0x1f4
            ULONG ProcessInserted : 1;                                        //0x1f4
            ULONG DefaultIoPriority : 3;                                      //0x1f4
            ULONG ProcessSelfDelete : 1;                                      //0x1f4
            ULONG SetTimerResolutionLink : 1;                                 //0x1f4
        };
    };
    union _LARGE_INTEGER CreateTime;                                        //0x1f8
    ULONGLONG ProcessQuotaUsage[2];                                         //0x200
    ULONGLONG ProcessQuotaPeak[2];                                          //0x210
    ULONGLONG PeakVirtualSize;                                              //0x220
    ULONGLONG VirtualSize;                                                  //0x228
    struct _LIST_ENTRY SessionProcessLinks;                                 //0x230
    union
    {
        VOID* ExceptionPortData;                                            //0x240
        ULONGLONG ExceptionPortValue;                                       //0x240
        ULONGLONG ExceptionPortState : 3;                                     //0x240
    };
    struct _EX_FAST_REF* Token;                                              //0x248
    ULONGLONG MmReserved;                                                   //0x250
    typedef struct _EX_PUSH_LOCK AddressCreationLock;                               //0x258
    typedef struct _EX_PUSH_LOCK PageTableCommitmentLock;                           //0x260
    typedef struct _ETHREAD* RotateInProgress;                                      //0x268
    typedef struct _ETHREAD* ForkInProgress;                                        //0x270
    struct _EJOB* volatile CommitChargeJob;                                 //0x278
    struct _RTL_AVL_TREE* CloneRoot;                                         //0x280
    volatile ULONGLONG NumberOfPrivatePages;                                //0x288
    volatile ULONGLONG NumberOfLockedPages;                                 //0x290
    VOID* Win32Process;                                                     //0x298
    struct _EJOB* volatile Job;                                             //0x2a0
    VOID* SectionObject;                                                    //0x2a8
    VOID* SectionBaseAddress;                                               //0x2b0
    ULONG Cookie;                                                           //0x2b8
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x2c0
    VOID* Win32WindowStation;                                               //0x2c8
    VOID* InheritedFromUniqueProcessId;                                     //0x2d0
    volatile ULONGLONG OwnerProcessId;                                      //0x2d8
    struct _PEB* Peb;                                                       //0x2e0
    struct _PSP_SESSION_SPACE* Session;                                     //0x2e8
    VOID* Spare1;                                                           //0x2f0
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x2f8
    struct _HANDLE_TABLE* ObjectTable;                                      //0x300
    VOID* DebugPort;                                                        //0x308
    struct _EWOW64PROCESS* WoW64Process;                                    //0x310
    typedef struct _EX_FAST_REF* DeviceMap;                                          //0x318
    VOID* EtwDataSource;                                                    //0x320
    ULONGLONG PageDirectoryPte;                                             //0x328
    struct _FILE_OBJECT* ImageFilePointer;                                  //0x330
    UCHAR ImageFileName[15];                                                //0x338
    UCHAR PriorityClass;                                                    //0x347
    VOID* SecurityPort;                                                     //0x348
    struct _SE_AUDIT_PROCESS_CREATION_INFO* SeAuditProcessCreationInfo;      //0x350
    struct _LIST_ENTRY JobLinks;                                            //0x358
    VOID* HighestUserAddress;                                               //0x368
    struct _LIST_ENTRY ThreadListHead;                                      //0x370
    volatile ULONG ActiveThreads;                                           //0x380
    ULONG ImagePathHash;                                                    //0x384
    ULONG DefaultHardErrorProcessing;                                       //0x388
    LONG LastThreadExitStatus;                                              //0x38c
    struct _EX_FAST_REF* PrefetchTrace;                                      //0x390
    VOID* LockedPagesList;                                                  //0x398
    union _LARGE_INTEGER ReadOperationCount;                                //0x3a0
    union _LARGE_INTEGER WriteOperationCount;                               //0x3a8
    union _LARGE_INTEGER OtherOperationCount;                               //0x3b0
    union _LARGE_INTEGER ReadTransferCount;                                 //0x3b8
    union _LARGE_INTEGER WriteTransferCount;                                //0x3c0
    union _LARGE_INTEGER OtherTransferCount;                                //0x3c8
    ULONGLONG CommitChargeLimit;                                            //0x3d0
    volatile ULONGLONG CommitCharge;                                        //0x3d8
    volatile ULONGLONG CommitChargePeak;                                    //0x3e0
    struct _MMSUPPORT_FULL* Vm;                                              //0x400
    struct _LIST_ENTRY MmProcessLinks;                                      //0x540
    volatile ULONG ModifiedPageCount;                                       //0x550
    LONG ExitStatus;                                                        //0x554
    struct _RTL_AVL_TREE* VadRoot;                                           //0x558
    VOID* VadHint;                                                          //0x560
    ULONGLONG VadCount;                                                     //0x568
    volatile ULONGLONG VadPhysicalPages;                                    //0x570
    ULONGLONG VadPhysicalPagesLimit;                                        //0x578
    struct _ALPC_PROCESS_CONTEXT* AlpcContext;                               //0x580
    struct _LIST_ENTRY TimerResolutionLink;                                 //0x5a0
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x5b0
    ULONG RequestedTimerResolution;                                         //0x5b8
    ULONG SmallestTimerResolution;                                          //0x5bc
    union _LARGE_INTEGER ExitTime;                                          //0x5c0
    struct _INVERTED_FUNCTION_TABLE_KERNEL_MODE* InvertedFunctionTable;     //0x5c8
    struct _EX_PUSH_LOCK InvertedFunctionTableLock;                         //0x5d0
    ULONG ActiveThreadsHighWatermark;                                       //0x5d8
    ULONG LargePrivateVadCount;                                             //0x5dc
    typedef struct _EX_PUSH_LOCK ThreadListLock;                                    //0x5e0
    VOID* WnfContext;                                                       //0x5e8
    struct _EJOB* ServerSilo;                                               //0x5f0
    UCHAR SignatureLevel;                                                   //0x5f8
    UCHAR SectionSignatureLevel;                                            //0x5f9
    struct _PS_PROTECTION* Protection;                                       //0x5fa
    UCHAR HangCount : 3;                                                      //0x5fb
    UCHAR GhostCount : 3;                                                     //0x5fb
    UCHAR PrefilterException : 1;                                             //0x5fb
    union
    {
        ULONG Flags3;                                                       //0x5fc
        struct
        {
            ULONG Minimal : 1;                                                //0x5fc
            ULONG ReplacingPageRoot : 1;                                      //0x5fc
            ULONG Crashed : 1;                                                //0x5fc
            ULONG JobVadsAreTracked : 1;                                      //0x5fc
            ULONG VadTrackingDisabled : 1;                                    //0x5fc
            ULONG AuxiliaryProcess : 1;                                       //0x5fc
            ULONG SubsystemProcess : 1;                                       //0x5fc
            ULONG IndirectCpuSets : 1;                                        //0x5fc
            ULONG RelinquishedCommit : 1;                                     //0x5fc
            ULONG HighGraphicsPriority : 1;                                   //0x5fc
            ULONG CommitFailLogged : 1;                                       //0x5fc
            ULONG ReserveFailLogged : 1;                                      //0x5fc
            ULONG SystemProcess : 1;                                          //0x5fc
            ULONG AllImagesAtBasePristineBase : 1;                            //0x5fc
            ULONG AddressPolicyFrozen : 1;                                    //0x5fc
            ULONG ProcessFirstResume : 1;                                     //0x5fc
            ULONG ForegroundExternal : 1;                                     //0x5fc
            ULONG ForegroundSystem : 1;                                       //0x5fc
            ULONG HighMemoryPriority : 1;                                     //0x5fc
            ULONG EnableProcessSuspendResumeLogging : 1;                      //0x5fc
            ULONG EnableThreadSuspendResumeLogging : 1;                       //0x5fc
            ULONG SecurityDomainChanged : 1;                                  //0x5fc
            ULONG SecurityFreezeComplete : 1;                                 //0x5fc
            ULONG VmProcessorHost : 1;                                        //0x5fc
            ULONG VmProcessorHostTransition : 1;                              //0x5fc
            ULONG AltSyscall : 1;                                             //0x5fc
            ULONG TimerResolutionIgnore : 1;                                  //0x5fc
            ULONG DisallowUserTerminate : 1;                                  //0x5fc
            ULONG EnableProcessRemoteExecProtectVmLogging : 1;                //0x5fc
            ULONG EnableProcessLocalExecProtectVmLogging : 1;                 //0x5fc
            ULONG MemoryCompressionProcess : 1;                               //0x5fc
            ULONG EnableProcessImpersonationLogging : 1;                      //0x5fc
        };
    };
    LONG DeviceAsid;                                                        //0x600
    VOID* SvmData;                                                          //0x608
    struct _EX_PUSH_LOCK SvmProcessLock;                                    //0x610
    ULONGLONG SvmLock;                                                      //0x618
    struct _LIST_ENTRY SvmProcessDeviceListHead;                            //0x620
    ULONGLONG LastFreezeInterruptTime;                                      //0x630
    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x638
    VOID* PicoContext;                                                      //0x640
    VOID* EnclaveTable;                                                     //0x648
    ULONGLONG EnclaveNumber;                                                //0x650
    struct _EX_PUSH_LOCK EnclaveLock;                                       //0x658
    ULONG HighPriorityFaultsAllowed;                                        //0x660
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x668
    VOID* VmContext;                                                        //0x670
    ULONGLONG SequenceNumber;                                               //0x678
    ULONGLONG CreateInterruptTime;                                          //0x680
    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x688
    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x690
    ULONGLONG LastAppStateUpdateTime;                                       //0x698
    ULONGLONG LastAppStateUptime : 61;                                        //0x6a0
    ULONGLONG LastAppState : 3;                                               //0x6a0
    volatile ULONGLONG SharedCommitCharge;                                  //0x6a8
    struct _EX_PUSH_LOCK SharedCommitLock;                                  //0x6b0
    struct _LIST_ENTRY SharedCommitLinks;                                   //0x6b8
    union
    {
        struct
        {
            ULONGLONG AllowedCpuSets;                                       //0x6c8
            ULONGLONG DefaultCpuSets;                                       //0x6d0
        };
        struct
        {
            ULONGLONG* AllowedCpuSetsIndirect;                              //0x6c8
            ULONGLONG* DefaultCpuSetsIndirect;                              //0x6d0
        };
    };
    VOID* DiskIoAttribution;                                                //0x6d8
    VOID* DxgProcess;                                                       //0x6e0
    ULONG Win32KFilterSet;                                                  //0x6e8
    USHORT Machine;                                                         //0x6ec
    UCHAR MmSlabIdentity;                                                   //0x6ee
    UCHAR Spare0;                                                           //0x6ef
    union  _PS_INTERLOCKED_TIMER_DELAY_VALUES* ProcessTimerDelay;     //0x6f0
    volatile ULONG KTimerSets;                                              //0x6f8
    volatile ULONG KTimer2Sets;                                             //0x6fc
    volatile ULONG ThreadTimerSets;                                         //0x700
    ULONGLONG VirtualTimerListLock;                                         //0x708
    struct _LIST_ENTRY VirtualTimerListHead;                                //0x710
    union
    {
        struct _WNF_STATE_NAME WakeChannel;                                 //0x720
        struct _PS_PROCESS_WAKE_INFORMATION* WakeInfo;                       //0x720
    };
    union
    {
        ULONG MitigationFlags;                                              //0x750
        struct
        {
            ULONG ControlFlowGuardEnabled : 1;                                //0x750
            ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x750
            ULONG ControlFlowGuardStrict : 1;                                 //0x750
            ULONG DisallowStrippedImages : 1;                                 //0x750
            ULONG ForceRelocateImages : 1;                                    //0x750
            ULONG HighEntropyASLREnabled : 1;                                 //0x750
            ULONG StackRandomizationDisabled : 1;                             //0x750
            ULONG ExtensionPointDisable : 1;                                  //0x750
            ULONG DisableDynamicCode : 1;                                     //0x750
            ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x750
            ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x750
            ULONG AuditDisableDynamicCode : 1;                                //0x750
            ULONG DisallowWin32kSystemCalls : 1;                              //0x750
            ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x750
            ULONG EnableFilteredWin32kAPIs : 1;                               //0x750
            ULONG AuditFilteredWin32kAPIs : 1;                                //0x750
            ULONG DisableNonSystemFonts : 1;                                  //0x750
            ULONG AuditNonSystemFontLoading : 1;                              //0x750
            ULONG PreferSystem32Images : 1;                                   //0x750
            ULONG ProhibitRemoteImageMap : 1;                                 //0x750
            ULONG AuditProhibitRemoteImageMap : 1;                            //0x750
            ULONG ProhibitLowILImageMap : 1;                                  //0x750
            ULONG AuditProhibitLowILImageMap : 1;                             //0x750
            ULONG SignatureMitigationOptIn : 1;                               //0x750
            ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x750
            ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x750
            ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x750
            ULONG AuditLoaderIntegrityContinuity : 1;                         //0x750
            ULONG EnableModuleTamperingProtection : 1;                        //0x750
            ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x750
            ULONG RestrictIndirectBranchPrediction : 1;                       //0x750
            ULONG IsolateSecurityDomain : 1;                                  //0x750
        } MitigationFlagsValues;                                            //0x750
    };
    union
    {
        ULONG MitigationFlags2;                                             //0x754
        struct
        {
            ULONG EnableExportAddressFilter : 1;                              //0x754
            ULONG AuditExportAddressFilter : 1;                               //0x754
            ULONG EnableExportAddressFilterPlus : 1;                          //0x754
            ULONG AuditExportAddressFilterPlus : 1;                           //0x754
            ULONG EnableRopStackPivot : 1;                                    //0x754
            ULONG AuditRopStackPivot : 1;                                     //0x754
            ULONG EnableRopCallerCheck : 1;                                   //0x754
            ULONG AuditRopCallerCheck : 1;                                    //0x754
            ULONG EnableRopSimExec : 1;                                       //0x754
            ULONG AuditRopSimExec : 1;                                        //0x754
            ULONG EnableImportAddressFilter : 1;                              //0x754
            ULONG AuditImportAddressFilter : 1;                               //0x754
            ULONG DisablePageCombine : 1;                                     //0x754
            ULONG SpeculativeStoreBypassDisable : 1;                          //0x754
            ULONG CetUserShadowStacks : 1;                                    //0x754
            ULONG AuditCetUserShadowStacks : 1;                               //0x754
            ULONG AuditCetUserShadowStacksLogged : 1;                         //0x754
            ULONG UserCetSetContextIpValidation : 1;                          //0x754
            ULONG AuditUserCetSetContextIpValidation : 1;                     //0x754
            ULONG AuditUserCetSetContextIpValidationLogged : 1;               //0x754
            ULONG CetUserShadowStacksStrictMode : 1;                          //0x754
            ULONG BlockNonCetBinaries : 1;                                    //0x754
            ULONG BlockNonCetBinariesNonEhcont : 1;                           //0x754
            ULONG AuditBlockNonCetBinaries : 1;                               //0x754
            ULONG AuditBlockNonCetBinariesLogged : 1;                         //0x754
            ULONG XtendedControlFlowGuard_Deprecated : 1;                     //0x754
            ULONG AuditXtendedControlFlowGuard_Deprecated : 1;                //0x754
            ULONG PointerAuthUserIp : 1;                                      //0x754
            ULONG AuditPointerAuthUserIp : 1;                                 //0x754
            ULONG AuditPointerAuthUserIpLogged : 1;                           //0x754
            ULONG CetDynamicApisOutOfProcOnly : 1;                            //0x754
            ULONG UserCetSetContextIpValidationRelaxedMode : 1;               //0x754
        } MitigationFlags2Values;                                           //0x754
    };
    VOID* PartitionObject;                                                  //0x758
    ULONGLONG SecurityDomain;                                               //0x760
    ULONGLONG ParentSecurityDomain;                                         //0x768
    VOID* CoverageSamplerContext;                                           //0x770
    VOID* MmHotPatchContext;                                                //0x778
    typedef struct _RTL_AVL_TREE* DynamicEHContinuationTargetsTree;                  //0x780
    typedef struct _EX_PUSH_LOCK* DynamicEHContinuationTargetsLock;                  //0x788
    struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES* DynamicEnforcedCetCompatibleRanges; //0x790
    ULONG DisabledComponentFlags;                                           //0x7a0
    volatile LONG PageCombineSequence;                                      //0x7a4
    typedef struct _EX_PUSH_LOCK EnableOptionalXStateFeaturesLock;                  //0x7a8
    ULONG* volatile PathRedirectionHashes;                                  //0x7b0
    struct _PS_SYSCALL_PROVIDER* SyscallProvider;                           //0x7b8
    struct _LIST_ENTRY SyscallProviderProcessLinks;                         //0x7c0
    struct _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT* SyscallProviderDispatchContext; //0x7d0
    union
    {
        ULONG MitigationFlags3;                                             //0x7d8
        struct
        {
            ULONG RestrictCoreSharing : 1;                                    //0x7d8
            ULONG DisallowFsctlSystemCalls : 1;                               //0x7d8
            ULONG AuditDisallowFsctlSystemCalls : 1;                          //0x7d8
            ULONG MitigationFlags3Spare : 29;                                 //0x7d8
        } MitigationFlags3Values;                                           //0x7d8
    };
    union
    {
        ULONG Flags4;                                                       //0x7dc
        struct
        {
            ULONG ThreadWasActive : 1;                                        //0x7dc
            ULONG MinimalTerminate : 1;                                       //0x7dc
            ULONG ImageExpansionDisable : 1;                                  //0x7dc
            ULONG SessionFirstProcess : 1;                                    //0x7dc
        };
    };
    union
    {
        ULONG SyscallUsage;                                                 //0x7e0
        struct
        {
            ULONG SystemModuleInformation : 1;                                //0x7e0
            ULONG SystemModuleInformationEx : 1;                              //0x7e0
            ULONG SystemLocksInformation : 1;                                 //0x7e0
            ULONG SystemStackTraceInformation : 1;                            //0x7e0
            ULONG SystemHandleInformation : 1;                                //0x7e0
            ULONG SystemExtendedHandleInformation : 1;                        //0x7e0
            ULONG SystemObjectInformation : 1;                                //0x7e0
            ULONG SystemBigPoolInformation : 1;                               //0x7e0
            ULONG SystemExtendedProcessInformation : 1;                       //0x7e0
            ULONG SystemSessionProcessInformation : 1;                        //0x7e0
            ULONG SystemMemoryTopologyInformation : 1;                        //0x7e0
            ULONG SystemMemoryChannelInformation : 1;                         //0x7e0
            ULONG SystemUnused : 1;                                           //0x7e0
            ULONG SystemPlatformBinaryInformation : 1;                        //0x7e0
            ULONG SystemFirmwareTableInformation : 1;                         //0x7e0
            ULONG SystemBootMetadataInformation : 1;                          //0x7e0
            ULONG SystemWheaIpmiHardwareInformation : 1;                      //0x7e0
            ULONG SystemSuperfetchPrefetch : 1;                               //0x7e0
            ULONG SystemSuperfetchPfnQuery : 1;                               //0x7e0
            ULONG SystemSuperfetchPrivSourceQuery : 1;                        //0x7e0
            ULONG SystemSuperfetchMemoryListQuery : 1;                        //0x7e0
            ULONG SystemSuperfetchMemoryRangesQuery : 1;                      //0x7e0
            ULONG SystemSuperfetchPfnSetPriority : 1;                         //0x7e0
            ULONG SystemSuperfetchMovePages : 1;                              //0x7e0
            ULONG SystemSuperfetchPfnSetPageHeat : 1;                         //0x7e0
            ULONG SysDbgGetTriageDump : 1;                                    //0x7e0
            ULONG SysDbgGetLiveKernelDump : 1;                                //0x7e0
            ULONG SyscallUsageValuesSpare : 5;                                //0x7e0
        } SyscallUsageValues;                                               //0x7e0
    };
    LONG SupervisorDeviceAsid;                                              //0x7e4
    VOID* SupervisorSvmData;                                                //0x7e8
    struct _PROCESS_NETWORK_COUNTERS* NetworkCounters;                      //0x7f0
    union _PROCESS_EXECUTION* Execution;                                     //0x7f8
    VOID* ThreadIndexTable;                                                 //0x800
};


using dump_procedure_ty = void( __fastcall* )( void*, _OBJECT_DUMP_CONTROL* );

using open_procedure_ty = LONG( __fastcall* )(
    _OB_OPEN_REASON,
    CHAR,
    struct _EPROCESS*,
    void*,
    ULONG*,
    ULONG
    );

using close_procedure_ty = void( __fastcall* )(
    _EPROCESS*,
    void*,
    unsigned long long,
    unsigned long long
    );

using delete_procedure_ty = void( __fastcall* )( void* );

using parse_procedure_ty = LONG( __fastcall* )(
    void* object_type,
    void* object,
    _ACCESS_STATE* access_state,
    CHAR access_mode,
    ULONG attributes,
    _UNICODE_STRING* complete_name,
    _UNICODE_STRING* remaining_name,
    void* context,
    _SECURITY_QUALITY_OF_SERVICE* sqos,
    void** found_object
    );

using parse_procedure_ex_ty = LONG( __fastcall* )(
    void* object_type,
    void* object,
    _ACCESS_STATE* access_state,
    CHAR access_mode,
    ULONG attributes,
    _UNICODE_STRING* complete_name,
    _UNICODE_STRING* remaining_name,
    void* context,
    _SECURITY_QUALITY_OF_SERVICE* sqos,
    _OB_EXTENDED_PARSE_PARAMETERS* extended_parameters,
    void** found_object
    );

using security_procedure_ty = LONG( __fastcall* )(
    void* object,
    _SECURITY_OPERATION_CODE operation_code,
    ULONG* security_information,
    void* security_descriptor,
    ULONG* buffer_length,
    void** returned_security_descriptor,
    _POOL_TYPE pool_type,
    _GENERIC_MAPPING* generic_mapping,
    CHAR access_mode
    );

using query_name_procedure_ty = LONG( __fastcall* )(
    void* object,
    UCHAR flags,
    _OBJECT_NAME_INFORMATION* name_info,
    ULONG name_info_length,
    ULONG* return_length,
    CHAR access_mode
    );


using okay_to_close_procedure_ty = UCHAR( __fastcall* )(
    _EPROCESS* process,   // The process closing the handle
    void* object,         // The object being closed
    void* context,        // Optional context (usually NULL)
    CHAR access_mode      // Access mode (KernelMode/UserMode)
    );



//0x78 bytes (sizeof)
typedef struct _OBJECT_TYPE_INITIALIZER
{
    USHORT Length;                                                          //0x0
    union
    {
        USHORT ObjectTypeFlags;                                             //0x2
        struct
        {
            UCHAR CaseInsensitive : 1;                                        //0x2
            UCHAR UnnamedObjectsOnly : 1;                                     //0x2
            UCHAR UseDefaultObject : 1;                                       //0x2
            UCHAR SecurityRequired : 1;                                       //0x2
            UCHAR MaintainHandleCount : 1;                                    //0x2
            UCHAR MaintainTypeList : 1;                                       //0x2
            UCHAR SupportsObjectCallbacks : 1;                                //0x2
            UCHAR CacheAligned : 1;                                           //0x2
            UCHAR UseExtendedParameters : 1;                                  //0x3
            UCHAR SeTrustConstraintMaskPresent : 1;                           //0x3
            UCHAR Reserved : 6;                                               //0x3
        };
    };
    ULONG ObjectTypeCode;                                                   //0x4
    ULONG InvalidAttributes;                                                //0x8
    struct _GENERIC_MAPPING GenericMapping;                                 //0xc
    ULONG ValidAccessMask;                                                  //0x1c
    ULONG RetainAccess;                                                     //0x20
    enum _POOL_TYPE PoolType;                                               //0x24
    ULONG DefaultPagedPoolCharge;                                           //0x28
    ULONG DefaultNonPagedPoolCharge;                                        //0x2c
    VOID( *DumpProcedure )( VOID* arg1, struct _OBJECT_DUMP_CONTROL* arg2 );   //0x30
    LONG ( *OpenProcedure )( enum _OB_OPEN_REASON arg1, CHAR arg2, struct _EPROCESS* arg3, VOID* arg4, ULONG* arg5, ULONG arg6 ); //0x38
    VOID( *CloseProcedure )( struct _EPROCESS* arg1, VOID* arg2, ULONGLONG arg3, ULONGLONG arg4 ); //0x40
    VOID( *DeleteProcedure )( VOID* arg1 );                                    //0x48
    union
    {
        LONG( *ParseProcedure )( VOID* arg1, VOID* arg2, struct _ACCESS_STATE* arg3, CHAR arg4, ULONG arg5, struct _UNICODE_STRING* arg6, struct _UNICODE_STRING* arg7, VOID* arg8, struct _SECURITY_QUALITY_OF_SERVICE* arg9, VOID** arg10 ); //0x50
        LONG( *ParseProcedureEx )( VOID* arg1, VOID* arg2, struct _ACCESS_STATE* arg3, CHAR arg4, ULONG arg5, struct _UNICODE_STRING* arg6, struct _UNICODE_STRING* arg7, VOID* arg8, struct _SECURITY_QUALITY_OF_SERVICE* arg9, struct _OB_EXTENDED_PARSE_PARAMETERS* arg10, VOID** arg11 ); //0x50
    };
    LONG( *SecurityProcedure )( VOID* arg1, enum _SECURITY_OPERATION_CODE arg2, ULONG* arg3, VOID* arg4, ULONG* arg5, VOID** arg6, enum _POOL_TYPE arg7, struct _GENERIC_MAPPING* arg8, CHAR arg9 ); //0x58
    LONG( *QueryNameProcedure )( VOID* arg1, UCHAR arg2, struct _OBJECT_NAME_INFORMATION* arg3, ULONG arg4, ULONG* arg5, CHAR arg6 ); //0x60
    UCHAR( *OkayToCloseProcedure )( struct _EPROCESS* arg1, VOID* arg2, VOID* arg3, CHAR arg4 ); //0x68
    ULONG WaitObjectFlagMask;                                               //0x70
    USHORT WaitObjectFlagOffset;                                            //0x74
    USHORT WaitObjectPointerOffset;                                         //0x76
};

//0xe0 bytes (sizeof)
struct _OBJECT_TYPE
{
    struct _LIST_ENTRY TypeList;                                            //0x0
    struct _UNICODE_STRING Name;                                            //0x10
    VOID* DefaultObject;                                                    //0x20
    UCHAR Index;                                                            //0x28
    ULONG TotalNumberOfObjects;                                             //0x2c
    ULONG TotalNumberOfHandles;                                             //0x30
    ULONG HighWaterNumberOfObjects;                                         //0x34
    ULONG HighWaterNumberOfHandles;                                         //0x38
    struct _OBJECT_TYPE_INITIALIZER TypeInfo;                               //0x40
    struct _EX_PUSH_LOCK TypeLock;                                          //0xb8
    ULONG Key;                                                              //0xc0
    struct _LIST_ENTRY CallbackList;                                        //0xc8
    ULONG SeMandatoryLabelMask;                                             //0xd8
    ULONG SeTrustConstraintMask;                                            //0xdc
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





#define KeGetPcr() ((PKPCR)__readgsqword((unsigned long)FIELD_OFFSET(KPCR, Self)))


//0x1c8 bytes (sizeof)
typedef struct _KPROCESS
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    struct _LIST_ENTRY ThreadListHead;                                      //0x30
    ULONG ProcessLock;                                                      //0x40
    ULONG ProcessTimerDelay;                                                //0x44
    ULONGLONG DeepFreezeStartTime;                                          //0x48
    struct _KAFFINITY_EX* Affinity;                                         //0x50
    struct _KAB_UM_PROCESS_CONTEXT* AutoBoostState;                          //0x58
    struct _LIST_ENTRY ReadyListHead;                                       //0x68
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x78
    struct _KAFFINITY_EX* ActiveProcessors;                                 //0x80
    union
    {
        struct
        {
            ULONG AutoAlignment : 1;                                          //0x88
            ULONG DisableBoost : 1;                                           //0x88
            ULONG DisableQuantum : 1;                                         //0x88
            ULONG DeepFreeze : 1;                                             //0x88
            ULONG TimerVirtualization : 1;                                    //0x88
            ULONG CheckStackExtents : 1;                                      //0x88
            ULONG CacheIsolationEnabled : 1;                                  //0x88
            ULONG PpmPolicy : 4;                                              //0x88
            ULONG VaSpaceDeleted : 1;                                         //0x88
            ULONG MultiGroup : 1;                                             //0x88
            ULONG ForegroundProcess : 1;                                      //0x88
            ULONG ReservedFlags : 18;                                         //0x88
        };
        volatile LONG ProcessFlags;                                         //0x88
    };
    ULONG Spare0c;                                                          //0x8c
    CHAR BasePriority;                                                      //0x90
    CHAR QuantumReset;                                                      //0x91
    CHAR Visited;                                                           //0x92
    union _KEXECUTE_OPTIONS* Flags;                                          //0x93
    struct _KGROUP_MASK* ActiveGroupsMask;                                   //0x98
    ULONGLONG ActiveGroupPadding[2];                                        //0xa8
    struct _KI_IDEAL_PROCESSOR_ASSIGNMENT_BLOCK* IdealProcessorAssignmentBlock; //0xb8
    ULONGLONG Padding[8];                                                   //0xc0
    ULONG Spare0d;                                                          //0x100
    USHORT IdealGlobalNode;                                                 //0x104
    USHORT Spare1;                                                          //0x106
    union  _KSTACK_COUNT* StackCount;                                 //0x108
    struct _LIST_ENTRY ProcessListEntry;                                    //0x110
    ULONGLONG CycleTime;                                                    //0x120
    ULONGLONG ContextSwitches;                                              //0x128
    struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x130
    ULONGLONG KernelTime;                                                   //0x138
    ULONGLONG UserTime;                                                     //0x140
    ULONGLONG ReadyTime;                                                    //0x148
    ULONG FreezeCount;                                                      //0x150
    ULONG Spare4;                                                           //0x154
    ULONGLONG UserDirectoryTableBase;                                       //0x158
    UCHAR AddressPolicy;                                                    //0x160
    UCHAR Spare2[7];                                                        //0x161
    VOID* InstrumentationCallback;                                          //0x168
    union
    {
        ULONGLONG SecureHandle;                                             //0x170
        struct
        {
            ULONGLONG SecureProcess : 1;                                      //0x170
            ULONGLONG TrustedApp : 1;                                         //0x170
        } Flags;                                                            //0x170
    } SecureState;                                                          //0x170
    ULONGLONG KernelWaitTime;                                               //0x178
    ULONGLONG UserWaitTime;                                                 //0x180
    ULONGLONG LastRebalanceQpc;                                             //0x188
    VOID* PerProcessorCycleTimes;                                           //0x190
    ULONGLONG ExtendedFeatureDisableMask;                                   //0x198
    USHORT PrimaryGroup;                                                    //0x1a0
    USHORT Spare3[3];                                                       //0x1a2
    VOID* UserCetLogging;                                                   //0x1a8
    struct _LIST_ENTRY CpuPartitionList;                                    //0x1b0
    struct _KPROCESS_AVAILABLE_CPU_STATE* AvailableCpuState;                //0x1c0
};


//0x38 bytes (sizeof)
struct _OBJECT_HEADER
{
    LONGLONG PointerCount;                                                  //0x0
    union
    {
        LONGLONG HandleCount;                                               //0x8
        VOID* NextToFree;                                                   //0x8
    };
    struct _EX_PUSH_LOCK Lock;                                              //0x10
    UCHAR TypeIndex;                                                        //0x18
    union
    {
        UCHAR TraceFlags;                                                   //0x19
        struct
        {
            UCHAR DbgRefTrace : 1;                                            //0x19
            UCHAR DbgTracePermanent : 1;                                      //0x19
        };
    };
    UCHAR InfoMask;                                                         //0x1a
    union
    {
        UCHAR Flags;                                                        //0x1b
        struct
        {
            UCHAR NewObject : 1;                                              //0x1b
            UCHAR KernelObject : 1;                                           //0x1b
            UCHAR KernelOnlyAccess : 1;                                       //0x1b
            UCHAR ExclusiveObject : 1;                                        //0x1b
            UCHAR PermanentObject : 1;                                        //0x1b
            UCHAR DefaultSecurityQuota : 1;                                   //0x1b
            UCHAR SingleHandleEntry : 1;                                      //0x1b
            UCHAR DeletedInline : 1;                                          //0x1b
        };
    };
    ULONG Reserved;                                                         //0x1c
    union
    {
        struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;                //0x20
        VOID* QuotaBlockCharged;                                            //0x20
    };
    VOID* SecurityDescriptor;                                               //0x28
    struct _QUAD Body;                                                      //0x30
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



//0x788 bytes (sizeof)
struct _ETHREAD
{
    typedef struct _KTHREAD Tcb;                                                    //0x0
    union _LARGE_INTEGER CreateTime;                                        //0x4c0
    union
    {
        union _LARGE_INTEGER ExitTime;                                      //0x4c8
        struct _LIST_ENTRY KeyedWaitChain;                                  //0x4c8
    };
    union
    {
        struct _LIST_ENTRY PostBlockList;                                   //0x4d8
        struct
        {
            VOID* ForwardLinkShadow;                                        //0x4d8
            VOID* StartAddress;                                             //0x4e0
        };
    };
    union
    {
        struct _TERMINATION_PORT* TerminationPort;                          //0x4e8
        struct _ETHREAD* ReaperLink;                                        //0x4e8
        VOID* KeyedWaitValue;                                               //0x4e8
    };
    ULONGLONG ActiveTimerListLock;                                          //0x4f0
    struct _LIST_ENTRY ActiveTimerListHead;                                 //0x4f8
    struct _CLIENT_ID Cid;                                                  //0x508
    union
    {
        struct _KSEMAPHORE KeyedWaitSemaphore;                              //0x518
        struct _KSEMAPHORE AlpcWaitSemaphore;                               //0x518
    };
    union _PS_CLIENT_SECURITY_CONTEXT* ClientSecurity;                       //0x538
    struct _LIST_ENTRY IrpList;                                             //0x540
    ULONGLONG TopLevelIrp;                                                  //0x550
    struct _DEVICE_OBJECT* DeviceToVerify;                                  //0x558
    VOID* Win32StartAddress;                                                //0x560
    VOID* ChargeOnlySession;                                                //0x568
    VOID* LegacyPowerObject;                                                //0x570
    struct _LIST_ENTRY ThreadListEntry;                                     //0x578
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x588
    typedef struct _EX_PUSH_LOCK ThreadLock;                                        //0x590
    ULONG ReadClusterSize;                                                  //0x598
    volatile ULONG MmLockOrdering;                                          //0x59c
    union
    {
        ULONG CrossThreadFlags;                                             //0x5a0
        struct
        {
            ULONG Terminated : 1;                                             //0x5a0
            ULONG ThreadInserted : 1;                                         //0x5a0
            ULONG HideFromDebugger : 1;                                       //0x5a0
            ULONG ActiveImpersonationInfo : 1;                                //0x5a0
            ULONG HardErrorsAreDisabled : 1;                                  //0x5a0
            ULONG BreakOnTermination : 1;                                     //0x5a0
            ULONG SkipCreationMsg : 1;                                        //0x5a0
            ULONG SkipTerminationMsg : 1;                                     //0x5a0
            ULONG CopyTokenOnOpen : 1;                                        //0x5a0
            ULONG ThreadIoPriority : 3;                                       //0x5a0
            ULONG ThreadPagePriority : 3;                                     //0x5a0
            ULONG RundownFail : 1;                                            //0x5a0
            ULONG UmsForceQueueTermination : 1;                               //0x5a0
            ULONG IndirectCpuSets : 1;                                        //0x5a0
            ULONG DisableDynamicCodeOptOut : 1;                               //0x5a0
            ULONG ExplicitCaseSensitivity : 1;                                //0x5a0
            ULONG PicoNotifyExit : 1;                                         //0x5a0
            ULONG DbgWerUserReportActive : 1;                                 //0x5a0
            ULONG ForcedSelfTrimActive : 1;                                   //0x5a0
            ULONG SamplingCoverage : 1;                                       //0x5a0
            ULONG ImpersonationSchedulingGroup : 1;                           //0x5a0
            ULONG ReservedCrossThreadFlags : 7;                               //0x5a0
        };
    };
    union
    {
        ULONG SameThreadPassiveFlags;                                       //0x5a4
        struct
        {
            ULONG ActiveExWorker : 1;                                         //0x5a4
            ULONG MemoryMaker : 1;                                            //0x5a4
            ULONG StoreLockThread : 2;                                        //0x5a4
            ULONG ClonedThread : 1;                                           //0x5a4
            ULONG KeyedEventInUse : 1;                                        //0x5a4
            ULONG SelfTerminate : 1;                                          //0x5a4
            ULONG RespectIoPriority : 1;                                      //0x5a4
            ULONG ActivePageLists : 1;                                        //0x5a4
            ULONG SecureContext : 1;                                          //0x5a4
            ULONG ZeroPageThread : 1;                                         //0x5a4
            ULONG WorkloadClass : 1;                                          //0x5a4
            ULONG GenerateDumpOnBadHandleAccess : 1;                          //0x5a4
            ULONG BalanceSetManager : 1;                                      //0x5a4
            ULONG ReservedSameThreadPassiveFlags : 18;                        //0x5a4
        };
    };
    union
    {
        ULONG SameThreadApcFlags;                                           //0x5a8
        struct
        {
            UCHAR OwnsProcessAddressSpaceExclusive : 1;                       //0x5a8
            UCHAR OwnsProcessAddressSpaceShared : 1;                          //0x5a8
            UCHAR HardFaultBehavior : 1;                                      //0x5a8
            volatile UCHAR StartAddressInvalid : 1;                           //0x5a8
            UCHAR EtwCalloutActive : 1;                                       //0x5a8
            UCHAR SuppressSymbolLoad : 1;                                     //0x5a8
            UCHAR Prefetching : 1;                                            //0x5a8
            UCHAR OwnsVadExclusive : 1;                                       //0x5a8
            UCHAR SystemPagePriorityActive : 1;                               //0x5a9
            UCHAR SystemPagePriority : 3;                                     //0x5a9
            UCHAR AllowUserWritesToExecutableMemory : 1;                      //0x5a9
            UCHAR AllowKernelWritesToExecutableMemory : 1;                    //0x5a9
            UCHAR OwnsVadShared : 1;                                          //0x5a9
            UCHAR PasidMsrValid : 1;                                          //0x5a9
            UCHAR SlabReplenishInProgress : 1;                                //0x5aa
        };
    };
    UCHAR CacheManagerActive;                                               //0x5ac
    UCHAR DisablePageFaultClustering;                                       //0x5ad
    UCHAR ActiveFaultCount;                                                 //0x5ae
    UCHAR LockOrderState;                                                   //0x5af
    ULONG SharedPsModuleLockAcquires;                                       //0x5b0
    ULONG MmReserved;                                                       //0x5b4
    ULONGLONG AlpcMessageId;                                                //0x5b8
    union
    {
        VOID* AlpcMessage;                                                  //0x5c0
        ULONG AlpcReceiveAttributeSet;                                      //0x5c0
    };
    struct _LIST_ENTRY AlpcWaitListEntry;                                   //0x5c8
    LONG ExitStatus;                                                        //0x5d8
    ULONG CacheManagerCount;                                                //0x5dc
    ULONG IoBoostCount;                                                     //0x5e0
    ULONG IoQoSBoostCount;                                                  //0x5e4
    ULONG IoQoSThrottleCount;                                               //0x5e8
    ULONG KernelStackReference;                                             //0x5ec
    struct _LIST_ENTRY BoostList;                                           //0x5f0
    struct _LIST_ENTRY DeboostList;                                         //0x600
    ULONGLONG BoostListLock;                                                //0x610
    ULONGLONG IrpListLock;                                                  //0x618
    VOID* ReservedForSynchTracking;                                         //0x620
    struct _SINGLE_LIST_ENTRY CmCallbackListHead;                           //0x628
    struct _GUID* ActivityId;                                               //0x630
    struct _SINGLE_LIST_ENTRY SeLearningModeListHead;                       //0x638
    VOID* VerifierContext;                                                  //0x640
    VOID* AdjustedClientToken;                                              //0x648
    VOID* WorkOnBehalfThread;                                               //0x650
    struct _PS_PROPERTY_SET* PropertySet;                                    //0x658
    VOID* PicoContext;                                                      //0x670
    ULONGLONG UserFsBase;                                                   //0x678
    ULONGLONG UserGsBase;                                                   //0x680
    struct _THREAD_ENERGY_VALUES* EnergyValues;                             //0x688
    union
    {
        ULONGLONG SelectedCpuSets;                                          //0x690
        ULONGLONG* SelectedCpuSetsIndirect;                                 //0x690
    };
    struct _EJOB* Silo;                                                     //0x698
    struct _UNICODE_STRING* ThreadName;                                     //0x6a0
    struct _CONTEXT* SetContextState;                                       //0x6a8
    VOID* EtwSupport;                                                       //0x6b0
    struct _LIST_ENTRY OwnerEntryListHead;                                  //0x6b8
    ULONGLONG DisownedOwnerEntryListLock;                                   //0x6c8
    struct _LIST_ENTRY DisownedOwnerEntryListHead;                          //0x6d0
    VOID* SchedulerSharedDataObject;                                        //0x6e0
    VOID* CmThreadInfo;                                                     //0x6e8
    VOID* FlsData;                                                          //0x6f0
    ULONG LastExpectedRunTime;                                              //0x6f8
    ULONG LastSoftParkElectionRunTime;                                      //0x6fc
    ULONGLONG LastSoftParkElectionGeneration;                               //0x700
    struct _GROUP_AFFINITY LastSoftParkElectionGroupAffinity;               //0x708
    ULONGLONG UserIsolationDomain;                                          //0x718
    union
    {
        struct _KAPC UpdateTebApc;                                          //0x720
        struct
        {
            UCHAR UpdateTebApcFill1[3];                                     //0x720
            CHAR Win32kPriorityFloor;                                       //0x723
        };
        struct
        {
            UCHAR UpdateTebApcFill2[4];                                     //0x720
            UCHAR LastSoftParkElectionQos;                                  //0x724
            UCHAR LastSoftParkElectionWorkloadType;                         //0x725
            UCHAR LastSoftParkElectionRunningType;                          //0x726
            UCHAR MmSlabIdentity;                                           //0x727
        };
        struct
        {
            UCHAR UpdateTebApcFill3[64];                                    //0x720
            union _RTL_THREAD_RNG_STATE* RngState;                           //0x760
        };
        struct
        {
            UCHAR UpdateTebApcFill4[72];                                    //0x720
            VOID* UsedByRngState;                                           //0x768
        };
        struct
        {
            UCHAR UpdateTebApcFill5[83];                                    //0x720
            UCHAR UpdateTebSpareByte2;                                      //0x773
            ULONG UpdateTebSpareLong2;                                      //0x774
        };
    };
    ULONGLONG Win32kThreadLock;                                             //0x778
    VOID* ThreadIndex;                                                      //0x780
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


//0xa0 bytes (sizeof)
struct _ALPC_COMPLETION_LIST
{
    struct _LIST_ENTRY Entry;                                               //0x0
    struct _EPROCESS* OwnerProcess;                                         //0x10
    typedef struct _EX_PUSH_LOCK CompletionListLock;                                //0x18
    struct _MDL* Mdl;                                                       //0x20
    VOID* UserVa;                                                           //0x28
    VOID* UserLimit;                                                        //0x30
    VOID* DataUserVa;                                                       //0x38
    VOID* SystemVa;                                                         //0x40
    ULONGLONG TotalSize;                                                    //0x48
    struct _ALPC_COMPLETION_LIST_HEADER* Header;                            //0x50
    VOID* List;                                                             //0x58
    ULONGLONG ListSize;                                                     //0x60
    VOID* Bitmap;                                                           //0x68
    ULONGLONG BitmapSize;                                                   //0x70
    VOID* Data;                                                             //0x78
    ULONGLONG DataSize;                                                     //0x80
    ULONG BitmapLimit;                                                      //0x88
    ULONG BitmapNextHint;                                                   //0x8c
    ULONG ConcurrencyCount;                                                 //0x90
    ULONG AttributeFlags;                                                   //0x94
    ULONG AttributeSize;                                                    //0x98
};


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
    ULONGLONG PageFrameNumber : 40;                                           //0x0
    ULONGLONG SoftwareWsIndex : 11;                                           //0x0
    ULONGLONG NoExecute : 1;                                                  //0x0
};

//0x518 bytes (sizeof)
struct HAL_PRIVATE_DISPATCH
{
    ULONG Version;                                                          //0x0
    struct _BUS_HANDLER* ( *HalHandlerForBus )( enum _INTERFACE_TYPE arg1, ULONG arg2 ); //0x8
    struct _BUS_HANDLER* ( *HalHandlerForConfigSpace )( enum _BUS_DATA_TYPE arg1, ULONG arg2 ); //0x10
    VOID( *HalLocateHiberRanges )( VOID* arg1 );                               //0x18
    LONG( *HalRegisterBusHandler )( enum _INTERFACE_TYPE arg1, enum _BUS_DATA_TYPE arg2, ULONG arg3, enum _INTERFACE_TYPE arg4, ULONG arg5, ULONG arg6, LONG( *arg7 )( struct _BUS_HANDLER* arg1 ), struct _BUS_HANDLER** arg8 ); //0x20
    VOID( *HalSetWakeEnable )( UCHAR arg1 );                                   //0x28
    LONG( *HalSetWakeAlarm )( ULONGLONG arg1, ULONGLONG arg2 );                //0x30
    UCHAR( *HalPciTranslateBusAddress )( enum _INTERFACE_TYPE arg1, ULONG arg2, union _LARGE_INTEGER arg3, ULONG* arg4, union _LARGE_INTEGER* arg5 ); //0x38
    LONG( *HalPciAssignSlotResources )( struct _UNICODE_STRING* arg1, struct _UNICODE_STRING* arg2, struct _DRIVER_OBJECT* arg3, struct _DEVICE_OBJECT* arg4, enum _INTERFACE_TYPE arg5, ULONG arg6, ULONG arg7, struct _CM_RESOURCE_LIST** arg8 ); //0x40
    VOID( *HalHaltSystem )( );                                                //0x48
    UCHAR( *HalFindBusAddressTranslation )( union _LARGE_INTEGER arg1, ULONG* arg2, union _LARGE_INTEGER* arg3, ULONGLONG* arg4, UCHAR arg5 ); //0x50
    UCHAR( *HalResetDisplay )( );                                             //0x58
    LONG( *HalAllocateMapRegisters )( struct _ADAPTER_OBJECT* arg1, ULONG arg2, ULONG arg3, struct _MAP_REGISTER_ENTRY* arg4 ); //0x60
    LONG( *KdSetupPciDeviceForDebugging )( VOID* arg1, struct _DEBUG_DEVICE_DESCRIPTOR* arg2 ); //0x68
    LONG( *KdReleasePciDeviceForDebugging )( struct _DEBUG_DEVICE_DESCRIPTOR* arg1 ); //0x70
    VOID* ( *KdGetAcpiTablePhase0 )( struct _LOADER_PARAMETER_BLOCK* arg1, ULONG arg2 ); //0x78
    VOID( *KdCheckPowerButton )( );                                           //0x80
    UCHAR( *HalVectorToIDTEntry )( ULONG arg1 );                               //0x88
    VOID* ( *KdMapPhysicalMemory64 )( union _LARGE_INTEGER arg1, ULONG arg2, UCHAR arg3 ); //0x90
    VOID( *KdUnmapVirtualAddress )( VOID* arg1, ULONG arg2, UCHAR arg3 );      //0x98
    ULONG( *KdGetPciDataByOffset )( ULONG arg1, ULONG arg2, VOID* arg3, ULONG arg4, ULONG arg5 ); //0xa0
    ULONG( *KdSetPciDataByOffset )( ULONG arg1, ULONG arg2, VOID* arg3, ULONG arg4, ULONG arg5 ); //0xa8
    ULONG( *HalGetInterruptVectorOverride )( enum _INTERFACE_TYPE arg1, ULONG arg2, ULONG arg3, ULONG arg4, UCHAR* arg5, ULONGLONG* arg6 ); //0xb0
    LONG( *HalGetVectorInputOverride )( ULONG arg1, struct _GROUP_AFFINITY* arg2, ULONG* arg3, enum _KINTERRUPT_POLARITY* arg4, struct _INTERRUPT_REMAPPING_INFO* arg5 ); //0xb8
    LONG( *HalLoadMicrocode )( VOID* arg1 );                                   //0xc0
    LONG( *HalUnloadMicrocode )( );                                           //0xc8
    LONG( *HalPostMicrocodeUpdate )( );                                       //0xd0
    LONG( *HalAllocateMessageTargetOverride )( struct _DEVICE_OBJECT* arg1, struct _GROUP_AFFINITY* arg2, ULONG arg3, enum _KINTERRUPT_MODE arg4, UCHAR arg5, ULONG* arg6, UCHAR* arg7, ULONG* arg8 ); //0xd8
    VOID( *HalFreeMessageTargetOverride )( struct _DEVICE_OBJECT* arg1, ULONG arg2, struct _GROUP_AFFINITY* arg3 ); //0xe0
    LONG( *HalDpReplaceBegin )( struct _HAL_DP_REPLACE_PARAMETERS* arg1, VOID** arg2 ); //0xe8
    VOID( *HalDpReplaceTarget )( VOID* arg1 );                                 //0xf0
    LONG( *HalDpReplaceControl )( ULONG arg1, VOID* arg2 );                    //0xf8
    VOID( *HalDpReplaceEnd )( VOID* arg1 );                                    //0x100
    VOID( *HalPrepareForBugcheck )( ULONG arg1 );                              //0x108
    UCHAR( *HalQueryWakeTime )( ULONGLONG* arg1, ULONGLONG* arg2 );            //0x110
    VOID( *HalReportIdleStateUsage )( UCHAR arg1, struct _KAFFINITY_EX* arg2 ); //0x118
    VOID( *HalTscSynchronization )( UCHAR arg1, ULONG* arg2 );                 //0x120
    LONG( *HalWheaInitProcessorGenericSection )( struct _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR* arg1, struct _WHEA_PROCESSOR_GENERIC_ERROR_SECTION* arg2 ); //0x128
    VOID( *HalStopLegacyUsbInterrupts )( enum _SYSTEM_POWER_STATE arg1 );      //0x130
    LONG( *HalReadWheaPhysicalMemory )( union _LARGE_INTEGER arg1, ULONG arg2, VOID* arg3 ); //0x138
    LONG( *HalWriteWheaPhysicalMemory )( union _LARGE_INTEGER arg1, ULONG arg2, VOID* arg3 ); //0x140
    LONG( *HalDpMaskLevelTriggeredInterrupts )( );                            //0x148
    LONG( *HalDpUnmaskLevelTriggeredInterrupts )( );                          //0x150
    LONG( *HalDpGetInterruptReplayState )( VOID* arg1, VOID** arg2 );          //0x158
    LONG( *HalDpReplayInterrupts )( VOID* arg1 );                              //0x160
    UCHAR( *HalQueryIoPortAccessSupported )( );                               //0x168
    LONG( *KdSetupIntegratedDeviceForDebugging )( VOID* arg1, struct _DEBUG_DEVICE_DESCRIPTOR* arg2 ); //0x170
    LONG( *KdReleaseIntegratedDeviceForDebugging )( struct _DEBUG_DEVICE_DESCRIPTOR* arg1 ); //0x178
    VOID( *HalGetEnlightenmentInformation )( struct _HAL_INTEL_ENLIGHTENMENT_INFORMATION* arg1 ); //0x180
    VOID* ( *HalAllocateEarlyPages )( struct _LOADER_PARAMETER_BLOCK* arg1, ULONG arg2, ULONGLONG* arg3, ULONG arg4 ); //0x188
    VOID* ( *HalMapEarlyPages )( ULONGLONG arg1, ULONG arg2, ULONG arg3 );      //0x190
    VOID* Dummy1;                                                           //0x198
    VOID* Dummy2;                                                           //0x1a0
    VOID( *HalNotifyProcessorFreeze )( UCHAR arg1, UCHAR arg2 );               //0x1a8
    LONG( *HalPrepareProcessorForIdle )( ULONG arg1 );                         //0x1b0
    VOID( *HalRegisterLogRoutine )( struct _HAL_LOG_REGISTER_CONTEXT* arg1 );  //0x1b8
    VOID( *HalResumeProcessorFromIdle )( );                                   //0x1c0
    VOID* Dummy;                                                            //0x1c8
    ULONG( *HalVectorToIDTEntryEx )( ULONG arg1 );                             //0x1d0
    LONG( *HalSecondaryInterruptQueryPrimaryInformation )( struct _INTERRUPT_VECTOR_DATA* arg1, ULONG* arg2 ); //0x1d8
    LONG( *HalMaskInterrupt )( ULONG arg1, ULONG arg2 );                       //0x1e0
    LONG( *HalUnmaskInterrupt )( ULONG arg1, ULONG arg2 );                     //0x1e8
    UCHAR( *HalIsInterruptTypeSecondary )( ULONG arg1, ULONG arg2 );           //0x1f0
    LONG( *HalAllocateGsivForSecondaryInterrupt )( CHAR* arg1, USHORT arg2, ULONG* arg3 ); //0x1f8
    LONG( *HalAddInterruptRemapping )( ULONG arg1, ULONG arg2, struct _PCI_BUSMASTER_DESCRIPTOR* arg3, UCHAR arg4, struct _INTERRUPT_VECTOR_DATA* arg5, ULONG arg6 ); //0x200
    VOID( *HalRemoveInterruptRemapping )( ULONG arg1, ULONG arg2, struct _PCI_BUSMASTER_DESCRIPTOR* arg3, UCHAR arg4, struct _INTERRUPT_VECTOR_DATA* arg5, ULONG arg6 ); //0x208
    VOID( *HalSaveAndDisableHvEnlightenment )( UCHAR arg1 );                   //0x210
    VOID( *HalRestoreHvEnlightenment )( );                                    //0x218
    VOID( *HalFlushIoBuffersExternalCache )( struct _MDL* arg1, UCHAR arg2 );  //0x220
    VOID( *HalFlushExternalCache )( UCHAR arg1 );                              //0x228
    LONG( *HalPciEarlyRestore )( enum _SYSTEM_POWER_STATE arg1 );              //0x230
    LONG( *HalGetProcessorId )( ULONG arg1, ULONG* arg2, ULONG* arg3 );        //0x238
    LONG( *HalAllocatePmcCounterSet )( ULONG arg1, enum _KPROFILE_SOURCE* arg2, ULONG arg3, struct _HAL_PMC_COUNTERS** arg4 ); //0x240
    VOID( *HalCollectPmcCounters )( struct _HAL_PMC_COUNTERS* arg1, ULONGLONG* arg2 ); //0x248
    VOID( *HalFreePmcCounterSet )( struct _HAL_PMC_COUNTERS* arg1 );           //0x250
    LONG( *HalProcessorHalt )( ULONG arg1, VOID* arg2, LONG( *arg3 )( VOID* arg1 ) ); //0x258
    ULONGLONG( *HalTimerQueryCycleCounter )( ULONGLONG* arg1 );                //0x260
    VOID* Dummy3;                                                           //0x268
    VOID( *HalPciMarkHiberPhase )( );                                         //0x270
    LONG( *HalQueryProcessorRestartEntryPoint )( union _LARGE_INTEGER* arg1 ); //0x278
    LONG( *HalRequestInterrupt )( ULONG arg1 );                                //0x280
    LONG( *HalEnumerateUnmaskedInterrupts )( UCHAR( *arg1 )( VOID* arg1, struct _HAL_UNMASKED_INTERRUPT_INFORMATION* arg2 ), VOID* arg2, struct _HAL_UNMASKED_INTERRUPT_INFORMATION* arg3 ); //0x288
    VOID( *HalFlushAndInvalidatePageExternalCache )( union _LARGE_INTEGER arg1 ); //0x290
    LONG( *KdEnumerateDebuggingDevices )( VOID* arg1, struct _DEBUG_DEVICE_DESCRIPTOR* arg2, enum KD_CALLBACK_ACTION( *arg3 )( struct _DEBUG_DEVICE_DESCRIPTOR* arg1 ) ); //0x298
    VOID( *HalFlushIoRectangleExternalCache )( struct _MDL* arg1, ULONG arg2, ULONG arg3, ULONG arg4, ULONG arg5, UCHAR arg6 ); //0x2a0
    VOID( *HalPowerEarlyRestore )( ULONG arg1 );                               //0x2a8
    LONG( *HalQueryCapsuleCapabilities )( VOID* arg1, ULONG arg2, ULONGLONG* arg3, ULONG* arg4 ); //0x2b0
    LONG( *HalUpdateCapsule )( VOID* arg1, ULONG arg2, union _LARGE_INTEGER arg3 ); //0x2b8
    UCHAR( *HalPciMultiStageResumeCapable )( );                               //0x2c0
    VOID( *HalDmaFreeCrashDumpRegisters )( ULONG arg1 );                       //0x2c8
    UCHAR( *HalAcpiAoacCapable )( );                                          //0x2d0
    LONG( *HalInterruptSetDestination )( struct _INTERRUPT_VECTOR_DATA* arg1, struct _GROUP_AFFINITY* arg2, ULONG* arg3 ); //0x2d8
    VOID( *HalGetClockConfiguration )( struct _HAL_CLOCK_TIMER_CONFIGURATION* arg1 ); //0x2e0
    VOID( *HalClockTimerActivate )( UCHAR arg1 );                              //0x2e8
    VOID( *HalClockTimerInitialize )( );                                      //0x2f0
    VOID( *HalClockTimerStop )( );                                            //0x2f8
    LONG( *HalClockTimerArm )( enum _HAL_CLOCK_TIMER_MODE arg1, ULONGLONG arg2, ULONGLONG* arg3 ); //0x300
    UCHAR( *HalTimerOnlyClockInterruptPending )( );                           //0x308
    VOID* ( *HalAcpiGetMultiNode )( );                                         //0x310
    VOID( *HalIommuRegisterDispatchTable )( struct _HAL_IOMMU_DISPATCH* arg1 ); //0x320
    VOID( *HalTimerWatchdogStart )( );                                        //0x328
    VOID( *HalTimerWatchdogResetCountdown )( );                               //0x330
    VOID( *HalTimerWatchdogStop )( );                                         //0x338
    UCHAR( *HalTimerWatchdogGeneratedLastReset )( );                          //0x340
    LONG( *HalTimerWatchdogTriggerSystemReset )( UCHAR arg1 );                 //0x348
    LONG( *HalInterruptVectorDataToGsiv )( struct _INTERRUPT_VECTOR_DATA* arg1, ULONG* arg2 ); //0x350
    LONG( *HalInterruptGetHighestPriorityInterrupt )( ULONG* arg1, UCHAR* arg2 ); //0x358
    LONG( *HalProcessorOn )( ULONG arg1 );                                     //0x360
    LONG( *HalProcessorOff )( );                                              //0x368
    LONG( *HalProcessorFreeze )( );                                           //0x370
    LONG( *HalDmaLinkDeviceObjectByToken )( ULONGLONG arg1, struct _DEVICE_OBJECT* arg2 ); //0x378
    LONG( *HalDmaCheckAdapterToken )( ULONGLONG arg1 );                        //0x380
    VOID* Dummy4;                                                           //0x388
    LONG( *HalTimerConvertPerformanceCounterToAuxiliaryCounter )( ULONGLONG arg1, ULONGLONG* arg2, ULONGLONG* arg3 ); //0x390
    LONG( *HalTimerConvertAuxiliaryCounterToPerformanceCounter )( ULONGLONG arg1, ULONGLONG* arg2, ULONGLONG* arg3 ); //0x398
    LONG( *HalTimerQueryAuxiliaryCounterFrequency )( ULONGLONG* arg1 );        //0x3a0
    LONG( *HalConnectThermalInterrupt )( UCHAR( *arg1 )( struct _KINTERRUPT* arg1, VOID* arg2 ) ); //0x3a8
    UCHAR( *HalIsEFIRuntimeActive )( );                                       //0x3b0
    ULONG( *HalTimerQueryAndResetRtcErrors )( UCHAR arg1, UCHAR arg2 );        //0x3b8
    VOID( *HalAcpiLateRestore )( );                                           //0x3c0
    LONG( *KdWatchdogDelayExpiration )( ULONGLONG* arg1 );                     //0x3c8
    LONG( *HalGetProcessorStats )( enum _HAL_PROCESSOR_STAT_TYPE arg1, ULONG arg2, ULONG arg3, ULONGLONG* arg4 ); //0x3d0
    ULONGLONG( *HalTimerWatchdogQueryDueTime )( UCHAR arg1 );                  //0x3d8
    LONG( *HalConnectSyntheticInterrupt )( UCHAR( *arg1 )( struct _KINTERRUPT* arg1, VOID* arg2 ) ); //0x3e0
    VOID( *HalPreprocessNmi )( ULONG arg1 );                                   //0x3e8
    LONG( *HalEnumerateEnvironmentVariablesWithFilter )( ULONG arg1, UCHAR( *arg2 )( struct _GUID* arg1, WCHAR* arg2 ), VOID* arg3, ULONG* arg4 ); //0x3f0
    LONG( *HalCaptureLastBranchRecordStack )( ULONG arg1, struct _HAL_LBR_ENTRY* arg2, ULONG* arg3 ); //0x3f8
    UCHAR( *HalClearLastBranchRecordStack )( );                               //0x400
    LONG( *HalConfigureLastBranchRecord )( ULONG arg1, ULONG arg2 );           //0x408
    UCHAR( *HalGetLastBranchInformation )( ULONG* arg1, ULONG* arg2 );         //0x410
    VOID( *HalResumeLastBranchRecord )( UCHAR arg1 );                          //0x418
    LONG( *HalStartLastBranchRecord )( ULONG arg1, ULONG* arg2 );              //0x420
    LONG( *HalStopLastBranchRecord )( ULONG arg1 );                            //0x428
    LONG( *HalIommuBlockDevice )( struct _IOMMU_DMA_DEVICE* arg1 );            //0x430
    LONG( *HalIommuUnblockDevice )( struct _EXT_IOMMU_DEVICE_ID* arg1, struct _DEVICE_OBJECT* arg2, struct _IOMMU_DMA_DEVICE** arg3 ); //0x438
    LONG( *HalGetIommuInterface )( ULONG arg1, struct _DMA_IOMMU_INTERFACE* arg2 ); //0x440
    LONG( *HalRequestGenericErrorRecovery )( VOID* arg1, ULONG* arg2 );        //0x448
    LONG( *HalTimerQueryHostPerformanceCounter )( ULONGLONG* arg1 );           //0x450
    LONG( *HalTopologyQueryProcessorRelationships )( ULONG arg1, ULONG arg2, UCHAR* arg3, UCHAR* arg4, UCHAR* arg5, ULONG* arg6, ULONG* arg7 ); //0x458
    VOID( *HalInitPlatformDebugTriggers )( );                                 //0x460
    VOID( *HalRunPlatformDebugTriggers )( UCHAR arg1 );                        //0x468
    VOID* ( *HalTimerGetReferencePage )( );                                    //0x470
    LONG( *HalGetHiddenProcessorPowerInterface )( struct _HIDDEN_PROCESSOR_POWER_INTERFACE* arg1 ); //0x478
    ULONG( *HalGetHiddenProcessorPackageId )( ULONG arg1 );                    //0x480
    ULONG( *HalGetHiddenPackageProcessorCount )( ULONG arg1 );                 //0x488
    LONG( *HalGetHiddenProcessorApicIdByIndex )( ULONG arg1, ULONG* arg2 );    //0x490
    LONG( *HalRegisterHiddenProcessorIdleState )( ULONG arg1, ULONGLONG arg2 ); //0x498
    VOID( *HalIommuReportIommuFault )( ULONGLONG arg1, struct _FAULT_INFORMATION* arg2 ); //0x4a0
    UCHAR( *HalIommuDmaRemappingCapable )( struct _EXT_IOMMU_DEVICE_ID* arg1, ULONG* arg2 ); //0x4a8
    LONG( *HalAllocatePmcCounterSetEx )( ULONG arg1, enum _KPROFILE_SOURCE* arg2, ULONG arg3, ULONG* arg4, struct _HAL_PMC_COUNTERS** arg5, ULONG* arg6 ); //0x4b0
    LONG( *HalStartProfileInterruptEx )( enum _KPROFILE_SOURCE arg1, ULONG* arg2, ULONG* arg3, enum _HAL_PMU_COUNTER_TYPE* arg4, struct _HAL_PMC_COUNTERS** arg5 ); //0x4b8
    LONG( *HalGetIommuInterfaceEx )( ULONG arg1, ULONGLONG arg2, struct _DMA_IOMMU_INTERFACE_EX* arg3 ); //0x4c0
    VOID( *HalNotifyIommuDomainPolicyChange )( struct _DEVICE_OBJECT* arg1 );  //0x4c8
    UCHAR( *HalPciGetDeviceLocationFromPhysicalAddress )( ULONGLONG arg1, USHORT* arg2, UCHAR* arg3, UCHAR* arg4, UCHAR* arg5 ); //0x4d0
    VOID( *HalInvokeSmc )( ULONGLONG arg1, ULONGLONG arg2, ULONGLONG arg3, ULONGLONG arg4, ULONGLONG arg5, ULONGLONG arg6, ULONGLONG arg7, ULONGLONG* arg8, ULONGLONG* arg9, ULONGLONG* arg10, ULONGLONG* arg11 ); //0x4d8
    VOID( *HalInvokeHvc )( ULONGLONG arg1, ULONGLONG arg2, ULONGLONG arg3, ULONGLONG arg4, ULONGLONG arg5, ULONGLONG arg6, ULONGLONG arg7, ULONGLONG* arg8, ULONGLONG* arg9, ULONGLONG* arg10, ULONGLONG* arg11 ); //0x4e0
    union _LARGE_INTEGER( *HalGetSoftRebootDatabase )( );                     //0x4e8
    LONG( *HalRequestPmuAccess )( );                                          //0x4f0
    LONG( *HalTopologyQueryProcessorCacheInformation )( ULONG arg1, UCHAR arg2, enum _PROCESSOR_CACHE_TYPE arg3, enum _PROCESSOR_CACHE_TYPE* arg4, VOID** arg5 ); //0x4f8
    VOID( *HalReleasePmuAccessRequest )( );                                   //0x500
    ULONG( *HalTimerQueryRtcErrors )( );                                      //0x508
    LONG( *HalExternalPciConfigSpaceAccess )( UCHAR arg1, VOID* arg2, USHORT arg3, UCHAR arg4, ULONG arg5, ULONG arg6, ULONG arg7, ULONG arg8, UCHAR* arg9, ULONG* arg10 ); //0x510
};

//0x58 bytes (sizeof)
typedef struct _PEB_LDR_DATA
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


typedef struct _PEB64
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
    CHAR PlaceholderCompatibilityModeReserved[7];                        //0x7b1
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