#include "includes.h"
#include "modules.h"
#include "nt_structs.h"
#include "hooks.h"
#include "log.h"
#include "helpers.h"

extern void VmExitHandler();

void VMM::SetupMsrBitmap( uint8_t* bitmap ) {
   
}


bool VMM::SetupVMCS( void* vmcsRegion, void* guestEntryPoint, uint64_t hostStackPointer ) {
    return 1;
}



bool VMM::EnableVMX() {
    // 1. Read IA32_FEATURE_CONTROL MSR (0x3A)
    uint64_t featureControl = __readmsr( 0x3A );
    DbgPrint( "[VMX] IA32_FEATURE_CONTROL: 0x%llx\n", featureControl );

    if ( !( featureControl & 0x1 ) ) {
        DbgPrint( "[VMX] Lock bit not set in IA32_FEATURE_CONTROL, attempting to set it\n" );
        uint64_t newFeatureControl = featureControl | 0x5; // Lock + enable VMX outside SMX
        __writemsr( 0x3A, newFeatureControl );
        featureControl = __readmsr( 0x3A );
        DbgPrint( "[VMX] IA32_FEATURE_CONTROL after write: 0x%llx\n", featureControl );

        if ( !( featureControl & 0x1 ) || !( featureControl & 0x4 ) ) {
            DbgPrint( "[VMX] Failed to set required bits in IA32_FEATURE_CONTROL\n" );
            return false;
        }
    }

    // 2. Enable CR4.VMXE
    uint64_t cr4 = __readcr4();
    DbgPrint( "[VMX] CR4 before setting VMXE: 0x%llx\n", cr4 );
    cr4 |= ( 1ull << 13 );  // Set VMXE (bit 13)
    __writecr4( cr4 );
    cr4 = __readcr4();
    DbgPrint( "[VMX] CR4 after setting VMXE: 0x%llx\n", cr4 );

    // 3. Allocate VMXON region
    void* vmxonRegion = VMM::AllocateVMXONRegion();
    if ( !vmxonRegion ) {
        DbgPrint( "[VMX] VMXON region allocation failed\n" );
        return false;
    }
    DbgPrint( "[VMX] VMXON region allocated at virtual address: %p\n", vmxonRegion );

    // 4. Translate to physical
    PHYSICAL_ADDRESS physVmxon = MmGetPhysicalAddress( vmxonRegion );
    DbgPrint( "[VMX] VMXON physical address: 0x%llx\n", physVmxon.QuadPart );

    if ( ( physVmxon.QuadPart & 0xFFF ) != 0 ) {
        DbgPrint( "[VMX] VMXON physical address is not page-aligned: 0x%llx\n", physVmxon.QuadPart );
        return false;
    }

    // 5. Execute VMXON
    int status = __vmx_on( ( unsigned __int64* )&physVmxon.QuadPart );
    if ( status != 0 ) {
        DbgPrint( "[VMX] __vmx_on failed with status 0x%x\n", status );
        return false;
    }
    DbgPrint( "[VMX] VMXON succeeded\n" );

    // 6. Allocate VMCS region
    void* vmcsRegion = VMM::AllocateVMXONRegion();  // Or use a separate AllocateVMCSRegion()
    if ( !vmcsRegion ) {
        DbgPrint( "[VMX] VMCS region allocation failed\n" );
        return false;
    }
    DbgPrint( "[VMX] VMCS region allocated at virtual address: %p\n", vmcsRegion );

    // 7. Translate to physical
    PHYSICAL_ADDRESS physVmcs = MmGetPhysicalAddress( vmcsRegion );
    DbgPrint( "[VMX] VMCS physical address: 0x%llx\n", physVmcs.QuadPart );

    if ( ( physVmcs.QuadPart & 0xFFF ) != 0 ) {
        DbgPrint( "[VMX] VMCS physical address is not page-aligned: 0x%llx\n", physVmcs.QuadPart );
        return false;
    }

    // 8. Load VMCS
    status = __vmx_vmptrld( ( unsigned __int64* )&physVmcs.QuadPart );
    if ( status != 0 ) {
        DbgPrint( "[VMX] __vmx_vmptrld failed with status 0x%x\n", status );
        return false;
    }
    DbgPrint( "[VMX] VMCS pointer loaded successfully\n" );

    return true;
}



void* VMM::AllocateVMXONRegion() {
    PHYSICAL_ADDRESS highestAddr;
    highestAddr.QuadPart = 0xFFFFFFFFFFFFFFFFULL;  // No upper limit, allocate anywhere

    void* region = MmAllocateContiguousMemory( PAGE_SIZE, highestAddr );
    if ( !region ) {
        DbgPrint( "Allocation failed\n" );
        return nullptr;
    }

    RtlZeroMemory( region, PAGE_SIZE );

    uint64_t vmxBasic = __readmsr( 0x480 );
    uint32_t revId = ( uint32_t )( vmxBasic & 0x7FFFFFFF );
    *( uint32_t* )region = revId;

    return region;
}

void* VMM::AllocateVMCS() {
    return nullptr;
}

bool VMM::LoadVMCS( void* vmcsRegion ) {
    // Get physical address of VMCS region
    PHYSICAL_ADDRESS phys = MmGetPhysicalAddress( vmcsRegion );
    uint64_t physAddr = phys.QuadPart;

    // Check page alignment
    if ( ( physAddr & 0xFFF ) != 0 ) {
        DbgPrint( "VMCS physical address is not page-aligned: 0x%llx\n", physAddr );
        return false;
    }

    // Ensure VMX revision ID is set before loading
    uint64_t vmxBasic = __readmsr( 0x480 );
    uint32_t revId = ( uint32_t )( vmxBasic & 0x7FFFFFFF );
    *( uint32_t* )vmcsRegion = revId;

    // VMPTRLD expects a pointer to the physical address variable
    int status = __vmx_vmptrld( &physAddr );
    if ( status != 0 ) {
        DbgPrint( "VMPTRLD failed with status 0x%x\n", status );
        return false;
    }
    return true;
}

bool VMM::LaunchVMXON( void* vmxonRegion ) {
    return true;
}




