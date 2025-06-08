#include "includes.h"
#include <bcrypt.h> // For BCryptGenRandom
#include <wdmsec.h> // For IoCreateDeviceSecure and SDDL constants

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5, // Used to get list of processes
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmRangeInformation = 20,
    SystemQueryAbstractCounters = 21,
    SystemQueryOverallPerformanceCounterInformation = 22,
    SystemKernelDebuggerInformation = 23,
    SystemCrashDumpInformation = 24,
    SystemExceptionInformation = 25,
    SystemCrashDumpStateInformation = 26,
    SystemKernelDebuggerFlags = 27,
    SystemContextSwitchInformation = 28,
    SystemRegistryQuotaInformation = 29,
    SystemExtendServiceTableInformation = 30,
    SystemPrioritySeparation = 31,
    SystemPlugPlayBusInformation = 32,
    SystemDockInformation = 33,
    SystemPowerInformation = 34,
    SystemProcessorSpeedInformation = 35,
    SystemCurrentTimeZoneInformation = 36,
    SystemLookasideInformation = 37
    // ... there are many more
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // Since Vista
    ULONG HardFaultCount; // Since Vista
    ULONG NumberOfThreadsHighWatermark; // Since Vista
    ULONGLONG CycleTime; // Since Windows Server 2003
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // Since Vista (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1]; // Variable number of threads
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

extern "C" NTSTATUS ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

// Helper Macro for Delay
#define RELATIVE_MILLISECONDS(ms) (-10000LL * (ms))

// Global variables for shared communication and polling mechanism
PEPROCESS   g_target_process = NULL;
PVOID       g_um_shared_comm_block_ptr = NULL; // User-mode VA of the SharedCommBlock
KSPIN_LOCK  g_comm_lock; // Spinlock to protect access to shared comm block and related globals
BOOLEAN     g_km_thread_should_run = FALSE; // Flag to control the polling / setup thread
PDEVICE_OBJECT g_device_object = NULL;

// Globals for Discovery and Attachment Thread
HANDLE      g_discovery_thread_handle = NULL;
BOOLEAN     g_discovery_thread_should_run = FALSE;

// --- START: Globals and Definitions for UM->KM Handshake ---
PDEVICE_OBJECT g_pHandshakeDeviceObject = NULL;
UNICODE_STRING g_handshake_device_name_us;
UNICODE_STRING g_handshake_symlink_name_us;
WCHAR g_handshake_device_name_buffer[128] = L"\\Device\\CoreSysCom_{E7A1B02C-0D9F-45C1-9D8E-F6B5C4A3210F}";
WCHAR g_handshake_symlink_name_buffer[128] = L"\\DosDevices\\CoreSysComLink_{E7A1B02C-0D9F-45C1-9D8E-F6B5C4A3210F}";

PVOID volatile g_obfuscated_ptr1_um_addr_via_handshake = NULL;
KEVENT g_handshake_completed_event;

// --- START: Globals for Polling Work Item ---
PWORK_QUEUE_ITEM g_pPollingWorkItem = NULL;
ULONG g_prng_seed = 0;
volatile LONG g_consecutive_idle_polls = 0;
const LONG MAX_IDLE_POLLS_BEFORE_INCREASE = 100;
const ULONG BASE_POLLING_DELAY_MS = 5;
const ULONG MAX_POLLING_DELAY_MS = 100;
const ULONG POLLING_JITTER_MS = 2;
// --- END: Globals for Polling Work Item ---

#define IOCTL_STEALTH_HANDSHAKE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define BEACON_PATTERN_SIZE_KM 16

typedef struct _STEALTH_HANDSHAKE_DATA {
    PVOID ObfuscatedPtrStruct1HeadUmAddress;
    UINT64 VerificationToken;
    UINT8 BeaconPattern[BEACON_PATTERN_SIZE_KM];
} STEALTH_HANDSHAKE_DATA, *PSTEALTH_HANDSHAKE_DATA;

UINT8 g_received_beacon_pattern_km[BEACON_PATTERN_SIZE_KM];
UINT64 g_received_um_verification_token = 0;
// const UINT64 SOME_PREDEFINED_CONSTANT_FOR_TOKEN_KM = 0xCAFEFEEDDEAFBEEFULL; // Removed, shared secret will be g_km_dynamic_obfuscation_xor_key

VOID DiscoveryAndAttachmentThread(PVOID StartContext); // Forward declaration

static VOID PrepareForUnload() {
    debug_print("[+] PrepareForUnload: Preparing driver for unload sequence.\n");
    KIRQL oldIrql;

    // Stop Discovery Thread (though it should have exited after handshake)
    if (g_discovery_thread_handle) {
        g_discovery_thread_should_run = FALSE; // Signal
        // Attempt to get a reference to the thread object to wait for it.
        PETHREAD discovery_thread_object_ref = NULL;
        NTSTATUS status_ref_discovery = ObReferenceObjectByHandle(
            g_discovery_thread_handle,
            THREAD_ALL_ACCESS, // Or THREAD_QUERY_INFORMATION | SYNCHRONIZE
            *PsThreadType,
            KernelMode,
            (PVOID*)&discovery_thread_object_ref,
            NULL
        );

        if (NT_SUCCESS(status_ref_discovery) && discovery_thread_object_ref) {
            debug_print("[+] PrepareForUnload: Waiting for DiscoveryAndAttachmentThread to terminate.\n");
            KeWaitForSingleObject(discovery_thread_object_ref, Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(discovery_thread_object_ref);
            debug_print("[+] PrepareForUnload: DiscoveryAndAttachmentThread terminated.\n");
        } else {
            debug_print("[-] PrepareForUnload: Failed to reference/wait for DiscoveryAndAttachmentThread. Status: 0x%X. It might have already exited.\n", status_ref_discovery);
        }
        // We close the handle in DriverUnload, not here, to avoid issues if DriverUnload is called separately.
        // ZwClose(g_discovery_thread_handle);
        // g_discovery_thread_handle = NULL;
    }

    // Stop Polling Work Item
    KeAcquireSpinLock(&g_comm_lock, &oldIrql);
    g_km_thread_should_run = FALSE;
    PWORK_QUEUE_ITEM localWorkItem = g_pPollingWorkItem; // Copy the pointer
    g_pPollingWorkItem = NULL; // Prevent further queuing from KmPollingWorkItemCallback itself
    KeReleaseSpinLock(&g_comm_lock, oldIrql);

    if (localWorkItem) {
        // Attempt to remove the work item from the queue if it's pending.
        // This is not straightforward as ExQueueWorkItem doesn't return something that can be "cancelled" easily.
        // The g_km_thread_should_run = FALSE check within the callback is the primary stop mechanism.
        // We can free the allocation here as it won't be requeued.
        debug_print("[+] PrepareForUnload: Polling work item signaled to stop and memory freed.\n");
        ExFreePoolWithTag(localWorkItem, 'WkIt'); // Ensure 'WkIt' matches allocation tag
    }

    // Clear shared UM pointers and dereference target process
    PEPROCESS processToDereference = NULL;
    KeAcquireSpinLock(&g_comm_lock, &oldIrql);
    if (g_target_process) {
        processToDereference = g_target_process;
        g_target_process = NULL;
    }
    g_um_shared_comm_block_ptr = NULL;
    // Also clear handshake-related globals that might hold stale UM data
    g_obfuscated_ptr1_um_addr_via_handshake = NULL;
    RtlZeroMemory(g_received_beacon_pattern_km, sizeof(g_received_beacon_pattern_km));
    g_received_um_verification_token = 0;

    KeReleaseSpinLock(&g_comm_lock, oldIrql);

    if (processToDereference) {
        ObDereferenceObject(processToDereference);
        debug_print("[+] PrepareForUnload: Target process dereferenced.\n");
    }

    debug_print("[+] PrepareForUnload: Driver activities quiesced.\n");
    // Note: Device object and symbolic link are cleaned up in DriverUnload.
}

NTSTATUS HandshakeDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp); // Forward declaration


ULONG       g_max_comm_slots = 4;

enum class CommCommand : uint32_t {
    REQUEST_NOP = 0,
    REQUEST_READ_MEMORY,
    REQUEST_WRITE_MEMORY,
    REQUEST_GET_MODULE_BASE,
    REQUEST_AOB_SCAN,
    REQUEST_ALLOCATE_MEMORY,
    REQUEST_DISCONNECT, // Added for clean disconnect
};

enum class SlotStatus : uint32_t {
    EMPTY = 0,
    UM_REQUEST_PENDING,
    KM_PROCESSING_REQUEST,
    KM_COMPLETED_SUCCESS,
    KM_COMPLETED_ERROR,
    UM_ACKNOWLEDGED
};

#pragma pack(push, 1)
struct CommunicationSlot {
    volatile SlotStatus status;
    uint32_t request_id;
    CommCommand command_id;
    uint64_t process_id;
    uint8_t parameters[256];
    uint32_t param_size;
    uint8_t output[256];
    uint32_t output_size;
    uint64_t result_status_code;
    uint8_t nonce[12];
    uint8_t mac_tag[16];
};

struct SharedCommBlock {
    volatile uint64_t signature;
    volatile uint32_t um_slot_index;
    volatile uint32_t km_slot_index;
    CommunicationSlot slots[4];
    volatile uint64_t honeypot_field;
};
#pragma pack(pop)

// struct SharedCommBlock defined above

#pragma pack(push, 1)
struct PtrStruct4_KM {
    SharedCommBlock* data_block;
    uint64_t obfuscation_value1;
    uint64_t obfuscation_value2;
};

struct PtrStruct3_KM {
    PtrStruct4_KM* next_ptr_struct;
    uint64_t obfuscation_value1;
    uint64_t obfuscation_value2;
};

struct PtrStruct2_KM {
    PtrStruct3_KM* next_ptr_struct;
    uint64_t obfuscation_value1;
    uint64_t obfuscation_value2;
};

struct PtrStruct1_KM {
    PtrStruct2_KM* next_ptr_struct;
    uint64_t head_signature;
    uint64_t obfuscation_value1;
};
#pragma pack(pop)

struct DynamicSignaturesRelay {
    UINT64 dynamic_head_signature;
    UINT64 dynamic_shared_comm_block_signature;
    UINT64 dynamic_obfuscation_xor_key;
    UINT8 beacon[BEACON_PATTERN_SIZE_KM];
};

UINT64 g_km_dynamic_head_signature = 0;
UINT64 g_km_dynamic_shared_comm_block_signature = 0;
UINT64 g_km_dynamic_obfuscation_xor_key = 0;
CHAR g_km_dynamic_head_signature_pattern_str[24];

namespace driver {
    NTSTATUS read_mem(PEPROCESS targetProcess, PVOID targetAddress, PVOID buffer, SIZE_T size);
    NTSTATUS write_mem(PEPROCESS targetProcess, PVOID targetAddress, PVOID buffer, SIZE_T size);
}

NTSTATUS SafeReadUmMemory(PEPROCESS target_process, PVOID um_address, PVOID km_buffer, SIZE_T size, PSIZE_T pbytes_read) {
    if (!target_process || !um_address || !km_buffer || size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE apc_state;
    SIZE_T bytes_read = 0;

    KeStackAttachProcess(target_process, &apc_state);
    __try {
        if ((ULONG_PTR)um_address < MmHighestUserAddress) {
             ProbeForRead(um_address, size, sizeof(UCHAR));
        }
        RtlCopyMemory(km_buffer, um_address, size);
        bytes_read = size;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        bytes_read = 0;
    }
    KeUnstackDetachProcess(&apc_state);

    if (pbytes_read) {
        *pbytes_read = bytes_read;
    }
    return status;
}

NTSTATUS SafeWriteUmMemory(PEPROCESS target_process, PVOID um_address, PVOID km_buffer, SIZE_T size, PSIZE_T pbytes_written) {
    if (!target_process || !um_address || !km_buffer || size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE apc_state;
    SIZE_T bytes_written = 0;

    KeStackAttachProcess(target_process, &apc_state);
    __try {
         if ((ULONG_PTR)um_address < MmHighestUserAddress) {
            ProbeForWrite(um_address, size, sizeof(UCHAR));
        }
        RtlCopyMemory(um_address, km_buffer, size);
        bytes_written = size;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        bytes_written = 0;
    }
    KeUnstackDetachProcess(&apc_state);

    if (pbytes_written) {
        *pbytes_written = bytes_written;
    }
    return status;
}

NTSTATUS FetchDynamicSignaturesFromProcess(PEPROCESS target_eprocess) {
    if (!target_eprocess) {
        debug_print("[-] FetchDynamicSignaturesFromProcess: Invalid target_eprocess.\n");
        return STATUS_INVALID_PARAMETER;
    }
    BOOLEAN is_beacon_valid = FALSE;
    for(int i=0; i < BEACON_PATTERN_SIZE_KM; ++i) {
        if (g_received_beacon_pattern_km[i] != 0) {
            is_beacon_valid = TRUE;
            break;
        }
    }
    if (!is_beacon_valid) {
        debug_print("[-] FetchDynamicSignaturesFromProcess: Beacon pattern is all zeros or not yet received.\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    SIZE_T bytes_read = 0;

    CHAR beacon_aob_pattern_str[BEACON_PATTERN_SIZE_KM * 3 + 1];
    RtlZeroMemory(beacon_aob_pattern_str, sizeof(beacon_aob_pattern_str));
    for (int i = 0; i < BEACON_PATTERN_SIZE_KM; ++i) {
        BYTE byte_val = g_received_beacon_pattern_km[i];
        CHAR nibble_high = (byte_val >> 4) & 0x0F;
        CHAR nibble_low = byte_val & 0x0F;
        beacon_aob_pattern_str[i * 3 + 0] = (nibble_high < 10) ? (nibble_high + '0') : (nibble_high - 10 + 'A');
        beacon_aob_pattern_str[i * 3 + 1] = (nibble_low < 10) ? (nibble_low + '0') : (nibble_low - 10 + 'A');
        if (i < (BEACON_PATTERN_SIZE_KM - 1)) {
            beacon_aob_pattern_str[i * 3 + 2] = ' ';
        }
    }
    debug_print("[+] FetchDynamicSignaturesFromProcess: Scanning for beacon pattern: \"%s\"\n", beacon_aob_pattern_str);

    UINT64 found_beacon_umva = 0;
    SIZE_T results_count = 0;
    UINT64 start_scan_address = 0;
    UINT64 end_scan_address = (PsGetProcessWow64Process(target_eprocess) != NULL) ?
                                 0x7FFFFFFF : (UINT64)MM_HIGHEST_USER_ADDRESS;

    status = AobScanProcessRanges(
        target_eprocess, start_scan_address, end_scan_address,
        beacon_aob_pattern_str, &found_beacon_umva, 1, &results_count );

    if (!NT_SUCCESS(status) || results_count == 0) {
        debug_print("[-] FetchDynamicSignaturesFromProcess: Beacon pattern AOB scan failed or not found. Status: 0x%X, Count: %zu\n", status, results_count);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    PVOID relay_struct_um_va = (PVOID)found_beacon_umva;
    debug_print("[+] FetchDynamicSignaturesFromProcess: DynamicSignaturesRelay struct (via beacon) potentially at UMVA: 0x%p.\n", relay_struct_um_va);

    DynamicSignaturesRelay km_relay_data_copy;
    status = SafeReadUmMemory(target_eprocess, relay_struct_um_va, &km_relay_data_copy, sizeof(DynamicSignaturesRelay), &bytes_read);
    if (!NT_SUCCESS(status) || bytes_read != sizeof(DynamicSignaturesRelay)) {
        debug_print("[-] FetchDynamicSignaturesFromProcess: Failed to read DynamicSignaturesRelay struct. Status: 0x%X, BytesRead: %zu\n", status, bytes_read);
        return status;
    }

    if (memcmp(km_relay_data_copy.beacon, g_received_beacon_pattern_km, BEACON_PATTERN_SIZE_KM) != 0) {
        debug_print("[-] FetchDynamicSignaturesFromProcess: Beacon mismatch after reading relay struct. Data corruption?\n");
        return STATUS_DATA_ERROR;
    }

    g_km_dynamic_head_signature = km_relay_data_copy.dynamic_head_signature;
    g_km_dynamic_shared_comm_block_signature = km_relay_data_copy.dynamic_shared_comm_block_signature;
    g_km_dynamic_obfuscation_xor_key = km_relay_data_copy.dynamic_obfuscation_xor_key;

    debug_print("[+] FetchDynamicSignaturesFromProcess: Dynamic signatures fetched and verified via beacon:\n");
    debug_print("    Head Signature: 0x%llX\n", g_km_dynamic_head_signature);
    debug_print("    Shared Block Signature: 0x%llX\n", g_km_dynamic_shared_comm_block_signature);
    debug_print("    XOR Key: 0x%llX\n", g_km_dynamic_obfuscation_xor_key);

    return STATUS_SUCCESS;
}

VOID DiscoveryAndAttachmentThread(PVOID StartContext) {
    UNREFERENCED_PARAMETER(StartContext);
    debug_print("[+] DiscoveryAndAttachmentThread started.\n");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS target_eprocess_handshake = NULL;
    PVOID um_ptr_struct1_addr_deobfuscated = NULL;
    SharedCommBlock* shared_comm_block_ptr_candidate = NULL;
    UINT64 initial_read_head_signature = 0; // Store the initially read head signature

    status = KeWaitForSingleObject(&g_handshake_completed_event, Executive, KernelMode, FALSE, NULL);
    if (!NT_SUCCESS(status)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed waiting for handshake event. Status: 0x%X\n", status);
        PsTerminateSystemThread(status);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Handshake event signaled.\n");

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_comm_lock, &oldIrql);
    if (g_target_process != NULL) { // g_target_process is set in HandshakeDeviceControl (IoGetCurrentProcess())
        target_eprocess_handshake = g_target_process;
        ObReferenceObject(target_eprocess_handshake);
    }
    KeReleaseSpinLock(&g_comm_lock, oldIrql);

    if (!target_eprocess_handshake) {
        debug_print("[-] DiscoveryAndAttachmentThread: target_eprocess_handshake is NULL after handshake. Aborting.\n");
        PsTerminateSystemThread(STATUS_INVALID_DEVICE_STATE);
        return;
    }

    if (g_obfuscated_ptr1_um_addr_via_handshake == NULL) {
        debug_print("[-] DiscoveryAndAttachmentThread: g_obfuscated_ptr1_um_addr_via_handshake is NULL. Aborting.\n");
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
        return;
    }

    if (g_received_um_verification_token == 0) {
        debug_print("[-] DiscoveryAndAttachmentThread: Handshake completed but g_received_um_verification_token is zero. Aborting setup.\n");
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
        return;
    }

    // Set the bootstrap XOR key from the handshake token. This may be overwritten by FetchDynamicSignaturesFromProcess.
    g_km_dynamic_obfuscation_xor_key = g_received_um_verification_token;
    debug_print("[+] DiscoveryAndAttachmentThread: Bootstrap g_km_dynamic_obfuscation_xor_key set from handshake token: 0x%llX\n", g_km_dynamic_obfuscation_xor_key);

    // --- Stage 1: Fetch dynamic signatures (this populates global signatures and session XOR key) ---
    // This must happen before the main pointer chain walk that uses these signatures/keys.
    status = FetchDynamicSignaturesFromProcess(target_eprocess_handshake);
    if (!NT_SUCCESS(status)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to fetch dynamic signatures. Status: 0x%X\n", status);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Fetched dynamic signatures successfully.\n");
    debug_print("    g_km_dynamic_head_signature: 0x%llX\n", g_km_dynamic_head_signature);
    debug_print("    g_km_dynamic_shared_comm_block_signature: 0x%llX\n", g_km_dynamic_shared_comm_block_signature);
    debug_print("    g_km_dynamic_obfuscation_xor_key (now session key): 0x%llX\n", g_km_dynamic_obfuscation_xor_key);

    // --- Stage 2: Pointer chain navigation (using SESSION XOR key and loaded signatures) ---
    um_ptr_struct1_addr_deobfuscated = (PtrStruct1_KM*)g_obfuscated_ptr1_um_addr_via_handshake; // Address is already deobfuscated by UM convention
    debug_print("[+] DiscoveryAndAttachmentThread: PtrStruct1_KM UMVA: 0x%p\n", um_ptr_struct1_addr_deobfuscated);

    PtrStruct1_KM km_ptr_struct1_copy;
    SIZE_T bytes_read_ps1 = 0;
    NTSTATUS status_read = SafeReadUmMemory(target_eprocess_handshake, um_ptr_struct1_addr_deobfuscated, &km_ptr_struct1_copy, sizeof(PtrStruct1_KM), &bytes_read_ps1);

    if (!NT_SUCCESS(status_read) || bytes_read_ps1 != sizeof(PtrStruct1_KM)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to read PtrStruct1_KM. Status: 0x%X, BytesRead: %zu\n", status_read, bytes_read_ps1);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status_read);
        return;
    }
    // Now verify PtrStruct1 head signature using the g_km_dynamic_head_signature loaded by FetchDynamicSignaturesFromProcess
    if (km_ptr_struct1_copy.head_signature != g_km_dynamic_head_signature) {
        debug_print("[-] DiscoveryAndAttachmentThread: PtrStruct1 head_signature mismatch. Read: 0x%llX, Expected: 0x%llX.\n",
                    km_ptr_struct1_copy.head_signature, g_km_dynamic_head_signature);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(STATUS_INVALID_SIGNATURE);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Read and VERIFIED PtrStruct1_KM. head_signature: 0x%llX\n", km_ptr_struct1_copy.head_signature);

    PVOID obfuscated_next_ptr = (PVOID)km_ptr_struct1_copy.obfuscation_value1;
    // Use the g_km_dynamic_obfuscation_xor_key which should now be the session key from FetchDynamicSignaturesFromProcess
    PtrStruct2_KM* ptr_struct2_um_va = (PtrStruct2_KM*)((uintptr_t)obfuscated_next_ptr ^ g_km_dynamic_obfuscation_xor_key);
    debug_print("[+] DiscoveryAndAttachmentThread: Deobfuscated PtrStruct2_KM UMVA: 0x%p\n", ptr_struct2_um_va);

    PtrStruct2_KM km_ptr_struct2_copy;
    SIZE_T bytes_read_ps2 = 0;
    status_read = SafeReadUmMemory(target_eprocess_handshake, ptr_struct2_um_va, &km_ptr_struct2_copy, sizeof(PtrStruct2_KM), &bytes_read_ps2);
    if (!NT_SUCCESS(status_read) || bytes_read_ps2 != sizeof(PtrStruct2_KM)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to read PtrStruct2_KM. Status: 0x%X\n", status_read);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status_read);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Read PtrStruct2_KM.\n");

    obfuscated_next_ptr = (PVOID)km_ptr_struct2_copy.obfuscation_value1;
    PtrStruct3_KM* ptr_struct3_um_va = (PtrStruct3_KM*)((uintptr_t)obfuscated_next_ptr ^ g_km_dynamic_obfuscation_xor_key);
    debug_print("[+] DiscoveryAndAttachmentThread: Deobfuscated PtrStruct3_KM UMVA: 0x%p\n", ptr_struct3_um_va);

    PtrStruct3_KM km_ptr_struct3_copy;
    SIZE_T bytes_read_ps3 = 0;
    status_read = SafeReadUmMemory(target_eprocess_handshake, ptr_struct3_um_va, &km_ptr_struct3_copy, sizeof(PtrStruct3_KM), &bytes_read_ps3);
    if (!NT_SUCCESS(status_read) || bytes_read_ps3 != sizeof(PtrStruct3_KM)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to read PtrStruct3_KM. Status: 0x%X\n", status_read);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status_read);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Read PtrStruct3_KM.\n");

    obfuscated_next_ptr = (PVOID)km_ptr_struct3_copy.obfuscation_value1;
    PtrStruct4_KM* ptr_struct4_um_va = (PtrStruct4_KM*)((uintptr_t)obfuscated_next_ptr ^ g_km_dynamic_obfuscation_xor_key);
    debug_print("[+] DiscoveryAndAttachmentThread: Deobfuscated PtrStruct4_KM UMVA: 0x%p\n", ptr_struct4_um_va);

    PtrStruct4_KM km_ptr_struct4_copy;
    SIZE_T bytes_read_ps4 = 0;
    status_read = SafeReadUmMemory(target_eprocess_handshake, ptr_struct4_um_va, &km_ptr_struct4_copy, sizeof(PtrStruct4_KM), &bytes_read_ps4);
    if (!NT_SUCCESS(status_read) || bytes_read_ps4 != sizeof(PtrStruct4_KM)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to read PtrStruct4_KM. Status: 0x%X\n", status_read);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status_read);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Read PtrStruct4_KM.\n");

    obfuscated_next_ptr = (PVOID)km_ptr_struct4_copy.obfuscation_value1;
    shared_comm_block_ptr_candidate = (SharedCommBlock*)((uintptr_t)obfuscated_next_ptr ^ g_km_dynamic_obfuscation_xor_key);
    debug_print("[+] DiscoveryAndAttachmentThread: Candidate SharedCommBlock UMVA: 0x%p\n", shared_comm_block_ptr_candidate);

    if (!shared_comm_block_ptr_candidate) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to deobfuscate SharedCommBlock address (NULL).\n");
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(STATUS_INVALID_ADDRESS);
        return;
    }

    // --- Stage 3: Final Verification of SharedCommBlock signature ---
    // initial_read_head_signature is no longer needed as it was verified against the loaded g_km_dynamic_head_signature.
    // Now verify the signature of the found SharedCommBlock.
    UINT64 final_shared_block_sig_check = 0;
    SIZE_T bytes_read_final_sig = 0;
    status_read = SafeReadUmMemory(target_eprocess_handshake,
                                   &((SharedCommBlock*)shared_comm_block_ptr_candidate)->signature,
                                   &final_shared_block_sig_check,
                                   sizeof(UINT64), &bytes_read_final_sig);

    if (!NT_SUCCESS(status_read) || bytes_read_final_sig != sizeof(UINT64)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to read signature from candidate SharedCommBlock. Status: 0x%X\n", status_read);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status_read);
        return;
    }

    if (final_shared_block_sig_check != g_km_dynamic_shared_comm_block_signature) {
        debug_print("[-] DiscoveryAndAttachmentThread: SharedCommBlock signature mismatch. Expected 0x%llX, Got 0x%llX.\n",
                    g_km_dynamic_shared_comm_block_signature, final_shared_block_sig_check);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(STATUS_INVALID_SIGNATURE);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: SharedCommBlock signature VERIFIED.\n");

    // All checks passed, finalize global setup
    KeAcquireSpinLock(&g_comm_lock, &oldIrql);
    if(g_target_process && g_target_process != target_eprocess_handshake) {
        // This case implies g_target_process was somehow changed or not the one we referenced.
        // To be safe, dereference the g_target_process that we are about to overwrite if it's different.
        // However, target_eprocess_handshake is the one holding the reference taken at the start of this thread.
        ObDereferenceObject(g_target_process);
    }
    g_target_process = target_eprocess_handshake;
    // The reference from target_eprocess_handshake is now "owned" by the global g_target_process.
    // So, we do not dereference target_eprocess_handshake if we reach this point.

    g_um_shared_comm_block_ptr = shared_comm_block_ptr_candidate;
    g_km_thread_should_run = TRUE;

    if (g_pPollingWorkItem == NULL) {
        g_pPollingWorkItem = (PWORK_QUEUE_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(WORK_QUEUE_ITEM), 'WkIt');
    }

    if (g_pPollingWorkItem) {
        ExInitializeWorkItem(g_pPollingWorkItem, KmPollingWorkItemCallback, NULL);
        ExQueueWorkItem(g_pPollingWorkItem, DelayedWorkQueue);
        debug_print("[+] DiscoveryAndAttachmentThread: Polling work item queued.\n");
    } else {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to allocate polling work item. Polling will not start.\n");
        g_km_thread_should_run = FALSE;
        g_um_shared_comm_block_ptr = NULL;
        ObDereferenceObject(g_target_process); // Release the reference we just gave to g_target_process
        g_target_process = NULL;
    }
    KeReleaseSpinLock(&g_comm_lock, oldIrql);

    debug_print("[+] DiscoveryAndAttachmentThread: Setup successful. Thread will exit (polling is now independent).\n");
}

VOID ProcessSlotRequest(PVOID slot_um_va, PEPROCESS handshake_eprocess) {
    if (!slot_um_va || !handshake_eprocess) {
        debug_print("[-] ProcessSlotRequest: Invalid parameters (slot_um_va or handshake_eprocess is NULL).\n");
        return;
    }

    CommunicationSlot km_slot_copy;
    NTSTATUS status;
    SIZE_T bytes_processed;
    PEPROCESS command_target_eprocess = NULL; // EPROCESS for the command's target PID

    // Read the slot using the handshake_eprocess context
    status = SafeReadUmMemory(handshake_eprocess, slot_um_va, &km_slot_copy, sizeof(CommunicationSlot), &bytes_processed);
    if (!NT_SUCCESS(status) || bytes_processed != sizeof(CommunicationSlot)) {
        debug_print("[-] ProcessSlotRequest: Failed to read slot from UMVA 0x%p using handshake_eprocess. Status: 0x%X, BytesRead: %zu\n", slot_um_va, status, bytes_processed);
        return;
    }

    if (km_slot_copy.status != SlotStatus::UM_REQUEST_PENDING) {
        return;
    }
    debug_print("[+] ProcessSlotRequest: Picked up pending request ID %u from UMVA 0x%p.\n", km_slot_copy.request_id, slot_um_va);

    UINT8 current_chacha_key[32];
    if (g_km_dynamic_obfuscation_xor_key == 0) {
        debug_print("[-] ProcessSlotRequest: g_km_dynamic_obfuscation_xor_key is 0. Cannot derive crypto keys for request ID %u.\n", km_slot_copy.request_id);
        km_slot_copy.result_status_code = STATUS_INVALID_KEY;
        km_slot_copy.status = SlotStatus::KM_COMPLETED_ERROR;
        // Write error back using handshake_eprocess context
        SafeWriteUmMemory(handshake_eprocess, slot_um_va, &km_slot_copy, sizeof(CommunicationSlot), NULL);
        return;
    }
    DeriveKeys(g_km_dynamic_obfuscation_xor_key, km_slot_copy.request_id, current_chacha_key);

    // AAD for Request Decryption: request_id (4) + command_id (4) + process_id (8) + param_size (4) = 20 bytes
    UINT8 aad_buffer_request[20];
    UINT32 current_req_aad_offset = 0;
    Serialize_UINT32_KM(aad_buffer_request + current_req_aad_offset, km_slot_copy.request_id);
    current_req_aad_offset += sizeof(km_slot_copy.request_id);
    Serialize_UINT32_KM(aad_buffer_request + current_req_aad_offset, (UINT32)km_slot_copy.command_id); // command_id is enum, cast to UINT32
    current_req_aad_offset += sizeof(km_slot_copy.command_id);
    Serialize_UINT64_KM(aad_buffer_request + current_req_aad_offset, km_slot_copy.process_id);
    current_req_aad_offset += sizeof(km_slot_copy.process_id);
    Serialize_UINT32_KM(aad_buffer_request + current_req_aad_offset, km_slot_copy.param_size);
    current_req_aad_offset += sizeof(km_slot_copy.param_size);

    NTSTATUS decrypt_status;
    if (km_slot_copy.param_size > 0) {
        decrypt_status = StandardLib_ChaCha20_Decrypt_KM(current_chacha_key, km_slot_copy.nonce, aad_buffer_request, current_req_aad_offset, km_slot_copy.parameters, km_slot_copy.param_size, km_slot_copy.parameters, km_slot_copy.mac_tag);
    } else {
        // If param_size is 0, still need to verify tag against AAD
        UINT8 dummy_plaintext; // Decrypt needs a non-null buffer, even for 0 size
        decrypt_status = StandardLib_ChaCha20_Decrypt_KM(current_chacha_key, km_slot_copy.nonce, aad_buffer_request, current_req_aad_offset, NULL, 0, &dummy_plaintext, km_slot_copy.mac_tag);
    }

    if (!NT_SUCCESS(decrypt_status)) {
        debug_print("[-] ProcessSlotRequest: ChaCha20-Poly1305 decryption/tag verification FAILED for request ID %u. Status: 0x%X\n", km_slot_copy.request_id, decrypt_status);
        km_slot_copy.result_status_code = (decrypt_status == STATUS_AUTH_TAG_MISMATCH) ? STATUS_MAC_INCORRECT : decrypt_status;
        km_slot_copy.status = SlotStatus::KM_COMPLETED_ERROR;
        SafeWriteUmMemory(handshake_eprocess, slot_um_va, &km_slot_copy, sizeof(CommunicationSlot), NULL);
        return;
    }
    debug_print("[+] ProcessSlotRequest: ChaCha20-Poly1305 DECRYPTED and VERIFIED parameters for request ID %u, size: %u\n", km_slot_copy.request_id, km_slot_copy.param_size);

    // Lookup the target process for the command
    status = PsLookupProcessByProcessId((HANDLE)km_slot_copy.process_id, &command_target_eprocess);
    if (!NT_SUCCESS(status) || !command_target_eprocess) {
        debug_print("[-] ProcessSlotRequest: Failed to lookup command target process PID %llu. Status: 0x%X\n", km_slot_copy.process_id, status);
        km_slot_copy.result_status_code = NT_SUCCESS(status) ? STATUS_PROCESS_IS_TERMINATING : status; // If lookup success but eprocess is NULL
        km_slot_copy.status = SlotStatus::KM_COMPLETED_ERROR;
        // No command_target_eprocess to dereference here
    } else {
        // Successfully looked up command_target_eprocess
        km_slot_copy.status = SlotStatus::KM_PROCESSING_REQUEST;
        NTSTATUS status_write_processing = SafeWriteUmMemory(handshake_eprocess,
                                   &((CommunicationSlot*)slot_um_va)->status,
                                   &km_slot_copy.status,
                                   sizeof(km_slot_copy.status),
                                   &bytes_processed);
        if (!NT_SUCCESS(status_write_processing) || bytes_processed != sizeof(km_slot_copy.status)) {
            debug_print("[-] ProcessSlotRequest: Failed to write KM_PROCESSING_REQUEST status for ReqID %u. Status: 0x%X\n", km_slot_copy.request_id, status_write_processing);
            // Continue to process the command if possible, but log this failure.
        }

        km_slot_copy.output_size = 0;
        RtlZeroMemory(km_slot_copy.output, sizeof(km_slot_copy.output));
        km_slot_copy.result_status_code = STATUS_UNSUCCESSFUL; // Default for command execution

        debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Entering command processing for PID %llu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.process_id);

        switch (km_slot_copy.command_id) {
            case CommCommand::REQUEST_READ_MEMORY: {
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - REQUEST_READ_MEMORY.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            if (km_slot_copy.param_size != (sizeof(UINT64) + sizeof(UINT64))) {
                km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Param size mismatch. Expected %zu, Got %u.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, (sizeof(UINT64) + sizeof(UINT64)), km_slot_copy.param_size);
                break;
            }

            UINT64 address_to_read = 0;
            UINT64 size_to_read_u64 = 0;
            memcpy(&address_to_read, km_slot_copy.parameters, sizeof(UINT64));
            memcpy(&size_to_read_u64, km_slot_copy.parameters + sizeof(UINT64), sizeof(UINT64));
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Addr: 0x%llX, Size: %llu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, address_to_read, size_to_read_u64);

            if (address_to_read == 0) {
                km_slot_copy.result_status_code = STATUS_INVALID_PARAMETER_1;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Address to read is NULL.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                break;
            }
            if (size_to_read_u64 == 0 || size_to_read_u64 > sizeof(km_slot_copy.output)) {
                km_slot_copy.result_status_code = STATUS_INVALID_BUFFER_SIZE;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Invalid read size %llu. Max output: %zu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, size_to_read_u64, sizeof(km_slot_copy.output));
                break;
            }
            UINT32 size_to_read = static_cast<UINT32>(size_to_read_u64);

            status = driver::read_mem(command_target_eprocess, (PVOID)address_to_read, km_slot_copy.output, size_to_read);
            if (NT_SUCCESS(status)) {
                km_slot_copy.output_size = size_to_read;
                km_slot_copy.result_status_code = STATUS_SUCCESS;
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Read %u bytes from 0x%llX successfully.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, size_to_read, address_to_read);
            } else {
                km_slot_copy.output_size = 0;
                km_slot_copy.result_status_code = status;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - driver::read_mem failed. Status: 0x%X.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, status);
            }
            break;
        }
        case CommCommand::REQUEST_WRITE_MEMORY: {
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - REQUEST_WRITE_MEMORY.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            UINT32 header_size = sizeof(UINT64) + sizeof(UINT64);
            if (km_slot_copy.param_size <= header_size) {
                km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Param size %u too small for headers (must be > %u).\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.param_size, header_size);
                break;
            }

            UINT64 address_to_write = 0;
            UINT64 size_to_write_u64 = 0;
            memcpy(&address_to_write, km_slot_copy.parameters, sizeof(UINT64));
            memcpy(&size_to_write_u64, km_slot_copy.parameters + sizeof(UINT64), sizeof(UINT64));
             debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Addr: 0x%llX, Size: %llu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, address_to_write, size_to_write_u64);

            if (address_to_write == 0) {
                 km_slot_copy.result_status_code = STATUS_INVALID_PARAMETER_1;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Address to write is NULL.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                 break;
            }
            UINT32 actual_data_size_in_params = km_slot_copy.param_size - header_size;
            if (size_to_write_u64 == 0 || size_to_write_u64 > actual_data_size_in_params) {
                 km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Write size %llu mismatch with param data size %u or zero size.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, size_to_write_u64, actual_data_size_in_params);
                 break;
            }
            UINT32 size_to_write = static_cast<UINT32>(size_to_write_u64);

            PVOID data_to_write = km_slot_copy.parameters + header_size;
            status = driver::write_mem(command_target_eprocess, (PVOID)address_to_write, data_to_write, size_to_write);
            if (NT_SUCCESS(status)) {
                 km_slot_copy.output_size = size_to_write;
                 km_slot_copy.result_status_code = STATUS_SUCCESS;
                 debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Wrote %u bytes to 0x%llX successfully.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, size_to_write, address_to_write);
            } else {
                km_slot_copy.output_size = 0;
                km_slot_copy.result_status_code = status;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - driver::write_mem failed. Status: 0x%X.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, status);
            }
            break;
        }
        case CommCommand::REQUEST_GET_MODULE_BASE: {
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - REQUEST_GET_MODULE_BASE.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            if (km_slot_copy.param_size < sizeof(WCHAR) || km_slot_copy.param_size > (sizeof(km_slot_copy.parameters)) || (km_slot_copy.param_size % sizeof(WCHAR) != 0) ) {
                 km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Invalid param_size %u for module name.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.param_size);
                 break;
            }

            PWCHAR module_name_buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, km_slot_copy.param_size + sizeof(WCHAR), 'NmBf');
            if (!module_name_buffer) {
                 km_slot_copy.result_status_code = STATUS_INSUFFICIENT_RESOURCES;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Failed to allocate buffer for module name.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                 break;
            }
            RtlZeroMemory(module_name_buffer, km_slot_copy.param_size + sizeof(WCHAR));
            memcpy(module_name_buffer, km_slot_copy.parameters, km_slot_copy.param_size);

            UNICODE_STRING module_name_us;
            RtlInitUnicodeString(&module_name_us, module_name_buffer);
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Module: %wZ.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, &module_name_us);


            PVOID module_base = NULL;
            if (PsGetProcessWow64Process(command_target_eprocess) != NULL) {
                 debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Target is WOW64, calling GetModuleBasex86.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                module_base = (PVOID)GetModuleBasex86(command_target_eprocess, module_name_us);
            } else {
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Target is x64, calling GetModuleBasex64.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                module_base = (PVOID)GetModuleBasex64(command_target_eprocess, module_name_us);
            }

            if (module_base) {
                memcpy(km_slot_copy.output, &module_base, sizeof(PVOID));
                km_slot_copy.output_size = sizeof(PVOID);
                km_slot_copy.result_status_code = STATUS_SUCCESS;
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Module %wZ found at 0x%p.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, &module_name_us, module_base);
            } else {
                km_slot_copy.result_status_code = STATUS_NOT_FOUND;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Module %wZ not found.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, &module_name_us);
            }
            ExFreePoolWithTag(module_name_buffer, 'NmBf');
            break;
        }
        case CommCommand::REQUEST_AOB_SCAN: {
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - REQUEST_AOB_SCAN.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            UINT32 header_size = sizeof(UINT64) + sizeof(UINT64);
            if (km_slot_copy.param_size <= header_size) {
                km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Param size %u too small for headers + pattern.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.param_size);
                break;
            }

            UINT64 start_scan_addr = 0;
            UINT64 scan_len = 0;
            memcpy(&start_scan_addr, km_slot_copy.parameters, sizeof(UINT64));
            memcpy(&scan_len, km_slot_copy.parameters + sizeof(UINT64), sizeof(UINT64));

            char* pattern_scan_str = (char*)(km_slot_copy.parameters + header_size);
            UINT32 actual_pattern_len_with_null = km_slot_copy.param_size - header_size;

            BOOLEAN found_null = FALSE;
            for(UINT32 i = 0; i < actual_pattern_len_with_null; ++i) {
                if (pattern_scan_str[i] == '\0') {
                    found_null = TRUE;
                    break;
                }
            }
            if (!found_null) {
                 km_slot_copy.result_status_code = STATUS_INVALID_PARAMETER;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - AOB pattern not null-terminated within param_size.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                 break;
            }
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - StartAddr: 0x%llX, ScanLen: %llu, Pattern: \"%s\".\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, start_scan_addr, scan_len, pattern_scan_str);

            UINT64 found_at_umva = 0;
            SIZE_T num_found = 0;
            status = AobScanProcessRanges(command_target_eprocess, start_scan_addr, start_scan_addr + scan_len,
                                          pattern_scan_str, &found_at_umva, 1, &num_found);
            if (NT_SUCCESS(status) && num_found > 0) {
                memcpy(km_slot_copy.output, &found_at_umva, sizeof(UINT64));
                km_slot_copy.output_size = sizeof(UINT64);
                km_slot_copy.result_status_code = STATUS_SUCCESS;
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - AOB Pattern found at 0x%llX.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, found_at_umva);
            } else {
                km_slot_copy.result_status_code = NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - AOB Pattern not found or error. ScanStatus: 0x%X, NumFound: %zu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, status, num_found);
            }
            break;
        }
        case CommCommand::REQUEST_ALLOCATE_MEMORY: {
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - REQUEST_ALLOCATE_MEMORY.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            if (km_slot_copy.param_size != (sizeof(UINT64) + sizeof(UINT64))) {
                 km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Invalid param_size %u. Expected %zu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.param_size, (sizeof(UINT64) + sizeof(UINT64)));
                 break;
            }

            UINT64 alloc_size = 0;
            UINT64 hint_addr = 0;
            memcpy(&alloc_size, km_slot_copy.parameters, sizeof(UINT64));
            memcpy(&hint_addr, km_slot_copy.parameters + sizeof(UINT64), sizeof(UINT64));
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - AllocSize: %llu, HintAddr: 0x%llX.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, alloc_size, hint_addr);

            if (alloc_size == 0) {
                km_slot_copy.result_status_code = STATUS_INVALID_PARAMETER_1;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Allocation size is zero.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                break;
            }

            PVOID allocated_base = NULL;
            if (hint_addr != 0) {
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Attempting allocation near hint 0x%llX.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, hint_addr);
                status = AllocateMemoryNearEx(command_target_eprocess, (PVOID)hint_addr, (SIZE_T)alloc_size, &allocated_base);
            } else {
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Attempting general allocation (no hint).\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                status = AllocateExecutableMemory(command_target_eprocess, &allocated_base, (SIZE_T)alloc_size);
            }

            if (NT_SUCCESS(status) && allocated_base) {
                memcpy(km_slot_copy.output, &allocated_base, sizeof(PVOID));
                km_slot_copy.output_size = sizeof(PVOID);
                km_slot_copy.result_status_code = STATUS_SUCCESS;
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Memory allocated at 0x%p, Size: %llu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, allocated_base, alloc_size);
            } else {
                 km_slot_copy.output_size = 0;
                 km_slot_copy.result_status_code = status;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Failed to allocate memory. Status: 0x%X.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, status);
            }
            break;
        }
        case CommCommand::REQUEST_DISCONNECT: {
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - REQUEST_DISCONNECT received.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);

            KIRQL oldIrql;
            KeAcquireSpinLock(&g_comm_lock, &oldIrql);

            g_km_thread_should_run = FALSE; // Signal polling thread to stop

            PEPROCESS processToDereference = g_target_process;
            g_target_process = NULL;
            g_um_shared_comm_block_ptr = NULL;

            KeReleaseSpinLock(&g_comm_lock, oldIrql);

            if (processToDereference) {
                // Important: Check if the process_id in the command matches the g_target_process's PID
                // before dereferencing. This is a command FROM this specific UM instance ABOUT itself.
                // The km_slot_copy.process_id is the PID of the UM instance sending the disconnect.
                HANDLE current_um_pid = PsGetProcessId(processToDereference);
                if (current_um_pid == (HANDLE)km_slot_copy.process_id) {
                    ObDereferenceObject(processToDereference);
                    debug_print("[+] ProcessSlotRequest: Disconnected. Target process (PID %llu) dereferenced.\n", km_slot_copy.process_id);
                } else {
                    // This shouldn't happen if logic is correct UM-side, but good to handle.
                    // We don't dereference if PIDs don't match, as it might be a stale g_target_process
                    // from a previous session or an unexpected PID in the command.
                    // The key thing is g_km_thread_should_run = FALSE and g_um_shared_comm_block_ptr = NULL are set.
                    debug_print("[!] ProcessSlotRequest: Disconnect for PID %llu, but current g_target_process PID is %p. Not dereferencing this g_target_process. Polling stopped.\n", km_slot_copy.process_id, current_um_pid);
                }
            } else {
                debug_print("[+] ProcessSlotRequest: Disconnected. No target process was globally attached. Polling stopped.\n");
            }

            km_slot_copy.result_status_code = STATUS_SUCCESS;
            km_slot_copy.output_size = 0;
            // Status will be set to KM_COMPLETED_SUCCESS by the common logic after the switch.
            break;
        }
        default:
            km_slot_copy.result_status_code = STATUS_NOT_IMPLEMENTED;
            debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Unimplemented command_id.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            break;
    }

        if (command_target_eprocess) {
            ObDereferenceObject(command_target_eprocess);
            command_target_eprocess = NULL;
        }
    } // End of else block for successful PsLookupProcessByProcessId

    // Determine final slot status based on result_status_code
    if (NT_SUCCESS(km_slot_copy.result_status_code)) {
        km_slot_copy.status = SlotStatus::KM_COMPLETED_SUCCESS;
    } else {
        // If status was already KM_COMPLETED_ERROR from PsLookup failure, it remains.
        // Otherwise, set it for command execution failures.
        if (km_slot_copy.status != SlotStatus::KM_COMPLETED_ERROR) {
             km_slot_copy.status = SlotStatus::KM_COMPLETED_ERROR;
        }
    }
    debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Command processing finished. Result status: 0x%X, Slot status: %u.\n",
        (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, (NTSTATUS)km_slot_copy.result_status_code, (UINT32)km_slot_copy.status);

    GenerateNonce_KM(km_slot_copy.nonce, sizeof(km_slot_copy.nonce), km_slot_copy.request_id);
    debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Generated new nonce for response.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);

    // AAD for Response Encryption: request_id (4) + output_size (4) + result_status_code (8) = 16 bytes
    UINT8 aad_buffer_response[16];
    UINT32 current_resp_aad_offset = 0;
    Serialize_UINT32_KM(aad_buffer_response + current_resp_aad_offset, km_slot_copy.request_id);
    current_resp_aad_offset += sizeof(km_slot_copy.request_id);
    Serialize_UINT32_KM(aad_buffer_response + current_resp_aad_offset, km_slot_copy.output_size);
    current_resp_aad_offset += sizeof(km_slot_copy.output_size);
    Serialize_UINT64_KM(aad_buffer_response + current_resp_aad_offset, km_slot_copy.result_status_code);
    current_resp_aad_offset += sizeof(km_slot_copy.result_status_code);

    if (km_slot_copy.output_size > 0) {
        StandardLib_ChaCha20_Encrypt_KM(current_chacha_key, km_slot_copy.nonce, aad_buffer_response, current_resp_aad_offset, km_slot_copy.output, km_slot_copy.output_size, km_slot_copy.output, km_slot_copy.mac_tag);
        debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - ChaCha20-Poly1305 ENCRYPTED output and generated MAC_TAG, size: %u.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.output_size);
    } else {
        // Even if output_size is 0, generate a tag for the AAD
        StandardLib_ChaCha20_Encrypt_KM(current_chacha_key, km_slot_copy.nonce, aad_buffer_response, current_resp_aad_offset, NULL, 0, NULL, km_slot_copy.mac_tag);
        debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - No output data to encrypt, but generated MAC_TAG for AAD.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
    }
    // StandardLib_Poly1305_MAC_KM is removed. Tag is generated by Encrypt_KM.

    // Zero out the key material after use
    RtlSecureZeroMemory(current_chacha_key, sizeof(current_chacha_key));

    // Write the final slot back using the handshake_eprocess context
    status = SafeWriteUmMemory(handshake_eprocess, slot_um_va, &km_slot_copy, sizeof(CommunicationSlot), &bytes_processed);
    if (!NT_SUCCESS(status) || bytes_processed != sizeof(CommunicationSlot)) {
        debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Failed to write updated slot to UM using handshake_eprocess. Status: 0x%X, BytesWritten: %zu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, status, bytes_processed);
    } else {
        debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Successfully updated slot in UM using handshake_eprocess.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
    }
}

VOID KmPollingWorkItemCallback(PVOID Parameter) {
    UNREFERENCED_PARAMETER(Parameter);

    KIRQL oldIrql;
    PEPROCESS local_handshake_process = NULL; // Renamed for clarity
    PVOID local_shared_comm_block_um_va = NULL;
    BOOLEAN request_processed_this_cycle = FALSE;

    KeAcquireSpinLock(&g_comm_lock, &oldIrql);
    PWORK_QUEUE_ITEM current_work_item_global_ptr_copy = g_pPollingWorkItem;
    if (!g_km_thread_should_run || !g_target_process || !g_um_shared_comm_block_ptr) {
        KeReleaseSpinLock(&g_comm_lock, oldIrql);
        return;
    }
    ObReferenceObject(g_target_process);
    local_handshake_process = g_target_process; // This is the process that initiated the handshake
    local_shared_comm_block_um_va = g_um_shared_comm_block_ptr;
    KeReleaseSpinLock(&g_comm_lock, oldIrql);

    if (!local_handshake_process || !local_shared_comm_block_um_va) {
        if (local_handshake_process) ObDereferenceObject(local_handshake_process);
        return;
    }

    UINT64 signature_from_um = 0;
    UINT32 obfuscated_km_slot_idx_read;
    UINT32 km_slot_idx_from_um;
    NTSTATUS status_read_sig;
    SIZE_T bytes_read_sig;

    status_read_sig = SafeReadUmMemory(local_handshake_process,
                                   &((SharedCommBlock*)local_shared_comm_block_um_va)->signature,
                                   &signature_from_um,
                                   sizeof(UINT64), &bytes_read_sig);
    if (!NT_SUCCESS(status_read_sig) || bytes_read_sig != sizeof(UINT64) || signature_from_um != g_km_dynamic_shared_comm_block_signature) {
        debug_print("[-] KmPollingWorkItemCallback: Failed to read valid signature from UM. ReadSig: 0x%llX, Expected: 0x%llX, Status: 0x%X\n", signature_from_um, g_km_dynamic_shared_comm_block_signature, status_read_sig);
        ObDereferenceObject(local_handshake_process);
        goto requeue_logic_label;
    }

    UINT64 honeypot_value_from_um = 0;
    SIZE_T bytes_read_honeypot = 0;
    const UINT64 EXPECTED_HONEYPOT_VALUE = 0xABADC0DED00DFEEDULL;
    NTSTATUS status_read_honeypot = SafeReadUmMemory(local_handshake_process,
                                   &((SharedCommBlock*)local_shared_comm_block_um_va)->honeypot_field,
                                   &honeypot_value_from_um, sizeof(UINT64), &bytes_read_honeypot);
    if (!NT_SUCCESS(status_read_honeypot) || bytes_read_honeypot != sizeof(UINT64)) {
        debug_print("[-] KmPollingWorkItemCallback: Failed to read honeypot field. Status: 0x%X\n", status_read_honeypot);
        ObDereferenceObject(local_handshake_process);
        goto requeue_logic_label;
    }
    if (honeypot_value_from_um != EXPECTED_HONEYPOT_VALUE) {
        debug_print("[!] KmPollingWorkItemCallback: Honeypot field mismatch! Expected 0x%llX, Got 0x%llX. Potential tampering. Halting polling.\n", EXPECTED_HONEYPOT_VALUE, honeypot_value_from_um);
        KeAcquireSpinLock(&g_comm_lock, &oldIrql);
        g_km_thread_should_run = FALSE;
        KeReleaseSpinLock(&g_comm_lock, oldIrql);
        ObDereferenceObject(local_handshake_process);
        return;
    }

    NTSTATUS status_read_idx;
    SIZE_T bytes_read_idx;
    status_read_idx = SafeReadUmMemory(local_handshake_process,
                                   &((SharedCommBlock*)local_shared_comm_block_um_va)->km_slot_index,
                                   &obfuscated_km_slot_idx_read,
                                   sizeof(UINT32), &bytes_read_idx);
    if (!NT_SUCCESS(status_read_idx) || bytes_read_idx != sizeof(UINT32)) {
        debug_print("[-] KmPollingWorkItemCallback: Failed to read obfuscated km_slot_index from UM. Status: 0x%X\n", status_read_idx);
        ObDereferenceObject(local_handshake_process);
        goto requeue_logic_label;
    }

    UINT64 sig_km = g_km_dynamic_shared_comm_block_signature;
    UINT32 derived_index_xor_key_poll = (UINT32)(sig_km & 0xFFFFFFFF) ^ (UINT32)(sig_km >> 32);
    if (g_km_dynamic_shared_comm_block_signature == 0) {
         debug_print("[-] KmPollingWorkItemCallback: g_km_dynamic_shared_comm_block_signature is 0 for index deobfuscation. Critical error.\n");
         ObDereferenceObject(local_handshake_process);
         goto requeue_logic_label;
    }
    km_slot_idx_from_um = DeobfuscateSlotIndex(obfuscated_km_slot_idx_read, derived_index_xor_key_poll);

    PVOID current_slot_um_va = (PVOID)&((SharedCommBlock*)local_shared_comm_block_um_va)->slots[km_slot_idx_from_um % g_max_comm_slots];
    SlotStatus current_slot_status_from_um;
    NTSTATUS status_read_slot_status;
    SIZE_T bytes_read_slot_status;
    status_read_slot_status = SafeReadUmMemory(local_handshake_process,
                                   &((CommunicationSlot*)current_slot_um_va)->status,
                                   &current_slot_status_from_um,
                                   sizeof(SlotStatus), &bytes_read_slot_status);

    if (!NT_SUCCESS(status_read_slot_status) || bytes_read_slot_status != sizeof(SlotStatus)) {
        debug_print("[-] KmPollingWorkItemCallback: Failed to read slot status from UMVA 0x%p. Status: 0x%X\n", current_slot_um_va, status_read_slot_status);
        ObDereferenceObject(local_handshake_process);
        goto requeue_logic_label;
    }

    if (current_slot_status_from_um == SlotStatus::UM_REQUEST_PENDING) {
        ProcessSlotRequest(current_slot_um_va, local_handshake_process); // Pass handshake_eprocess for slot R/W context
        request_processed_this_cycle = TRUE;

        UINT32 next_km_slot_idx_plain = (km_slot_idx_from_um + 1) % g_max_comm_slots;
        UINT32 obfuscated_next_km_slot_idx = ObfuscateSlotIndex(next_km_slot_idx_plain, derived_index_xor_key_poll);

        NTSTATUS status_write_idx = SafeWriteUmMemory(local_handshake_process,
                                                &((SharedCommBlock*)local_shared_comm_block_um_va)->km_slot_index,
                                                &obfuscated_next_km_slot_idx,
                                                sizeof(UINT32), NULL);
        if (!NT_SUCCESS(status_write_idx)) {
            debug_print("[-] KmPollingWorkItemCallback: Failed to write updated obfuscated km_slot_index to UM. Status: 0x%X\n", status_write_idx);
        }
    }

    ObDereferenceObject(local_handshake_process);
    local_handshake_process = NULL;

requeue_logic_label:
    if (local_handshake_process) {
        ObDereferenceObject(local_handshake_process);
        local_handshake_process = NULL;
    }

    ULONG current_delay_ms;
    if (request_processed_this_cycle) {
        InterlockedExchange(&g_consecutive_idle_polls, 0);
        current_delay_ms = BASE_POLLING_DELAY_MS;
    } else {
        LONG idle_count = InterlockedIncrement(&g_consecutive_idle_polls);
        if (idle_count > MAX_IDLE_POLLS_BEFORE_INCREASE) {
            ULONG additional_delay = min((idle_count - MAX_IDLE_POLLS_BEFORE_INCREASE) / 10, MAX_POLLING_DELAY_MS - BASE_POLLING_DELAY_MS);
            current_delay_ms = BASE_POLLING_DELAY_MS + additional_delay;
            current_delay_ms = min(current_delay_ms, MAX_POLLING_DELAY_MS);
        } else {
            current_delay_ms = BASE_POLLING_DELAY_MS;
        }
    }

    ULONG jitter_ms = GetRandomJitter(POLLING_JITTER_MS);
    current_delay_ms += jitter_ms;
    if (current_delay_ms < 1) current_delay_ms = 1;

    KeAcquireSpinLock(&g_comm_lock, &oldIrql);
    if (g_km_thread_should_run && g_pPollingWorkItem != NULL && g_pPollingWorkItem == current_work_item_global_ptr_copy ) {
        LARGE_INTEGER delay_interval;
        delay_interval.QuadPart = RELATIVE_MILLISECONDS(current_delay_ms);
        KeReleaseSpinLock(&g_comm_lock, oldIrql);

        KeDelayExecutionThread(KernelMode, FALSE, &delay_interval);

        KeAcquireSpinLock(&g_comm_lock, &oldIrql);
        if (g_km_thread_should_run && g_pPollingWorkItem != NULL && g_pPollingWorkItem == current_work_item_global_ptr_copy) {
             ExQueueWorkItem(g_pPollingWorkItem, DelayedWorkQueue);
        }
    }
// --- END: Globals for Polling Work Item ---
/*
#define U32_TO_LE(x) (x) // Assuming little-endian environment for kernel
#define LE_TO_U32(x) (x)

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QUARTER_ROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTATE_LEFT(d, 16); \
    c += d; b ^= c; b = ROTATE_LEFT(b, 12); \
    a += b; d ^= a; d = ROTATE_LEFT(d, 8);  \
    c += d; b ^= c; b = ROTATE_LEFT(b, 7)

typedef struct {
    UINT32 state[16];
    UINT8 keystream_block[64];
    UINT32 block_counter_low; // Lower 32 bits of a 64-bit counter
    UINT32 block_counter_high; // Higher 32 bits of a 64-bit counter
} chacha20_context_km;

static void chacha20_block_km(chacha20_context_km* ctx, UINT32 output[16]) {
    UINT32 x[16];
    int i;

    for (i = 0; i < 16; ++i) {
        x[i] = ctx->state[i];
    }

    for (i = 0; i < 20; i += 2) { // 10 double rounds
        // Odd round
        QUARTER_ROUND(x[0], x[4], x[8],  x[12]);
        QUARTER_ROUND(x[1], x[5], x[9],  x[13]);
        QUARTER_ROUND(x[2], x[6], x[10], x[14]);
        QUARTER_ROUND(x[3], x[7], x[11], x[15]);
        // Even round
        QUARTER_ROUND(x[0], x[5], x[10], x[15]);
        QUARTER_ROUND(x[1], x[6], x[11], x[12]);
        QUARTER_ROUND(x[2], x[7], x[8],  x[13]);
        QUARTER_ROUND(x[3], x[4], x[9],  x[14]);
    }

    for (i = 0; i < 16; ++i) {
        output[i] = x[i] + ctx->state[i];
    }
}

static void chacha20_setup_km(chacha20_context_km* ctx, const UINT8* key, UINT32 key_len, const UINT8* nonce, UINT32 nonce_len, UINT64 counter) {
    if (key_len != 32) {
        // Handle error: Key length must be 256 bits (32 bytes)
        // For simplicity in this context, we might assume correct usage or add debug prints.
        // In a real scenario, return an error or use a default/fallback.
        debug_print("[-] chacha20_setup_km: Invalid key length %u. Expected 32 bytes.\n", key_len);
        // Setting a zero key for now to indicate failure, though this is not ideal for security.
        RtlZeroMemory(ctx->state, sizeof(ctx->state));
        ctx->state[0] = 0xDEADBEE0; // Magic number to indicate error state
        return;
    }

    ctx->state[0] = 0x61707865; // "expa"
    ctx->state[1] = 0x3320646e; // "nd 3"
    ctx->state[2] = 0x79622d32; // "2-by"
    ctx->state[3] = 0x6b206574; // "te k"

    // Key (256-bit)
    ctx->state[4]  = LE_TO_U32(((UINT32*)key)[0]);
    ctx->state[5]  = LE_TO_U32(((UINT32*)key)[1]);
    ctx->state[6]  = LE_TO_U32(((UINT32*)key)[2]);
    ctx->state[7]  = LE_TO_U32(((UINT32*)key)[3]);
    ctx->state[8]  = LE_TO_U32(((UINT32*)key)[4]);
    ctx->state[9]  = LE_TO_U32(((UINT32*)key)[5]);
    ctx->state[10] = LE_TO_U32(((UINT32*)key)[6]);
    ctx->state[11] = LE_TO_U32(((UINT32*)key)[7]);

    ctx->block_counter_low = (UINT32)(counter & 0xFFFFFFFF);
    ctx->block_counter_high = (UINT32)(counter >> 32); // Should be 0 for ChaCha20 as per RFC 8439 (block counter is 32-bit)

    ctx->state[12] = ctx->block_counter_low;

    if (nonce_len == 12) { // 96-bit nonce
        ctx->state[13] = LE_TO_U32(((UINT32*)nonce)[0]);
        ctx->state[14] = LE_TO_U32(((UINT32*)nonce)[1]);
        ctx->state[15] = LE_TO_U32(((UINT32*)nonce)[2]);
    } else if (nonce_len == 8) { // 64-bit nonce (IETF legacy)
        // For 64-bit nonces, counter is typically split.
        // However, RFC8439 specifies 96-bit nonce and 32-bit counter for state[12].
        // This example prioritizes RFC8439. If 8-byte nonce is critical, state setup needs adjustment.
        // For now, let's assume 12-byte nonce is used as per the CommunicationSlot struct.
        // Pad with zeros or handle as error if strict adherence to a specific 8-byte nonce scheme is needed.
        debug_print("[-] chacha20_setup_km: Nonce length is 8 bytes. Expected 12 bytes. Padding with 0 for now.\n");
        ctx->state[13] = LE_TO_U32(((UINT32*)nonce)[0]);
        ctx->state[14] = LE_TO_U32(((UINT32*)nonce)[1]);
        ctx->state[15] = 0; // Or some other padding/error indication
    } else {
        // Handle error: Invalid nonce length
        debug_print("[-] chacha20_setup_km: Invalid nonce length %u. Expected 12 bytes.\n", nonce_len);
        ctx->state[13] = 0xDEADBEE1; // Magic numbers
        ctx->state[14] = 0xDEADBEE2;
        ctx->state[15] = 0xDEADBEE3;
        return;
    }
}

static void chacha20_keystream_block_km(chacha20_context_km* ctx) {
    UINT32 block_output[16];
    chacha20_block_km(ctx, block_output);

    for (int i = 0; i < 16; ++i) {
        ((UINT32*)ctx->keystream_block)[i] = U32_TO_LE(block_output[i]);
    }

    ctx->state[12]++; // Increment block counter (low part)
    if (ctx->state[12] == 0) { // Check for overflow
        ctx->state[13]++; // Increment high part of counter (nonce part if using 64-bit counter scheme, or just part of nonce field)
                          // For RFC8439's 32-bit counter, overflow into state[13] is not standard.
                          // This would typically mean the counter has wrapped, which is > 256GB of data.
                          // For this implementation, we'll assume state[12] is the sole block counter.
                          // If state[13] needs to be part of a larger counter, the spec changes.
        // According to RFC 8439, the block counter is only state[12].
        // If it wraps, that's fine, it just means a lot of data has been processed.
        // No need to increment state[13] which is part of the nonce.
    }
}

// Actual ChaCha20 encryption/decryption function
// Output buffer can be the same as input buffer for in-place operation
static void chacha20_process_km(const UINT8* key, const UINT8* nonce, UINT32 nonce_len, UINT64 initial_counter,
                               const UINT8* input, UINT8* output, UINT32 data_size) {
    chacha20_context_km ctx;
    UINT32 keystream_pos = 64; // Start as if the block is already used up to trigger generation

    // Key length is fixed at 32 bytes for ChaCha20. Nonce is 12 bytes.
    chacha20_setup_km(&ctx, key, 32, nonce, nonce_len, initial_counter);
    if (ctx.state[0] == 0xDEADBEE0) { // Check for setup error
        debug_print("[-] chacha20_process_km: Context setup failed (key error). Zeroing output.\n");
        if (output != input) RtlZeroMemory(output, data_size); // Avoid zeroing input if in-place
        return;
    }
    if (ctx.state[13] == 0xDEADBEE1) { // Check for setup error
        debug_print("[-] chacha20_process_km: Context setup failed (nonce error). Zeroing output.\n");
        if (output != input) RtlZeroMemory(output, data_size);
        return;
    }


    for (UINT32 i = 0; i < data_size; ++i) {
        if (keystream_pos >= 64) {
            chacha20_keystream_block_km(&ctx);
            keystream_pos = 0;
        }
        output[i] = input[i] ^ ctx.keystream_block[keystream_pos];
        keystream_pos++;
    }
}
*/
// --- END: Globals for Polling Work Item ---

#define IOCTL_STEALTH_HANDSHAKE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define BEACON_PATTERN_SIZE_KM 16

typedef struct _STEALTH_HANDSHAKE_DATA {
    PVOID ObfuscatedPtrStruct1HeadUmAddress;
    UINT64 VerificationToken;
    UINT8 BeaconPattern[BEACON_PATTERN_SIZE_KM];
} STEALTH_HANDSHAKE_DATA, *PSTEALTH_HANDSHAKE_DATA;

UINT8 g_received_beacon_pattern_km[BEACON_PATTERN_SIZE_KM];
UINT64 g_received_um_verification_token = 0;
// const UINT64 SOME_PREDEFINED_CONSTANT_FOR_TOKEN_KM = 0xCAFEFEEDDEAFBEEFULL; // Removed, shared secret will be g_km_dynamic_obfuscation_xor_key

VOID DiscoveryAndAttachmentThread(PVOID StartContext); // Forward declaration
NTSTATUS HandshakeDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp); // Forward declaration


ULONG       g_max_comm_slots = 4;

enum class CommCommand : uint32_t {
    REQUEST_NOP = 0,
    REQUEST_READ_MEMORY,
    REQUEST_WRITE_MEMORY,
    REQUEST_GET_MODULE_BASE,
    REQUEST_AOB_SCAN,
    REQUEST_ALLOCATE_MEMORY,
};

enum class SlotStatus : uint32_t {
    EMPTY = 0,
    UM_REQUEST_PENDING,
    KM_PROCESSING_REQUEST,
    KM_COMPLETED_SUCCESS,
    KM_COMPLETED_ERROR,
    UM_ACKNOWLEDGED
};

#pragma pack(push, 1)
struct CommunicationSlot {
    volatile SlotStatus status;
    uint32_t request_id;
    CommCommand command_id;
    uint64_t process_id;
    uint8_t parameters[256];
    uint32_t param_size;
    uint8_t output[256];
    uint32_t output_size;
    uint64_t result_status_code;
    uint8_t nonce[12];
    uint8_t mac_tag[16];
};

struct SharedCommBlock {
    volatile uint64_t signature;
    volatile uint32_t um_slot_index;
    volatile uint32_t km_slot_index;
    CommunicationSlot slots[4];
    volatile uint64_t honeypot_field;
};
#pragma pack(pop)

// struct SharedCommBlock defined above

#pragma pack(push, 1)
struct PtrStruct4_KM {
    SharedCommBlock* data_block;
    uint64_t obfuscation_value1;
    uint64_t obfuscation_value2;
};

struct PtrStruct3_KM {
    PtrStruct4_KM* next_ptr_struct;
    uint64_t obfuscation_value1;
    uint64_t obfuscation_value2;
};

struct PtrStruct2_KM {
    PtrStruct3_KM* next_ptr_struct;
    uint64_t obfuscation_value1;
    uint64_t obfuscation_value2;
};

struct PtrStruct1_KM {
    PtrStruct2_KM* next_ptr_struct;
    uint64_t head_signature;
    uint64_t obfuscation_value1;
};
#pragma pack(pop)

struct DynamicSignaturesRelay {
    UINT64 dynamic_head_signature;
    UINT64 dynamic_shared_comm_block_signature;
    UINT64 dynamic_obfuscation_xor_key;
    UINT8 beacon[BEACON_PATTERN_SIZE_KM];
};

UINT64 g_km_dynamic_head_signature = 0;
UINT64 g_km_dynamic_shared_comm_block_signature = 0;
UINT64 g_km_dynamic_obfuscation_xor_key = 0;
CHAR g_km_dynamic_head_signature_pattern_str[24];

namespace driver {
    NTSTATUS read_mem(PEPROCESS targetProcess, PVOID targetAddress, PVOID buffer, SIZE_T size);
    NTSTATUS write_mem(PEPROCESS targetProcess, PVOID targetAddress, PVOID buffer, SIZE_T size);
}

NTSTATUS SafeReadUmMemory(PEPROCESS target_process, PVOID um_address, PVOID km_buffer, SIZE_T size, PSIZE_T pbytes_read) {
    if (!target_process || !um_address || !km_buffer || size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE apc_state;
    SIZE_T bytes_read = 0;

    KeStackAttachProcess(target_process, &apc_state);
    __try {
        if ((ULONG_PTR)um_address < MmHighestUserAddress) {
             ProbeForRead(um_address, size, sizeof(UCHAR));
        }
        RtlCopyMemory(km_buffer, um_address, size);
        bytes_read = size;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        bytes_read = 0;
    }
    KeUnstackDetachProcess(&apc_state);

    if (pbytes_read) {
        *pbytes_read = bytes_read;
    }
    return status;
}

NTSTATUS SafeWriteUmMemory(PEPROCESS target_process, PVOID um_address, PVOID km_buffer, SIZE_T size, PSIZE_T pbytes_written) {
    if (!target_process || !um_address || !km_buffer || size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE apc_state;
    SIZE_T bytes_written = 0;

    KeStackAttachProcess(target_process, &apc_state);
    __try {
         if ((ULONG_PTR)um_address < MmHighestUserAddress) {
            ProbeForWrite(um_address, size, sizeof(UCHAR));
        }
        RtlCopyMemory(um_address, km_buffer, size);
        bytes_written = size;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        bytes_written = 0;
    }
    KeUnstackDetachProcess(&apc_state);

    if (pbytes_written) {
        *pbytes_written = bytes_written;
    }
    return status;
}

NTSTATUS FetchDynamicSignaturesFromProcess(PEPROCESS target_eprocess) {
    if (!target_eprocess) {
        debug_print("[-] FetchDynamicSignaturesFromProcess: Invalid target_eprocess.\n");
        return STATUS_INVALID_PARAMETER;
    }
    BOOLEAN is_beacon_valid = FALSE;
    for(int i=0; i < BEACON_PATTERN_SIZE_KM; ++i) {
        if (g_received_beacon_pattern_km[i] != 0) {
            is_beacon_valid = TRUE;
            break;
        }
    }
    if (!is_beacon_valid) {
        debug_print("[-] FetchDynamicSignaturesFromProcess: Beacon pattern is all zeros or not yet received.\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    SIZE_T bytes_read = 0;

    CHAR beacon_aob_pattern_str[BEACON_PATTERN_SIZE_KM * 3 + 1];
    RtlZeroMemory(beacon_aob_pattern_str, sizeof(beacon_aob_pattern_str));
    for (int i = 0; i < BEACON_PATTERN_SIZE_KM; ++i) {
        BYTE byte_val = g_received_beacon_pattern_km[i];
        CHAR nibble_high = (byte_val >> 4) & 0x0F;
        CHAR nibble_low = byte_val & 0x0F;
        beacon_aob_pattern_str[i * 3 + 0] = (nibble_high < 10) ? (nibble_high + '0') : (nibble_high - 10 + 'A');
        beacon_aob_pattern_str[i * 3 + 1] = (nibble_low < 10) ? (nibble_low + '0') : (nibble_low - 10 + 'A');
        if (i < (BEACON_PATTERN_SIZE_KM - 1)) {
            beacon_aob_pattern_str[i * 3 + 2] = ' ';
        }
    }
    debug_print("[+] FetchDynamicSignaturesFromProcess: Scanning for beacon pattern: \"%s\"\n", beacon_aob_pattern_str);

    UINT64 found_beacon_umva = 0;
    SIZE_T results_count = 0;
    UINT64 start_scan_address = 0;
    UINT64 end_scan_address = (PsGetProcessWow64Process(target_eprocess) != NULL) ?
                                 0x7FFFFFFF : (UINT64)MM_HIGHEST_USER_ADDRESS;

    status = AobScanProcessRanges(
        target_eprocess, start_scan_address, end_scan_address,
        beacon_aob_pattern_str, &found_beacon_umva, 1, &results_count );

    if (!NT_SUCCESS(status) || results_count == 0) {
        debug_print("[-] FetchDynamicSignaturesFromProcess: Beacon pattern AOB scan failed or not found. Status: 0x%X, Count: %zu\n", status, results_count);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    PVOID relay_struct_um_va = (PVOID)found_beacon_umva;
    debug_print("[+] FetchDynamicSignaturesFromProcess: DynamicSignaturesRelay struct (via beacon) potentially at UMVA: 0x%p.\n", relay_struct_um_va);

    DynamicSignaturesRelay km_relay_data_copy;
    status = SafeReadUmMemory(target_eprocess, relay_struct_um_va, &km_relay_data_copy, sizeof(DynamicSignaturesRelay), &bytes_read);
    if (!NT_SUCCESS(status) || bytes_read != sizeof(DynamicSignaturesRelay)) {
        debug_print("[-] FetchDynamicSignaturesFromProcess: Failed to read DynamicSignaturesRelay struct. Status: 0x%X, BytesRead: %zu\n", status, bytes_read);
        return status;
    }

    if (memcmp(km_relay_data_copy.beacon, g_received_beacon_pattern_km, BEACON_PATTERN_SIZE_KM) != 0) {
        debug_print("[-] FetchDynamicSignaturesFromProcess: Beacon mismatch after reading relay struct. Data corruption?\n");
        return STATUS_DATA_ERROR;
    }

    g_km_dynamic_head_signature = km_relay_data_copy.dynamic_head_signature;
    g_km_dynamic_shared_comm_block_signature = km_relay_data_copy.dynamic_shared_comm_block_signature;
    g_km_dynamic_obfuscation_xor_key = km_relay_data_copy.dynamic_obfuscation_xor_key;

    debug_print("[+] FetchDynamicSignaturesFromProcess: Dynamic signatures fetched and verified via beacon:\n");
    debug_print("    Head Signature: 0x%llX\n", g_km_dynamic_head_signature);
    debug_print("    Shared Block Signature: 0x%llX\n", g_km_dynamic_shared_comm_block_signature);
    debug_print("    XOR Key: 0x%llX\n", g_km_dynamic_obfuscation_xor_key);

    return STATUS_SUCCESS;
}

VOID DiscoveryAndAttachmentThread(PVOID StartContext) {
    UNREFERENCED_PARAMETER(StartContext);
    debug_print("[+] DiscoveryAndAttachmentThread started.\n");

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS target_eprocess_handshake = NULL;
    PVOID um_ptr_struct1_addr_deobfuscated = NULL;
    SharedCommBlock* shared_comm_block_ptr_candidate = NULL;
    UINT64 initial_read_head_signature = 0; // Store the initially read head signature

    status = KeWaitForSingleObject(&g_handshake_completed_event, Executive, KernelMode, FALSE, NULL);
    if (!NT_SUCCESS(status)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed waiting for handshake event. Status: 0x%X\n", status);
        PsTerminateSystemThread(status);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Handshake event signaled.\n");

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_comm_lock, &oldIrql);
    if (g_target_process != NULL) { // g_target_process is set in HandshakeDeviceControl (IoGetCurrentProcess())
        target_eprocess_handshake = g_target_process;
        ObReferenceObject(target_eprocess_handshake);
    }
    KeReleaseSpinLock(&g_comm_lock, oldIrql);

    if (!target_eprocess_handshake) {
        debug_print("[-] DiscoveryAndAttachmentThread: target_eprocess_handshake is NULL after handshake. Aborting.\n");
        PsTerminateSystemThread(STATUS_INVALID_DEVICE_STATE);
        return;
    }

    if (g_obfuscated_ptr1_um_addr_via_handshake == NULL) {
        debug_print("[-] DiscoveryAndAttachmentThread: g_obfuscated_ptr1_um_addr_via_handshake is NULL. Aborting.\n");
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
        return;
    }

    if (g_received_um_verification_token == 0) {
        debug_print("[-] DiscoveryAndAttachmentThread: Handshake completed but g_received_um_verification_token is zero. Aborting setup.\n");
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
        return;
    }

    // Set the bootstrap XOR key from the handshake token. This may be overwritten by FetchDynamicSignaturesFromProcess.
    g_km_dynamic_obfuscation_xor_key = g_received_um_verification_token;
    debug_print("[+] DiscoveryAndAttachmentThread: Bootstrap g_km_dynamic_obfuscation_xor_key set from handshake token: 0x%llX\n", g_km_dynamic_obfuscation_xor_key);

    // --- Stage 1: Fetch dynamic signatures (this populates global signatures and session XOR key) ---
    // This must happen before the main pointer chain walk that uses these signatures/keys.
    status = FetchDynamicSignaturesFromProcess(target_eprocess_handshake);
    if (!NT_SUCCESS(status)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to fetch dynamic signatures. Status: 0x%X\n", status);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Fetched dynamic signatures successfully.\n");
    debug_print("    g_km_dynamic_head_signature: 0x%llX\n", g_km_dynamic_head_signature);
    debug_print("    g_km_dynamic_shared_comm_block_signature: 0x%llX\n", g_km_dynamic_shared_comm_block_signature);
    debug_print("    g_km_dynamic_obfuscation_xor_key (now session key): 0x%llX\n", g_km_dynamic_obfuscation_xor_key);

    // --- Stage 2: Pointer chain navigation (using SESSION XOR key and loaded signatures) ---
    um_ptr_struct1_addr_deobfuscated = (PtrStruct1_KM*)g_obfuscated_ptr1_um_addr_via_handshake; // Address is already deobfuscated by UM convention
    debug_print("[+] DiscoveryAndAttachmentThread: PtrStruct1_KM UMVA: 0x%p\n", um_ptr_struct1_addr_deobfuscated);

    PtrStruct1_KM km_ptr_struct1_copy;
    SIZE_T bytes_read_ps1 = 0;
    NTSTATUS status_read = SafeReadUmMemory(target_eprocess_handshake, um_ptr_struct1_addr_deobfuscated, &km_ptr_struct1_copy, sizeof(PtrStruct1_KM), &bytes_read_ps1);

    if (!NT_SUCCESS(status_read) || bytes_read_ps1 != sizeof(PtrStruct1_KM)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to read PtrStruct1_KM. Status: 0x%X, BytesRead: %zu\n", status_read, bytes_read_ps1);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status_read);
        return;
    }
    // Now verify PtrStruct1 head signature using the g_km_dynamic_head_signature loaded by FetchDynamicSignaturesFromProcess
    if (km_ptr_struct1_copy.head_signature != g_km_dynamic_head_signature) {
        debug_print("[-] DiscoveryAndAttachmentThread: PtrStruct1 head_signature mismatch. Read: 0x%llX, Expected: 0x%llX.\n",
                    km_ptr_struct1_copy.head_signature, g_km_dynamic_head_signature);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(STATUS_INVALID_SIGNATURE);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Read and VERIFIED PtrStruct1_KM. head_signature: 0x%llX\n", km_ptr_struct1_copy.head_signature);

    PVOID obfuscated_next_ptr = (PVOID)km_ptr_struct1_copy.obfuscation_value1;
    // Use the g_km_dynamic_obfuscation_xor_key which should now be the session key from FetchDynamicSignaturesFromProcess
    PtrStruct2_KM* ptr_struct2_um_va = (PtrStruct2_KM*)((uintptr_t)obfuscated_next_ptr ^ g_km_dynamic_obfuscation_xor_key);
    debug_print("[+] DiscoveryAndAttachmentThread: Deobfuscated PtrStruct2_KM UMVA: 0x%p\n", ptr_struct2_um_va);

    PtrStruct2_KM km_ptr_struct2_copy;
    SIZE_T bytes_read_ps2 = 0;
    status_read = SafeReadUmMemory(target_eprocess_handshake, ptr_struct2_um_va, &km_ptr_struct2_copy, sizeof(PtrStruct2_KM), &bytes_read_ps2);
    if (!NT_SUCCESS(status_read) || bytes_read_ps2 != sizeof(PtrStruct2_KM)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to read PtrStruct2_KM. Status: 0x%X\n", status_read);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status_read);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Read PtrStruct2_KM.\n");

    obfuscated_next_ptr = (PVOID)km_ptr_struct2_copy.obfuscation_value1;
    PtrStruct3_KM* ptr_struct3_um_va = (PtrStruct3_KM*)((uintptr_t)obfuscated_next_ptr ^ g_km_dynamic_obfuscation_xor_key);
    debug_print("[+] DiscoveryAndAttachmentThread: Deobfuscated PtrStruct3_KM UMVA: 0x%p\n", ptr_struct3_um_va);

    PtrStruct3_KM km_ptr_struct3_copy;
    SIZE_T bytes_read_ps3 = 0;
    status_read = SafeReadUmMemory(target_eprocess_handshake, ptr_struct3_um_va, &km_ptr_struct3_copy, sizeof(PtrStruct3_KM), &bytes_read_ps3);
    if (!NT_SUCCESS(status_read) || bytes_read_ps3 != sizeof(PtrStruct3_KM)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to read PtrStruct3_KM. Status: 0x%X\n", status_read);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status_read);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Read PtrStruct3_KM.\n");

    obfuscated_next_ptr = (PVOID)km_ptr_struct3_copy.obfuscation_value1;
    PtrStruct4_KM* ptr_struct4_um_va = (PtrStruct4_KM*)((uintptr_t)obfuscated_next_ptr ^ g_km_dynamic_obfuscation_xor_key);
    debug_print("[+] DiscoveryAndAttachmentThread: Deobfuscated PtrStruct4_KM UMVA: 0x%p\n", ptr_struct4_um_va);

    PtrStruct4_KM km_ptr_struct4_copy;
    SIZE_T bytes_read_ps4 = 0;
    status_read = SafeReadUmMemory(target_eprocess_handshake, ptr_struct4_um_va, &km_ptr_struct4_copy, sizeof(PtrStruct4_KM), &bytes_read_ps4);
    if (!NT_SUCCESS(status_read) || bytes_read_ps4 != sizeof(PtrStruct4_KM)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to read PtrStruct4_KM. Status: 0x%X\n", status_read);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status_read);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: Read PtrStruct4_KM.\n");

    obfuscated_next_ptr = (PVOID)km_ptr_struct4_copy.obfuscation_value1;
    shared_comm_block_ptr_candidate = (SharedCommBlock*)((uintptr_t)obfuscated_next_ptr ^ g_km_dynamic_obfuscation_xor_key);
    debug_print("[+] DiscoveryAndAttachmentThread: Candidate SharedCommBlock UMVA: 0x%p\n", shared_comm_block_ptr_candidate);

    if (!shared_comm_block_ptr_candidate) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to deobfuscate SharedCommBlock address (NULL).\n");
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(STATUS_INVALID_ADDRESS);
        return;
    }

    // --- Stage 3: Final Verification of SharedCommBlock signature ---
    // initial_read_head_signature is no longer needed as it was verified against the loaded g_km_dynamic_head_signature.
    // Now verify the signature of the found SharedCommBlock.
    UINT64 final_shared_block_sig_check = 0;
    SIZE_T bytes_read_final_sig = 0;
    status_read = SafeReadUmMemory(target_eprocess_handshake,
                                   &((SharedCommBlock*)shared_comm_block_ptr_candidate)->signature,
                                   &final_shared_block_sig_check,
                                   sizeof(UINT64), &bytes_read_final_sig);

    if (!NT_SUCCESS(status_read) || bytes_read_final_sig != sizeof(UINT64)) {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to read signature from candidate SharedCommBlock. Status: 0x%X\n", status_read);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(status_read);
        return;
    }

    if (final_shared_block_sig_check != g_km_dynamic_shared_comm_block_signature) {
        debug_print("[-] DiscoveryAndAttachmentThread: SharedCommBlock signature mismatch. Expected 0x%llX, Got 0x%llX.\n",
                    g_km_dynamic_shared_comm_block_signature, final_shared_block_sig_check);
        ObDereferenceObject(target_eprocess_handshake);
        PsTerminateSystemThread(STATUS_INVALID_SIGNATURE);
        return;
    }
    debug_print("[+] DiscoveryAndAttachmentThread: SharedCommBlock signature VERIFIED.\n");

    // All checks passed, finalize global setup
    KeAcquireSpinLock(&g_comm_lock, &oldIrql);
    if(g_target_process && g_target_process != target_eprocess_handshake) {
        // This case implies g_target_process was somehow changed or not the one we referenced.
        // To be safe, dereference the g_target_process that we are about to overwrite if it's different.
        // However, target_eprocess_handshake is the one holding the reference taken at the start of this thread.
        ObDereferenceObject(g_target_process);
    }
    g_target_process = target_eprocess_handshake;
    // The reference from target_eprocess_handshake is now "owned" by the global g_target_process.
    // So, we do not dereference target_eprocess_handshake if we reach this point.

    g_um_shared_comm_block_ptr = shared_comm_block_ptr_candidate;
    g_km_thread_should_run = TRUE;

    if (g_pPollingWorkItem == NULL) {
        g_pPollingWorkItem = (PWORK_QUEUE_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(WORK_QUEUE_ITEM), 'WkIt');
    }

    if (g_pPollingWorkItem) {
        ExInitializeWorkItem(g_pPollingWorkItem, KmPollingWorkItemCallback, NULL);
        ExQueueWorkItem(g_pPollingWorkItem, DelayedWorkQueue);
        debug_print("[+] DiscoveryAndAttachmentThread: Polling work item queued.\n");
    } else {
        debug_print("[-] DiscoveryAndAttachmentThread: Failed to allocate polling work item. Polling will not start.\n");
        g_km_thread_should_run = FALSE;
        g_um_shared_comm_block_ptr = NULL;
        ObDereferenceObject(g_target_process); // Release the reference we just gave to g_target_process
        g_target_process = NULL;
    }
    KeReleaseSpinLock(&g_comm_lock, oldIrql);

    debug_print("[+] DiscoveryAndAttachmentThread: Setup successful. Thread will exit (polling is now independent).\n");
}

VOID ProcessSlotRequest(PVOID slot_um_va, PEPROCESS handshake_eprocess) {
    if (!slot_um_va || !handshake_eprocess) {
        debug_print("[-] ProcessSlotRequest: Invalid parameters (slot_um_va or handshake_eprocess is NULL).\n");
        return;
    }

    CommunicationSlot km_slot_copy;
    NTSTATUS status;
    SIZE_T bytes_processed;
    PEPROCESS command_target_eprocess = NULL; // EPROCESS for the command's target PID

    // Read the slot using the handshake_eprocess context
    status = SafeReadUmMemory(handshake_eprocess, slot_um_va, &km_slot_copy, sizeof(CommunicationSlot), &bytes_processed);
    if (!NT_SUCCESS(status) || bytes_processed != sizeof(CommunicationSlot)) {
        debug_print("[-] ProcessSlotRequest: Failed to read slot from UMVA 0x%p using handshake_eprocess. Status: 0x%X, BytesRead: %zu\n", slot_um_va, status, bytes_processed);
        return;
    }

    if (km_slot_copy.status != SlotStatus::UM_REQUEST_PENDING) {
        return;
    }
    debug_print("[+] ProcessSlotRequest: Picked up pending request ID %u from UMVA 0x%p.\n", km_slot_copy.request_id, slot_um_va);

    UINT8 current_chacha_key[32];
    UINT8 current_poly_key[32];
    if (g_km_dynamic_obfuscation_xor_key == 0) {
        debug_print("[-] ProcessSlotRequest: g_km_dynamic_obfuscation_xor_key is 0. Cannot derive crypto keys for request ID %u.\n", km_slot_copy.request_id);
        km_slot_copy.result_status_code = STATUS_INVALID_KEY;
        km_slot_copy.status = SlotStatus::KM_COMPLETED_ERROR;
        // Write error back using handshake_eprocess context
        SafeWriteUmMemory(handshake_eprocess, slot_um_va, &km_slot_copy, sizeof(CommunicationSlot), NULL);
        return;
    }
    DeriveKeys(g_km_dynamic_obfuscation_xor_key, km_slot_copy.request_id, current_chacha_key, current_poly_key);

    // AAD for Request Decryption: request_id (4) + command_id (4) + process_id (8) + param_size (4) = 20 bytes
    UINT8 aad_buffer_request[20];
    UINT32 current_req_aad_offset = 0;
    Serialize_UINT32_KM(aad_buffer_request + current_req_aad_offset, km_slot_copy.request_id);
    current_req_aad_offset += sizeof(km_slot_copy.request_id);
    Serialize_UINT32_KM(aad_buffer_request + current_req_aad_offset, (UINT32)km_slot_copy.command_id); // command_id is enum, cast to UINT32
    current_req_aad_offset += sizeof(km_slot_copy.command_id);
    Serialize_UINT64_KM(aad_buffer_request + current_req_aad_offset, km_slot_copy.process_id);
    current_req_aad_offset += sizeof(km_slot_copy.process_id);
    Serialize_UINT32_KM(aad_buffer_request + current_req_aad_offset, km_slot_copy.param_size);
    current_req_aad_offset += sizeof(km_slot_copy.param_size);

    NTSTATUS decrypt_status;
    if (km_slot_copy.param_size > 0) {
        decrypt_status = StandardLib_ChaCha20_Decrypt_KM(current_chacha_key, km_slot_copy.nonce, aad_buffer_request, current_req_aad_offset, km_slot_copy.parameters, km_slot_copy.param_size, km_slot_copy.parameters, km_slot_copy.mac_tag);
    } else {
        // If param_size is 0, still need to verify tag against AAD
        UINT8 dummy_plaintext; // Decrypt needs a non-null buffer, even for 0 size
        decrypt_status = StandardLib_ChaCha20_Decrypt_KM(current_chacha_key, km_slot_copy.nonce, aad_buffer_request, current_req_aad_offset, NULL, 0, &dummy_plaintext, km_slot_copy.mac_tag);
    }

    if (!NT_SUCCESS(decrypt_status)) {
        debug_print("[-] ProcessSlotRequest: ChaCha20-Poly1305 decryption/tag verification FAILED for request ID %u. Status: 0x%X\n", km_slot_copy.request_id, decrypt_status);
        km_slot_copy.result_status_code = (decrypt_status == STATUS_AUTH_TAG_MISMATCH) ? STATUS_MAC_INCORRECT : decrypt_status;
        km_slot_copy.status = SlotStatus::KM_COMPLETED_ERROR;
        SafeWriteUmMemory(handshake_eprocess, slot_um_va, &km_slot_copy, sizeof(CommunicationSlot), NULL);
        return;
    }
    debug_print("[+] ProcessSlotRequest: ChaCha20-Poly1305 DECRYPTED and VERIFIED parameters for request ID %u, size: %u\n", km_slot_copy.request_id, km_slot_copy.param_size);

    // Lookup the target process for the command
    status = PsLookupProcessByProcessId((HANDLE)km_slot_copy.process_id, &command_target_eprocess);
    if (!NT_SUCCESS(status) || !command_target_eprocess) {
        debug_print("[-] ProcessSlotRequest: Failed to lookup command target process PID %llu. Status: 0x%X\n", km_slot_copy.process_id, status);
        km_slot_copy.result_status_code = NT_SUCCESS(status) ? STATUS_PROCESS_IS_TERMINATING : status; // If lookup success but eprocess is NULL
        km_slot_copy.status = SlotStatus::KM_COMPLETED_ERROR;
        // No command_target_eprocess to dereference here
    } else {
        // Successfully looked up command_target_eprocess
        km_slot_copy.status = SlotStatus::KM_PROCESSING_REQUEST;
        NTSTATUS status_write_processing = SafeWriteUmMemory(handshake_eprocess,
                                   &((CommunicationSlot*)slot_um_va)->status,
                                   &km_slot_copy.status,
                                   sizeof(km_slot_copy.status),
                                   &bytes_processed);
        if (!NT_SUCCESS(status_write_processing) || bytes_processed != sizeof(km_slot_copy.status)) {
            debug_print("[-] ProcessSlotRequest: Failed to write KM_PROCESSING_REQUEST status for ReqID %u. Status: 0x%X\n", km_slot_copy.request_id, status_write_processing);
            // Continue to process the command if possible, but log this failure.
        }

        km_slot_copy.output_size = 0;
        RtlZeroMemory(km_slot_copy.output, sizeof(km_slot_copy.output));
        km_slot_copy.result_status_code = STATUS_UNSUCCESSFUL; // Default for command execution

        debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Entering command processing for PID %llu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.process_id);

        switch (km_slot_copy.command_id) {
            case CommCommand::REQUEST_READ_MEMORY: {
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - REQUEST_READ_MEMORY.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            if (km_slot_copy.param_size != (sizeof(UINT64) + sizeof(UINT64))) {
                km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Param size mismatch. Expected %zu, Got %u.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, (sizeof(UINT64) + sizeof(UINT64)), km_slot_copy.param_size);
                break;
            }

            UINT64 address_to_read = 0;
            UINT64 size_to_read_u64 = 0;
            memcpy(&address_to_read, km_slot_copy.parameters, sizeof(UINT64));
            memcpy(&size_to_read_u64, km_slot_copy.parameters + sizeof(UINT64), sizeof(UINT64));
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Addr: 0x%llX, Size: %llu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, address_to_read, size_to_read_u64);

            if (address_to_read == 0) {
                km_slot_copy.result_status_code = STATUS_INVALID_PARAMETER_1;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Address to read is NULL.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                break;
            }
            if (size_to_read_u64 == 0 || size_to_read_u64 > sizeof(km_slot_copy.output)) {
                km_slot_copy.result_status_code = STATUS_INVALID_BUFFER_SIZE;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Invalid read size %llu. Max output: %zu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, size_to_read_u64, sizeof(km_slot_copy.output));
                break;
            }
            UINT32 size_to_read = static_cast<UINT32>(size_to_read_u64);

            status = driver::read_mem(command_target_eprocess, (PVOID)address_to_read, km_slot_copy.output, size_to_read);
            if (NT_SUCCESS(status)) {
                km_slot_copy.output_size = size_to_read;
                km_slot_copy.result_status_code = STATUS_SUCCESS;
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Read %u bytes from 0x%llX successfully.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, size_to_read, address_to_read);
            } else {
                km_slot_copy.output_size = 0;
                km_slot_copy.result_status_code = status;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - driver::read_mem failed. Status: 0x%X.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, status);
            }
            break;
        }
        case CommCommand::REQUEST_WRITE_MEMORY: {
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - REQUEST_WRITE_MEMORY.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            UINT32 header_size = sizeof(UINT64) + sizeof(UINT64);
            if (km_slot_copy.param_size <= header_size) {
                km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Param size %u too small for headers (must be > %u).\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.param_size, header_size);
                break;
            }

            UINT64 address_to_write = 0;
            UINT64 size_to_write_u64 = 0;
            memcpy(&address_to_write, km_slot_copy.parameters, sizeof(UINT64));
            memcpy(&size_to_write_u64, km_slot_copy.parameters + sizeof(UINT64), sizeof(UINT64));
             debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Addr: 0x%llX, Size: %llu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, address_to_write, size_to_write_u64);

            if (address_to_write == 0) {
                 km_slot_copy.result_status_code = STATUS_INVALID_PARAMETER_1;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Address to write is NULL.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                 break;
            }
            UINT32 actual_data_size_in_params = km_slot_copy.param_size - header_size;
            if (size_to_write_u64 == 0 || size_to_write_u64 > actual_data_size_in_params) {
                 km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Write size %llu mismatch with param data size %u or zero size.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, size_to_write_u64, actual_data_size_in_params);
                 break;
            }
            UINT32 size_to_write = static_cast<UINT32>(size_to_write_u64);

            PVOID data_to_write = km_slot_copy.parameters + header_size;
            status = driver::write_mem(command_target_eprocess, (PVOID)address_to_write, data_to_write, size_to_write);
            if (NT_SUCCESS(status)) {
                 km_slot_copy.output_size = size_to_write;
                 km_slot_copy.result_status_code = STATUS_SUCCESS;
                 debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Wrote %u bytes to 0x%llX successfully.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, size_to_write, address_to_write);
            } else {
                km_slot_copy.output_size = 0;
                km_slot_copy.result_status_code = status;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - driver::write_mem failed. Status: 0x%X.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, status);
            }
            break;
        }
        case CommCommand::REQUEST_GET_MODULE_BASE: {
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - REQUEST_GET_MODULE_BASE.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            if (km_slot_copy.param_size < sizeof(WCHAR) || km_slot_copy.param_size > (sizeof(km_slot_copy.parameters)) || (km_slot_copy.param_size % sizeof(WCHAR) != 0) ) {
                 km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Invalid param_size %u for module name.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.param_size);
                 break;
            }

            PWCHAR module_name_buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, km_slot_copy.param_size + sizeof(WCHAR), 'NmBf');
            if (!module_name_buffer) {
                 km_slot_copy.result_status_code = STATUS_INSUFFICIENT_RESOURCES;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Failed to allocate buffer for module name.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                 break;
            }
            RtlZeroMemory(module_name_buffer, km_slot_copy.param_size + sizeof(WCHAR));
            memcpy(module_name_buffer, km_slot_copy.parameters, km_slot_copy.param_size);

            UNICODE_STRING module_name_us;
            RtlInitUnicodeString(&module_name_us, module_name_buffer);
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Module: %wZ.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, &module_name_us);


            PVOID module_base = NULL;
            if (PsGetProcessWow64Process(command_target_eprocess) != NULL) {
                 debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Target is WOW64, calling GetModuleBasex86.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                module_base = (PVOID)GetModuleBasex86(command_target_eprocess, module_name_us);
            } else {
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Target is x64, calling GetModuleBasex64.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                module_base = (PVOID)GetModuleBasex64(command_target_eprocess, module_name_us);
            }

            if (module_base) {
                memcpy(km_slot_copy.output, &module_base, sizeof(PVOID));
                km_slot_copy.output_size = sizeof(PVOID);
                km_slot_copy.result_status_code = STATUS_SUCCESS;
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Module %wZ found at 0x%p.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, &module_name_us, module_base);
            } else {
                km_slot_copy.result_status_code = STATUS_NOT_FOUND;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Module %wZ not found.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, &module_name_us);
            }
            ExFreePoolWithTag(module_name_buffer, 'NmBf');
            break;
        }
        case CommCommand::REQUEST_AOB_SCAN: {
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - REQUEST_AOB_SCAN.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            UINT32 header_size = sizeof(UINT64) + sizeof(UINT64);
            if (km_slot_copy.param_size <= header_size) {
                km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Param size %u too small for headers + pattern.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.param_size);
                break;
            }

            UINT64 start_scan_addr = 0;
            UINT64 scan_len = 0;
            memcpy(&start_scan_addr, km_slot_copy.parameters, sizeof(UINT64));
            memcpy(&scan_len, km_slot_copy.parameters + sizeof(UINT64), sizeof(UINT64));

            char* pattern_scan_str = (char*)(km_slot_copy.parameters + header_size);
            UINT32 actual_pattern_len_with_null = km_slot_copy.param_size - header_size;

            BOOLEAN found_null = FALSE;
            for(UINT32 i = 0; i < actual_pattern_len_with_null; ++i) {
                if (pattern_scan_str[i] == '\0') {
                    found_null = TRUE;
                    break;
                }
            }
            if (!found_null) {
                 km_slot_copy.result_status_code = STATUS_INVALID_PARAMETER;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - AOB pattern not null-terminated within param_size.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                 break;
            }
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - StartAddr: 0x%llX, ScanLen: %llu, Pattern: \"%s\".\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, start_scan_addr, scan_len, pattern_scan_str);

            UINT64 found_at_umva = 0;
            SIZE_T num_found = 0;
            status = AobScanProcessRanges(command_target_eprocess, start_scan_addr, start_scan_addr + scan_len,
                                          pattern_scan_str, &found_at_umva, 1, &num_found);
            if (NT_SUCCESS(status) && num_found > 0) {
                memcpy(km_slot_copy.output, &found_at_umva, sizeof(UINT64));
                km_slot_copy.output_size = sizeof(UINT64);
                km_slot_copy.result_status_code = STATUS_SUCCESS;
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - AOB Pattern found at 0x%llX.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, found_at_umva);
            } else {
                km_slot_copy.result_status_code = NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - AOB Pattern not found or error. ScanStatus: 0x%X, NumFound: %zu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, status, num_found);
            }
            break;
        }
        case CommCommand::REQUEST_ALLOCATE_MEMORY: {
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - REQUEST_ALLOCATE_MEMORY.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            if (km_slot_copy.param_size != (sizeof(UINT64) + sizeof(UINT64))) {
                 km_slot_copy.result_status_code = STATUS_INFO_LENGTH_MISMATCH;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Invalid param_size %u. Expected %zu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.param_size, (sizeof(UINT64) + sizeof(UINT64)));
                 break;
            }

            UINT64 alloc_size = 0;
            UINT64 hint_addr = 0;
            memcpy(&alloc_size, km_slot_copy.parameters, sizeof(UINT64));
            memcpy(&hint_addr, km_slot_copy.parameters + sizeof(UINT64), sizeof(UINT64));
            debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - AllocSize: %llu, HintAddr: 0x%llX.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, alloc_size, hint_addr);

            if (alloc_size == 0) {
                km_slot_copy.result_status_code = STATUS_INVALID_PARAMETER_1;
                debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Allocation size is zero.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                break;
            }

            PVOID allocated_base = NULL;
            if (hint_addr != 0) {
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Attempting allocation near hint 0x%llX.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, hint_addr);
                status = AllocateMemoryNearEx(command_target_eprocess, (PVOID)hint_addr, (SIZE_T)alloc_size, &allocated_base);
            } else {
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Attempting general allocation (no hint).\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
                status = AllocateExecutableMemory(command_target_eprocess, &allocated_base, (SIZE_T)alloc_size);
            }

            if (NT_SUCCESS(status) && allocated_base) {
                memcpy(km_slot_copy.output, &allocated_base, sizeof(PVOID));
                km_slot_copy.output_size = sizeof(PVOID);
                km_slot_copy.result_status_code = STATUS_SUCCESS;
                debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Memory allocated at 0x%p, Size: %llu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, allocated_base, alloc_size);
            } else {
                 km_slot_copy.output_size = 0;
                 km_slot_copy.result_status_code = status;
                 debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Failed to allocate memory. Status: 0x%X.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, status);
            }
            break;
        }
        case IOCTL_REQUEST_UNLOAD_DRIVER: {
            debug_print("[+] HandshakeDeviceControl: IOCTL_REQUEST_UNLOAD_DRIVER received from PID %lu.\n", (ULONG)(ULONG_PTR)PsGetProcessId(callingProcess));
            // Security check: Potentially verify if the calling process has the necessary privileges (e.g., admin).
            // This can be done using SePrivilegeCheck or by checking the SID of the caller.
            // For this example, we assume that the IOCTL's SDDL in IoCreateDeviceSecure handles sufficient access control.

            PrepareForUnload(); // Call the function to quiesce driver activities
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0; // No data to return for this IOCTL
            debug_print("[+] HandshakeDeviceControl: IOCTL_REQUEST_UNLOAD_DRIVER processed successfully.\n");
            break;
        }
        default:
            km_slot_copy.result_status_code = STATUS_NOT_IMPLEMENTED;
            debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Unimplemented command_id.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
            break;
    }

        if (command_target_eprocess) {
            ObDereferenceObject(command_target_eprocess);
            command_target_eprocess = NULL;
        }
    } // End of else block for successful PsLookupProcessByProcessId

    // Determine final slot status based on result_status_code
    if (NT_SUCCESS(km_slot_copy.result_status_code)) {
        km_slot_copy.status = SlotStatus::KM_COMPLETED_SUCCESS;
    } else {
        // If status was already KM_COMPLETED_ERROR from PsLookup failure, it remains.
        // Otherwise, set it for command execution failures.
        if (km_slot_copy.status != SlotStatus::KM_COMPLETED_ERROR) {
             km_slot_copy.status = SlotStatus::KM_COMPLETED_ERROR;
        }
    }
    debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Command processing finished. Result status: 0x%X, Slot status: %u.\n",
        (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, (NTSTATUS)km_slot_copy.result_status_code, (UINT32)km_slot_copy.status);

    GenerateNonce_KM(km_slot_copy.nonce, sizeof(km_slot_copy.nonce), km_slot_copy.request_id);
    debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Generated new nonce for response.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);

    // AAD for Response Encryption: request_id (4) + output_size (4) + result_status_code (8) = 16 bytes
    UINT8 aad_buffer_response[16];
    UINT32 current_resp_aad_offset = 0;
    Serialize_UINT32_KM(aad_buffer_response + current_resp_aad_offset, km_slot_copy.request_id);
    current_resp_aad_offset += sizeof(km_slot_copy.request_id);
    Serialize_UINT32_KM(aad_buffer_response + current_resp_aad_offset, km_slot_copy.output_size);
    current_resp_aad_offset += sizeof(km_slot_copy.output_size);
    Serialize_UINT64_KM(aad_buffer_response + current_resp_aad_offset, km_slot_copy.result_status_code);
    current_resp_aad_offset += sizeof(km_slot_copy.result_status_code);

    if (km_slot_copy.output_size > 0) {
        StandardLib_ChaCha20_Encrypt_KM(current_chacha_key, km_slot_copy.nonce, aad_buffer_response, current_resp_aad_offset, km_slot_copy.output, km_slot_copy.output_size, km_slot_copy.output, km_slot_copy.mac_tag);
        debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - ChaCha20-Poly1305 ENCRYPTED output and generated MAC_TAG, size: %u.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, km_slot_copy.output_size);
    } else {
        // Even if output_size is 0, generate a tag for the AAD
        StandardLib_ChaCha20_Encrypt_KM(current_chacha_key, km_slot_copy.nonce, aad_buffer_response, current_resp_aad_offset, NULL, 0, NULL, km_slot_copy.mac_tag);
        debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - No output data to encrypt, but generated MAC_TAG for AAD.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
    }
    // StandardLib_Poly1305_MAC_KM is removed. Tag is generated by Encrypt_KM.

    // Write the final slot back using the handshake_eprocess context
    status = SafeWriteUmMemory(handshake_eprocess, slot_um_va, &km_slot_copy, sizeof(CommunicationSlot), &bytes_processed);
    if (!NT_SUCCESS(status) || bytes_processed != sizeof(CommunicationSlot)) {
        debug_print("[-] ProcessSlotRequest: CMD %u (ReqID %u) - Failed to write updated slot to UM using handshake_eprocess. Status: 0x%X, BytesWritten: %zu.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id, status, bytes_processed);
    } else {
        debug_print("[+] ProcessSlotRequest: CMD %u (ReqID %u) - Successfully updated slot in UM using handshake_eprocess.\n", (UINT32)km_slot_copy.command_id, km_slot_copy.request_id);
    }
}

VOID KmPollingWorkItemCallback(PVOID Parameter) {
    UNREFERENCED_PARAMETER(Parameter);

    KIRQL oldIrql;
    PEPROCESS local_handshake_process = NULL; // Renamed for clarity
    PVOID local_shared_comm_block_um_va = NULL;
    BOOLEAN request_processed_this_cycle = FALSE;

    KeAcquireSpinLock(&g_comm_lock, &oldIrql);
    PWORK_QUEUE_ITEM current_work_item_global_ptr_copy = g_pPollingWorkItem;
    if (!g_km_thread_should_run || !g_target_process || !g_um_shared_comm_block_ptr) {
        KeReleaseSpinLock(&g_comm_lock, oldIrql);
        return;
    }
    ObReferenceObject(g_target_process);
    local_handshake_process = g_target_process; // This is the process that initiated the handshake
    local_shared_comm_block_um_va = g_um_shared_comm_block_ptr;
    KeReleaseSpinLock(&g_comm_lock, oldIrql);

    if (!local_handshake_process || !local_shared_comm_block_um_va) {
        if (local_handshake_process) ObDereferenceObject(local_handshake_process);
        return;
    }

    UINT64 signature_from_um = 0;
    UINT32 obfuscated_km_slot_idx_read;
    UINT32 km_slot_idx_from_um;
    NTSTATUS status_read_sig;
    SIZE_T bytes_read_sig;

    status_read_sig = SafeReadUmMemory(local_handshake_process,
                                   &((SharedCommBlock*)local_shared_comm_block_um_va)->signature,
                                   &signature_from_um,
                                   sizeof(UINT64), &bytes_read_sig);
    if (!NT_SUCCESS(status_read_sig) || bytes_read_sig != sizeof(UINT64) || signature_from_um != g_km_dynamic_shared_comm_block_signature) {
        debug_print("[-] KmPollingWorkItemCallback: Failed to read valid signature from UM. ReadSig: 0x%llX, Expected: 0x%llX, Status: 0x%X\n", signature_from_um, g_km_dynamic_shared_comm_block_signature, status_read_sig);
        ObDereferenceObject(local_handshake_process);
        goto requeue_logic_label;
    }

    UINT64 honeypot_value_from_um = 0;
    SIZE_T bytes_read_honeypot = 0;
    const UINT64 EXPECTED_HONEYPOT_VALUE = 0xABADC0DED00DFEEDULL;
    NTSTATUS status_read_honeypot = SafeReadUmMemory(local_handshake_process,
                                   &((SharedCommBlock*)local_shared_comm_block_um_va)->honeypot_field,
                                   &honeypot_value_from_um, sizeof(UINT64), &bytes_read_honeypot);
    if (!NT_SUCCESS(status_read_honeypot) || bytes_read_honeypot != sizeof(UINT64)) {
        debug_print("[-] KmPollingWorkItemCallback: Failed to read honeypot field. Status: 0x%X\n", status_read_honeypot);
        ObDereferenceObject(local_handshake_process);
        goto requeue_logic_label;
    }
    if (honeypot_value_from_um != EXPECTED_HONEYPOT_VALUE) {
        debug_print("[!] KmPollingWorkItemCallback: Honeypot field mismatch! Expected 0x%llX, Got 0x%llX. Potential tampering. Halting polling.\n", EXPECTED_HONEYPOT_VALUE, honeypot_value_from_um);
        KeAcquireSpinLock(&g_comm_lock, &oldIrql);
        g_km_thread_should_run = FALSE;
        KeReleaseSpinLock(&g_comm_lock, oldIrql);
        ObDereferenceObject(local_handshake_process);
        return;
    }

    NTSTATUS status_read_idx;
    SIZE_T bytes_read_idx;
    status_read_idx = SafeReadUmMemory(local_handshake_process,
                                   &((SharedCommBlock*)local_shared_comm_block_um_va)->km_slot_index,
                                   &obfuscated_km_slot_idx_read,
                                   sizeof(UINT32), &bytes_read_idx);
    if (!NT_SUCCESS(status_read_idx) || bytes_read_idx != sizeof(UINT32)) {
        debug_print("[-] KmPollingWorkItemCallback: Failed to read obfuscated km_slot_index from UM. Status: 0x%X\n", status_read_idx);
        ObDereferenceObject(local_handshake_process);
        goto requeue_logic_label;
    }

    UINT64 sig_km = g_km_dynamic_shared_comm_block_signature;
    UINT32 derived_index_xor_key_poll = (UINT32)(sig_km & 0xFFFFFFFF) ^ (UINT32)(sig_km >> 32);
    if (g_km_dynamic_shared_comm_block_signature == 0) {
         debug_print("[-] KmPollingWorkItemCallback: g_km_dynamic_shared_comm_block_signature is 0 for index deobfuscation. Critical error.\n");
         ObDereferenceObject(local_handshake_process);
         goto requeue_logic_label;
    }
    km_slot_idx_from_um = DeobfuscateSlotIndex(obfuscated_km_slot_idx_read, derived_index_xor_key_poll);

    PVOID current_slot_um_va = (PVOID)&((SharedCommBlock*)local_shared_comm_block_um_va)->slots[km_slot_idx_from_um % g_max_comm_slots];
    SlotStatus current_slot_status_from_um;
    NTSTATUS status_read_slot_status;
    SIZE_T bytes_read_slot_status;
    status_read_slot_status = SafeReadUmMemory(local_handshake_process,
                                   &((CommunicationSlot*)current_slot_um_va)->status,
                                   &current_slot_status_from_um,
                                   sizeof(SlotStatus), &bytes_read_slot_status);

    if (!NT_SUCCESS(status_read_slot_status) || bytes_read_slot_status != sizeof(SlotStatus)) {
        debug_print("[-] KmPollingWorkItemCallback: Failed to read slot status from UMVA 0x%p. Status: 0x%X\n", current_slot_um_va, status_read_slot_status);
        ObDereferenceObject(local_handshake_process);
        goto requeue_logic_label;
    }

    if (current_slot_status_from_um == SlotStatus::UM_REQUEST_PENDING) {
        ProcessSlotRequest(current_slot_um_va, local_handshake_process); // Pass handshake_eprocess for slot R/W context
        request_processed_this_cycle = TRUE;

        UINT32 next_km_slot_idx_plain = (km_slot_idx_from_um + 1) % g_max_comm_slots;
        UINT32 obfuscated_next_km_slot_idx = ObfuscateSlotIndex(next_km_slot_idx_plain, derived_index_xor_key_poll);

        NTSTATUS status_write_idx = SafeWriteUmMemory(local_handshake_process,
                                                &((SharedCommBlock*)local_shared_comm_block_um_va)->km_slot_index,
                                                &obfuscated_next_km_slot_idx,
                                                sizeof(UINT32), NULL);
        if (!NT_SUCCESS(status_write_idx)) {
            debug_print("[-] KmPollingWorkItemCallback: Failed to write updated obfuscated km_slot_index to UM. Status: 0x%X\n", status_write_idx);
        }
    }

    ObDereferenceObject(local_handshake_process);
    local_handshake_process = NULL;

requeue_logic_label:
    if (local_handshake_process) {
        ObDereferenceObject(local_handshake_process);
        local_handshake_process = NULL;
    }

    ULONG current_delay_ms;
    if (request_processed_this_cycle) {
        InterlockedExchange(&g_consecutive_idle_polls, 0);
        current_delay_ms = BASE_POLLING_DELAY_MS;
    } else {
        LONG idle_count = InterlockedIncrement(&g_consecutive_idle_polls);
        if (idle_count > MAX_IDLE_POLLS_BEFORE_INCREASE) {
            ULONG additional_delay = min((idle_count - MAX_IDLE_POLLS_BEFORE_INCREASE) / 10, MAX_POLLING_DELAY_MS - BASE_POLLING_DELAY_MS);
            current_delay_ms = BASE_POLLING_DELAY_MS + additional_delay;
            current_delay_ms = min(current_delay_ms, MAX_POLLING_DELAY_MS);
        } else {
            current_delay_ms = BASE_POLLING_DELAY_MS;
        }
    }

    ULONG jitter_ms = GetRandomJitter(POLLING_JITTER_MS);
    current_delay_ms += jitter_ms;
    if (current_delay_ms < 1) current_delay_ms = 1;

    KeAcquireSpinLock(&g_comm_lock, &oldIrql);
    if (g_km_thread_should_run && g_pPollingWorkItem != NULL && g_pPollingWorkItem == current_work_item_global_ptr_copy ) {
        LARGE_INTEGER delay_interval;
        delay_interval.QuadPart = RELATIVE_MILLISECONDS(current_delay_ms);
        KeReleaseSpinLock(&g_comm_lock, oldIrql);

        KeDelayExecutionThread(KernelMode, FALSE, &delay_interval);

        KeAcquireSpinLock(&g_comm_lock, &oldIrql);
        if (g_km_thread_should_run && g_pPollingWorkItem != NULL && g_pPollingWorkItem == current_work_item_global_ptr_copy) {
             ExQueueWorkItem(g_pPollingWorkItem, DelayedWorkQueue);
        }
    }
    KeReleaseSpinLock(&g_comm_lock, oldIrql);
}


// --- START: ChaCha20 Implementation (COMMENTED OUT) ---
/*
#define U32_TO_LE(x) (x) // Assuming little-endian environment for kernel
#define LE_TO_U32(x) (x)

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QUARTER_ROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTATE_LEFT(d, 16); \
    c += d; b ^= c; b = ROTATE_LEFT(b, 12); \
    a += b; d ^= a; d = ROTATE_LEFT(d, 8);  \
    c += d; b ^= c; b = ROTATE_LEFT(b, 7)

typedef struct {
    UINT32 state[16];
    UINT8 keystream_block[64];
    UINT32 block_counter_low; // Lower 32 bits of a 64-bit counter
    UINT32 block_counter_high; // Higher 32 bits of a 64-bit counter
} chacha20_context_km;

static void chacha20_block_km(chacha20_context_km* ctx, UINT32 output[16]) {
    UINT32 x[16];
    int i;

    for (i = 0; i < 16; ++i) {
        x[i] = ctx->state[i];
    }

    for (i = 0; i < 20; i += 2) { // 10 double rounds
        // Odd round
        QUARTER_ROUND(x[0], x[4], x[8],  x[12]);
        QUARTER_ROUND(x[1], x[5], x[9],  x[13]);
        QUARTER_ROUND(x[2], x[6], x[10], x[14]);
        QUARTER_ROUND(x[3], x[7], x[11], x[15]);
        // Even round
        QUARTER_ROUND(x[0], x[5], x[10], x[15]);
        QUARTER_ROUND(x[1], x[6], x[11], x[12]);
        QUARTER_ROUND(x[2], x[7], x[8],  x[13]);
        QUARTER_ROUND(x[3], x[4], x[9],  x[14]);
    }

    for (i = 0; i < 16; ++i) {
        output[i] = x[i] + ctx->state[i];
    }
}

static void chacha20_setup_km(chacha20_context_km* ctx, const UINT8* key, UINT32 key_len, const UINT8* nonce, UINT32 nonce_len, UINT64 counter) {
    if (key_len != 32) {
        // Handle error: Key length must be 256 bits (32 bytes)
        // For simplicity in this context, we might assume correct usage or add debug prints.
        // In a real scenario, return an error or use a default/fallback.
        debug_print("[-] chacha20_setup_km: Invalid key length %u. Expected 32 bytes.\n", key_len);
        // Setting a zero key for now to indicate failure, though this is not ideal for security.
        RtlZeroMemory(ctx->state, sizeof(ctx->state));
        ctx->state[0] = 0xDEADBEE0; // Magic number to indicate error state
        return;
    }

    ctx->state[0] = 0x61707865; // "expa"
    ctx->state[1] = 0x3320646e; // "nd 3"
    ctx->state[2] = 0x79622d32; // "2-by"
    ctx->state[3] = 0x6b206574; // "te k"

    // Key (256-bit)
    ctx->state[4]  = LE_TO_U32(((UINT32*)key)[0]);
    ctx->state[5]  = LE_TO_U32(((UINT32*)key)[1]);
    ctx->state[6]  = LE_TO_U32(((UINT32*)key)[2]);
    ctx->state[7]  = LE_TO_U32(((UINT32*)key)[3]);
    ctx->state[8]  = LE_TO_U32(((UINT32*)key)[4]);
    ctx->state[9]  = LE_TO_U32(((UINT32*)key)[5]);
    ctx->state[10] = LE_TO_U32(((UINT32*)key)[6]);
    ctx->state[11] = LE_TO_U32(((UINT32*)key)[7]);

    ctx->block_counter_low = (UINT32)(counter & 0xFFFFFFFF);
    ctx->block_counter_high = (UINT32)(counter >> 32); // Should be 0 for ChaCha20 as per RFC 8439 (block counter is 32-bit)

    ctx->state[12] = ctx->block_counter_low;

    if (nonce_len == 12) { // 96-bit nonce
        ctx->state[13] = LE_TO_U32(((UINT32*)nonce)[0]);
        ctx->state[14] = LE_TO_U32(((UINT32*)nonce)[1]);
        ctx->state[15] = LE_TO_U32(((UINT32*)nonce)[2]);
    } else if (nonce_len == 8) { // 64-bit nonce (IETF legacy)
        // For 64-bit nonces, counter is typically split.
        // However, RFC8439 specifies 96-bit nonce and 32-bit counter for state[12].
        // This example prioritizes RFC8439. If 8-byte nonce is critical, state setup needs adjustment.
        // For now, let's assume 12-byte nonce is used as per the CommunicationSlot struct.
        // Pad with zeros or handle as error if strict adherence to a specific 8-byte nonce scheme is needed.
        debug_print("[-] chacha20_setup_km: Nonce length is 8 bytes. Expected 12 bytes. Padding with 0 for now.\n");
        ctx->state[13] = LE_TO_U32(((UINT32*)nonce)[0]);
        ctx->state[14] = LE_TO_U32(((UINT32*)nonce)[1]);
        ctx->state[15] = 0; // Or some other padding/error indication
    } else {
        // Handle error: Invalid nonce length
        debug_print("[-] chacha20_setup_km: Invalid nonce length %u. Expected 12 bytes.\n", nonce_len);
        ctx->state[13] = 0xDEADBEE1; // Magic numbers
        ctx->state[14] = 0xDEADBEE2;
        ctx->state[15] = 0xDEADBEE3;
        return;
    }
}

static void chacha20_keystream_block_km(chacha20_context_km* ctx) {
    UINT32 block_output[16];
    chacha20_block_km(ctx, block_output);

    for (int i = 0; i < 16; ++i) {
        ((UINT32*)ctx->keystream_block)[i] = U32_TO_LE(block_output[i]);
    }

    ctx->state[12]++; // Increment block counter (low part)
    if (ctx->state[12] == 0) { // Check for overflow
        ctx->state[13]++; // Increment high part of counter (nonce part if using 64-bit counter scheme, or just part of nonce field)
                          // For RFC8439's 32-bit counter, overflow into state[13] is not standard.
                          // This would typically mean the counter has wrapped, which is > 256GB of data.
                          // For this implementation, we'll assume state[12] is the sole block counter.
                          // If state[13] needs to be part of a larger counter, the spec changes.
        // According to RFC 8439, the block counter is only state[12].
        // If it wraps, that's fine, it just means a lot of data has been processed.
        // No need to increment state[13] which is part of the nonce.
    }
}

// Actual ChaCha20 encryption/decryption function
// Output buffer can be the same as input buffer for in-place operation
static void chacha20_process_km(const UINT8* key, const UINT8* nonce, UINT32 nonce_len, UINT64 initial_counter,
                               const UINT8* input, UINT8* output, UINT32 data_size) {
    chacha20_context_km ctx;
    UINT32 keystream_pos = 64; // Start as if the block is already used up to trigger generation

    // Key length is fixed at 32 bytes for ChaCha20. Nonce is 12 bytes.
    chacha20_setup_km(&ctx, key, 32, nonce, nonce_len, initial_counter);
    if (ctx.state[0] == 0xDEADBEE0) { // Check for setup error
        debug_print("[-] chacha20_process_km: Context setup failed (key error). Zeroing output.\n");
        if (output != input) RtlZeroMemory(output, data_size); // Avoid zeroing input if in-place
        return;
    }
    if (ctx.state[13] == 0xDEADBEE1) { // Check for setup error
        debug_print("[-] chacha20_process_km: Context setup failed (nonce error). Zeroing output.\n");
        if (output != input) RtlZeroMemory(output, data_size);
        return;
    }


    for (UINT32 i = 0; i < data_size; ++i) {
        if (keystream_pos >= 64) {
            chacha20_keystream_block_km(&ctx);
            keystream_pos = 0;
        }
        output[i] = input[i] ^ ctx.keystream_block[keystream_pos];
        keystream_pos++;
    }
}
*/
// --- END: ChaCha20 Implementation (COMMENTED OUT) ---

// --- START: Serialization Helpers KM ---
static inline void Serialize_UINT32_KM(UINT8* dest, UINT32 val) {
    memcpy(dest, &val, sizeof(UINT32));
}
static inline void Serialize_UINT64_KM(UINT8* dest, UINT64 val) {
    memcpy(dest, &val, sizeof(UINT64));
}
// --- END: Serialization Helpers KM ---

// --- START: Standard Library Crypto Implementations (CNG) ---
VOID StandardLib_ChaCha20_Encrypt_KM(UINT8* key_bytes, UINT8* nonce, const UINT8* aad_data, UINT32 aad_data_size, UINT8* buffer_plaintext, UINT32 plaintext_size, UINT8* buffer_ciphertext, UINT8* output_tag_16_bytes) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    ULONG cbResult = 0;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo); // Zeros and sets cbSize, dwInfoVersion

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_CHACHA20_POLY1305_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        debug_print("[-] StandardLib_ChaCha20_Encrypt_KM: BCryptOpenAlgorithmProvider failed 0x%X\n", status);
        if (buffer_ciphertext != buffer_plaintext && plaintext_size > 0) memcpy(buffer_ciphertext, buffer_plaintext, plaintext_size);
        if (output_tag_16_bytes) RtlZeroMemory(output_tag_16_bytes, 16);
        return;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key_bytes, 32, 0);
    if (!NT_SUCCESS(status)) {
        debug_print("[-] StandardLib_ChaCha20_Encrypt_KM: BCryptGenerateSymmetricKey failed 0x%X\n", status);
        if (buffer_ciphertext != buffer_plaintext && plaintext_size > 0) memcpy(buffer_ciphertext, buffer_plaintext, plaintext_size);
        if (output_tag_16_bytes) RtlZeroMemory(output_tag_16_bytes, 16);
        goto Cleanup;
    }

    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;
    authInfo.pbAuthData = (PUCHAR)aad_data; // Cast from const UINT8*
    authInfo.cbAuthData = aad_data_size;
    authInfo.pbTag = output_tag_16_bytes;
    authInfo.cbTag = 16;
    // authInfo.pbMacContext, cbMacContext, dwFlags remain 0 / NULL as per BCRYPT_INIT_AUTH_MODE_INFO

    status = BCryptEncrypt(hKey, buffer_plaintext, plaintext_size, &authInfo, NULL, 0, buffer_ciphertext, plaintext_size, &cbResult, 0);
    if (!NT_SUCCESS(status)) {
        debug_print("[-] StandardLib_ChaCha20_Encrypt_KM: BCryptEncrypt failed 0x%X\n", status);
        if (buffer_ciphertext != buffer_plaintext && plaintext_size > 0) memcpy(buffer_ciphertext, buffer_plaintext, plaintext_size);
        if (output_tag_16_bytes) RtlZeroMemory(output_tag_16_bytes, 16); // Ensure tag is zero on error
    } else if (cbResult != plaintext_size) {
        debug_print("[-] StandardLib_ChaCha20_Encrypt_KM: BCryptEncrypt cbResult mismatch. Expected %u, Got %lu\n", plaintext_size, cbResult);
        if (buffer_ciphertext != buffer_plaintext && plaintext_size > 0) memcpy(buffer_ciphertext, buffer_plaintext, plaintext_size);
        if (output_tag_16_bytes) RtlZeroMemory(output_tag_16_bytes, 16);
    }

Cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
}

NTSTATUS StandardLib_ChaCha20_Decrypt_KM(UINT8* key_bytes, UINT8* nonce, const UINT8* aad_data, UINT32 aad_data_size, UINT8* buffer_ciphertext, UINT32 ciphertext_size, UINT8* buffer_plaintext, UINT8* input_tag_16_bytes) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    ULONG cbResult = 0;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_CHACHA20_POLY1305_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        debug_print("[-] StandardLib_ChaCha20_Decrypt_KM: BCryptOpenAlgorithmProvider failed 0x%X\n", status);
        if (buffer_plaintext != buffer_ciphertext && ciphertext_size > 0) memcpy(buffer_plaintext, buffer_ciphertext, ciphertext_size);
        return status;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key_bytes, 32, 0);
    if (!NT_SUCCESS(status)) {
        debug_print("[-] StandardLib_ChaCha20_Decrypt_KM: BCryptGenerateSymmetricKey failed 0x%X\n", status);
        if (buffer_plaintext != buffer_ciphertext && ciphertext_size > 0) memcpy(buffer_plaintext, buffer_ciphertext, ciphertext_size);
        goto Cleanup;
    }

    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;
    authInfo.pbAuthData = (PUCHAR)aad_data; // Cast from const UINT8*
    authInfo.cbAuthData = aad_data_size;
    authInfo.pbTag = input_tag_16_bytes; // Input tag for verification
    authInfo.cbTag = 16;
    // authInfo.pbMacContext, cbMacContext, dwFlags remain 0 / NULL

    status = BCryptDecrypt(hKey, buffer_ciphertext, ciphertext_size, &authInfo, NULL, 0, buffer_plaintext, ciphertext_size, &cbResult, 0);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_AUTH_TAG_MISMATCH) {
             debug_print("[-] StandardLib_ChaCha20_Decrypt_KM: BCryptDecrypt failed - STATUS_AUTH_TAG_MISMATCH (Tag verification failed)\n");
        } else {
             debug_print("[-] StandardLib_ChaCha20_Decrypt_KM: BCryptDecrypt failed 0x%X\n", status);
        }
        if (buffer_plaintext != buffer_ciphertext && ciphertext_size > 0) memcpy(buffer_plaintext, buffer_ciphertext, ciphertext_size); // Or zero out plaintext
    } else if (cbResult != ciphertext_size) {
        debug_print("[-] StandardLib_ChaCha20_Decrypt_KM: BCryptDecrypt cbResult mismatch. Expected %u, Got %lu\n", ciphertext_size, cbResult);
        if (buffer_plaintext != buffer_ciphertext && ciphertext_size > 0) memcpy(buffer_plaintext, buffer_ciphertext, ciphertext_size);
        status = STATUS_DATA_ERROR; // Indicate a data error if sizes don't match
    }

Cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

// StandardLib_Poly1305_MAC_KM and StandardLib_Poly1305_Verify_KM (formerly HMAC-SHA256 based) are removed.
// ChaCha20-Poly1305 AEAD handles authentication directly.

// --- END: Standard Library Crypto Implementations (CNG) ---


// --- START: ChaCha20 and Poly1305 Stubs ---
// MODIFIED DeriveKeys Function
VOID DeriveKeys(UINT64 base_key, UINT32 request_id, UINT8* chacha_key) {
    RtlZeroMemory(chacha_key, 32);

    UINT64 temp_key_material[4];
    temp_key_material[0] = base_key;
    temp_key_material[1] = base_key ^ 0xAAAAAAAAAAAAAAAA;
    temp_key_material[2] = base_key ^ request_id;
    temp_key_material[3] = base_key ^ 0x5555555555555555;

    for (int i = 0; i < 32; ++i) {
        chacha_key[i] = ((UINT8*)&temp_key_material[0])[i % 8] ^
                        ((UINT8*)&temp_key_material[1])[(i + 1) % 8] ^
                        ((UINT8*)&temp_key_material[2])[(i + 2) % 8] ^
                        ((UINT8*)&temp_key_material[3])[(i + 3) % 8] ^
                        (UINT8)(i + 0xAB + (request_id & 0xFF));
    }

    RtlSecureZeroMemory(temp_key_material, sizeof(temp_key_material));
}

// Helper function to generate a byte of keystream for ChaCha20 placeholder
VOID generate_placeholder_keystream_byte(UINT8 key_byte, UINT8 nonce_byte, UINT8 counter_byte, UINT8 prev_keystream_byte, UINT8* out_keystream_byte) {
    *out_keystream_byte = key_byte ^ nonce_byte ^ counter_byte ^ prev_keystream_byte;
}

// Symmetric ChaCha20 placeholder (encryption) - COMMENTED OUT, replaced by StandardLib_ChaCha20_Encrypt_KM
/*
VOID chacha20_encrypt_placeholder(UINT8* key, UINT8* nonce, UINT8* buffer_to_encrypt_in_place, UINT32 data_size, UINT8* output_unused_if_inplace) {
    // UNREFERENCED_PARAMETER(output_unused_if_inplace); // Will be used if not in-place
    // The nonce for CommunicationSlot is 12 bytes.
    // The initial counter for ChaCha20 is usually 0 or 1. For AEAD, it's often 1 for the encryption part after Poly1305 key gen.
    // Here, we'll use 0 as a default initial block counter for simplicity, as per typical ChaCha20 stream usage.
    // If output_unused_if_inplace is different from buffer_to_encrypt_in_place, then it's not in-place.
    if (output_unused_if_inplace != buffer_to_encrypt_in_place && output_unused_if_inplace != NULL) {
        chacha20_process_km(key, nonce, 12, 0, buffer_to_encrypt_in_place, output_unused_if_inplace, data_size);
    } else { // In-place
        chacha20_process_km(key, nonce, 12, 0, buffer_to_encrypt_in_place, buffer_to_encrypt_in_place, data_size);
    }
}
*/

// Symmetric ChaCha20 placeholder (decryption) - COMMENTED OUT, replaced by StandardLib_ChaCha20_Decrypt_KM
/*
VOID chacha20_decrypt_placeholder(UINT8* key, UINT8* nonce, UINT8* buffer_to_decrypt_in_place, UINT32 data_size, UINT8* output_unused_if_inplace) {
    // UNREFERENCED_PARAMETER(output_unused_if_inplace); // Will be used if not in-place
    // Same logic as encryption for ChaCha20
    if (output_unused_if_inplace != buffer_to_decrypt_in_place && output_unused_if_inplace != NULL) {
        chacha20_process_km(key, nonce, 12, 0, buffer_to_decrypt_in_place, output_unused_if_inplace, data_size);
    } else { // In-place
        chacha20_process_km(key, nonce, 12, 0, buffer_to_decrypt_in_place, buffer_to_decrypt_in_place, data_size);
    }
}
*/

// MODIFIED GenerateNonce_KM (formerly GenerateNonce)
VOID GenerateNonce_KM(UINT8* nonce_buffer, UINT32 size, UINT32 request_id) {
    if (size == 0 || nonce_buffer == NULL) return;

    NTSTATUS status = BCryptGenRandom(
        NULL, // No specific algorithm provider handle, use system default RNG
        nonce_buffer,
        size,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (!NT_SUCCESS(status)) {
        // Fallback or error logging if BCryptGenRandom fails
        // For simplicity in this step, we might just zero the buffer or use the old method as a fallback
        // However, a real implementation should handle this failure robustly.
        debug_print("[-] GenerateNonce_KM: BCryptGenRandom failed with status 0x%X. Zeroing nonce.\n", status);
        RtlZeroMemory(nonce_buffer, size);
        // As a minimal fallback, XOR with request_id to ensure some variability if BCrypt fails
        // This is not ideal but better than an all-zero or static nonce on failure.
        for (UINT32 i = 0; i < size; ++i) {
            nonce_buffer[i] ^= (UINT8)((request_id >> ((i % 4) * 8)) & 0xFF);
        }
    } else {
        // Optionally, still mix in request_id to ensure deterministic difference for different request_ids
        // even if BCryptGenRandom somehow outputted the same sequence (highly unlikely).
        // This step can be debated; a good CSPRNG should make this unnecessary.
        // For this example, let's add it for demonstration of the idea.
        for (UINT32 i = 0; i < size; ++i) {
            nonce_buffer[i] ^= (UINT8)((request_id >> ((i % 4) * 8)) & 0xFF);
        }
    }
}
// --- END: ChaCha20 and Poly1305 Stubs ---

// const UINT32 INDEX_XOR_KEY_DERIVATION_MASK = 0xABCDEF01; // Removed

__forceinline UINT32 ObfuscateSlotIndex(UINT32 index, UINT32 key) {
    return index ^ key;
}

__forceinline UINT32 DeobfuscateSlotIndex(UINT32 obfuscated_index, UINT32 key) {
    return obfuscated_index ^ key;
}

NTSTATUS IrpPassthroughHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);
    NTSTATUS status = STATUS_SUCCESS;
    debug_print("[+] Kernel Component: driver_main entered.\n");

    UNICODE_STRING sddl_admin_system_all;
    RtlInitUnicodeString(&sddl_admin_system_all, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"); // Grant Generic All to System and Built-in Administrators

    KeInitializeEvent(&g_handshake_completed_event, NotificationEvent, FALSE);

    g_handshake_device_name_us.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, sizeof(g_handshake_device_name_buffer), 'DevN');
    if (!g_handshake_device_name_us.Buffer) {
        debug_print("[-] driver_main: Failed to allocate buffer for handshake device name.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        RtlCopyMemory(g_handshake_device_name_us.Buffer, g_handshake_device_name_buffer, sizeof(g_handshake_device_name_buffer));
        g_handshake_device_name_us.Length = sizeof(g_handshake_device_name_buffer) - sizeof(WCHAR);
        g_handshake_device_name_us.MaximumLength = sizeof(g_handshake_device_name_buffer);
    }

    if(NT_SUCCESS(status)) {
        g_handshake_symlink_name_us.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, sizeof(g_handshake_symlink_name_buffer), 'SymL');
        if (!g_handshake_symlink_name_us.Buffer) {
            debug_print("[-] driver_main: Failed to allocate buffer for handshake symlink name.\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            if (g_handshake_device_name_us.Buffer) ExFreePoolWithTag(g_handshake_device_name_us.Buffer, 'DevN');
            g_handshake_device_name_us.Buffer = NULL;
        } else {
            RtlCopyMemory(g_handshake_symlink_name_us.Buffer, g_handshake_symlink_name_buffer, sizeof(g_handshake_symlink_name_buffer));
            g_handshake_symlink_name_us.Length = sizeof(g_handshake_symlink_name_buffer) - sizeof(WCHAR);
            g_handshake_symlink_name_us.MaximumLength = sizeof(g_handshake_symlink_name_buffer);
        }
    }

    if (NT_SUCCESS(status)) {
        status = IoCreateDeviceSecure(
            driver_object,
            0, // DeviceExtensionSize
            &g_handshake_device_name_us,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN, // DeviceCharacteristics
            FALSE, // Exclusive
            &sddl_admin_system_all, // DefaultSDDL
            NULL, // DeviceClassGuid
            &g_pHandshakeDeviceObject
        );

        if (!NT_SUCCESS(status)) {
            debug_print("[-] driver_main: Failed to create secure handshake device object. Status: 0x%X\n", status);
            if (g_handshake_device_name_us.Buffer) ExFreePoolWithTag(g_handshake_device_name_us.Buffer, 'DevN');
            if (g_handshake_symlink_name_us.Buffer) ExFreePoolWithTag(g_handshake_symlink_name_us.Buffer, 'SymL');
            g_handshake_device_name_us.Buffer = NULL;
            g_handshake_symlink_name_us.Buffer = NULL;
            g_pHandshakeDeviceObject = NULL;
        } else {
            debug_print("[+] driver_main: Handshake device object created successfully.\n");
            status = IoCreateSymbolicLink(&g_handshake_symlink_name_us, &g_handshake_device_name_us);
            if (!NT_SUCCESS(status)) {
                debug_print("[-] driver_main: Failed to create symbolic link for handshake device. Status: 0x%X\n", status);
                IoDeleteDevice(g_pHandshakeDeviceObject);
                g_pHandshakeDeviceObject = NULL;
                if (g_handshake_device_name_us.Buffer) ExFreePoolWithTag(g_handshake_device_name_us.Buffer, 'DevN');
                if (g_handshake_symlink_name_us.Buffer) ExFreePoolWithTag(g_handshake_symlink_name_us.Buffer, 'SymL');
                g_handshake_device_name_us.Buffer = NULL;
                g_handshake_symlink_name_us.Buffer = NULL;
            } else {
                debug_print("[+] driver_main: Symbolic link for handshake device created successfully.\n");
            }
        }
    } else {
        debug_print("[-] driver_main: Skipping handshake device creation due to buffer allocation failures.\n");
    }

    KeInitializeSpinLock(&g_comm_lock);

    g_discovery_thread_should_run = TRUE;
    OBJECT_ATTRIBUTES oa_discovery;
    InitializeObjectAttributes(&oa_discovery, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    if (NT_SUCCESS(status)) {
        NTSTATUS thread_status = PsCreateSystemThread(
            &g_discovery_thread_handle, (ACCESS_MASK)0, &oa_discovery,
            (HANDLE)0, NULL, DiscoveryAndAttachmentThread, NULL );

        if (!NT_SUCCESS(thread_status)) {
            debug_print("[-] driver_main: Failed to create DiscoveryAndAttachmentThread! Status: 0x%X\n", thread_status);
            g_discovery_thread_handle = NULL;
            status = thread_status;
        } else {
            debug_print("[+] driver_main: DiscoveryAndAttachmentThread created successfully.\n");
        }
    }


    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        driver_object->MajorFunction[i] = IrpPassthroughHandler;
    }
    driver_object->MajorFunction[IRP_MJ_CREATE] = IrpPassthroughHandler;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = IrpPassthroughHandler;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandshakeDeviceControl;

    driver_object->DriverUnload = [](PDRIVER_OBJECT drvObj) {
        debug_print("[+] Kernel Component: DriverUnload called.\n");
        UNREFERENCED_PARAMETER(drvObj);

        if (g_discovery_thread_handle) {
            g_discovery_thread_should_run = FALSE;
            PETHREAD discovery_thread_object_ref = NULL;
            NTSTATUS status_ref_discovery = ObReferenceObjectByHandle(
                g_discovery_thread_handle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&discovery_thread_object_ref, NULL);
            if (NT_SUCCESS(status_ref_discovery) && discovery_thread_object_ref) {
                KeWaitForSingleObject(discovery_thread_object_ref, Executive, KernelMode, FALSE, NULL);
                ObDereferenceObject(discovery_thread_object_ref);
                debug_print("[+] DriverUnload: DiscoveryAndAttachmentThread terminated.\n");
            } else {
                debug_print("[-] DriverUnload: Failed to reference/wait for DiscoveryAndAttachmentThread. Status: 0x%X\n", status_ref_discovery);
            }
            ZwClose(g_discovery_thread_handle);
            g_discovery_thread_handle = NULL;
        }

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_comm_lock, &oldIrql);
        g_km_thread_should_run = FALSE;
        PWORK_QUEUE_ITEM localWorkItem = g_pPollingWorkItem;
        g_pPollingWorkItem = NULL;
        KeReleaseSpinLock(&g_comm_lock, oldIrql);

        if (localWorkItem) {
            debug_print("[+] DriverUnload: Signaled polling to stop. Freeing work item structure.\n");
            ExFreePoolWithTag(localWorkItem, 'WkIt');
        }

        PEPROCESS process_to_deref_km = NULL;
        KeAcquireSpinLock(&g_comm_lock, &oldIrql);
        if (g_target_process) {
            process_to_deref_km = g_target_process;
            g_target_process = NULL;
        }
        g_um_shared_comm_block_ptr = NULL;
        KeReleaseSpinLock(&g_comm_lock, oldIrql);

        if (process_to_deref_km) {
            ObDereferenceObject(process_to_deref_km);
            debug_print("[+] DriverUnload: Target process dereferenced.\n");
        }

        if (g_handshake_symlink_name_us.Buffer && g_handshake_symlink_name_us.Length > 0) {
            if(g_pHandshakeDeviceObject != NULL) { // Check if device object exists before trying to delete symlink
                IoDeleteSymbolicLink(&g_handshake_symlink_name_us);
                debug_print("[+] DriverUnload: Handshake symbolic link deleted.\n"); // Changed message for clarity
            }
        }
        if (g_handshake_symlink_name_us.Buffer) {
             ExFreePoolWithTag(g_handshake_symlink_name_us.Buffer, 'SymL');
             g_handshake_symlink_name_us.Buffer = NULL;
             // RtlInitUnicodeString(&g_handshake_symlink_name_us, NULL); // Not strictly needed as buffer is NULL
        }

        if (g_pHandshakeDeviceObject) {
            IoDeleteDevice(g_pHandshakeDeviceObject);
            g_pHandshakeDeviceObject = NULL;
            debug_print("[+] DriverUnload: Handshake device object deleted.\n");  // Changed message for clarity
        }
        if (g_handshake_device_name_us.Buffer) {
            ExFreePoolWithTag(g_handshake_device_name_us.Buffer, 'DevN');
            g_handshake_device_name_us.Buffer = NULL;
            // RtlInitUnicodeString(&g_handshake_device_name_us, NULL); // Not strictly needed
        }

        if (g_obfuscated_ptr1_um_addr_via_handshake) g_obfuscated_ptr1_um_addr_via_handshake = NULL;

        debug_print("[+] Kernel Component: DriverUnload finished.\n");
    };
    return status;
}

NTSTATUS DriverEntry() {
    debug_print("[+] Windows Kernel Audio Component.\n");
    UNICODE_STRING driver_name{};
    RtlInitUnicodeString(&driver_name, L"\\Driver\\SysCoreCom");
    return IoCreateDriver(&driver_name, driver_main);
}
