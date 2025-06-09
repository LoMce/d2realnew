#pragma once
#include <ntifs.h>
#include <windef.h>
#include <stdint.h>

#if DBG // DBG is commonly used for kernel debug builds
#define debug_print(format, ...) DbgPrint(format, __VA_ARGS__)
#else
#define debug_print(format, ...) // Expands to nothing in non-DBG builds
#endif

// New IOCTL for driver unload
// Using METHOD_NEITHER and FILE_ANY_ACCESS is typical for simple trigger IOCTLs
// that don't transfer data and can be called by a privileged user.
// Function code 0x902 should be unique within this driver's IOCTLs.
#define IOCTL_REQUEST_UNLOAD_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_NEITHER, FILE_ANY_ACCESS)

#ifndef MEM_IMAGE
#define MEM_IMAGE    0x1000000
#endif
#ifndef MEM_MAPPED
#define MEM_MAPPED   0x40000
#endif
#ifndef MEM_PRIVATE
#define MEM_PRIVATE  0x20000
#endif

NTSTATUS InstallTrampolineHook(
	PEPROCESS targetProcess,
	uintptr_t targetAddress,
	PVOID hookFunction,
	SIZE_T hookLength,
	uintptr_t* outTrampoline
);

NTSTATUS UninstallHook(PEPROCESS TargetProcess, uintptr_t HookAddress);
//some unexported functions and structs

extern "C" NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(IN PEPROCESS Process);
extern "C" NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(IN PEPROCESS Process);
typedef PVOID(*PFN_PSGETPROCESSWOW64PROCESS)(PEPROCESS Process);

// used to create IOCTL driver compatible with kdmapper
extern "C" NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName,
	PDRIVER_INITIALIZE InitializationFunction);

// used to implement read and write functionality
extern "C" NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
	PEPROCESS TargetProcess, PVOID TargetAddress,
	SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize);

NTSTATUS physical_read_process_memory(HANDLE pid, PVOID source, PVOID destination, SIZE_T size, SIZE_T* bytesRead);

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void); // not exported

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;

typedef struct _PEB32 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;  // in bytes
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;  // LDR_*
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	//    PVOID			LoadedImports;
	//    // seems they are exist only on XP !!! PVOID
	//    EntryPointActivationContext;	// -same-
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// Global Device Object
extern PDEVICE_OBJECT g_device_object;

// Work Item for Polling
typedef struct _KM_POLLING_WORK_ITEM_CONTEXT {
    ULONG_PTR Reserved; // Placeholder for future use
} KM_POLLING_WORK_ITEM_CONTEXT, *PKM_POLLING_WORK_ITEM_CONTEXT;

IO_WORKITEM_ROUTINE KmPollingWorkItemRoutine;
KSTART_ROUTINE KmInitialSetupThread;

// Handle for the setup thread (which queues work items)
extern HANDLE g_km_setup_thread_handle;
// Pointer to the allocated work item
extern PIO_WORKITEM g_polling_work_item;

// --- START: Definitions for UM->KM Handshake (must match UM's STEALTH_HANDSHAKE_DATA_UM) ---
// KM side definition for the data received from User Mode during handshake
#define BEACON_PATTERN_SIZE_KM 16 // Ensure this matches UM's BEACON_PATTERN_SIZE

typedef struct _STEALTH_HANDSHAKE_DATA_KM {
    PVOID ObfuscatedPtrStruct1HeadUmAddress; // UM VA of the PtrStruct1_UM head
    UINT64 VerificationToken;                // Token for UM/KM to verify (e.g., dynamic_obfuscation_xor_key)
    UINT8 BeaconPattern[BEACON_PATTERN_SIZE_KM]; // Beacon pattern from UM to help KM find DynamicSignaturesRelay
    UINT64 BeaconSalt;                       // Salt for the beacon
} STEALTH_HANDSHAKE_DATA_KM, *PSTEALTH_HANDSHAKE_DATA_KM;
// --- END: Definitions for UM->KM Handshake ---


// --- START: Shared Communication Structures ---
// These enums and structs are shared between KM and UM.

#define MAX_COMM_SLOTS_KM 4 // Using a KM-specific define if needed, or ensure UM's MAX_COMM_SLOTS is consistent
#define MAX_PARAM_SIZE_KM 256
#define MAX_OUTPUT_SIZE_KM 256

enum class CommCommand : uint32_t {
    REQUEST_NOP = 0,
    REQUEST_READ_MEMORY,
    REQUEST_WRITE_MEMORY,
    REQUEST_GET_MODULE_BASE,
    REQUEST_AOB_SCAN,
    REQUEST_ALLOCATE_MEMORY,
    REQUEST_DISCONNECT,
    REQUEST_FREE_MEMORY, // Added for freeing memory
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
    uint8_t parameters[MAX_PARAM_SIZE_KM];
    uint32_t param_size;
    uint8_t output[MAX_OUTPUT_SIZE_KM];
    uint32_t output_size;
    uint64_t result_status_code;
    uint8_t nonce[12];
    uint8_t mac_tag[16]; // Changed from mac to mac_tag to match UM
    UINT8 KernelPadding1[7]; // Padding
    UINT8 KernelPadding2[13]; // Padding
};

struct SharedCommBlock {
    volatile uint64_t signature;
    volatile uint32_t um_slot_index;
    volatile uint32_t km_slot_index;
    CommunicationSlot slots[MAX_COMM_SLOTS_KM]; // Use defined constant
    volatile uint64_t honeypot_field;
    volatile ULONG km_fully_initialized_flag; // Added for KM ready signal
    UINT8 KernelPaddingBlock[11]; // Padding for SharedCommBlock
};
#pragma pack(pop)

// --- END: Shared Communication Structures ---


// Shared communication related globals (already defined in main.cpp, declared here for access)
// These are already in main.cpp, ensure they are declared extern if needed across files,
// but for now, this subtask focuses on main.cpp and includes.h for these specific new declarations.

// Global for storing received beacon salt
extern UINT64 g_received_beacon_salt_km;
// Global for the beacon pattern received from UM (potentially to be salted)
extern UINT8 g_received_beacon_pattern_km[BEACON_PATTERN_SIZE_KM];

// Globals for dynamic IOCTL and device/symlink names
extern ULONG g_dynamic_handshake_ioctl_code;
extern WCHAR g_dynamic_device_name_buffer[128];
extern WCHAR g_dynamic_symlink_name_buffer[128];
extern UNICODE_STRING g_dynamic_device_name_us;
extern UNICODE_STRING g_dynamic_symlink_name_us;

// Globals for dynamic driver name
extern UNICODE_STRING g_dynamic_driver_name_us;
extern WCHAR g_dynamic_driver_name_buffer[128];

// Globals for dynamic pool tags
extern ULONG g_pool_tag_devn; // Original: 'DevN'
extern ULONG g_pool_tag_syml; // Original: 'SymL'
extern ULONG g_pool_tag_wkit; // Original: 'WkIt'
extern ULONG g_pool_tag_nmbf; // Original: 'NmBf'

// extern PEPROCESS g_target_process;
// extern PVOID g_um_shared_comm_block_ptr; // This is a UM VA, KM should not dereference directly without care
// extern KSPIN_LOCK g_comm_lock;
// extern BOOLEAN g_km_thread_should_run;
// extern ULONG_PTR g_shared_comm_block_signature; // This is g_km_dynamic_shared_comm_block_signature
// extern ULONG g_max_comm_slots; // This is MAX_COMM_SLOTS_KM