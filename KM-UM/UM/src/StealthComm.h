#pragma once

#include <Windows.h>
#include <cstdint>
#include <atomic>
#include <iostream> // For std::cerr, min/max. Consider alternatives for header.

// Minimal NTSTATUS definitions
#ifndef NTSTATUS
typedef long NTSTATUS;
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT ((NTSTATUS)0x00000102L)
#endif
#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY ((NTSTATUS)0xC0000017L)
#endif
// This one clashes with KM's ntdef.h if this header were ever included in KM.
// For UM only, it's fine. Or use a different name like MY_NT_SUCCESS.
#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif

// NTSTATUS Success Macro (for User Mode) - Retaining MY_NT_SUCCESS for existing uses if any, but prefer NT_SUCCESS
#ifndef MY_NT_SUCCESS
#define MY_NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif


// Stealth Communication Protocol Definitions
#define MAX_COMM_SLOTS 4
// #define SIGNATURE_VALUE 0xDEADBEEFCAFEBABE // Unique signature for shared block - REMOVED for dynamic signature
#define MAX_PARAM_SIZE 256
#define MAX_OUTPUT_SIZE 256

enum class CommCommand : uint32_t {
    REQUEST_NOP = 0,
    REQUEST_READ_MEMORY,
    REQUEST_WRITE_MEMORY,
    REQUEST_GET_MODULE_BASE,
    REQUEST_AOB_SCAN,
    REQUEST_ALLOCATE_MEMORY,
    REQUEST_DISCONNECT, // Added for clean disconnect
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

#pragma pack(push, 1) // Ensure consistent packing with KM
struct CommunicationSlot {
    volatile SlotStatus status;
    uint32_t request_id;
    CommCommand command_id;
    uint64_t process_id;

    uint8_t parameters[MAX_PARAM_SIZE];
    uint32_t param_size;

    uint8_t output[MAX_OUTPUT_SIZE];
    uint32_t output_size;

    uint64_t result_status_code;

    // Added for ChaCha20 + Poly1305
    uint8_t nonce[12]; // ChaCha20 Nonce/IV
    uint8_t mac_tag[16];   // Poly1305 MAC Tag (renamed from mac)
    uint8_t UserPadding1[7]; // Matches KernelPadding1[7]
    uint8_t UserPadding2[13]; // Matches KernelPadding2[13]
};

struct SharedCommBlock {
    volatile uint64_t signature;
    volatile uint32_t um_slot_index;
    volatile uint32_t km_slot_index;
    CommunicationSlot slots[MAX_COMM_SLOTS];
    volatile uint64_t honeypot_field; // Added honeypot field
    volatile ULONG km_fully_initialized_flag; // Added for KM ready signal
    uint8_t UserPaddingBlock[11]; // Matches KernelPaddingBlock[11]
};
#pragma pack(pop) // Restore default packing

namespace StealthComm {

// --- START: Definitions for UM->KM Handshake (must match KM) ---
// These are now dynamically read from the registry in InitializeStealthComm.
// const WCHAR HANDSHAKE_DEVICE_SYMLINK_NAME_UM[] = L"\\\\Global??\\CoreSysComLink_{E7A1B02C-0D9F-45C1-9D8E-F6B5C4A3210F}";
// #define IOCTL_STEALTH_HANDSHAKE_UM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define BEACON_PATTERN_SIZE 16 // Define beacon size

// Structure for handshake data (must match KM)
typedef struct _STEALTH_HANDSHAKE_DATA_UM {
    PVOID ObfuscatedPtrStruct1HeadUmAddress; // UM VA
    UINT64 VerificationToken; // Optional: for UM/KM to verify each other
    UINT8 BeaconPattern[BEACON_PATTERN_SIZE]; // Beacon pattern to help KM find DynamicSignaturesRelay
    UINT64 BeaconSalt; // Added BeaconSalt
} STEALTH_HANDSHAKE_DATA_UM, *PSTEALTH_HANDSHAKE_DATA_UM;
// --- END: Definitions for UM->KM Handshake ---

// Structure to hold dynamic signatures and keys, to be relayed to KM
// The beacon is now the first member, so finding the beacon means finding this struct.
struct DynamicSignaturesRelay {
    UINT8 beacon[BEACON_PATTERN_SIZE]; // This beacon will be AOB scanned by KM
    uint64_t dynamic_head_signature;
    uint64_t dynamic_shared_comm_block_signature;
    uint64_t dynamic_obfuscation_xor_key;
};

// Forward declaration
struct SharedCommBlock;

// Quad Chained Pointer Structures
struct PtrStruct4_UM {
    volatile SharedCommBlock* data_block;
    uint64_t obfuscation_value1;
    uint64_t obfuscation_value2;
};

struct PtrStruct3_UM {
    volatile PtrStruct4_UM* next_ptr_struct;
    uint64_t obfuscation_value1;
    uint64_t obfuscation_value2;
};

struct PtrStruct2_UM {
    volatile PtrStruct3_UM* next_ptr_struct;
    uint64_t obfuscation_value1;
    uint64_t obfuscation_value2;
};

struct PtrStruct1_UM {
    volatile PtrStruct2_UM* next_ptr_struct;
    uint64_t head_signature; // New signature for kernel to find this head
    uint64_t obfuscation_value1;
};

// New signature for the head of the chain
// #define HEAD_SIGNATURE_VALUE 0xABCDEF0123456789 // REMOVED for dynamic signature

extern SharedCommBlock* g_shared_comm_block;
extern std::atomic<uint32_t> g_next_request_id;

NTSTATUS InitializeStealthComm(); // Changed return type from bool to NTSTATUS
void ShutdownStealthComm(); // Added for proper deallocation

// NTSTATUS version of SubmitRequestAndWait - this is the one to keep and use.
// The bool version will be removed from the .cpp file.
NTSTATUS SubmitRequestAndWait(
    CommCommand command,
    uint64_t target_pid,
    const uint8_t* params,
    uint32_t params_size,
    uint8_t* output_buf,
    uint32_t& output_size, // In: max_size, Out: actual_size
    // uint64_t& km_status_code, // Removed, NTSTATUS return is used for overall status
    uint32_t timeout_ms = 5000
);

// Public API functions to be updated to use the NTSTATUS SubmitRequestAndWait
// and return NTSTATUS or handle it internally.

NTSTATUS ReadMemory(uint64_t target_pid, uintptr_t address, void* buffer, size_t size, size_t* bytes_read);
NTSTATUS WriteMemory(uint64_t target_pid, uintptr_t address, const void* buffer, size_t size, size_t* bytes_written);
uintptr_t GetModuleBase(uint64_t target_pid, const wchar_t* module_name); // Returns 0 on failure
uintptr_t AobScan(uint64_t target_pid, uintptr_t start_address, size_t scan_size,
                  const char* pattern, const char* mask,
                  uint8_t* out_saved_bytes, size_t saved_bytes_size); // Returns 0 on failure, saved_bytes not currently filled
uintptr_t AllocateMemory(uint64_t target_pid, size_t size, uintptr_t hint_address = 0); // Returns 0 on failure
NTSTATUS FreeMemory(uint64_t target_pid, uintptr_t address, size_t size);

} // namespace StealthComm
