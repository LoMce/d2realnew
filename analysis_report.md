# Analysis Report for ResponsibleImGui Project

## Introduction

This report provides a comprehensive analysis of the "ResponsibleImGui" project, focusing on its kernel driver and user-mode components. The objective was to examine and rate its stealthiness, functionality, and kernel-user communication mechanisms based on the provided source code (`KM-UM/KM/src/main.cpp`, `KM-UM/UM/src/StealthComm.h`, `ResponsibleImGui/Source/ImGui Standalone/DriverComm.h`) and project documentation (`README.md`).

## Section 1: Driver Loading and Initial Hiding Techniques

The driver employs several techniques to achieve initial stealth upon loading:

*   **Driver Loading (`kdmapper.exe`):**
    *   While the `README.md` did not explicitly mention `kdmapper.exe`, its presence in the `ResponsibleImGui/Source/ImGui Standalone/` directory (as per `ls` output) and the problem description imply its potential use.
    *   Using a known mapper like `kdmapper` offers convenience and features for bypassing Driver Signature Enforcement (DSE) but is a significant detection vector due to its known signatures and patterns. A custom mapper would be stealthier but harder to develop.

*   **Dynamic Naming:**
    *   **Driver Name:** Generated in `DriverEntry` by creating a GUID, taking the first 8 characters, and prepending a static prefix (`L"\\Driver\\SysMod"`). Example: `\Driver\SysModxxxxxxxx`.
    *   **Device and Symbolic Link Names:** Also dynamically generated using prefixes (`L"\\Device\\CoreSysCom_"` and `L"\\DosDevices\\CoreSysComLink_"`) combined with a dynamic component (likely GUID-based), though their exact generation code isn't in `DriverEntry` but is handled before `driver_main` which uses them.
    *   **Effectiveness:** This significantly hinders static detection based on fixed names but the static prefixes could become IOCs.

*   **Randomized Pool Tags:**
    *   Initialized in `DriverEntry`. A random XOR key (`dynamic_pool_xor_key`) is generated and applied to base tags like 'DevN', 'SymL', 'WkIt', 'NmBf'.
    *   **Effectiveness:** Offers moderate stealth against pool scanning tools looking for fixed malicious tags. However, advanced analysis might still group these allocations.

*   **Registry Configuration Storage:**
    *   The function `WriteDynamicConfigToRegistry` stores the dynamic symbolic link name and IOCTL code in the registry at `NEW_REG_PATH` (`L"\Registry\Machine\SOFTWARE\SystemFrameworksSvc\RuntimeState"`).
    *   The path `SystemFrameworksSvc` sounds plausible but doesn't appear to be a standard system path, making it potentially suspicious if monitored.
    *   Storing this configuration is necessary for UM discovery but the registry write itself is a detectable event and a potential point of suspicion. The driver also includes `DeleteDynamicConfigFromRegistry` for cleanup.

*   **Overall Initial Hiding Assessment:**
    *   The combination of dynamic naming and randomized pool tags provides a reasonable defense against immediate static detection.
    *   However, behavioral monitoring (driver load, registry writes), memory analysis (unbacked code sections), and the potential use of a known mapper can still lead to detection.

## Section 2: Kernel-User Communication Channel

The communication between the kernel driver and user-mode application is designed with multiple layers of obfuscation and security:

*   **Handshake Mechanism:**
    1.  **Initiation (UM):** Calls a dynamic IOCTL code (`g_dynamic_handshake_ioctl_code`), retrieved from the registry.
    2.  **Data Sent (UM to KM):** `STEALTH_HANDSHAKE_DATA_UM` structure containing:
        *   `ObfuscatedPtrStruct1HeadUmAddress`: UM Virtual Address (VA) of the first structure in an obfuscated pointer chain.
        *   `VerificationToken`: Initial XOR key.
        *   `BeaconPattern`: Random byte pattern.
        *   `BeaconSalt`: Random 64-bit salt.
    3.  **Beacon Scan (KM):** In `FetchDynamicSignaturesFromProcess`, KM XORs `BeaconPattern` with `BeaconSalt` and performs an AOB scan for this "salted beacon" in the UM process's memory.
    4.  **`DynamicSignaturesRelay` (UM):** The AOB scan locates this structure. KM reads it and de-obfuscates its members (`dynamic_head_signature`, `dynamic_shared_comm_block_signature`, `dynamic_obfuscation_xor_key`) by XORing them with `BeaconSalt`. These become the authoritative session keys/signatures.
    *   **Implications:** Dynamic IOCTL, AOB scan, and salting improve stealth and make automated analysis harder.

*   **Obfuscated Pointer Chain (`DiscoveryAndAttachmentThread`):**
    1.  KM starts with `g_obfuscated_ptr1_um_addr_via_handshake`.
    2.  It reads `PtrStruct1_KM` (kernel's copy), verifies `head_signature` against `g_km_dynamic_head_signature`.
    3.  `PtrStructN_KM.obfuscation_value1` is XORed with the true session key (`g_km_dynamic_obfuscation_xor_key` from `DynamicSignaturesRelay`) to find the UMVA of `PtrStruct(N+1)_UM`.
    4.  This chain (`PtrStruct1` -> `PtrStruct2` -> `PtrStruct3` -> `PtrStruct4`) eventually reveals the UMVA of the `SharedCommBlock`.
    *   **Effectiveness:** Highly effective in obscuring the path to the `SharedCommBlock` from static analysis or manual memory tracing without the session key.

*   **Shared Communication Block (`SharedCommBlock`):**
    *   **Structure:** Contains `signature`, `um_slot_index`, `km_slot_index`, an array of `CommunicationSlot`s, a `honeypot_field`, and `km_fully_initialized_flag`.
    *   **Verification:** `signature` is checked against `g_km_dynamic_shared_comm_block_signature`.
    *   **Honeypot:** `honeypot_field` is verified as `g_km_dynamic_shared_comm_block_signature ^ 0x123456789ABCDEF0ULL`. A simple anti-tampering measure.
    *   **Slot Indices:** `um_slot_index` and `km_slot_index` are obfuscated/de-obfuscated using a key derived from `g_km_dynamic_shared_comm_block_signature` to manage command slots.

*   **Command Encryption (`CommunicationSlot` / `ProcessSlotRequest`):**
    *   **Per-Request Keys:** Unique 32-byte ChaCha20 keys are derived for each command using `DeriveKeys(g_km_dynamic_obfuscation_xor_key, request_id, ...)`.
    *   **AAD:** ChaCha20-Poly1305 uses Additional Authenticated Data (AAD) to protect command metadata (request_id, command_id, PIDs, sizes, status codes) against tampering.
    *   **Nonces:** Unique 12-byte nonces are generated for each encryption operation using `BCryptGenRandom` and XORing with the `request_id`.
    *   **Security:** Provides a high level of security (confidentiality and integrity) for command data, assuming the session key (`g_km_dynamic_obfuscation_xor_key`) is secret.

*   **Overall Communication Assessment:**
    *   Strengths include strong AEAD encryption, per-request keys, a sophisticated handshake, and obfuscation of critical structures.
    *   Weaknesses include reliance on UM integrity during the handshake, registry artifacts, and the simplicity of the honeypot if the driver is reversed.

## Section 3: Core Driver Functionality for Memory Manipulation

The driver provides several core memory manipulation capabilities, primarily handled within `ProcessSlotRequest` by dispatching `CommCommand`s:

*   **`REQUEST_READ_MEMORY`:**
    *   Extracts target address and size from parameters.
    *   Calls `driver::read_mem` (likely wrapping `SafeReadUmMemory`).
    *   Returns data in `km_slot_copy.output`. Limited to `MAX_OUTPUT_SIZE` (256 bytes).

*   **`REQUEST_WRITE_MEMORY`:**
    *   Extracts target address, size, and data to write.
    *   Calls `driver::write_mem` (likely wrapping `SafeWriteUmMemory`).
    *   Write size limited by `MAX_PARAM_SIZE` (256 bytes) minus headers.

*   **`REQUEST_GET_MODULE_BASE`:**
    *   Extracts module name.
    *   Handles WoW64 processes (`PsGetProcessWow64Process`) by calling appropriate utility functions (`GetModuleBasex86` or `GetModuleBasex64`, which are assumed custom implementations for PEB parsing).
    *   Returns base address in `km_slot_copy.output`.

*   **`REQUEST_AOB_SCAN`:**
    *   Extracts start address, scan length, and AOB pattern string.
    *   Calls `AobScanProcessRanges` (custom implementation).
    *   Returns found address in `km_slot_copy.output`.

*   **`REQUEST_ALLOCATE_MEMORY`:**
    *   Extracts allocation size and an optional hint address.
    *   Calls `AllocateMemoryNearEx` (if hint provided) or `AllocateExecutableMemory` (custom implementations, likely using `ZwAllocateVirtualMemory`).
    *   Returns allocated base address in `km_slot_copy.output`.

*   **`REQUEST_FREE_MEMORY`:**
    *   Extracts address to free.
    *   Uses `ObOpenObjectByPointer` to get a target process handle, then `ZwFreeVirtualMemory` with `MEM_RELEASE` flag after attaching to the process.

*   **Safety Measures (`SafeReadUmMemory` / `SafeWriteUmMemory`):**
    *   These crucial utilities use `KeStackAttachProcess` to switch to the target process context.
    *   They employ `ProbeForRead`/`ProbeForWrite` to validate memory accessibility.
    *   Operations are wrapped in `__try`/`__except` blocks to catch exceptions and prevent system crashes, returning error statuses instead.

*   **Overall Functionality Assessment:**
    *   The driver offers a comprehensive suite of essential memory operations for game cheating or process manipulation.
    *   Reliability is enhanced by safety measures in memory access functions.
    *   Limitations include small buffer sizes for read/write operations per request and the absence of direct driver commands for memory protection changes or remote thread creation.

## Section 4: User-Mode Application Structure and Features

The user-mode component, `ResponsibleImGui`, is designed to interact with the kernel driver and provide a user interface:

*   **Application Structure:**
    *   **`Source/ImGui Standalone/`:** Contains the main UI application (`ImGui Standalone.vcxproj`) built with Dear ImGui. This part includes `DriverComm.h`/`.cpp` for interfacing with `StealthComm.h` and also contains `kdmapper.exe` and `KM.sys`, suggesting it handles driver loading.
    *   **`Source/Loader/`:** A separate project (`Loader.vcxproj`) likely responsible for initial tasks like authentication (KeyAuth is mentioned in `README.md`) and potentially updates or pre-loading steps.

*   **Interfacing with the Driver (`DriverComm.h`):**
    *   This header declares functions like `attach_to_process`, `read_memory`, `write_memory`, `get_module_base_info`, `aob_scan_info`, `allocate_memory_ex`, `free_memory_ex`, and `RequestDriverUnload`.
    *   These functions serve as a higher-level API that translates requests into calls to `StealthComm::SubmitRequestAndWait`, sending the appropriate `CommCommand` enum to the driver.

*   **Correlating README Features with Driver Capabilities:**
    *   **Memory Management & AOB Scanning:** Directly map to `REQUEST_READ_MEMORY`, `REQUEST_WRITE_MEMORY`, and `REQUEST_AOB_SCAN`.
    *   **Codecave Injection:** Uses `REQUEST_ALLOCATE_MEMORY` (for executable memory) and `REQUEST_WRITE_MEMORY` (to write shellcode).
    *   **Hotkey System, Teleport Manager:** Primarily UM logic but use driver functions (read/write memory) to interact with game data (e.g., write new coordinates, read/write config values).
    *   **Game Features (Player Management, View Angle Control, Flight System, etc.):** Heavily rely on the driver's memory read/write capabilities to interact with and modify game data structures in real-time.
    *   The driver's capabilities are generally sufficient to support the listed features, with code injection being a key enabler.

*   **Overall Purpose of User-Mode Application:**
    *   `ResponsibleImGui` is primarily a **game cheating tool**.
    *   Its extensive game-specific features (Player Management, Flight System, etc.) and the use of ImGui (common for cheat UIs), along with an authentication system, point towards this purpose rather than a generic memory editing tool.

## Section 5: Ratings and Justification

**Stealthiness Rating: 680 / 1000**

*   **Justification:**
    *   **Positives:** Dynamic naming of driver/device/symlink objects and IOCTL codes, randomized pool tags, and an obfuscated pointer chain with AOB scan for `SharedCommBlock` discovery significantly hinder static analysis and casual detection. Encrypted communication also prevents trivial snooping.
    *   **Negatives:** The most significant detractor is the likely use of a known mapper (`kdmapper.exe`), which is a major detection vector. Registry usage for initial communication setup is an observable event. The driver's code, once mapped, is still discoverable through conventional means (enumerating driver objects, memory scanning for unbacked executable code). The honeypot is simple, and static prefixes in names could become IOCs. Lacks advanced rootkit techniques for deeper hiding.

**Functionality Rating: 800 / 1000**

*   **Justification:**
    *   **Positives:** Provides a robust set of core memory operations: read, write (with safety via `KeStackAttachProcess` and probing), module base retrieval (WoW64 aware), AOB scanning, and memory allocation/freeing in the target process. These primitives effectively support the wide array of game cheating features described in the `README.md`, including "Codecave Injection."
    *   **Negatives/Limitations:** Read/write operations are limited to 256 bytes per request (less for writes due to headers), making bulk transfers inefficient. Lacks direct driver commands for changing memory protection or creating remote threads, which might require more complex user-mode logic or shellcode.

**Communication Rating: 850 / 1000**

*   **Justification:**
    *   **Positives:** Employs strong AEAD encryption (ChaCha20-Poly1305) with per-request key derivation and unique nonces, ensuring confidentiality and integrity of command data. AAD protects metadata. The sophisticated handshake (dynamic IOCTL, AOB scan for `DynamicSignaturesRelay`, salted beacon/relay) and the obfuscated pointer chain for `SharedCommBlock` discovery are very strong for secure session establishment and operational secrecy. Basic integrity checks for the shared block (signature, honeypot) and obfuscated slot indices add further layers.
    *   **Negatives:** The security model heavily relies on the user-mode process being secure during the initial handshake; compromise at this stage could unravel the session security. Registry storage of the initial IOCTL/symlink is a discoverable artifact. The honeypot is simple if the driver binary is analyzed. The complexity, while a strength, could hide implementation flaws.

## Conclusion

The ResponsibleImGui project, including its kernel driver, demonstrates a sophisticated attempt at creating a stealthy and functional game cheating tool. The communication protocol is well-secured with modern encryption and obfuscation techniques. The driver provides essential memory manipulation capabilities. However, its overall stealth is potentially undermined by the use of a known mapper and standard detection vectors like registry artifacts and the discoverability of mapped kernel code. While strong in many aspects, particularly communication security and core functionality, its stealthiness has notable caveats that could be exploited by anti-cheat systems.
