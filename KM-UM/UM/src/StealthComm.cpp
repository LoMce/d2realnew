#include "StealthComm.h"
#include <Windows.h>
#include <bcrypt.h> // For BCryptGenRandom
// Note: Link against bcrypt.lib for BCryptGenRandom
// #include <iostream> // Replaced by Logging.h
#include <vector>
#include <cstring>
// #include <random> // Replaced by GetTickCount64 and simple LCG for nonce
// #include <iomanip> // For std::hex, std::setw, std::setfill - Logging should handle formatting
#include <atomic>  // For g_next_request_id
#include "Logging.h" // Assuming Logging.h is accessible

// Define global variables within the StealthComm namespace
namespace StealthComm {
    // --- START: Slot Index Obfuscation/De-obfuscation Utility (UM) ---
    static uint32_t ObfuscateSlotIndex_UM(uint32_t index, uint32_t key) {
        return index ^ key;
    }

    static uint32_t DeobfuscateSlotIndex_UM(uint32_t obfuscated_index, uint32_t key) {
        return obfuscated_index ^ key;
    }
    // --- END: Slot Index Obfuscation/De-obfuscation Utility (UM) ---

    // --- START: Standard Library Crypto Implementations (UM - CNG) ---
    static void StandardLib_ChaCha20_Encrypt_UM(uint8_t* key_bytes, uint8_t* nonce, const uint8_t* aad_data, uint32_t aad_data_size, uint8_t* buffer_plaintext, uint32_t plaintext_size, uint8_t* buffer_ciphertext, uint8_t* output_tag_16_bytes) {
        NTSTATUS status = 0xC0000001; // STATUS_UNSUCCESSFUL
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        ULONG cbResult = 0;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo); // Zeros and sets cbSize, dwInfoVersion

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_CHACHA20_POLY1305_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
        if (!NT_SUCCESS(status)) {
            LogMessageF("[-] StandardLib_ChaCha20_Encrypt_UM: BCryptOpenAlgorithmProvider failed 0x%lX", status);
            if (buffer_ciphertext != buffer_plaintext && plaintext_size > 0) memcpy(buffer_ciphertext, buffer_plaintext, plaintext_size); // Copy plaintext to ciphertext on error if distinct buffers
            if (output_tag_16_bytes) memset(output_tag_16_bytes, 0, 16); // Zero out tag on error
            return;
        }

        status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key_bytes, 32, 0);
        if (!NT_SUCCESS(status)) {
            LogMessageF("[-] StandardLib_ChaCha20_Encrypt_UM: BCryptGenerateSymmetricKey failed 0x%lX", status);
            if (buffer_ciphertext != buffer_plaintext && plaintext_size > 0) memcpy(buffer_ciphertext, buffer_plaintext, plaintext_size);
            if (output_tag_16_bytes) memset(output_tag_16_bytes, 0, 16);
            goto Cleanup;
        }

        authInfo.pbNonce = nonce;
        authInfo.cbNonce = 12; // Standard ChaCha20 nonce size
        authInfo.pbAuthData = (PUCHAR)aad_data;
        authInfo.cbAuthData = aad_data_size;
        authInfo.pbTag = output_tag_16_bytes;
        authInfo.cbTag = 16; // Standard Poly1305 tag size
        // authInfo.pbMacContext, cbMacContext, dwFlags remain 0 / NULL

        status = BCryptEncrypt(hKey, buffer_plaintext, plaintext_size, &authInfo, NULL, 0, buffer_ciphertext, plaintext_size, &cbResult, 0);
        if (!NT_SUCCESS(status)) {
            LogMessageF("[-] StandardLib_ChaCha20_Encrypt_UM: BCryptEncrypt failed 0x%lX", status);
            if (buffer_ciphertext != buffer_plaintext && plaintext_size > 0) memcpy(buffer_ciphertext, buffer_plaintext, plaintext_size);
            // Tag is already written to by BCryptEncrypt or zeroed by pbTag, but good to be sure on error path
            if (output_tag_16_bytes) memset(output_tag_16_bytes, 0, 16);
        } else if (cbResult != plaintext_size) {
            LogMessageF("[-] StandardLib_ChaCha20_Encrypt_UM: BCryptEncrypt cbResult mismatch. Expected %u, Got %lu", plaintext_size, cbResult);
            // This case might indicate a more severe issue. Consider how to handle.
            // For safety, ensure ciphertext is not partially written or misleading.
            if (buffer_ciphertext != buffer_plaintext && plaintext_size > 0) memcpy(buffer_ciphertext, buffer_plaintext, plaintext_size); // Or zero out ciphertext
            if (output_tag_16_bytes) memset(output_tag_16_bytes, 0, 16);
        }

    Cleanup:
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    static bool StandardLib_ChaCha20_Decrypt_UM(uint8_t* key_bytes, uint8_t* nonce, const uint8_t* aad_data, uint32_t aad_data_size, uint8_t* buffer_ciphertext, uint32_t ciphertext_size, uint8_t* buffer_plaintext, uint8_t* input_tag_16_bytes) {
        NTSTATUS status = 0xC0000001; // STATUS_UNSUCCESSFUL
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        ULONG cbResult = 0;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_CHACHA20_POLY1305_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
        if (!NT_SUCCESS(status)) {
            LogMessageF("[-] StandardLib_ChaCha20_Decrypt_UM: BCryptOpenAlgorithmProvider failed 0x%lX", status);
            if (buffer_plaintext != buffer_ciphertext && ciphertext_size > 0) memcpy(buffer_plaintext, buffer_ciphertext, ciphertext_size); // Copy ciphertext to plaintext on error
            return false;
        }

        status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key_bytes, 32, 0);
        if (!NT_SUCCESS(status)) {
            LogMessageF("[-] StandardLib_ChaCha20_Decrypt_UM: BCryptGenerateSymmetricKey failed 0x%lX", status);
            if (buffer_plaintext != buffer_ciphertext && ciphertext_size > 0) memcpy(buffer_plaintext, buffer_ciphertext, ciphertext_size);
            goto CleanupFalse;
        }

        authInfo.pbNonce = nonce;
        authInfo.cbNonce = 12;
        authInfo.pbAuthData = (PUCHAR)aad_data;
        authInfo.cbAuthData = aad_data_size;
        authInfo.pbTag = input_tag_16_bytes; // Input tag for verification
        authInfo.cbTag = 16;
        // authInfo.pbMacContext, cbMacContext, dwFlags remain 0 / NULL

        status = BCryptDecrypt(hKey, buffer_ciphertext, ciphertext_size, &authInfo, NULL, 0, buffer_plaintext, ciphertext_size, &cbResult, 0);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_AUTH_TAG_MISMATCH) { // 0xC000A002
                LogMessage("[-] StandardLib_ChaCha20_Decrypt_UM: BCryptDecrypt failed - STATUS_AUTH_TAG_MISMATCH (Tag verification failed)");
            } else {
                LogMessageF("[-] StandardLib_ChaCha20_Decrypt_UM: BCryptDecrypt failed 0x%lX", status);
            }
            if (buffer_plaintext != buffer_ciphertext && ciphertext_size > 0) memcpy(buffer_plaintext, buffer_ciphertext, ciphertext_size); // Or zero out plaintext
            goto CleanupFalse;
        } else if (cbResult != ciphertext_size) {
             LogMessageF("[-] StandardLib_ChaCha20_Decrypt_UM: BCryptDecrypt cbResult mismatch. Expected %u, Got %lu", ciphertext_size, cbResult);
             if (buffer_plaintext != buffer_ciphertext && ciphertext_size > 0) memcpy(buffer_plaintext, buffer_ciphertext, ciphertext_size);
             goto CleanupFalse;
        }

        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        return true;

    CleanupFalse:
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // StandardLib_Poly1305_MAC_UM and StandardLib_Poly1305_Verify_UM are removed as ChaCha20-Poly1305 (AEAD) handles this.

    // --- END: Standard Library Crypto Implementations (UM - CNG) ---

    // --- START: Crypto Placeholders (UM) ---
    // Placeholder Key Derivation Function (mirrors KM)
    static void DeriveKeys_UM(UINT64 base_key, UINT32 request_id, uint8_t* chacha_key) {
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

        // Zero out temp_key_material
        volatile PVOID p = temp_key_material; // Ensure memset is not optimized away
        memset((PVOID)p, 0, sizeof(temp_key_material));
    }

    // Placeholder Nonce Generation (mirrors KM)
    static void GenerateNonce_UM(uint8_t* nonce_buffer, uint32_t size, UINT32 request_id) {
        if (size == 0 || nonce_buffer == NULL) return;

        NTSTATUS status = BCryptGenRandom(
            NULL, // No specific algorithm provider handle, use system default RNG
            nonce_buffer,
            size,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (!NT_SUCCESS(status)) {
            // Fallback or error logging if BCryptGenRandom fails
            LogMessageF("[-] GenerateNonce_UM: BCryptGenRandom failed with status 0x%lX. Zeroing nonce.", status);
            memset(nonce_buffer, 0, size);
            // As a minimal fallback, XOR with request_id
            for (UINT32 i = 0; i < size; ++i) {
                nonce_buffer[i] ^= (UINT8)((request_id >> ((i % 4) * 8)) & 0xFF);
            }
        } else {
            // Optionally, still mix in request_id
            for (UINT32 i = 0; i < size; ++i) {
                nonce_buffer[i] ^= (UINT8)((request_id >> ((i % 4) * 8)) & 0xFF);
            }
        }
    }

    // Commented out placeholder functions (chacha20_encrypt_placeholder_UM, chacha20_decrypt_placeholder_UM,
    // poly1305_mac_placeholder_UM, poly1305_verify_placeholder_UM) are removed.
    // --- END: Crypto Placeholders (UM) ---

    DynamicSignaturesRelay g_dynamic_signatures_relay_data;
    SharedCommBlock* g_shared_comm_block = nullptr;
    std::atomic<uint32_t> g_next_request_id(1);
    PtrStruct1_UM* g_ptr_struct1_head_um = nullptr;
    PtrStruct2_UM* g_ptr_struct2_um = nullptr;
    PtrStruct3_UM* g_ptr_struct3_um = nullptr;
    PtrStruct4_UM* g_ptr_struct4_um = nullptr;

    // ... (Serialization functions - UNCHANGED) ...
    static void Serialize_uint64(uint8_t* dest, uint64_t val) {
        memcpy(dest, &val, sizeof(uint64_t));
    }

    static uint64_t Deserialize_uint64(const uint8_t* src) {
        uint64_t val;
        memcpy(&val, src, sizeof(uint64_t));
        return val;
    }

    static void Serialize_wstring(uint8_t* dest, const wchar_t* str, uint32_t& actual_size_bytes) {
        if (!str) {
            actual_size_bytes = 0;
            return;
        }
        actual_size_bytes = (static_cast<uint32_t>(wcslen(str)) + 1) * sizeof(wchar_t);
        if (actual_size_bytes > MAX_PARAM_SIZE) {
            actual_size_bytes = MAX_PARAM_SIZE - (MAX_PARAM_SIZE % sizeof(wchar_t));
             if (actual_size_bytes > 0) {
                memcpy(dest, str, actual_size_bytes - sizeof(wchar_t));
                reinterpret_cast<wchar_t*>(dest)[(actual_size_bytes / sizeof(wchar_t)) - 1] = L'\0';
            } else {
                 actual_size_bytes = 0;
            }
            LogMessage("[!] Serialize_wstring: Warning - WString too long, truncated.");
            return;
        }
        memcpy(dest, str, actual_size_bytes);
    }

    // ... (InitializeStealthComm - UNCHANGED) ...
    NTSTATUS InitializeStealthComm() {
        if (g_shared_comm_block != nullptr) {
            LogMessage("[-] InitializeStealthComm: Attempted to re-initialize while already active. Call ShutdownStealthComm first.");
            return 0xC00000AA; // STATUS_ALREADY_INITIALIZED
        }
        // std::random_device rd; // Not needed if mt19937_64 is seeded differently or not used for these specific globals
        // std::mt19937_64 gen(rd());
        // Using GetTickCount64 for seed to avoid potential issues with std::random_device availability/quality in some environments
        std::mt19937_64 gen(GetTickCount64());
        std::uniform_int_distribution<uint64_t> distrib(1, UINT64_MAX);

        do { g_dynamic_signatures_relay_data.dynamic_head_signature = distrib(gen); } while (g_dynamic_signatures_relay_data.dynamic_head_signature == 0);
        do { g_dynamic_signatures_relay_data.dynamic_shared_comm_block_signature = distrib(gen); } while (g_dynamic_signatures_relay_data.dynamic_shared_comm_block_signature == 0);
        do { g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key = distrib(gen); } while (g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key == 0);

        uint64_t beacon_part1 = g_dynamic_signatures_relay_data.dynamic_head_signature ^ 0xFFEEDDCCBBAA9988ULL;
        uint64_t beacon_part2 = g_dynamic_signatures_relay_data.dynamic_shared_comm_block_signature ^ 0x1122334455667700ULL;

        memset(g_dynamic_signatures_relay_data.beacon, 0, BEACON_PATTERN_SIZE);
        if (BEACON_PATTERN_SIZE >= sizeof(uint64_t)) {
            memcpy(g_dynamic_signatures_relay_data.beacon, &beacon_part1, sizeof(uint64_t));
        }
        if (BEACON_PATTERN_SIZE >= 2 * sizeof(uint64_t)) {
            memcpy(g_dynamic_signatures_relay_data.beacon + sizeof(uint64_t), &beacon_part2, sizeof(uint64_t));
        }
        for(int i=0; i < BEACON_PATTERN_SIZE; ++i) {
            if(g_dynamic_signatures_relay_data.beacon[i] == 0) {
                g_dynamic_signatures_relay_data.beacon[i] = (uint8_t)((distrib(gen) % 255) + 1);
            }
        }

        g_shared_comm_block = static_cast<SharedCommBlock*>(VirtualAlloc(
            nullptr, sizeof(SharedCommBlock), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ));
        if (!g_shared_comm_block) {
            LogMessage("[-] InitializeStealthComm: Failed to allocate memory for SharedCommBlock.");
            return STATUS_NO_MEMORY; // Or a more specific error for VirtualAlloc failure
        }

        uint64_t sig_um = g_dynamic_signatures_relay_data.dynamic_shared_comm_block_signature;
        uint32_t derived_index_xor_key_um_init = (uint32_t)(sig_um & 0xFFFFFFFF) ^ (uint32_t)(sig_um >> 32);
        if (g_dynamic_signatures_relay_data.dynamic_shared_comm_block_signature == 0) {
            LogMessage("[-] InitializeStealthComm: dynamic_shared_comm_block_signature is 0. Cannot derive index XOR key.");
            VirtualFree(g_shared_comm_block, 0, MEM_RELEASE);
            g_shared_comm_block = nullptr;
            return STATUS_INVALID_PARAMETER; // Or a custom error
        }

        g_shared_comm_block->signature = g_dynamic_signatures_relay_data.dynamic_shared_comm_block_signature;
        g_shared_comm_block->um_slot_index = ObfuscateSlotIndex_UM(0, derived_index_xor_key_um_init);
        g_shared_comm_block->km_slot_index = 0;
        g_shared_comm_block->honeypot_field = 0xABADC0DED00DFEEDULL; // KM Expected Value
        g_shared_comm_block->km_fully_initialized_flag = 0; // Explicitly initialize to 0

        for (int i = 0; i < MAX_COMM_SLOTS; ++i) {
            g_shared_comm_block->slots[i].status = SlotStatus::EMPTY;
            g_shared_comm_block->slots[i].request_id = 0;
        }

        g_ptr_struct4_um = static_cast<PtrStruct4_UM*>(VirtualAlloc(nullptr, sizeof(PtrStruct4_UM), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!g_ptr_struct4_um) { ShutdownStealthComm(); return STATUS_NO_MEMORY; }
        g_ptr_struct4_um->data_block = g_shared_comm_block;
        g_ptr_struct4_um->obfuscation_value2 = 0;

        g_ptr_struct3_um = static_cast<PtrStruct3_UM*>(VirtualAlloc(nullptr, sizeof(PtrStruct3_UM), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!g_ptr_struct3_um) { ShutdownStealthComm(); return STATUS_NO_MEMORY; }
        g_ptr_struct3_um->next_ptr_struct = g_ptr_struct4_um;
        g_ptr_struct3_um->obfuscation_value2 = 0;

        g_ptr_struct2_um = static_cast<PtrStruct2_UM*>(VirtualAlloc(nullptr, sizeof(PtrStruct2_UM), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!g_ptr_struct2_um) { ShutdownStealthComm(); return STATUS_NO_MEMORY; }
        g_ptr_struct2_um->next_ptr_struct = g_ptr_struct3_um;
        g_ptr_struct2_um->obfuscation_value2 = 0;

        g_ptr_struct1_head_um = static_cast<PtrStruct1_UM*>(VirtualAlloc(nullptr, sizeof(PtrStruct1_UM), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!g_ptr_struct1_head_um) { ShutdownStealthComm(); return STATUS_NO_MEMORY; }
        g_ptr_struct1_head_um->next_ptr_struct = g_ptr_struct2_um;
        g_ptr_struct1_head_um->head_signature = g_dynamic_signatures_relay_data.dynamic_head_signature;

        g_ptr_struct1_head_um->obfuscation_value1 = (uint64_t)(g_ptr_struct1_head_um->next_ptr_struct) ^ g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key;
        g_ptr_struct2_um->obfuscation_value1 = (uint64_t)(g_ptr_struct2_um->next_ptr_struct) ^ g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key;
        g_ptr_struct3_um->obfuscation_value1 = (uint64_t)(g_ptr_struct3_um->next_ptr_struct) ^ g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key;
        g_ptr_struct4_um->obfuscation_value1 = (uint64_t)(g_ptr_struct4_um->data_block) ^ g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key;

        HANDLE hDevice = CreateFileW(
            HANDSHAKE_DEVICE_SYMLINK_NAME_UM, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

        if (hDevice == INVALID_HANDLE_VALUE) {
            LogMessageF("[-] InitializeStealthComm: Failed to open handle to KM handshake device. Error: %lu", GetLastError());
            ShutdownStealthComm();
            return STATUS_DEVICE_DOES_NOT_EXIST; // Or a more general error
        }

        STEALTH_HANDshake_DATA_UM handshakeData;
        handshakeData.ObfuscatedPtrStruct1HeadUmAddress = (PVOID)g_ptr_struct1_head_um;
        if (g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key == 0) {
            LogMessage("[-] InitializeStealthComm: dynamic_obfuscation_xor_key is 0. Cannot generate handshake token.");
            CloseHandle(hDevice);
            ShutdownStealthComm();
            return STATUS_INVALID_PARAMETER; // Or a custom error
        }
        handshakeData.VerificationToken = g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key;
        memcpy(handshakeData.BeaconPattern, g_dynamic_signatures_relay_data.beacon, BEACON_PATTERN_SIZE);

        DWORD bytesReturned = 0;
        BOOL success = DeviceIoControl(
            hDevice, IOCTL_STEALTH_HANDSHAKE_UM, &handshakeData, sizeof(STEALTH_HANDshake_DATA_UM),
            nullptr, 0, &bytesReturned, nullptr );
        CloseHandle(hDevice);

        if (!success) {
            LogMessageF("[-] InitializeStealthComm: DeviceIoControl for handshake failed. Error: %lu", GetLastError());
            ShutdownStealthComm();
            return STATUS_IO_DEVICE_ERROR; // Or a more general error
        }

        // Poll for KM ready flag
        bool km_ready = false;
        const int timeout_ms = 2000; // Max 2 seconds wait
        const int poll_interval_ms = 100;
        int elapsed_ms = 0;

        LogMessage("[+] InitializeStealthComm: Handshake IOCTL sent. Waiting for KM ready signal...");

        while (elapsed_ms < timeout_ms) {
            if (g_shared_comm_block->km_fully_initialized_flag == 1) {
                km_ready = true;
                break;
            }
            Sleep(poll_interval_ms);
            elapsed_ms += poll_interval_ms;
        }

        if (!km_ready) {
            LogMessage("[-] InitializeStealthComm: Timed out waiting for KM to set km_fully_initialized_flag.");
            // Consider if a disconnect IOCTL should be sent here if one existed for aborting setup.
            // For now, just shut down UM side.
            ShutdownStealthComm(); // Clean up UM resources
            return STATUS_TIMEOUT;
        }

        LogMessage("[+] InitializeStealthComm: KM ready signal received. StealthComm fully initialized.");
        return STATUS_SUCCESS;
    }


    bool SubmitRequestAndWait(
        CommCommand command, uint64_t target_pid, const uint8_t* params, uint32_t params_size,
        uint8_t* output_buf, uint32_t& output_size,
        uint64_t& km_status_code, uint32_t timeout_ms)
    {
        if (!g_shared_comm_block) {
            LogMessageF("[-] SubmitRequestAndWait: Shared communication block not initialized for ReqID %u.", g_next_request_id.load());
            return false;
        }
        if (params_size > MAX_PARAM_SIZE) {
            LogMessageF("[-] SubmitRequestAndWait: Params size %u too large for ReqID %u.", params_size, g_next_request_id.load());
            return false;
        }

        uint32_t request_id = g_next_request_id.fetch_add(1);
        uint64_t sig_um_runtime = g_dynamic_signatures_relay_data.dynamic_shared_comm_block_signature;
        uint32_t derived_index_xor_key_um_runtime = (uint32_t)(sig_um_runtime & 0xFFFFFFFF) ^ (uint32_t)(sig_um_runtime >> 32);

        if (g_dynamic_signatures_relay_data.dynamic_shared_comm_block_signature == 0) {
             LogMessageF("[-] SubmitRequestAndWait: ReqID %u - dynamic_shared_comm_block_signature is 0. Cannot manage slot indices.", request_id);
            return false;
        }
        if (g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key == 0) {
             LogMessageF("[-] SubmitRequestAndWait: ReqID %u - dynamic_obfuscation_xor_key is 0. Cannot derive crypto keys.", request_id);
            return false;
        }

        uint32_t obfuscated_um_slot_index_read = g_shared_comm_block->um_slot_index;
        uint32_t current_um_slot_index_plain = DeobfuscateSlotIndex_UM(obfuscated_um_slot_index_read, derived_index_xor_key_um_runtime);

        CommunicationSlot* slot = nullptr;
        bool slot_found = false;
        uint32_t actual_slot_index_plain = 0;

        for (int i = 0; i < MAX_COMM_SLOTS; ++i) {
            uint32_t try_index_plain = (current_um_slot_index_plain + i) % MAX_COMM_SLOTS;
            SlotStatus current_status_atomic = static_cast<SlotStatus>(InterlockedCompareExchange(
                reinterpret_cast<volatile LONG*>(&g_shared_comm_block->slots[try_index_plain].status),
                static_cast<LONG>(SlotStatus::UM_REQUEST_PENDING),
                static_cast<LONG>(SlotStatus::EMPTY)
            ));

            if (current_status_atomic == SlotStatus::EMPTY) {
                slot = &g_shared_comm_block->slots[try_index_plain];
                actual_slot_index_plain = try_index_plain;
                slot_found = true;
                break;
            } else {
                 current_status_atomic = static_cast<SlotStatus>(InterlockedCompareExchange(
                    reinterpret_cast<volatile LONG*>(&g_shared_comm_block->slots[try_index_plain].status),
                    static_cast<LONG>(SlotStatus::UM_REQUEST_PENDING),
                    static_cast<LONG>(SlotStatus::UM_ACKNOWLEDGED)
                ));
                 if (current_status_atomic == SlotStatus::UM_ACKNOWLEDGED) {
                    slot = &g_shared_comm_block->slots[try_index_plain];
                    actual_slot_index_plain = try_index_plain;
                    slot_found = true;
                    break;
                 }
            }
        }

        if (!slot_found) {
            LogMessageF("[-] SubmitRequestAndWait: ReqID %u - No free communication slot available. Start search plain index: %u", request_id, current_um_slot_index_plain);
            return false;
        }

        uint8_t current_chacha_key_um[32];
        DeriveKeys_UM(g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key, request_id, current_chacha_key_um);

        slot->request_id = request_id;
        slot->command_id = command;
        slot->process_id = target_pid;

        GenerateNonce_UM(slot->nonce, sizeof(slot->nonce), request_id);

        // AAD for Request: request_id (4) + command_id (4) + process_id (8) + param_size (4) = 20 bytes
        uint8_t aad_buffer_request[20];
        uint32_t current_offset = 0;
        memcpy(aad_buffer_request + current_offset, &request_id, sizeof(request_id));
        current_offset += sizeof(request_id);
        memcpy(aad_buffer_request + current_offset, &command, sizeof(command)); // Use 'command' directly
        current_offset += sizeof(command);
        memcpy(aad_buffer_request + current_offset, &target_pid, sizeof(target_pid));
        current_offset += sizeof(target_pid);
        memcpy(aad_buffer_request + current_offset, &params_size, sizeof(params_size));
        current_offset += sizeof(params_size);
        // Total AAD size for request = current_offset (should be 20)

        if (params && params_size > 0) {
            // Encrypt in-place for params, then copy to slot->parameters if needed.
            // Or, if params is read-only, copy to slot->parameters first, then encrypt in slot.
            // Assuming params can be directly used if not modified, or copied if it's const.
            // Let's assume slot->parameters is the target for ciphertext.
            memcpy(slot->parameters, params, params_size); // Copy plaintext to slot first
            StandardLib_ChaCha20_Encrypt_UM(current_chacha_key_um, slot->nonce, aad_buffer_request, current_offset, slot->parameters, params_size, slot->parameters, slot->mac_tag); // Already mac_tag
        } else {
            // Even if params_size is 0, we still need to generate a tag for the AAD
            StandardLib_ChaCha20_Encrypt_UM(current_chacha_key_um, slot->nonce, aad_buffer_request, current_offset, nullptr, 0, nullptr, slot->mac_tag); // Already mac_tag
        }
        slot->param_size = params_size;
        // StandardLib_Poly1305_MAC_UM is removed. Tag is generated by Encrypt_UM.
        slot->output_size = 0;

        uint32_t next_um_slot_index_plain = (actual_slot_index_plain + 1) % MAX_COMM_SLOTS;
        uint32_t obfuscated_next_um_slot_index = ObfuscateSlotIndex_UM(next_um_slot_index_plain, derived_index_xor_key_um_runtime);
        g_shared_comm_block->um_slot_index = obfuscated_next_um_slot_index;

        DWORD start_time = GetTickCount();
        bool processed_response = false;

        while (GetTickCount() - start_time < timeout_ms) {
            SlotStatus current_slot_status_volatile = slot->status;
            if (current_slot_status_volatile == SlotStatus::KM_COMPLETED_SUCCESS || current_slot_status_volatile == SlotStatus::KM_COMPLETED_ERROR) {
                if (slot->request_id != request_id) {
                    LogMessageF("[-] SubmitRequestAndWait: ReqID %u - Mismatched request ID in slot! Expected %u, Got %u. Critical error.", request_id, request_id, slot->request_id);
                    InterlockedExchange(reinterpret_cast<volatile LONG*>(&slot->status), static_cast<LONG>(SlotStatus::EMPTY));
                    return false;
                }

                km_status_code = slot->result_status_code;
                uint32_t max_output_buf_size = output_size; // Preserve original buffer capacity
                output_size = 0; // Will be set to actual decrypted data size

                // AAD for Response: slot->request_id (4) + slot->output_size (4) + slot->result_status_code (8) = 16 bytes
                uint8_t aad_buffer_response[16];
                uint32_t response_aad_offset = 0;
                memcpy(aad_buffer_response + response_aad_offset, &slot->request_id, sizeof(slot->request_id));
                response_aad_offset += sizeof(slot->request_id);
                memcpy(aad_buffer_response + response_aad_offset, &slot->output_size, sizeof(slot->output_size)); // This is the ENCRYPTED output size from KM
                response_aad_offset += sizeof(slot->output_size);
                memcpy(aad_buffer_response + response_aad_offset, &slot->result_status_code, sizeof(slot->result_status_code));
                response_aad_offset += sizeof(slot->result_status_code);
                // Total AAD size for response = response_aad_offset (should be 16)

                bool decryption_ok = false;
                if (slot->output_size > 0) {
                    // Decrypt in-place in slot->output
                    decryption_ok = StandardLib_ChaCha20_Decrypt_UM(current_chacha_key_um, slot->nonce, aad_buffer_response, response_aad_offset, slot->output, slot->output_size, slot->output, slot->mac_tag); // Already mac_tag
                } else {
                    // If output_size is 0, still need to verify tag against AAD
                    uint8_t dummy_plaintext; // Decrypt needs a non-null buffer, even for 0 size
                    decryption_ok = StandardLib_ChaCha20_Decrypt_UM(current_chacha_key_um, slot->nonce, aad_buffer_response, response_aad_offset, nullptr, 0, &dummy_plaintext, slot->mac_tag); // Already mac_tag
                }

                if (!decryption_ok) {
                    LogMessageF("[-] SubmitRequestAndWait: ReqID %u - RESPONSE DECRYPTION/TAG VERIFICATION FAILED.", request_id);
                    km_status_code = 0xC000A002; // STATUS_AUTH_TAG_MISMATCH
                    // Do not copy output if decryption failed
                } else {
                    // Decryption was successful (includes tag verification)
                    if (current_slot_status_volatile == SlotStatus::KM_COMPLETED_SUCCESS && MY_NT_SUCCESS(km_status_code)) {
                        if (output_buf && max_output_buf_size > 0 && slot->output_size > 0) {
                            uint32_t copy_size = min(max_output_buf_size, slot->output_size);
                            memcpy(output_buf, slot->output, copy_size);
                            output_size = copy_size; // Set to actual size of data copied to user buffer
                        } else {
                            output_size = 0; // No buffer or no data to copy
                        }
                    } else {
                         output_size = 0; // KM reported error, or decryption succeeded but status was bad
                    }
                }
                processed_response = true;
                break;
            }
            Sleep(5);
        }

        // Zero out the key material after use
        volatile PVOID p_key = current_chacha_key_um; // Ensure memset is not optimized away
        memset((PVOID)p_key, 0, sizeof(current_chacha_key_um));

        InterlockedExchange(reinterpret_cast<volatile LONG*>(&slot->status), static_cast<LONG>(SlotStatus::UM_ACKNOWLEDGED));

        if (!processed_response && MY_NT_SUCCESS(km_status_code)) { // Check km_status_code if not processed
            LogMessageF("[-] SubmitRequestAndWait: ReqID %u - Request timed out, but km_status_code was 0x%llX.", request_id, km_status_code);
            // If it timed out but KM might have processed it, this is a risky state.
            // For now, we return false, but this might need more sophisticated handling.
            return false;
        } else if (!processed_response) {
             LogMessageF("[-] SubmitRequestAndWait: ReqID %u - Request timed out.", request_id);
            return false;
        }

        return (slot->status == SlotStatus::UM_ACKNOWLEDGED && MY_NT_SUCCESS(km_status_code));
    }

    // ... (Public API functions: ReadMemory, WriteMemory, GetModuleBase, AobScan, AllocateMemory - UNCHANGED) ...
    // These will now use the updated SubmitRequestAndWait which calls the new crypto placeholders.
    bool ReadMemory(uint64_t target_pid, uintptr_t address, void* buffer, size_t size, size_t* bytes_read) {
        if (bytes_read) *bytes_read = 0;
        if (!buffer || size == 0) {
            LogMessage("[-] ReadMemory: Invalid buffer or zero size.");
            return false;
        }

        uint8_t params[sizeof(uintptr_t) + sizeof(size_t)];
        uint32_t params_size = 0;
        Serialize_uint64(params, address);
        params_size += sizeof(uintptr_t);
        Serialize_uint64(params + params_size, size);
        params_size += sizeof(size_t);

        uint8_t* temp_output_buf = new (std::nothrow) uint8_t[static_cast<uint32_t>(size)];
        if (!temp_output_buf) {
            LogMessage("[-] ReadMemory: Failed to allocate temporary output buffer.");
            return false;
        }

        uint32_t actual_read_by_km = static_cast<uint32_t>(size);
        uint64_t km_status_code = 0;

        bool success = SubmitRequestAndWait(
            CommCommand::REQUEST_READ_MEMORY, target_pid, params, params_size,
            temp_output_buf, actual_read_by_km, km_status_code );

        if (success && MY_NT_SUCCESS(km_status_code)) {
            if (actual_read_by_km <= size) {
                if (bytes_read) *bytes_read = actual_read_by_km;
                memcpy(buffer, temp_output_buf, actual_read_by_km);
                delete[] temp_output_buf;
                return true;
            } else {
                 LogMessageF("[-] ReadMemory: KM success but returned output_size (%u) > requested size (%zu).", actual_read_by_km, size);
            }
        } else if (!MY_NT_SUCCESS(km_status_code)) {
             LogMessageF("[-] ReadMemory: KM returned error status: 0x%llX for address 0x%p", km_status_code, (void*)address);
        } else if (!success) {
            LogMessageF("[-] ReadMemory: SubmitRequestAndWait failed for address 0x%p", (void*)address);
        }
        delete[] temp_output_buf;
        return false;
    }

    bool WriteMemory(uint64_t target_pid, uintptr_t address, const void* buffer, size_t size, size_t* bytes_written) {
        if (bytes_written) *bytes_written = 0;
        if (!buffer || size == 0) {
            LogMessage("[-] WriteMemory: Invalid buffer or zero size.");
            return false;
        }
        if (size > (MAX_PARAM_SIZE - sizeof(uintptr_t) - sizeof(size_t))) {
             LogMessageF("[-] WriteMemory: Data size %zu too large for params buffer.", size);
            return false;
        }

        uint8_t params[MAX_PARAM_SIZE];
        uint32_t params_size = 0;
        Serialize_uint64(params, address);
        params_size += sizeof(uintptr_t);
        Serialize_uint64(params + params_size, size);
        params_size += sizeof(size_t);
        memcpy(params + params_size, buffer, size);
        params_size += static_cast<uint32_t>(size);

        uint8_t temp_output_buf[1];
        uint32_t actual_bytes_written_by_km = 0;
        uint64_t km_status_code = 0;

        bool success = SubmitRequestAndWait(
            CommCommand::REQUEST_WRITE_MEMORY, target_pid, params, params_size,
            temp_output_buf, actual_bytes_written_by_km, km_status_code );

        if (success && MY_NT_SUCCESS(km_status_code)) {
            if (actual_bytes_written_by_km == size) {
                if (bytes_written) *bytes_written = actual_bytes_written_by_km;
                return true;
            } else {
                LogMessageF("[-] WriteMemory: KM success but byte count mismatch. KM wrote: %u, expected: %zu", actual_bytes_written_by_km, size);
                if (bytes_written) *bytes_written = actual_bytes_written_by_km;
                return false;
            }
        }
        if (!MY_NT_SUCCESS(km_status_code)) {
             LogMessageF("[-] WriteMemory: KM returned error status: 0x%llX for address 0x%p", km_status_code, (void*)address);
        } else if (!success) {
            LogMessageF("[-] WriteMemory: SubmitRequestAndWait failed for address 0x%p", (void*)address);
        }
        return false;
    }

    uintptr_t GetModuleBase(uint64_t target_pid, const wchar_t* module_name) {
        if (!module_name || module_name[0] == L'\0') {
            LogMessage("[-] GetModuleBase: Invalid module name.");
            return 0;
        }
        uint8_t params[MAX_PARAM_SIZE];
        uint32_t params_size = 0;
        Serialize_wstring(params, module_name, params_size); // This logs truncation errors internally
        if (params_size == 0 || params_size > MAX_PARAM_SIZE) {
            // LogMessage("[-] GetModuleBase: Module name too long, empty, or serialization failed."); // Redundant if Serialize_wstring logs
            return 0;
        }

        uint8_t output_buf[sizeof(uintptr_t)];
        uint32_t output_size_in_out = sizeof(uintptr_t);
        uint64_t km_status_code = 0;

        bool success = SubmitRequestAndWait(
            CommCommand::REQUEST_GET_MODULE_BASE, target_pid, params, params_size,
            output_buf, output_size_in_out, km_status_code );

        if (success && MY_NT_SUCCESS(km_status_code)) {
            if (output_size_in_out == sizeof(uintptr_t)) {
                 uintptr_t module_base = Deserialize_uint64(output_buf);
                 return module_base;
            } else {
                // Convert module_name to char* for LogMessageF or use a wide string logger if available
                char narrow_module_name[128];
                size_t converted_chars = 0;
                wcstombs_s(&converted_chars, narrow_module_name, sizeof(narrow_module_name), module_name, _TRUNCATE);
                LogMessageF("[-] GetModuleBase: KM success but output_size (%u) != sizeof(uintptr_t) for module %s.", output_size_in_out, narrow_module_name);
                return 0;
            }
        }
        if (!MY_NT_SUCCESS(km_status_code) && !(km_status_code == 0xC0000034L /*STATUS_OBJECT_NAME_NOT_FOUND*/ || km_status_code == 0xC0000225L /*STATUS_NOT_FOUND*/ ) ) {
            char narrow_module_name_err[128];
            size_t converted_chars_err = 0;
            wcstombs_s(&converted_chars_err, narrow_module_name_err, sizeof(narrow_module_name_err), module_name, _TRUNCATE);
            LogMessageF("[-] GetModuleBase: KM returned error status: 0x%llX for module %s", km_status_code, narrow_module_name_err);
        } else if (!success) {
            char narrow_module_name_fail[128];
            size_t converted_chars_fail = 0;
            wcstombs_s(&converted_chars_fail, narrow_module_name_fail, sizeof(narrow_module_name_fail), module_name, _TRUNCATE);
            LogMessageF("[-] GetModuleBase: SubmitRequestAndWait failed for module %s", narrow_module_name_fail);
        }
        return 0;
    }

    uintptr_t AobScan(uint64_t target_pid, uintptr_t start_address, size_t scan_size,
                      const char* pattern, const char* mask,
                      uint8_t* out_saved_bytes, size_t saved_bytes_size) {
        UNREFERENCED_PARAMETER(mask);

        if (!pattern || pattern[0] == '\0') {
            LogMessage("[-] AobScan: Invalid or empty pattern.");
            return 0;
        }

        uint8_t params[MAX_PARAM_SIZE];
        uint32_t current_offset = 0;
        Serialize_uint64(params + current_offset, start_address);
        current_offset += sizeof(uintptr_t);
        Serialize_uint64(params + current_offset, scan_size);
        current_offset += sizeof(size_t);

        size_t pattern_str_len = strlen(pattern) + 1;
        if (current_offset + pattern_str_len > MAX_PARAM_SIZE) {
            LogMessage("[-] AobScan: Pattern string too long for parameters buffer.");
            return 0;
        }
        memcpy(params + current_offset, pattern, pattern_str_len);
        current_offset += static_cast<uint32_t>(pattern_str_len);

        uint8_t output_buf[sizeof(uintptr_t)];
        uint32_t output_buf_capacity = sizeof(uintptr_t);
        uint64_t km_status_code = 0;

        bool success = SubmitRequestAndWait(
            CommCommand::REQUEST_AOB_SCAN, target_pid, params, current_offset,
            output_buf, output_buf_capacity, km_status_code );

        if (out_saved_bytes && saved_bytes_size > 0) {
            memset(out_saved_bytes, 0, saved_bytes_size);
        }

        if (success && MY_NT_SUCCESS(km_status_code)) {
            if (output_buf_capacity == sizeof(uintptr_t)) {
                uintptr_t found_address = Deserialize_uint64(output_buf);
                return found_address;
            } else if (output_buf_capacity == 0 && MY_NT_SUCCESS(km_status_code)) {
                 return 0;
            } else {
                LogMessageF("[-] AobScan: KM success but returned unexpected output_size (%u). Expected sizeof(uintptr_t) or 0.", output_buf_capacity);
                return 0;
            }
        }
        if (!MY_NT_SUCCESS(km_status_code) && !(km_status_code == 0xC0000034L || km_status_code == 0xC0000225L )) {
            LogMessageF("[-] AobScan: KM returned error status: 0x%llX for pattern \"%s\".", km_status_code, pattern);
        } else if (!success) {
             LogMessageF("[-] AobScan: SubmitRequestAndWait failed for pattern \"%s\".", pattern);
        }
        return 0;
    }

    uintptr_t AllocateMemory(uint64_t target_pid, size_t size, uintptr_t hint_address) {
        if (size == 0) {
            LogMessage("[-] AllocateMemory: Allocation size cannot be zero.");
            return 0;
        }
        uint8_t params[sizeof(size_t) + sizeof(uintptr_t)]; // Params are: UINT64 size, UINT64 hint_address
        uint32_t params_size = 0;
        Serialize_uint64(params, size);
        params_size += sizeof(uint64_t);
        Serialize_uint64(params + params_size, hint_address);
        params_size += sizeof(uint64_t);

        uint8_t output_buf[sizeof(uintptr_t)];
        uint32_t output_size_in_out = sizeof(uintptr_t);
        uint64_t km_status_code = 0;

        bool success = SubmitRequestAndWait(
            CommCommand::REQUEST_ALLOCATE_MEMORY, target_pid, params, params_size,
            output_buf, output_size_in_out, km_status_code
        );

        if (success && MY_NT_SUCCESS(km_status_code)) {
            if (output_size_in_out == sizeof(uintptr_t)) {
                uintptr_t allocated_address = Deserialize_uint64(output_buf);
                if (allocated_address != 0) {
                    return allocated_address;
                } else {
                    LogMessageF("[-] AllocateMemory: KM reported success but returned allocated address 0 for size %zu.", size);
                    return 0;
                }
            } else {
                 LogMessageF("[-] AllocateMemory: KM success but returned unexpected output_size (%u). Expected sizeof(uintptr_t).", output_size_in_out);
                return 0;
            }
        }
        if (!MY_NT_SUCCESS(km_status_code)) {
            LogMessageF("[-] AllocateMemory: KM returned error status: 0x%llX for size %zu.", km_status_code, size);
        } else if(!success) {
            LogMessageF("[-] AllocateMemory: SubmitRequestAndWait failed for size %zu.", size);
        }
        return 0;
    }
    // ... (ShutdownStealthComm - UNCHANGED) ...
    void ShutdownStealthComm() {
        // This function itself does not log, but the actions it calls (VirtualFree) might have OS-level events.
        // If verbose logging of shutdown is needed, add LogMessage calls here.
        if (g_ptr_struct1_head_um) { VirtualFree(g_ptr_struct1_head_um, 0, MEM_RELEASE); g_ptr_struct1_head_um = nullptr; }
        if (g_ptr_struct2_um) { VirtualFree(g_ptr_struct2_um, 0, MEM_RELEASE); g_ptr_struct2_um = nullptr; }
        if (g_ptr_struct3_um) { VirtualFree(g_ptr_struct3_um, 0, MEM_RELEASE); g_ptr_struct3_um = nullptr; }
        if (g_ptr_struct4_um) { VirtualFree(g_ptr_struct4_um, 0, MEM_RELEASE); g_ptr_struct4_um = nullptr; }
        if (g_shared_comm_block) { VirtualFree(g_shared_comm_block, 0, MEM_RELEASE); g_shared_comm_block = nullptr; }
    }

    bool FreeMemory(uint64_t target_pid, uintptr_t address, size_t size) {
        if (address == 0) {
            LogMessage("[-] FreeMemory: Address cannot be zero.");
            return false;
        }
        // Size is passed to KM, but KM's ZwFreeVirtualMemory with MEM_RELEASE will use 0 for size.
        // We still send the original allocation size for potential logging or future use if KM changes.
        uint8_t params[sizeof(uintptr_t) + sizeof(size_t)];
        uint32_t params_size = 0;
        Serialize_uint64(params, address);
        params_size += sizeof(uintptr_t);
        Serialize_uint64(params + params_size, size);
        params_size += sizeof(size_t);

        uint8_t output_buf[1]; // No real output expected
        uint32_t output_size_in_out = 0;
        uint64_t km_status_code = 0;

        bool success = SubmitRequestAndWait(
            CommCommand::REQUEST_FREE_MEMORY, target_pid, params, params_size,
            output_buf, output_size_in_out, km_status_code);

        if (!success || !MY_NT_SUCCESS(km_status_code)) {
            LogMessageF("[-] FreeMemory: Failed to free memory at address 0x%p. KM Status: 0x%llX", (void*)address, km_status_code);
            return false;
        }
        LogMessageF("[+] FreeMemory: Successfully requested KM to free memory at 0x%p", (void*)address); // Keep debug log for success
        return true;
    }

    // Note: km_status_code from slot is now directly returned if KM_COMPLETED_ERROR.
    // If timeout or other UM-side issue, specific NTSTATUS codes are returned.
    NTSTATUS SubmitRequestAndWait( // Changed return type
        CommCommand command, uint64_t target_pid, const uint8_t* params, uint32_t params_size,
        uint8_t* output_buf, uint32_t& output_size, // output_size is In/Out
        /*uint64_t& km_status_code,*/ uint32_t timeout_ms) // km_status_code removed from params, will be return value
    {
        if (!g_shared_comm_block) {
            LogMessageF("[-] SubmitRequestAndWait: Shared communication block not initialized for ReqID %u.", g_next_request_id.load());
            return STATUS_INVALID_DEVICE_STATE; // Or a custom error
        }
        if (params_size > MAX_PARAM_SIZE) {
            LogMessageF("[-] SubmitRequestAndWait: Params size %u too large for ReqID %u.", params_size, g_next_request_id.load());
            return STATUS_INVALID_BUFFER_SIZE; // Or a custom error
        }

        uint32_t request_id = g_next_request_id.fetch_add(1);
        uint64_t sig_um_runtime = g_dynamic_signatures_relay_data.dynamic_shared_comm_block_signature;
        uint32_t derived_index_xor_key_um_runtime = (uint32_t)(sig_um_runtime & 0xFFFFFFFF) ^ (uint32_t)(sig_um_runtime >> 32);

        if (g_dynamic_signatures_relay_data.dynamic_shared_comm_block_signature == 0) {
             LogMessageF("[-] SubmitRequestAndWait: ReqID %u - dynamic_shared_comm_block_signature is 0. Cannot manage slot indices.", request_id);
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key == 0) {
             LogMessageF("[-] SubmitRequestAndWait: ReqID %u - dynamic_obfuscation_xor_key is 0. Cannot derive crypto keys.", request_id);
            return STATUS_INVALID_KEY;
        }

        uint32_t obfuscated_um_slot_index_read = g_shared_comm_block->um_slot_index;
        uint32_t current_um_slot_index_plain = DeobfuscateSlotIndex_UM(obfuscated_um_slot_index_read, derived_index_xor_key_um_runtime);

        CommunicationSlot* slot = nullptr;
        bool slot_found = false;
        uint32_t actual_slot_index_plain = 0;

        for (int i = 0; i < MAX_COMM_SLOTS; ++i) {
            uint32_t try_index_plain = (current_um_slot_index_plain + i) % MAX_COMM_SLOTS;
            SlotStatus current_status_atomic = static_cast<SlotStatus>(InterlockedCompareExchange(
                reinterpret_cast<volatile LONG*>(&g_shared_comm_block->slots[try_index_plain].status),
                static_cast<LONG>(SlotStatus::UM_REQUEST_PENDING),
                static_cast<LONG>(SlotStatus::EMPTY)
            ));

            if (current_status_atomic == SlotStatus::EMPTY) {
                slot = &g_shared_comm_block->slots[try_index_plain];
                actual_slot_index_plain = try_index_plain;
                slot_found = true;
                break;
            } else {
                 current_status_atomic = static_cast<SlotStatus>(InterlockedCompareExchange(
                    reinterpret_cast<volatile LONG*>(&g_shared_comm_block->slots[try_index_plain].status),
                    static_cast<LONG>(SlotStatus::UM_REQUEST_PENDING),
                    static_cast<LONG>(SlotStatus::UM_ACKNOWLEDGED)
                ));
                 if (current_status_atomic == SlotStatus::UM_ACKNOWLEDGED) {
                    slot = &g_shared_comm_block->slots[try_index_plain];
                    actual_slot_index_plain = try_index_plain;
                    slot_found = true;
                    break;
                 }
            }
        }

        if (!slot_found) {
            LogMessageF("[-] SubmitRequestAndWait: ReqID %u - No free communication slot available. Start search plain index: %u", request_id, current_um_slot_index_plain);
            return STATUS_NO_MEMORY; // Or a more specific "no available slot" error
        }

        uint8_t current_chacha_key_um[32];
        DeriveKeys_UM(g_dynamic_signatures_relay_data.dynamic_obfuscation_xor_key, request_id, current_chacha_key_um);

        slot->request_id = request_id;
        slot->command_id = command;
        slot->process_id = target_pid;

        GenerateNonce_UM(slot->nonce, sizeof(slot->nonce), request_id);

        uint8_t aad_buffer_request[20];
        uint32_t current_offset = 0;
        memcpy(aad_buffer_request + current_offset, &request_id, sizeof(request_id));
        current_offset += sizeof(request_id);
        memcpy(aad_buffer_request + current_offset, &command, sizeof(command));
        current_offset += sizeof(command);
        memcpy(aad_buffer_request + current_offset, &target_pid, sizeof(target_pid));
        current_offset += sizeof(target_pid);
        memcpy(aad_buffer_request + current_offset, &params_size, sizeof(params_size));
        current_offset += sizeof(params_size);

        if (params && params_size > 0) {
            memcpy(slot->parameters, params, params_size);
            StandardLib_ChaCha20_Encrypt_UM(current_chacha_key_um, slot->nonce, aad_buffer_request, current_offset, slot->parameters, params_size, slot->parameters, slot->mac_tag); // Already mac_tag
        } else {
            StandardLib_ChaCha20_Encrypt_UM(current_chacha_key_um, slot->nonce, aad_buffer_request, current_offset, nullptr, 0, nullptr, slot->mac_tag); // Already mac_tag
        }
        slot->param_size = params_size;
        slot->output_size = 0; // Initialize output size for KM
        slot->result_status_code = STATUS_PENDING; // Initial status

        uint32_t next_um_slot_index_plain = (actual_slot_index_plain + 1) % MAX_COMM_SLOTS;
        uint32_t obfuscated_next_um_slot_index = ObfuscateSlotIndex_UM(next_um_slot_index_plain, derived_index_xor_key_um_runtime);
        g_shared_comm_block->um_slot_index = obfuscated_next_um_slot_index;

        DWORD start_time = GetTickCount();
        bool processed_response = false;
        NTSTATUS final_status = STATUS_UNSUCCESSFUL; // Default to unsuccessful

        while (GetTickCount() - start_time < timeout_ms) {
            SlotStatus current_slot_status_volatile = slot->status; // Read volatile once
            if (current_slot_status_volatile == SlotStatus::KM_COMPLETED_SUCCESS || current_slot_status_volatile == SlotStatus::KM_COMPLETED_ERROR) {
                if (slot->request_id != request_id) {
                    LogMessageF("[-] SubmitRequestAndWait: ReqID %u - Mismatched request ID in slot! Expected %u, Got %u. Critical error.", request_id, request_id, slot->request_id);
                    final_status = STATUS_DATA_ERROR; // Critical error
                    // Do not change slot status here, let UM_ACKNOWLEDGED handle it if possible
                    processed_response = true; // Break loop, error state
                    break;
                }

                final_status = static_cast<NTSTATUS>(slot->result_status_code);
                uint32_t max_output_buf_size = output_size;
                output_size = 0;

                uint8_t aad_buffer_response[16];
                uint32_t response_aad_offset = 0;
                memcpy(aad_buffer_response + response_aad_offset, &slot->request_id, sizeof(slot->request_id));
                response_aad_offset += sizeof(slot->request_id);
                memcpy(aad_buffer_response + response_aad_offset, &slot->output_size, sizeof(slot->output_size));
                response_aad_offset += sizeof(slot->output_size);
                memcpy(aad_buffer_response + response_aad_offset, &slot->result_status_code, sizeof(slot->result_status_code));
                response_aad_offset += sizeof(slot->result_status_code);

                bool decryption_ok = false;
                if (slot->output_size > 0 && slot->output_size <= MAX_OUTPUT_SIZE_KM) { // Check against KM max
                    decryption_ok = StandardLib_ChaCha20_Decrypt_UM(current_chacha_key_um, slot->nonce, aad_buffer_response, response_aad_offset, slot->output, slot->output_size, slot->output, slot->mac_tag); // Already mac_tag
                } else if (slot->output_size == 0) {
                    uint8_t dummy_plaintext;
                    decryption_ok = StandardLib_ChaCha20_Decrypt_UM(current_chacha_key_um, slot->nonce, aad_buffer_response, response_aad_offset, nullptr, 0, &dummy_plaintext, slot->mac_tag); // Already mac_tag
                } else { // output_size > MAX_OUTPUT_SIZE_KM
                     LogMessageF("[-] SubmitRequestAndWait: ReqID %u - KM returned output_size (%u) > MAX_OUTPUT_SIZE_KM (%u).", request_id, slot->output_size, MAX_OUTPUT_SIZE_KM);
                     final_status = STATUS_BUFFER_OVERFLOW; // Or similar error
                     decryption_ok = false; // Cannot proceed with decryption
                }


                if (!decryption_ok) {
                    LogMessageF("[-] SubmitRequestAndWait: ReqID %u - RESPONSE DECRYPTION/TAG VERIFICATION FAILED.", request_id);
                    if (NT_SUCCESS(final_status)) { // If KM reported success but decryption failed
                        final_status = STATUS_MAC_INCORRECT; // More specific error
                    }
                } else {
                    if (NT_SUCCESS(final_status)) { // KM success and decryption success
                        if (output_buf && max_output_buf_size > 0 && slot->output_size > 0) {
                            uint32_t copy_size = min(max_output_buf_size, slot->output_size);
                            memcpy(output_buf, slot->output, copy_size);
                            output_size = copy_size;
                        } else {
                            output_size = 0;
                        }
                    } else { // KM error, but decryption was okay (e.g. tag verified for 0 output)
                         output_size = 0;
                    }
                }
                processed_response = true;
                break;
            }
            Sleep(5); // Polling interval
        }

        volatile PVOID p_key = current_chacha_key_um;
        memset((PVOID)p_key, 0, sizeof(current_chacha_key_um));

        InterlockedExchange(reinterpret_cast<volatile LONG*>(&slot->status), static_cast<LONG>(SlotStatus::UM_ACKNOWLEDGED));

        if (!processed_response) {
            LogMessageF("[-] SubmitRequestAndWait: ReqID %u - Request timed out.", request_id);
            return STATUS_TIMEOUT;
        }

        return final_status;
    }

    NTSTATUS ReadMemory(uint64_t target_pid, uintptr_t address, void* buffer, size_t size, size_t* bytes_read) {
        if (bytes_read) *bytes_read = 0;
        if (!buffer || size == 0) {
            LogMessage("[-] ReadMemory: Invalid buffer or zero size.");
            return STATUS_INVALID_PARAMETER;
        }

        uint8_t params[sizeof(uintptr_t) + sizeof(size_t)];
        uint32_t params_size = 0;
        Serialize_uint64(params, address);
        params_size += sizeof(uintptr_t);
        Serialize_uint64(params + params_size, size);
        params_size += sizeof(size_t);

        // Output buffer is managed by this function, not directly by slot.
        // Max output size for read is MAX_OUTPUT_SIZE (256 bytes) per slot.
        // If requested size > MAX_OUTPUT_SIZE, this simple wrapper needs adjustment
        // or the KM needs to handle chunking (which it doesn't currently).
        // For now, assume 'size' will be <= MAX_OUTPUT_SIZE.
        if (size > MAX_OUTPUT_SIZE_KM) { // Check against KM's max output
            LogMessageF("[-] ReadMemory: Requested read size %zu exceeds MAX_OUTPUT_SIZE_KM %u.", size, MAX_OUTPUT_SIZE_KM);
            return STATUS_BUFFER_TOO_SMALL;
        }

        uint8_t temp_output_buf[MAX_OUTPUT_SIZE_KM]; // Use KM's max
        uint32_t actual_read_by_km_or_slot_max = MAX_OUTPUT_SIZE_KM; // Pass max capacity of temp_output_buf

        NTSTATUS status = SubmitRequestAndWait(
            CommCommand::REQUEST_READ_MEMORY, target_pid, params, params_size,
            temp_output_buf, actual_read_by_km_or_slot_max /* In: buffer capacity, Out: actual data size from KM */);

        if (NT_SUCCESS(status)) {
            // actual_read_by_km_or_slot_max now holds the actual number of bytes placed in temp_output_buf by SubmitRequestAndWait
            if (actual_read_by_km_or_slot_max <= size) { // Should be equal to 'size' if KM read 'size' bytes
                if (bytes_read) *bytes_read = actual_read_by_km_or_slot_max;
                memcpy(buffer, temp_output_buf, actual_read_by_km_or_slot_max);
            } else {
                 // This case should ideally not happen if KM respects the requested size and slot limits.
                 LogMessageF("[-] ReadMemory: SubmitRequestAndWait returned more data (%u) than requested size (%zu) or slot capacity.", actual_read_by_km_or_slot_max, size);
                 if (bytes_read) *bytes_read = 0; // Indicate error or partial/no data
                 return STATUS_INTERNAL_ERROR; // Or some other error
            }
        } else {
             // LogMessageF("[-] ReadMemory: SubmitRequestAndWait failed with status 0x%lX", status); // Already logged by SubmitRequestAndWait
        }
        return status;
    }

    NTSTATUS WriteMemory(uint64_t target_pid, uintptr_t address, const void* buffer, size_t size, size_t* bytes_written) {
        if (bytes_written) *bytes_written = 0;
        if (!buffer || size == 0) {
            LogMessage("[-] WriteMemory: Invalid buffer or zero size.");
            return STATUS_INVALID_PARAMETER;
        }
        // Param buffer for write: address (u64) + size_to_write (u64) + data_itself (up to MAX_PARAM_SIZE - headers)
        if (size > (MAX_PARAM_SIZE_KM - (sizeof(uintptr_t) + sizeof(size_t)))) {
             LogMessageF("[-] WriteMemory: Data size %zu too large for params buffer.", size);
            return STATUS_BUFFER_TOO_SMALL;
        }

        uint8_t params[MAX_PARAM_SIZE_KM];
        uint32_t params_size = 0;
        Serialize_uint64(params, address);
        params_size += sizeof(uintptr_t);
        Serialize_uint64(params + params_size, size); // Tell KM how much data is being sent
        params_size += sizeof(size_t);
        memcpy(params + params_size, buffer, size);
        params_size += static_cast<uint32_t>(size);

        uint8_t temp_output_buf[1]; // KM's REQUEST_WRITE_MEMORY might return bytes_written in output
        uint32_t output_data_len = 0; // In: capacity (0 is fine if no data expected), Out: actual output size

        NTSTATUS status = SubmitRequestAndWait(
            CommCommand::REQUEST_WRITE_MEMORY, target_pid, params, params_size,
            temp_output_buf, output_data_len);

        if (NT_SUCCESS(status)) {
            // KM's current REQUEST_WRITE_MEMORY sets output_size = size_to_write on success.
            if (output_data_len == size) { // Check if KM confirmed writing 'size' bytes.
                if (bytes_written) *bytes_written = size; // KM is expected to write all or fail.
            } else {
                // This might indicate an issue if KM wrote less than requested but reported success.
                // Or if output_data_len was not set as expected.
                LogMessageF("[-] WriteMemory: KM success but output_data_len (%u) != requested size (%zu).", output_data_len, size);
                if (bytes_written) *bytes_written = output_data_len; // Report what KM claimed
                // Consider returning an error if this mismatch is critical
            }
        }
        return status;
    }

    uintptr_t GetModuleBase(uint64_t target_pid, const wchar_t* module_name) {
        if (!module_name || module_name[0] == L'\0') {
            LogMessage("[-] GetModuleBase: Invalid module name.");
            return 0; // Keep returning 0 for error in this specific wrapper for now
        }
        uint8_t params[MAX_PARAM_SIZE_KM];
        uint32_t params_size = 0;
        // Custom serialization for wstring to ensure it fits and is null-terminated.
        size_t module_name_len_bytes = (wcslen(module_name) + 1) * sizeof(wchar_t);
        if (module_name_len_bytes > MAX_PARAM_SIZE_KM) {
            // Convert module_name to char* for LogMessageF or use a wide string logger if available
            char narrow_module_name[128]; // Assuming module names are not excessively long
            size_t converted_chars = 0;
            wcstombs_s(&converted_chars, narrow_module_name, sizeof(narrow_module_name), module_name, _TRUNCATE);
            LogMessageF("[-] GetModuleBase: Module name '%s' too long.", narrow_module_name);
            return 0;
        }
        memcpy(params, module_name, module_name_len_bytes);
        params_size = static_cast<uint32_t>(module_name_len_bytes);


        uint8_t output_buf[sizeof(uintptr_t)];
        uint32_t output_size_in_out = sizeof(uintptr_t); // Expecting a uintptr_t back

        NTSTATUS status = SubmitRequestAndWait(
            CommCommand::REQUEST_GET_MODULE_BASE, target_pid, params, params_size,
            output_buf, output_size_in_out);

        if (NT_SUCCESS(status)) {
            if (output_size_in_out == sizeof(uintptr_t)) {
                 uintptr_t module_base = Deserialize_uint64(output_buf);
                 return module_base;
            } else {
                char narrow_module_name_out[128];
                size_t converted_chars_out = 0;
                wcstombs_s(&converted_chars_out, narrow_module_name_out, sizeof(narrow_module_name_out), module_name, _TRUNCATE);
                LogMessageF("[-] GetModuleBase: KM success but output_size (%u) != sizeof(uintptr_t) for module %s.", output_size_in_out, narrow_module_name_out);
                return 0;
            }
        }
        // Log specific error from SubmitRequestAndWait if needed.
        // SubmitRequestAndWait or KM might have already logged.
        // Only log if status is an error and not a "not found" type error for this one.
        if (!NT_SUCCESS(status) && !(status == 0xC0000034L /*STATUS_OBJECT_NAME_NOT_FOUND typically from ObReferenceObjectByName*/ || status == 0xC0000225L /*STATUS_NOT_FOUND*/ ) ) {
             char narrow_module_name_err_km[128];
             size_t converted_chars_err_km = 0;
             wcstombs_s(&converted_chars_err_km, narrow_module_name_err_km, sizeof(narrow_module_name_err_km), module_name, _TRUNCATE);
             LogMessageF("[-] GetModuleBase: KM returned error status: 0x%lX for module %s", status, narrow_module_name_err_km);
        }
        return 0;
    }

    uintptr_t AobScan(uint64_t target_pid, uintptr_t start_address, size_t scan_size,
                      const char* pattern, const char* mask,
                      uint8_t* out_saved_bytes, size_t saved_bytes_size) {
        UNREFERENCED_PARAMETER(mask); // Mask is not used by current KM AOB scan
        UNREFERENCED_PARAMETER(out_saved_bytes); // Not filled by current KM AOB scan
        UNREFERENCED_PARAMETER(saved_bytes_size);

        if (!pattern || pattern[0] == '\0') {
            LogMessage("[-] AobScan: Invalid or empty pattern.");
            return 0;
        }

        uint8_t params[MAX_PARAM_SIZE_KM];
        uint32_t current_offset = 0;
        Serialize_uint64(params + current_offset, start_address);
        current_offset += sizeof(uintptr_t);
        Serialize_uint64(params + current_offset, scan_size);
        current_offset += sizeof(size_t);

        size_t pattern_str_len = strlen(pattern) + 1; // Include null terminator
        if (current_offset + pattern_str_len > MAX_PARAM_SIZE_KM) {
            LogMessage("[-] AobScan: Pattern string too long for parameters buffer.");
            return 0;
        }
        memcpy(params + current_offset, pattern, pattern_str_len);
        current_offset += static_cast<uint32_t>(pattern_str_len);

        uint8_t output_buf[sizeof(uintptr_t)];
        uint32_t output_buf_capacity = sizeof(uintptr_t); // Expecting a uintptr_t back

        NTSTATUS status = SubmitRequestAndWait(
            CommCommand::REQUEST_AOB_SCAN, target_pid, params, current_offset,
            output_buf, output_buf_capacity);

        if (NT_SUCCESS(status)) {
            if (output_buf_capacity == sizeof(uintptr_t)) { // Found
                uintptr_t found_address = Deserialize_uint64(output_buf);
                return found_address;
            } else if (output_buf_capacity == 0 && NT_SUCCESS(status)) { // Not found but KM call was success
                 return 0;
            } else { // Unexpected output size
                LogMessageF("[-] AobScan: KM success but returned unexpected output_size (%u). Expected sizeof(uintptr_t) or 0.", output_buf_capacity);
                return 0;
            }
        }
        // Only log if status is an error and not a "not found" type error for this one.
        if (!NT_SUCCESS(status) && !(status == 0xC0000034L || status == 0xC0000225L )) {
             LogMessageF("[-] AobScan: KM returned error status: 0x%lX for pattern \"%s\".", status, pattern);
        }
        return 0;
    }

    uintptr_t AllocateMemory(uint64_t target_pid, size_t size, uintptr_t hint_address) {
        if (size == 0) {
            LogMessage("[-] AllocateMemory: Allocation size cannot be zero.");
            return 0;
        }
        uint8_t params[sizeof(uint64_t) + sizeof(uintptr_t)];
        uint32_t params_size = 0;
        Serialize_uint64(params, size); // First param: size
        params_size += sizeof(uint64_t);
        Serialize_uint64(params + params_size, hint_address); // Second param: hint_address
        params_size += sizeof(uintptr_t);

        uint8_t output_buf[sizeof(uintptr_t)];
        uint32_t output_size_in_out = sizeof(uintptr_t);

        NTSTATUS status = SubmitRequestAndWait(
            CommCommand::REQUEST_ALLOCATE_MEMORY, target_pid, params, params_size,
            output_buf, output_size_in_out);

        if (NT_SUCCESS(status)) {
            if (output_size_in_out == sizeof(uintptr_t)) {
                uintptr_t allocated_address = Deserialize_uint64(output_buf);
                if (allocated_address != 0) {
                    return allocated_address;
                } else { // KM success but returned 0, unusual
                    LogMessageF("[-] AllocateMemory: KM reported success but returned allocated address 0 for size %zu.", size);
                    return 0;
                }
            } else {
                 LogMessageF("[-] AllocateMemory: KM success but returned unexpected output_size (%u). Expected sizeof(uintptr_t).", output_size_in_out);
                return 0;
            }
        }
        // LogMessageF("[-] AllocateMemory: SubmitRequestAndWait failed with status 0x%lX for size %zu", status, size); // Already logged by SubmitRequestAndWait
        return 0;
    }

    NTSTATUS FreeMemory(uint64_t target_pid, uintptr_t address, size_t size) { // Return NTSTATUS
        if (address == 0) {
            LogMessage("[-] FreeMemory: Address cannot be zero.");
            return STATUS_INVALID_PARAMETER_2; // Address is param 2 conceptually after PID
        }

        uint8_t params[sizeof(uintptr_t) + sizeof(size_t)];
        uint32_t params_size = 0;
        Serialize_uint64(params, address);
        params_size += sizeof(uintptr_t);
        Serialize_uint64(params + params_size, size); // KM expects size 0 for MEM_RELEASE, but we send what UM provides.
        params_size += sizeof(size_t);

        uint8_t output_buf[1];
        uint32_t output_size_in_out = 0;

        NTSTATUS status = SubmitRequestAndWait(
            CommCommand::REQUEST_FREE_MEMORY, target_pid, params, params_size,
            output_buf, output_size_in_out);

        // SubmitRequestAndWait already logs general errors like timeout.
        // We might log specific failure for FreeMemory if status is an error.
        if (!NT_SUCCESS(status)) {
            LogMessageF("[-] FreeMemory: Failed to free memory at address 0x%p. Status: 0x%lX", (void*)address, status);
        }
        else { // Only log success in debug
             LogMessageF("[+] FreeMemory: Successfully requested KM to free memory at 0x%p", (void*)address);
        }
        return status;
    }

} // namespace StealthComm
