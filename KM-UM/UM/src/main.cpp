/*
 * =====================================================================================
 *
 *       Filename:  KM-UM/UM/src/main.cpp
 *
 *    Description:  This console application appears to be an older version, testbed,
 *                  or command-line interface for interacting with the KM component.
 *                  Its functionality is largely, if not entirely, superseded by the
 *                  ImGui application located in "ResponsibleImGui/Source/ImGui Standalone".
 *
 *                  This file is likely DEPRECATED and kept for reference or specific
 *                  testing purposes only. For the main user interface and features,
 *                  please refer to the ImGui application.
 *
 * =====================================================================================
 */
﻿#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>
#include <string.h>
#include <cwchar>
#include "aobs.h"
// #include "addys.h" // Not directly used
#include <cstdint>

#include "StealthComm.h"

// Global variables
// uintptr_t MovementInstruction = 0; // Assigned but not used later in this main.cpp
// uintptr_t LocalPlayerAddress = 0; // Assigned but not used later in this main.cpp
uintptr_t KillauraInstruction = 0; // Used for shellcode injection logic

static DWORD get_process_id(const wchar_t* process_name) {
	DWORD process_id{ 0 };

	HANDLE snap_shot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
	if (snap_shot == INVALID_HANDLE_VALUE) {
        #ifdef _DEBUG
        std::cerr << "[-] get_process_id: CreateToolhelp32Snapshot failed. Error: " << GetLastError() << std::endl;
        #endif
		return process_id;
	}

	PROCESSENTRY32W entry{};
	entry.dwSize = sizeof(decltype(entry));

	if (Process32FirstW(snap_shot, &entry) == TRUE) {
		if (_wcsicmp(process_name, entry.szExeFile) == 0) {
			process_id = entry.th32ProcessID;
		}
		else {
			while (Process32NextW(snap_shot, &entry) == TRUE) {
				if (_wcsicmp(process_name, entry.szExeFile) == 0) {
					process_id = entry.th32ProcessID;
					break;
				}
			}
		}
	} else {
        #ifdef _DEBUG
        std::cerr << "[-] get_process_id: Process32FirstW failed. Error: " << GetLastError() << std::endl;
        #endif
    }
	CloseHandle(snap_shot);
	return process_id;
}

// Removed get_module_base_local
// Removed AOBScan_local

int main() {
    // Add this block
    std::cout << "*******************************************************************" << std::endl;
    std::cout << "* WARNING: This command-line application is DEPRECATED.           *" << std::endl;
    std::cout << "* Its functionality is superseded by the ImGui application found  *" << std::endl;
    std::cout << "* in the 'ResponsibleImGui/Source/ImGui Standalone' directory.    *" << std::endl;
    std::cout << "* This tool is kept for reference or specific testing only.       *" << std::endl;
    std::cout << "*******************************************************************" << std::endl << std::endl;

    const DWORD pid_dw = get_process_id(L"destiny2.exe"); // Example process
    uint64_t pid = static_cast<uint64_t>(pid_dw);

    if (pid == 0) {
        std::cerr << "[-] Failed to get process id for destiny2.exe!" << std::endl;
        std::cin.get();
        return -1;
    }
    #ifdef _DEBUG
    std::cout << "[+] Process destiny2.exe found with PID: " << pid_dw << std::endl;
    #endif

    if (!StealthComm::InitializeStealthComm()) {
        std::cerr << "[-] Failed to initialize StealthComm." << std::endl;
        std::cin.get();
        return -1;
    }
    #ifdef _DEBUG
    std::cout << "[+] StealthComm initialized successfully." << std::endl;
    #endif

    uintptr_t game_base_address = StealthComm::GetModuleBase(pid, L"destiny2.exe");
    if (game_base_address != 0) {
        #ifdef _DEBUG
        std::cout << "[+] StealthComm::GetModuleBase: destiny2.exe base address: 0x"
                  << std::hex << game_base_address << std::dec << std::endl;
        #endif
    } else {
        std::cerr << "[-] StealthComm::GetModuleBase: Failed to get module base for destiny2.exe." << std::endl;
        // Depending on requirements, this might be a fatal error.
        // For this example, we'll allow it to continue to attempt other operations if possible.
    }

    // AOB Scan for KillauraInstruction (example)
    // Ensure KillauraAOB and KillauraAOBMask are defined in aobs.h
    size_t scan_region_size = 0x5000000; // Example scan size, adjust as needed
    if (game_base_address != 0) {
        #ifdef _DEBUG
        std::cout << "[+] Attempting AOB scan for KillauraInstruction within destiny2.exe..." << std::endl;
        #endif
        // Step 1: Perform AOB (Array of Bytes) scan to find the target instruction address.
        KillauraInstruction = StealthComm::AobScan(pid, game_base_address, scan_region_size,
                                                   reinterpret_cast<const char*>(KillauraAOB), KillauraAOBMask,
                                                   nullptr, 0);
        if (KillauraInstruction != 0) {
            #ifdef _DEBUG
            std::cout << "[+] StealthComm::AobScan found KillauraInstruction at: 0x"
                      << std::hex << KillauraInstruction << std::dec << std::endl;
            #endif
        } else {
            std::cerr << "[-] StealthComm::AobScan failed to find KillauraInstruction." << std::endl;
        }
    } else {
        std::cerr << "[-] Skipping KillauraInstruction AOB scan due to missing game base address." << std::endl;
    }

    #ifdef _DEBUG
    // std::cout << "[DEBUG] Movement Instruction (if scanned) = 0x" << std::hex << MovementInstruction << std::dec << std::endl;
    std::cout << "[DEBUG] Killaura Instruction = 0x" << std::hex << KillauraInstruction << std::dec << std::endl;
    #endif
    // std::cin.get(); // Optional pause

    uintptr_t hookFunctionAddress = 0;
    if (KillauraInstruction != 0) {
        #ifdef _DEBUG
        std::cout << "[+] KillauraInstruction found. Attempting to allocate memory for shellcode near 0x"
                  << std::hex << KillauraInstruction << std::dec << "..." << std::endl;
        #endif
        // Step 2: Allocate executable memory in the target process for the shellcode (codecave).
        // The KillauraInstruction address is passed as a hint for proximity.
        hookFunctionAddress = StealthComm::AllocateMemory(pid, 100, KillauraInstruction); // Allocate 100 bytes
        if (hookFunctionAddress != 0) {
            #ifdef _DEBUG
            std::cout << "[+] StealthComm::AllocateMemory: Successfully allocated memory for shellcode at: 0x"
                      << std::hex << hookFunctionAddress << std::dec << std::endl;
            #endif
        } else {
            std::cerr << "[-] StealthComm::AllocateMemory: Failed to allocate memory for shellcode." << std::endl;
        }
    } else {
        #ifdef _DEBUG
        std::cout << "[-] KillauraInstruction is 0. Skipping memory allocation and shellcode injection." << std::endl;
        #endif
    }

    // Shellcode to write
    uint8_t shellcode[] = {
        // Example shellcode (modify as needed):
        // mov dword ptr [rcx+20h], 42340000h ; Example: Modify some value
        0xC7, 0x41, 0x20, 0x00, 0x00, 0x34, 0x42,
        // original 5 bytes from KillauraInstruction (if needed for trampoline)
        // For a simple relative jump back:
        // jmp rel32 ; E9 DD CC BB AA
        0xE9, 0x00, 0x00, 0x00, 0x00 // Placeholder for the relative jump offset
    };
    const size_t original_instruction_len = 5; // Assuming the jump we overwrite is 5 bytes for KillauraInstruction

    if (hookFunctionAddress != 0 && KillauraInstruction != 0) {
        // Step 3: Construct the shellcode.
        // Calculate the relative offset for the JMP instruction at the end of the shellcode
        // to jump back to the original execution flow (KillauraInstruction + original_instruction_len).
        uintptr_t returnAddress = KillauraInstruction + original_instruction_len;
        int32_t relJmpOffset = static_cast<int32_t>(returnAddress - (hookFunctionAddress + sizeof(shellcode)));
        // Patch the calculated offset into the shellcode.
        memcpy(shellcode + sizeof(shellcode) - sizeof(int32_t), &relJmpOffset, sizeof(int32_t));

        #ifdef _DEBUG
        std::cout << "[+] Shellcode constructed. Target return address: 0x" << std::hex << returnAddress << std::dec << std::endl;
        std::cout << "[+]   Shellcode location: 0x" << std::hex << hookFunctionAddress << std::dec << std::endl;
        std::cout << "[+]   Relative jump offset: 0x" << std::hex << relJmpOffset << std::dec << std::endl;
        #endif

        size_t bytes_written = 0;
        // Step 4: Write the constructed shellcode to the allocated memory in the target process.
        if (StealthComm::WriteMemory(pid, hookFunctionAddress, shellcode, sizeof(shellcode), &bytes_written)) {
            if (bytes_written == sizeof(shellcode)) {
                #ifdef _DEBUG
                std::cout << "[+] StealthComm::WriteMemory: Shellcode written to allocated memory successfully!" << std::endl;
                #endif
                // Step 5: (Commented out) Place the hook. This would involve overwriting the original
                // instructions at KillauraInstruction with a JMP instruction to hookFunctionAddress.
                // Example: uint8_t jmp_to_hook_shellcode[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
                // int32_t rel_jmp_to_hook = static_cast<int32_t>(hookFunctionAddress - (KillauraInstruction + 5));
                // memcpy(jmp_to_hook_shellcode + 1, &rel_jmp_to_hook, sizeof(int32_t));
                // StealthComm::WriteMemory(pid, KillauraInstruction, jmp_to_hook_shellcode, sizeof(jmp_to_hook_shellcode), &bytes_written);
                // std::cout << "[+] Actual hook placed at KillauraInstruction (if previous line uncommented)." << std::endl;
            } else {
                std::cerr << "[-] StealthComm::WriteMemory: Wrote shellcode, but byte count mismatch. Wrote: "
                          << bytes_written << ", expected: " << sizeof(shellcode) << std::endl;
            }
        } else {
            std::cerr << "[-] StealthComm::WriteMemory: Failed to write shellcode to allocated memory." << std::endl;
        }
    } else {
        #ifdef _DEBUG
        if (KillauraInstruction == 0) std::cout << "[-] Skipping shellcode writing because KillauraInstruction is 0." << std::endl;
        if (hookFunctionAddress == 0) std::cout << "[-] Skipping shellcode writing because hookFunctionAddress is 0." << std::endl;
        #endif
    }

    #ifdef _DEBUG
    std::cout << "[+] Operations complete. Press Enter to shut down StealthComm and exit." << std::endl;
    #else
    std::cout << "Stealth operations finished. Press Enter to exit." << std::endl; // Minimal output for release
    #endif
    std::cin.get();

    StealthComm::ShutdownStealthComm();
    #ifdef _DEBUG
    std::cout << "[+] StealthComm shut down." << std::endl;
    #endif
    return 0;
}
