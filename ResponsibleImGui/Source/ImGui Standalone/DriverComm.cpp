#include "DriverComm.h"
#include <Windows.h>
// #include <TlHelp32.h> // Not needed here if get_process_id is external to DriverComm
#include <iostream>
#include <cstring> // For memcpy, wcslen, etc.
// StealthComm.h is included via DriverComm.h

namespace DriverComm {

    DWORD g_pid = 0; // Global PID for this module, set by attach_to_process

    bool attach_to_process(const DWORD pid_to_attach) {
        if (pid_to_attach == 0) {
            std::cerr << "[-] DriverComm::attach_to_process: Invalid PID (0)." << std::endl;
            return false;
        }
        if (!StealthComm::InitializeStealthComm()) {
            std::cerr << "[-] DriverComm::attach_to_process: StealthComm::InitializeStealthComm() failed." << std::endl;
            return false;
        }
        DriverComm::g_pid = pid_to_attach;
        #ifdef _DEBUG
        std::cout << "[+] DriverComm::attach_to_process: Successfully initialized StealthComm and attached to PID: " << pid_to_attach << std::endl;
        #endif
        // Optionally, perform a simple test read or NOP command to confirm KM side is responsive.
        return true;
    }

    void shutdown() {
        #ifdef _DEBUG
        std::cout << "[+] DriverComm::shutdown: Shutting down StealthComm..." << std::endl;
        #endif
        StealthComm::ShutdownStealthComm();
        DriverComm::g_pid = 0; // Reset PID
    }

    template <class T>
    T read_memory(const std::uintptr_t addr) {
        T temp_buffer = {}; // Initialize to default value (e.g., 0, false, nullptr)
        if (DriverComm::g_pid == 0) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::read_memory: Not attached to any process (PID is 0). Call attach_to_process first." << std::endl;
            #endif
            return temp_buffer;
        }
        if (addr == 0) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::read_memory: Attempted to read from NULL address." << std::endl;
            #endif
            return temp_buffer;
        }

        size_t bytes_read = 0;
        if (!StealthComm::ReadMemory(DriverComm::g_pid, addr, &temp_buffer, sizeof(T), &bytes_read)) {
            #ifdef _DEBUG
            // StealthComm::ReadMemory might already log, but a DriverComm level log can be useful.
            // std::cerr << "[-] DriverComm::read_memory: StealthComm::ReadMemory failed for address 0x" << std::hex << addr << std::dec << std::endl;
            #endif
            // Return default-initialized buffer on failure
        } else if (bytes_read != sizeof(T)) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::read_memory: Read size mismatch for address 0x" << std::hex << addr
                      << std::dec << ". Expected " << sizeof(T) << ", Got " << bytes_read << std::endl;
            #endif
            // Partial read or error, return default-initialized buffer
            RtlZeroMemory(&temp_buffer, sizeof(T)); // Zero out on partial read for safety
        }
        return temp_buffer;
    }

    template <class T>
    bool write_memory(const std::uintptr_t addr, const T& value) {
        if (DriverComm::g_pid == 0) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::write_memory: Not attached to any process (PID is 0). Call attach_to_process first." << std::endl;
            #endif
            return false;
        }
         if (addr == 0) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::write_memory: Attempted to write to NULL address." << std::endl;
            #endif
            return false;
        }

        size_t bytes_written = 0;
        bool success = StealthComm::WriteMemory(DriverComm::g_pid, addr, &value, sizeof(T), &bytes_written);
        if (!success) {
             #ifdef _DEBUG
            // std::cerr << "[-] DriverComm::write_memory: StealthComm::WriteMemory failed for address 0x" << std::hex << addr << std::dec << std::endl;
            #endif
        } else if (bytes_written != sizeof(T)) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::write_memory: Write size mismatch for address 0x" << std::hex << addr
                      << std::dec << ". Expected " << sizeof(T) << ", Wrote " << bytes_written << std::endl;
            #endif
            return false; // Indicate error on partial write
        }
        return success && (bytes_written == sizeof(T));
    }

    // Explicit instantiations
    template bool write_memory<bool>(const std::uintptr_t addr, const bool& value);
    template bool write_memory<int>(const std::uintptr_t addr, const int& value);
    template bool write_memory<float>(const std::uintptr_t addr, const float& value);
    template bool write_memory<double>(const std::uintptr_t addr, const double& value);
    template bool write_memory<uint8_t>(const std::uintptr_t addr, const uint8_t& value);
    template bool write_memory<uint16_t>(const std::uintptr_t addr, const uint16_t& value);
    template bool write_memory<uint32_t>(const std::uintptr_t addr, const uint32_t& value);
    template bool write_memory<uint64_t>(const std::uintptr_t addr, const uint64_t& value);
    // Example for pointer types if used, though less common for generic T like this
    // template bool write_memory<void*>(const std::uintptr_t addr, void* const& value);


    template int read_memory<int>(const std::uintptr_t addr);
    template float read_memory<float>(const std::uintptr_t addr);
    template double read_memory<double>(const std::uintptr_t addr);
    template bool read_memory<bool>(const std::uintptr_t addr);
    template uint8_t read_memory<uint8_t>(const std::uintptr_t addr);
    template uint16_t read_memory<uint16_t>(const std::uintptr_t addr);
    template uint32_t read_memory<uint32_t>(const std::uintptr_t addr);
    template uint64_t read_memory<uint64_t>(const std::uintptr_t addr);
    // Example for pointer types
    // template void* read_memory<void*>(const std::uintptr_t addr);


    bool allocate_memory(DWORD pid_arg, SIZE_T size, uintptr_t& out_address, PVOID allocHint) {
        if (pid_arg == 0 && DriverComm::g_pid == 0) { // Allow passing PID or using global
             std::cerr << "[-] DriverComm::allocate_memory: PID not set and not provided." << std::endl;
            return false;
        }
        DWORD target_pid_to_use = (pid_arg != 0) ? pid_arg : DriverComm::g_pid;

        out_address = StealthComm::AllocateMemory(static_cast<uint64_t>(target_pid_to_use), size, reinterpret_cast<uintptr_t>(allocHint));
        if (out_address != 0) {
            #ifdef _DEBUG
            // StealthComm logs this, so DriverComm might not need to.
            // std::cout << "[+] DriverComm::allocate_memory: Allocated " << size << " bytes at: 0x" << std::hex << out_address << " for PID " << target_pid_to_use << std::dec << std::endl;
            #endif
            return true;
        }
        #ifdef _DEBUG
        // std::cerr << "[-] DriverComm::allocate_memory: Failed to allocate memory for PID " << target_pid_to_use << "." << std::endl;
        #endif
        return false;
    }

    uintptr_t GetModuleBase(DWORD pid_arg, const wchar_t* module_name) {
         if (pid_arg == 0 && DriverComm::g_pid == 0) {
            std::cerr << "[-] DriverComm::GetModuleBase: PID not set and not provided." << std::endl;
            return 0;
        }
        DWORD target_pid_to_use = (pid_arg != 0) ? pid_arg : DriverComm::g_pid;
        uintptr_t base = StealthComm::GetModuleBase(static_cast<uint64_t>(target_pid_to_use), module_name);
        // if (base == 0) {
        //     #ifdef _DEBUG
        //     std::wcerr << L"[-] DriverComm::GetModuleBase: Failed to get base for module '" << module_name << L"' in PID " << target_pid_to_use << std::endl;
        //     #endif
        // }
        return base;
    }

    uintptr_t AOBScan(uintptr_t startAddress, SIZE_T regionSize, const char* pattern, const char* mask) {
        if (DriverComm::g_pid == 0) {
            std::cerr << "[-] DriverComm::AOBScan: PID not set. Call attach_to_process first." << std::endl;
            return 0;
        }
        uintptr_t result_addr = StealthComm::AobScan(DriverComm::g_pid, startAddress, regionSize, pattern, mask, nullptr, 0);
        // if (result_addr == 0) {
        //     #ifdef _DEBUG
        //     std::cerr << "[-] DriverComm::AOBScan: Pattern not found. Start: 0x" << std::hex << startAddress << ", Size: " << regionSize << ", Pattern: " << pattern << std::dec << std::endl;
        //     #endif
        // }
        return result_addr;
    }

} // namespace DriverComm
