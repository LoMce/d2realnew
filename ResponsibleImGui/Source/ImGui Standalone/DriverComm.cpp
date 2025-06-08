#include "DriverComm.h"
#include <Windows.h>
// #include <TlHelp32.h> // Not needed here if get_process_id is external to DriverComm
#include <iostream>
#include <cstring> // For memcpy, wcslen, etc.
// StealthComm.h is included via DriverComm.h

namespace DriverComm {

    DWORD g_pid = 0; // Global PID for this module, set by attach_to_process

    NTSTATUS attach_to_process(const DWORD pid_to_attach) { // Returns NTSTATUS
        if (pid_to_attach == 0) {
            std::cerr << "[-] DriverComm::attach_to_process: Invalid PID (0)." << std::endl;
            return STATUS_INVALID_PARAMETER_1; // Using common NTSTATUS codes
        }
        // StealthComm::InitializeStealthComm now returns NTSTATUS
        NTSTATUS status = StealthComm::InitializeStealthComm();
        if (!NT_SUCCESS(status)) {
            std::cerr << "[-] DriverComm::attach_to_process: StealthComm::InitializeStealthComm() failed with status 0x" << std::hex << status << std::dec << std::endl;
            return status;
        }
        DriverComm::g_pid = pid_to_attach;
        #ifdef _DEBUG
        std::cout << "[+] DriverComm::attach_to_process: Successfully initialized StealthComm and attached to PID: " << pid_to_attach << std::endl;
        #endif
        return STATUS_SUCCESS;
    }

    void shutdown() {
        #ifdef _DEBUG
        std::cout << "[+] DriverComm::shutdown: Shutting down StealthComm..." << std::endl;
        #endif
        StealthComm::ShutdownStealthComm();
        DriverComm::g_pid = 0; // Reset PID
    }

    template <class T>
    NTSTATUS read_memory(const std::uintptr_t addr, T& out_value) {
        out_value = {}; // Initialize to default
        if (DriverComm::g_pid == 0) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::read_memory: Not attached (PID is 0)." << std::endl;
            #endif
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (addr == 0) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::read_memory: Attempted to read from NULL address." << std::endl;
            #endif
            return STATUS_INVALID_PARAMETER_1; // Address is param 1
        }

        size_t bytes_read = 0;
        NTSTATUS status = StealthComm::ReadMemory(DriverComm::g_pid, addr, &out_value, sizeof(T), &bytes_read);

        if (!NT_SUCCESS(status)) {
            // StealthComm::ReadMemory already logs its errors.
            // Log DriverComm specific context if needed.
            #ifdef _DEBUG
            // std::cerr << "[-] DriverComm::read_memory: StealthComm::ReadMemory failed for address 0x" << std::hex << addr << " with status 0x" << status << std::dec << std::endl;
            #endif
            RtlZeroMemory(&out_value, sizeof(T)); // Zero out on failure
            return status;
        }

        if (bytes_read != sizeof(T)) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::read_memory: Read size mismatch for address 0x" << std::hex << addr
                      << std::dec << ". Expected " << sizeof(T) << ", Got " << bytes_read << std::endl;
            #endif
            RtlZeroMemory(&out_value, sizeof(T)); // Zero out on partial read for safety
            return STATUS_PARTIAL_COPY; // Or a more specific error
        }
        return STATUS_SUCCESS;
    }

    template <class T>
    NTSTATUS write_memory(const std::uintptr_t addr, const T& value) {
        if (DriverComm::g_pid == 0) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::write_memory: Not attached (PID is 0)." << std::endl;
            #endif
            return STATUS_INVALID_DEVICE_STATE;
        }
         if (addr == 0) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::write_memory: Attempted to write to NULL address." << std::endl;
            #endif
            return STATUS_INVALID_PARAMETER_1;
        }

        size_t bytes_written = 0;
        NTSTATUS status = StealthComm::WriteMemory(DriverComm::g_pid, addr, &value, sizeof(T), &bytes_written);

        if (!NT_SUCCESS(status)) {
            #ifdef _DEBUG
            // std::cerr << "[-] DriverComm::write_memory: StealthComm::WriteMemory failed for address 0x" << std::hex << addr << " with status 0x" << status << std::dec << std::endl;
            #endif
            return status;
        }

        if (bytes_written != sizeof(T)) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::write_memory: Write size mismatch for address 0x" << std::hex << addr
                      << std::dec << ". Expected " << sizeof(T) << ", Wrote " << bytes_written << std::endl;
            #endif
            return STATUS_PARTIAL_COPY; // Indicate error on partial write
        }
        return STATUS_SUCCESS;
    }

    // Explicit instantiations
    template bool write_memory<bool>(const std::uintptr_t addr, const bool& value);
    template bool write_memory<int>(const std::uintptr_t addr, const int& value);
    template bool write_memory<float>(const std::uintptr_t addr, const float& value);
    template bool write_memory<double>(const std::uintptr_t addr, const double& value);
    template bool write_memory<uint8_t>(const std::uintptr_t addr, const uint8_t& value);
    template bool write_memory<uint16_t>(const std::uintptr_t addr, const uint16_t& value);
    template NTSTATUS write_memory<bool>(const std::uintptr_t addr, const bool& value);
    template NTSTATUS write_memory<int>(const std::uintptr_t addr, const int& value);
    template NTSTATUS write_memory<float>(const std::uintptr_t addr, const float& value);
    template NTSTATUS write_memory<double>(const std::uintptr_t addr, const double& value);
    template NTSTATUS write_memory<uint8_t>(const std::uintptr_t addr, const uint8_t& value);
    template NTSTATUS write_memory<uint16_t>(const std::uintptr_t addr, const uint16_t& value);
    template NTSTATUS write_memory<uint32_t>(const std::uintptr_t addr, const uint32_t& value);
    template NTSTATUS write_memory<uint64_t>(const std::uintptr_t addr, const uint64_t& value);
    // template NTSTATUS write_memory<void*>(const std::uintptr_t addr, void* const& value);

    template NTSTATUS read_memory<int>(const std::uintptr_t addr, int& out_value);
    template NTSTATUS read_memory<float>(const std::uintptr_t addr, float& out_value);
    template NTSTATUS read_memory<double>(const std::uintptr_t addr, double& out_value);
    template NTSTATUS read_memory<bool>(const std::uintptr_t addr, bool& out_value);
    template NTSTATUS read_memory<uint8_t>(const std::uintptr_t addr, uint8_t& out_value);
    template NTSTATUS read_memory<uint16_t>(const std::uintptr_t addr, uint16_t& out_value);
    template NTSTATUS read_memory<uint32_t>(const std::uintptr_t addr, uint32_t& out_value);
    template NTSTATUS read_memory<uint64_t>(const std::uintptr_t addr, uint64_t& out_value);
    // template NTSTATUS read_memory<void*>(const std::uintptr_t addr, void*& out_value);


    // New NTSTATUS returning function
    NTSTATUS allocate_memory_ex(DWORD pid, SIZE_T size, uintptr_t& out_address, PVOID allocHint) {
        out_address = 0;
        DWORD target_pid_to_use = (pid != 0) ? pid : DriverComm::g_pid;
        if (target_pid_to_use == 0) {
            std::cerr << "[-] DriverComm::allocate_memory_ex: PID not set and not provided." << std::endl;
            return STATUS_INVALID_PARAMETER; // Or STATUS_INVALID_DEVICE_STATE
        }
        // StealthComm::AllocateMemory returns uintptr_t (0 on error), not NTSTATUS directly.
        // We need to infer NTSTATUS or modify StealthComm::AllocateMemory.
        // For now, assume 0 means failure from StealthComm::AllocateMemory.
        out_address = StealthComm::AllocateMemory(static_cast<uint64_t>(target_pid_to_use), size, reinterpret_cast<uintptr_t>(allocHint));
        if (out_address != 0) {
            return STATUS_SUCCESS;
        } else {
            // StealthComm::AllocateMemory already logs.
            return STATUS_NO_MEMORY; // Generic failure if StealthComm returned 0
        }
    }
    // Old compatible function
    bool allocate_memory(DWORD pid_arg, SIZE_T size, uintptr_t& out_address, PVOID allocHint) {
        return NT_SUCCESS(allocate_memory_ex(pid_arg, size, out_address, allocHint));
    }


    NTSTATUS get_module_base_info(DWORD pid, const wchar_t* module_name, uintptr_t& out_base_address) {
        out_base_address = 0;
        DWORD target_pid_to_use = (pid != 0) ? pid : DriverComm::g_pid;
        if (target_pid_to_use == 0) {
            std::cerr << "[-] DriverComm::get_module_base_info: PID not set and not provided." << std::endl;
            return STATUS_INVALID_PARAMETER;
        }
        // StealthComm::GetModuleBase returns uintptr_t (0 on error)
        out_base_address = StealthComm::GetModuleBase(static_cast<uint64_t>(target_pid_to_use), module_name);
        if (out_base_address == 0) {
            // StealthComm::GetModuleBase logs more detailed errors internally.
            // Return a general error; could be STATUS_NOT_FOUND or other from underlying calls.
            return STATUS_NOT_FOUND; // Or map from a StealthComm error if it provided one
        }
        return STATUS_SUCCESS;
    }
    // Old compatible function
    uintptr_t GetModuleBase(DWORD pid_arg, const wchar_t* module_name) {
        uintptr_t base_addr = 0;
        get_module_base_info(pid_arg, module_name, base_addr);
        return base_addr; // Returns 0 on failure
    }


    NTSTATUS aob_scan_info(DWORD pid_to_use, uintptr_t startAddress, SIZE_T regionSize, const char* pattern, const char* mask, uintptr_t& out_found_address) {
        out_found_address = 0;
        DWORD target_pid_to_use_final = (pid_to_use != 0) ? pid_to_use : DriverComm::g_pid;
        if (target_pid_to_use_final == 0) {
            std::cerr << "[-] DriverComm::aob_scan_info: PID not set." << std::endl;
            return STATUS_INVALID_PARAMETER;
        }
        // StealthComm::AobScan returns uintptr_t (0 on error/not found)
        out_found_address = StealthComm::AobScan(target_pid_to_use_final, startAddress, regionSize, pattern, mask, nullptr, 0);
        if (out_found_address == 0) {
            // StealthComm::AobScan logs.
            return STATUS_NOT_FOUND; // Or a more specific error if StealthComm could provide one
        }
        return STATUS_SUCCESS;
    }
    // Old compatible function
    uintptr_t AOBScan(uintptr_t startAddress, SIZE_T regionSize, const char* pattern, const char* mask) {
        uintptr_t found_addr = 0;
        aob_scan_info(DriverComm::g_pid, startAddress, regionSize, pattern, mask, found_addr);
        return found_addr; // Returns 0 on failure
    }


    NTSTATUS read_memory_buffer(const std::uintptr_t addr, void* buffer, SIZE_T size, SIZE_T* out_bytes_read) {
        if (out_bytes_read) *out_bytes_read = 0;
        if (DriverComm::g_pid == 0) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (addr == 0) {
            return STATUS_INVALID_PARAMETER_1;
        }
        if (!buffer) {
            return STATUS_INVALID_PARAMETER_2;
        }
        if (size == 0) {
            return STATUS_SUCCESS; // Nothing to read
        }
        // StealthComm::ReadMemory now returns NTSTATUS
        return StealthComm::ReadMemory(DriverComm::g_pid, addr, buffer, size, out_bytes_read);
    }

    NTSTATUS write_memory_buffer(const std::uintptr_t addr, const void* buffer, SIZE_T size, SIZE_T* out_bytes_written) {
        if (out_bytes_written) *out_bytes_written = 0;
        if (DriverComm::g_pid == 0) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (addr == 0) {
            return STATUS_INVALID_PARAMETER_1;
        }
        if (!buffer) {
            return STATUS_INVALID_PARAMETER_2;
        }
        if (size == 0) {
            return STATUS_SUCCESS; // Nothing to write
        }
        // StealthComm::WriteMemory now returns NTSTATUS
        return StealthComm::WriteMemory(DriverComm::g_pid, addr, buffer, size, out_bytes_written);
    }

    NTSTATUS free_memory_ex(DWORD pid, uintptr_t address, SIZE_T size) {
        DWORD target_pid_to_use = (pid != 0) ? pid : DriverComm::g_pid;
        if (target_pid_to_use == 0) {
            std::cerr << "[-] DriverComm::free_memory_ex: PID not set." << std::endl;
            return STATUS_INVALID_PARAMETER;
        }
        if (address == 0) {
            std::cerr << "[-] DriverComm::free_memory_ex: Address cannot be zero." << std::endl;
            return STATUS_INVALID_PARAMETER_2;
        }
        // StealthComm::FreeMemory now returns NTSTATUS
        NTSTATUS status = StealthComm::FreeMemory(static_cast<uint64_t>(target_pid_to_use), address, size);
        if (!NT_SUCCESS(status)) {
            #ifdef _DEBUG
            std::cerr << "[-] DriverComm::free_memory_ex: StealthComm::FreeMemory failed for address 0x" << std::hex << address << " with status 0x" << status << std::dec << std::endl;
            #endif
        }
        return status;
    }
    // Old compatible function
    bool free_memory(uintptr_t address, SIZE_T size) {
        return NT_SUCCESS(free_memory_ex(DriverComm::g_pid, address, size));
    }

} // namespace DriverComm
