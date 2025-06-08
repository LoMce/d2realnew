#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>

// Scan flag bitmask definitions (These are generic and can remain if used by client code)
#define SCAN_FLAG_WRITABLE        0x01
#define SCAN_FLAG_EXECUTABLE      0x02
#define SCAN_FLAG_COPYONWRITE     0x04
#define SCAN_FLAG_COMMITTED_ONLY  0x08
#define SCAN_FLAG_FASTSCAN_4      0x10
#define SCAN_FLAG_FASTSCAN_8      0x20

// Include the StealthComm header
// Corrected relative path assuming KM-UM and ResponsibleImGui are siblings
#include "../../../KM-UM/UM/src/StealthComm.h"

namespace DriverComm {

    // Attempts to initialize communication with the driver and sets the target process.
    // This should be called before any other DriverComm functions.
    // Returns NTSTATUS for more detailed error information.
    NTSTATUS attach_to_process(const DWORD pid);

    // Shuts down communication with the driver.
    void shutdown();

    // Returns NTSTATUS. Data is returned via 'out_value'.
    template <class T>
    NTSTATUS read_memory(const std::uintptr_t addr, T& out_value);

    // Returns NTSTATUS.
    template <class T>
    NTSTATUS write_memory(const std::uintptr_t addr, const T& value);

    // Returns NTSTATUS.
    NTSTATUS read_memory_buffer(const std::uintptr_t addr, void* buffer, SIZE_T size, SIZE_T* out_bytes_read = nullptr);
    NTSTATUS write_memory_buffer(const std::uintptr_t addr, const void* buffer, SIZE_T size, SIZE_T* out_bytes_written = nullptr);

    // Returns NTSTATUS. Base address is returned via 'out_base_address'.
    NTSTATUS get_module_base_info(DWORD pid, const wchar_t* module_name, uintptr_t& out_base_address);
    // Retain old GetModuleBase for compatibility if direct uintptr_t return is preferred in some places,
    // but it will internally call get_module_base_info and handle status.
    uintptr_t GetModuleBase(DWORD pid, const wchar_t* module_name);


    // Returns NTSTATUS. Found address is returned via 'out_found_address'.
    NTSTATUS aob_scan_info(DWORD pid_to_use, uintptr_t startAddress, SIZE_T regionSize, const char* pattern, const char* mask, uintptr_t& out_found_address);
    // Retain old AOBScan for compatibility.
    uintptr_t AOBScan(uintptr_t startAddress, SIZE_T regionSize, const char* pattern, const char* mask);


    // Returns NTSTATUS. Allocated address is returned via 'out_address'.
    NTSTATUS allocate_memory_ex(DWORD pid, SIZE_T size, uintptr_t& out_address, PVOID allocHint = nullptr);
    // Retain old allocate_memory for compatibility.
    bool allocate_memory(DWORD pid, SIZE_T size, uintptr_t& out_address, PVOID allocHint = nullptr);


    // Returns NTSTATUS.
    NTSTATUS free_memory_ex(DWORD pid, uintptr_t address, SIZE_T size);
    // Retain old free_memory for compatibility
    bool free_memory(uintptr_t address, SIZE_T size);

}
