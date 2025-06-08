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
    bool attach_to_process(const DWORD pid);

    // Shuts down communication with the driver.
    void shutdown();

    template <class T>
    T read_memory(const std::uintptr_t addr);

    template <class T>
    bool write_memory(const std::uintptr_t addr, const T& value);

    bool read_memory_buffer(const std::uintptr_t addr, void* buffer, SIZE_T size);
    bool write_memory_buffer(const std::uintptr_t addr, const void* buffer, SIZE_T size);

    // Gets the base address of a module in the specified process.
    uintptr_t GetModuleBase(DWORD pid, const wchar_t* module_name);

    // Performs an Array of Bytes (AOB) scan in the target process.
    // Returns the address of the found pattern, or nullptr if not found.
    // mask parameter is currently not used by underlying StealthComm::AobScan.
    uintptr_t AOBScan(uintptr_t startAddress, SIZE_T regionSize, const char* pattern, const char* mask);

    // Allocates memory in the target process.
    // out_address will contain the base address of the allocated memory on success.
    // allocHint is an optional address to guide where memory should be allocated.
    bool allocate_memory(DWORD pid, SIZE_T size, uintptr_t& out_address, PVOID allocHint = nullptr);

}
