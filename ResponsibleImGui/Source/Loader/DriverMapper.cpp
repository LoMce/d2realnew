#include "DriverMapper.h"
#include "embedded/kdmapper_exe.h" // Contains const unsigned char kdmapper_exe[] and kdmapper_exe_len
#include "embedded/KM_sys.h"      // Contains const unsigned char KM_sys[] and KM_sys_len
#include <iostream>
#include <fstream>
#include <string> // Required for std::string, std::wstring
#include <vector> // Required for std::vector
#include <Windows.h>
#include <filesystem> // For std::filesystem::path operations if needed, though GetTempPathW/GetTempFileNameW are primary

// Note: <filesystem> might require C++17. If using an older standard,
// manual path concatenation would be needed, or stick to GetTempFileNameW's output.

namespace DriverMapper {

static bool ExecuteKdmapper(const unsigned char* kdmapper_data, unsigned int kdmapper_size, const unsigned char* driver_data, unsigned int driver_size) {
    std::wcout << L"[+] Starting kdmapper execution using temporary files..." << std::endl;

    wchar_t tempPathChars[MAX_PATH];
    DWORD pathLen = GetTempPathW(MAX_PATH, tempPathChars);
    if (pathLen == 0 || pathLen > MAX_PATH) {
        std::wcerr << L"[-] ExecuteKdmapper: GetTempPathW failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Create unique temporary file for kdmapper.exe
    wchar_t tempKdmapperPath[MAX_PATH];
    UINT kdmapperFileResult = GetTempFileNameW(tempPathChars, L"KDM", 0, tempKdmapperPath);
    if (kdmapperFileResult == 0) {
        std::wcerr << L"[-] ExecuteKdmapper: GetTempFileNameW for kdmapper.exe failed. Error: " << GetLastError() << std::endl;
        return false;
    }
    std::wstring kdmapperPathStr = tempKdmapperPath;
    // GetTempFileNameW creates a 0-byte file. Let's use this name but write with .exe extension.
    // Or, ensure the name used by CreateProcess ends with .exe.
    // For simplicity, we'll rename/recreate ensuring .exe. A more robust way is to append to a generated name.
    DeleteFileW(kdmapperPathStr.c_str()); // Delete the 0-byte file created by GetTempFileNameW
    kdmapperPathStr += L".exe"; // Append .exe extension


    // Create unique temporary file for the driver (e.g., KM.sys)
    wchar_t tempDriverSysPath[MAX_PATH];
    UINT driverFileResult = GetTempFileNameW(tempPathChars, L"SYS", 0, tempDriverSysPath);
    if (driverFileResult == 0) {
        std::wcerr << L"[-] ExecuteKdmapper: GetTempFileNameW for driver .sys file failed. Error: " << GetLastError() << std::endl;
        DeleteFileW(kdmapperPathStr.c_str()); // Clean up kdmapper if created
        return false;
    }
    std::wstring driverSysPathStr = tempDriverSysPath;
    // Rename to have .sys extension for clarity if needed, though kdmapper doesn't strictly require it for the path argument.
    // DeleteFileW(driverSysPathStr.c_str());
    // driverSysPathStr += L".sys";


    // Write kdmapper_data to tempKdmapperPath
    std::ofstream kdmapperFile(kdmapperPathStr, std::ios::binary | std::ios::trunc);
    if (!kdmapperFile.is_open()) {
        std::wcerr << L"[-] ExecuteKdmapper: Failed to create temporary kdmapper file: " << kdmapperPathStr << std::endl;
        DeleteFileW(driverSysPathStr.c_str());
        return false;
    }
    kdmapperFile.write(reinterpret_cast<const char*>(kdmapper_data), kdmapper_size);
    kdmapperFile.close();
    std::wcout << L"[+] ExecuteKdmapper: kdmapper.exe written to: " << kdmapperPathStr << std::endl;

    // Write driver_data to tempDriverSysPath
    std::ofstream driverFile(driverSysPathStr, std::ios::binary | std::ios::trunc);
    if (!driverFile.is_open()) {
        std::wcerr << L"[-] ExecuteKdmapper: Failed to create temporary driver file: " << driverSysPathStr << std::endl;
        DeleteFileW(kdmapperPathStr.c_str()); // Clean up kdmapper
        return false;
    }
    driverFile.write(reinterpret_cast<const char*>(driver_data), driver_size);
    driverFile.close();
    std::wcout << L"[+] ExecuteKdmapper: Driver .sys data written to: " << driverSysPathStr << std::endl;

    // Construct command line for kdmapper.exe
    // Example: "C:\temp\kdmapperXYZ.exe" /free /mdl /unlink "C:\temp\driverABC.sys"
    std::wstringstream commandLineStream;
    commandLineStream << L"\"" << kdmapperPathStr << L"\" /free /mdl /unlink \"" << driverSysPathStr << L"\"";
    std::wstring commandLine = commandLineStream.str();
    std::wcout << L"[+] ExecuteKdmapper: Command line: " << commandLine << std::endl;

    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    // si.dwFlags = STARTF_USESHOWWINDOW; // Optional: control window visibility
    // si.wShowWindow = SW_HIDE;         // Optional: hide window

    bool success = false;
    DWORD exitCode = 1; // Assume failure initially

    // Create a mutable version of commandLine for CreateProcessW
    std::vector<wchar_t> cmdLineVec(commandLine.begin(), commandLine.end());
    cmdLineVec.push_back(L'\0'); // Null-terminate

    if (CreateProcessW(
        nullptr,           // Application name (use command line)
        cmdLineVec.data(), // Command line
        nullptr,           // Process security attributes
        nullptr,           // Thread security attributes
        FALSE,             // bInheritHandles
        CREATE_NO_WINDOW,  // Creation flags (or 0 for default)
        nullptr,           // Environment
        nullptr,           // Current directory
        &si,               // STARTUPINFO
        &pi                // PROCESS_INFORMATION
    )) {
        std::wcout << L"[+] ExecuteKdmapper: kdmapper.exe process created. PID: " << pi.dwProcessId << std::endl;
        std::wcout << L"[+] ExecuteKdmapper: Waiting for kdmapper.exe to finish..." << std::endl;
        WaitForSingleObject(pi.hProcess, INFINITE); // Wait indefinitely

        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
            if (exitCode == 0) {
                std::wcout << L"[+] ExecuteKdmapper: kdmapper.exe exited successfully (Exit Code: 0)." << std::endl;
                success = true;
            } else {
                std::wcerr << L"[-] ExecuteKdmapper: kdmapper.exe failed (Exit Code: " << exitCode << L")." << std::endl;
            }
        } else {
            std::wcerr << L"[-] ExecuteKdmapper: GetExitCodeProcess failed. Error: " << GetLastError() << std::endl;
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        std::wcerr << L"[-] ExecuteKdmapper: CreateProcessW failed for kdmapper.exe. Error: " << GetLastError() << std::endl;
    }

    // Cleanup temporary files
    if (!DeleteFileW(kdmapperPathStr.c_str())) {
        std::wcerr << L"[-] ExecuteKdmapper: Failed to delete temporary kdmapper.exe: " << kdmapperPathStr << L". Error: " << GetLastError() << std::endl;
    } else {
        std::wcout << L"[+] ExecuteKdmapper: Cleaned up temporary kdmapper.exe: " << kdmapperPathStr << std::endl;
    }
    if (!DeleteFileW(driverSysPathStr.c_str())) {
        std::wcerr << L"[-] ExecuteKdmapper: Failed to delete temporary driver .sys file: " << driverSysPathStr << L". Error: " << GetLastError() << std::endl;
    } else {
        std::wcout << L"[+] ExecuteKdmapper: Cleaned up temporary driver .sys file: " << driverSysPathStr << std::endl;
    }

    return success;
}


bool MapDriver() {
    std::wcout << L"[+] Starting driver mapping process..." << std::endl;
    
    try {
        // Using embedded data from headers
        if (!ExecuteKdmapper(kdmapper_exe, kdmapper_exe_len, KM_sys, KM_sys_len)) {
            std::wcerr << L"[-] Driver mapping failed using kdmapper." << std::endl;
            return false;
        }
        
        std::wcout << L"[+] Driver mapping process completed by kdmapper." << std::endl;
        Sleep(1000); // Brief pause for driver to initialize (common practice)

        if (IsDriverLoaded()) { // This will now use the NOP check
            std::wcout << L"[+] Driver presence verified after mapping!" << std::endl;
            return true;
        } else {
            std::wcerr << L"[-] Driver presence verification failed after mapping attempt!" << std::endl;
            return false;
        }
    }
    catch (const std::exception& e) {
        std::wcerr << L"[-] Exception during driver mapping: " << e.what() << std::endl;
        return false;
    }
     catch (...) {
        std::wcerr << L"[-] Unknown exception during driver mapping." << std::endl;
        return false;
    }
}

bool IsDriverLoaded() {
    std::wcout << L"[*] IsDriverLoaded: Attempting to verify driver presence via StealthComm NOP..." << std::endl;

    if (!StealthComm::g_shared_comm_block) { // Check if UM side is initialized
         std::wcout << L"[~] IsDriverLoaded: StealthComm not initialized by main logic yet. Attempting temporary init for check." << std::endl;
        if (!StealthComm::InitializeStealthComm()) {
            std::wcerr << L"[-] IsDriverLoaded: StealthComm::InitializeStealthComm() failed during temporary check. Assuming driver is not loaded." << std::endl;
            return false; // Cannot check if comms cannot be initialized
        }
         std::wcout << L"[+] IsDriverLoaded: StealthComm temporarily initialized for check." << std::endl;
    }


    uint64_t km_status_code = 0;
    uint8_t dummy_output[1];
    uint32_t output_size = 0;

    bool request_success = StealthComm::SubmitRequestAndWait(
        CommCommand::REQUEST_NOP,
        (uint64_t)GetCurrentProcessId(),
        nullptr, 0,
        dummy_output, output_size,
        km_status_code,
        1000
    );

    // If we did a temporary init, consider shutting it down.
    // However, the main application logic might rely on it staying initialized if MapDriver was called first.
    // For this specific function, if it did a *temporary* init, it should ideally clean up.
    // This part is tricky without knowing the broader application flow.
    // For now, let's assume if g_shared_comm_block was NULL initially, we should shut down.
    // This needs careful consideration in the context of the whole loader.
    // A simple flag passed to InitializeStealthComm could indicate "init_for_check_only".
    // For now, we won't automatically shut down here to avoid breaking main flow if it was already up.

    if (request_success && MY_NT_SUCCESS(km_status_code)) {
        std::wcout << L"[+] IsDriverLoaded: REQUEST_NOP successful. Driver appears to be loaded and responsive." << std::endl;
        return true;
    } else {
        if (!request_success) {
            std::wcerr << L"[-] IsDriverLoaded: SubmitRequestAndWait for NOP failed." << std::endl;
        }
        if (!MY_NT_SUCCESS(km_status_code)) {
            std::wcerr << L"[-] IsDriverLoaded: NOP command failed with KM status: 0x" << std::hex << km_status_code << std::dec << std::endl;
        }
        std::wcerr << L"[-] IsDriverLoaded: Driver does not appear to be loaded or responsive." << std::endl;
        return false;
    }
}

} // namespace DriverMapper
