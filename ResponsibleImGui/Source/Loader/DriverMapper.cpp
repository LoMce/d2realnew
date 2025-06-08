#include "DriverMapper.h"
#include "embedded/kdmapper_exe.h" // Contains const unsigned char kdmapper_exe[] and kdmapper_exe_len
#include "embedded/KM_sys.h"      // Contains const unsigned char KM_sys[] and KM_sys_len
// #include <iostream> // Replaced by Logging.h
#include <fstream>
#include <string> // Required for std::string, std::wstring
#include <vector> // Required for std::vector
#include <Windows.h>
#include <filesystem> // For std::filesystem::path operations if needed, though GetTempPathW/GetTempFileNameW are primary
#include <sstream> // For std::wstringstream
#include "../ImGui Standalone/Logging.h" // Added Logging.h

// Note: <filesystem> might require C++17. If using an older standard,
// manual path concatenation would be needed, or stick to GetTempFileNameW's output.

// Helper to convert wstring to string for logging
static std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

namespace DriverMapper {

static bool ExecuteKdmapper(const unsigned char* kdmapper_data, unsigned int kdmapper_size, const unsigned char* driver_data, unsigned int driver_size) {
    LogMessage("[+] Starting kdmapper execution using temporary files...");

    wchar_t tempPathChars[MAX_PATH];
    DWORD pathLen = GetTempPathW(MAX_PATH, tempPathChars);
    if (pathLen == 0 || pathLen > MAX_PATH) {
        LogMessageF("[-] ExecuteKdmapper: GetTempPathW failed. Error: %lu", GetLastError());
        return false;
    }

    // Create unique temporary file for kdmapper.exe
    wchar_t tempKdmapperPath[MAX_PATH];
    UINT kdmapperFileResult = GetTempFileNameW(tempPathChars, L"KDM", 0, tempKdmapperPath);
    if (kdmapperFileResult == 0) {
        LogMessageF("[-] ExecuteKdmapper: GetTempFileNameW for kdmapper.exe failed. Error: %lu", GetLastError());
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
        LogMessageF("[-] ExecuteKdmapper: GetTempFileNameW for driver .sys file failed. Error: %lu", GetLastError());
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
        LogMessageF("[-] ExecuteKdmapper: Failed to create temporary kdmapper file: %s", WStringToString(kdmapperPathStr).c_str());
        DeleteFileW(driverSysPathStr.c_str());
        return false;
    }
    kdmapperFile.write(reinterpret_cast<const char*>(kdmapper_data), kdmapper_size);
    kdmapperFile.close();
    LogMessageF("[+] ExecuteKdmapper: kdmapper.exe written to: %s", WStringToString(kdmapperPathStr).c_str());

    // Write driver_data to tempDriverSysPath
    std::ofstream driverFile(driverSysPathStr, std::ios::binary | std::ios::trunc);
    if (!driverFile.is_open()) {
        LogMessageF("[-] ExecuteKdmapper: Failed to create temporary driver file: %s", WStringToString(driverSysPathStr).c_str());
        DeleteFileW(kdmapperPathStr.c_str()); // Clean up kdmapper
        return false;
    }
    driverFile.write(reinterpret_cast<const char*>(driver_data), driver_size);
    driverFile.close();
    LogMessageF("[+] ExecuteKdmapper: Driver .sys data written to: %s", WStringToString(driverSysPathStr).c_str());

    // Construct command line for kdmapper.exe
    // Example: "C:\temp\kdmapperXYZ.exe" /free /mdl /unlink "C:\temp\driverABC.sys"
    std::wstringstream commandLineStream;
    commandLineStream << L"\"" << kdmapperPathStr << L"\" /free /mdl /unlink \"" << driverSysPathStr << L"\"";
    std::wstring commandLine = commandLineStream.str();
    LogMessageF("[+] ExecuteKdmapper: Command line: %s", WStringToString(commandLine).c_str());

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
        LogMessageF("[+] ExecuteKdmapper: kdmapper.exe process created. PID: %lu", pi.dwProcessId);
        LogMessage("[+] ExecuteKdmapper: Waiting for kdmapper.exe to finish...");
        WaitForSingleObject(pi.hProcess, INFINITE); // Wait indefinitely

        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
            if (exitCode == 0) {
                LogMessage("[+] ExecuteKdmapper: kdmapper.exe exited successfully (Exit Code: 0).");
                success = true;
            } else {
                LogMessageF("[-] ExecuteKdmapper: kdmapper.exe failed (Exit Code: %lu).", exitCode);
            }
        } else {
            LogMessageF("[-] ExecuteKdmapper: GetExitCodeProcess failed. Error: %lu", GetLastError());
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        LogMessageF("[-] ExecuteKdmapper: CreateProcessW failed for kdmapper.exe. Error: %lu", GetLastError());
    }

    // Cleanup temporary files
    if (!DeleteFileW(kdmapperPathStr.c_str())) {
        LogMessageF("[-] ExecuteKdmapper: Failed to delete temporary kdmapper.exe: %s. Error: %lu", WStringToString(kdmapperPathStr).c_str(), GetLastError());
    } else {
        LogMessageF("[+] ExecuteKdmapper: Cleaned up temporary kdmapper.exe: %s", WStringToString(kdmapperPathStr).c_str());
    }
    if (!DeleteFileW(driverSysPathStr.c_str())) {
        LogMessageF("[-] ExecuteKdmapper: Failed to delete temporary driver .sys file: %s. Error: %lu", WStringToString(driverSysPathStr).c_str(), GetLastError());
    } else {
        LogMessageF("[+] ExecuteKdmapper: Cleaned up temporary driver .sys file: %s", WStringToString(driverSysPathStr).c_str());
    }

    return success;
}


bool MapDriver() {
    LogMessage("[+] Starting driver mapping process...");
    
    try {
        // Using embedded data from headers
        if (!ExecuteKdmapper(kdmapper_exe, kdmapper_exe_len, KM_sys, KM_sys_len)) {
            LogMessage("[-] Driver mapping failed using kdmapper.");
            return false;
        }
        
        LogMessage("[+] Driver mapping process completed by kdmapper.");
        Sleep(1000); // Brief pause for driver to initialize (common practice)

        if (IsDriverLoaded()) { // This will now use the NOP check
            LogMessage("[+] Driver presence verified after mapping!");
            return true;
        } else {
            LogMessage("[-] Driver presence verification failed after mapping attempt!");
            return false;
        }
    }
    catch (const std::exception& e) {
        LogMessageF("[-] Exception during driver mapping: %s", e.what());
        return false;
    }
     catch (...) {
        LogMessage("[-] Unknown exception during driver mapping.");
        return false;
    }
}

bool IsDriverLoaded() {
    LogMessage("[*] IsDriverLoaded: Attempting to verify driver presence via StealthComm NOP...");

    bool was_initialized_by_us = false;
    if (!StealthComm::g_shared_comm_block) { // Check if not already initialized by someone else
        LogMessage("[~] IsDriverLoaded: StealthComm not initialized by main logic yet. Attempting temporary init for check.");
        NTSTATUS init_status = StealthComm::InitializeStealthComm();
        if (!NT_SUCCESS(init_status)) {
            LogMessageF("[-] IsDriverLoaded: StealthComm::InitializeStealthComm() failed with status 0x%lX. Assuming driver is not loaded.", init_status);
            return false; // Cannot check if comms cannot be initialized
        }
        was_initialized_by_us = true;
        LogMessage("[+] IsDriverLoaded: StealthComm temporarily initialized for check.");
    } else {
        LogMessage("[*] IsDriverLoaded: StealthComm was already initialized. Proceeding with check.");
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

    bool final_result = false;
    if (request_success && NT_SUCCESS(km_status_code)) { // Changed MY_NT_SUCCESS to NT_SUCCESS
        LogMessage("[+] IsDriverLoaded: REQUEST_NOP successful. Driver appears to be loaded and responsive.");
        final_result = true;
    } else {
        if (!request_success) {
            LogMessage("[-] IsDriverLoaded: SubmitRequestAndWait for NOP failed.");
        }
        if (!NT_SUCCESS(km_status_code)) { // Changed MY_NT_SUCCESS to NT_SUCCESS
            LogMessageF("[-] IsDriverLoaded: NOP command failed with KM status: 0x%llX", km_status_code);
        }
        LogMessage("[-] IsDriverLoaded: Driver does not appear to be loaded or responsive.");
        final_result = false;
    }

    if (was_initialized_by_us) {
        StealthComm::ShutdownStealthComm();
        LogMessage("[+] IsDriverLoaded: StealthComm temporarily initialized by us has been shut down.");
    }

    return final_result;
}

} // namespace DriverMapper
