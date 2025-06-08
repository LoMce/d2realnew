#include <Windows.h>
// #include <iostream> // Replaced by Logging.h
#include <string>
#include <vector>
#include <sstream> // For std::wstringstream if used, or for general string manipulation
#include "../ImGui Standalone/Logging.h" // Added Logging.h
#include <filesystem>
#include <fstream>
#include <memory>
#include <chrono>
#include <thread>
#include <algorithm>

// Forward declarations
#include "KeyAuthManager.h"
#include "DriverMapper.h"
#include "UpdateManager.h"

// Embedded executable
#include "embedded/iuic_exe.h"

/*
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
MAKE SURE YOU DISABLE THE CONSOLE IN IUIC_ImGui\main.cpp WHEN PUSHING RELEASE BUILDS
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
*/

// Version information
// 1.0.5 - added external overlay, it kinda acts funny tho
//
// 1.0.6 - fixed external overlay, added new feature, cleaned up menu
#define LOADER_VERSION "1.0.6"

// Helper to convert wstring to string for logging (if not already in a common header)
static std::string WStringToStringLoader(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

namespace Loader {
    
    class LoaderManager {
    public:
        LoaderManager() = default;
        ~LoaderManager() = default;

        bool Initialize() {
            LogMessage("[+] Hated Loader Initializing...");
            
            // Initialize KeyAuth
            try {
                KeyAuthManager::Initialize();
                LogMessage("[+] KeyAuth initialized successfully");
            }
            catch (const std::exception& e) {
                LogMessageF("[-] KeyAuth initialization failed: %s", e.what());
                return false;
            }
            
            return true;
        }        bool Run() {
            // Step 1: Check for updates
            if (!CheckForUpdates()) {
                // If update is being installed, exit gracefully
                return true;
            }

            // Step 2: Authenticate user
            if (!AuthenticateUser()) {
                LogMessage("[-] Authentication failed");
                return false;
            }

            // Step 3: Map the driver
            if (!MapDriver()) {
                LogMessage("[-] Driver mapping failed");
                return false;
            }

            // Step 4: Extract and launch the main executable
            if (!LaunchMainExecutable()) {
                LogMessage("[-] Failed to launch main executable");
                return false;
            }

            return true;
        }

        void Cleanup() {
            KeyAuthManager::Cleanup();
            DriverMapper::CleanupTempFiles();
        }

    private:        bool AuthenticateUser() {
            LogMessage("[+] Starting authentication process...");
            
            // Try to load saved credentials first
            if (!KeyAuthManager::gTriedAuto) {
                KeyAuthManager::gTriedAuto = true;
                char tempLicense[128];
                
                if (KeyAuthManager::LoadCredentials(tempLicense, sizeof(tempLicense))) {
                    LogMessage("[+] Found saved credentials, attempting auto-login...");
                    
                    // Copy to main license buffer
                    strcpy_s(KeyAuthManager::License, 128, tempLicense);
                    
                    // Initialize if not already done
                    if (!KeyAuthManager::gHasInitialized) {
                        KeyAuthManager::KeyAuthApp.init();
                        KeyAuthManager::gHasInitialized = true;
                    }
                    
                    // Try to authenticate with saved license
                    KeyAuthManager::KeyAuthApp.license(KeyAuthManager::License);
                    
                    if (KeyAuthManager::KeyAuthApp.response.success) {
                        // Check HWID match
                        if (strcmp(KeyAuthManager::savedHwid, KeyAuthManager::KeyAuthApp.user_data.hwid.c_str()) == 0) {
                            KeyAuthManager::isAuthenticated = true;
                            LogMessage("[+] Auto-login successful!");
                            LogMessageF("[+] Welcome back, %s", KeyAuthManager::KeyAuthApp.user_data.username.c_str());
                            LogMessageF("[+] Time remaining: %s", KeyAuthManager::GetTimeRemaining().c_str());
                            return true;
                        } else {
                            LogMessage("[-] HWID mismatch - license locked to another machine");
                            KeyAuthManager::ClearCredentials();
                        }
                    } else {
                        LogMessage("[-] Saved license invalid");
                        KeyAuthManager::ClearCredentials();
                    }
                }
            }
            
            // Check if already authenticated
            if (KeyAuthManager::IsAuthenticated()) {
                LogMessage("[+] User already authenticated");
                return true;
            }

            // Show console-based login prompt
            return PerformConsoleLogin();
        }

        bool PerformConsoleLogin() {
            std::string licenseKey;
            int maxAttempts = 3;
            int attempts = 0;

            // Console interaction for login - keep std::cout and std::cin for this part.
            // Output prompts are fine, they are not debug spam.
            while (attempts < maxAttempts) {
                std::cout << "\n====== Hated Authentication ======" << std::endl;
                std::cout << "Enter your license key: ";
                std::getline(std::cin, licenseKey);                if (licenseKey.empty()) {
                    std::cout << "[-] License key cannot be empty" << std::endl;
                    attempts++;
                    continue;
                }
                
                std::cout << "[+] Authenticating..." << std::endl;
                
                try {
                    // Copy to license buffer
                    strcpy_s(KeyAuthManager::License, 128, licenseKey.c_str());

                    // Perform authentication
                    if (!KeyAuthManager::gHasInitialized) {
                        KeyAuthManager::KeyAuthApp.init();
                        KeyAuthManager::gHasInitialized = true;
                    }

                    KeyAuthManager::KeyAuthApp.license(KeyAuthManager::License);
                    
                    if (KeyAuthManager::KeyAuthApp.response.success) {
                        KeyAuthManager::isAuthenticated = true;
                        KeyAuthManager::SaveCredentials(KeyAuthManager::License);
                        
                        std::cout << "[+] Authentication successful!" << std::endl;
                        std::cout << "[+] Welcome, " << KeyAuthManager::KeyAuthApp.user_data.username << std::endl;
                        std::cout << "[+] Time remaining: " << KeyAuthManager::GetTimeRemaining() << std::endl;
                        
                        return true;
                    } else {
                        std::cout << "[-] Authentication failed: " << KeyAuthManager::KeyAuthApp.response.message << std::endl;
                    }
                }
                catch (const std::exception& e) {
                    std::cout << "[-] Authentication error: " << e.what() << std::endl;
                }

                attempts++;
                if (attempts < maxAttempts) {
                    std::cout << "[-] Attempts remaining: " << (maxAttempts - attempts) << std::endl;
                }
            }

            std::cout << "[-] Maximum authentication attempts reached" << std::endl;
            return false;
        }

        bool MapDriver() {
            LogMessage("[+] Starting driver mapping process...");
            
            try {
                if (DriverMapper::MapDriver()) { // DriverMapper::MapDriver logs internally now
                    LogMessage("[+] Driver mapped successfully!");
                    return true;
                } else {
                    LogMessage("[-] Driver mapping failed!"); // MapDriver already logs specifics
                    return false;
                }
            }
            catch (const std::exception& e) {
                LogMessageF("[-] Driver mapping exception: %s", e.what());
                return false;
            }
        }

        bool LaunchMainExecutable() {
            LogMessage("[+] Extracting and launching main executable...");
            
            try {
                // Create temp directory
                std::wstring tempDir = GetTempDirectory();
                if (tempDir.empty()) {
                    LogMessage("[-] Failed to get temp directory");
                    return false;
                }

                // Generate unique filename
                DWORD tickCount = GetTickCount();
                std::wstring exePath = tempDir + L"\Hated_" + std::to_wstring(tickCount) + L".exe";

                // Extract embedded executable
                if (!ExtractExecutable(exePath)) {
                    LogMessage("[-] Failed to extract executable"); // ExtractExecutable logs specifics
                    return false;
                }

                // Launch the executable
                if (!LaunchExecutable(exePath)) {
                    LogMessage("[-] Failed to launch executable"); // LaunchExecutable logs specifics
                    DeleteFileW(exePath.c_str()); // Clean up on failure
                    return false;
                }

                LogMessage("[+] Main executable launched successfully!");
                
                // Optionally wait a bit before cleaning up
                std::this_thread::sleep_for(std::chrono::seconds(2));
                
                // Clean up the extracted file
                if (DeleteFileW(exePath.c_str())) {
                    LogMessage("[+] Temporary executable cleaned up");
                } else {
                    LogMessage("[!] Warning: Failed to clean up temporary executable");
                }

                return true;
            }
            catch (const std::exception& e) {
                LogMessageF("[-] Exception launching executable: %s", e.what());
                return false;
            }
        }

        std::wstring GetTempDirectory() {
            wchar_t tempPath[MAX_PATH];
            DWORD result = GetTempPathW(MAX_PATH, tempPath);
            
            if (result == 0 || result > MAX_PATH) {
                return L"";
            }
            
            return std::wstring(tempPath);
        }

        bool ExtractExecutable(const std::wstring& filePath) {
            try {
                std::ofstream file(filePath, std::ios::binary);
                if (!file.is_open()) {
                    LogMessageF("[-] Failed to create executable file: %s", WStringToStringLoader(filePath).c_str());
                    return false;
                }
                
                file.write(reinterpret_cast<const char*>(IUIC_ImGui_exe), IUIC_ImGui_exe_len);
                file.close();
                
                if (!FileExists(filePath)) {
                    LogMessageF("[-] Executable extraction verification failed: %s", WStringToStringLoader(filePath).c_str());
                    return false;
                }
                
                LogMessageF("[+] Extracted executable: %s (%u bytes)", WStringToStringLoader(filePath).c_str(), IUIC_ImGui_exe_len);
                return true;
            }
            catch (const std::exception& e) {
                LogMessageF("[-] Exception extracting executable: %s", e.what());
                return false;
            }
        }

        bool LaunchExecutable(const std::wstring& exePath) {
            STARTUPINFOW si = {};
            PROCESS_INFORMATION pi = {};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_SHOW; // Show the main application window
            
            LogMessageF("[+] Launching: %s", WStringToStringLoader(exePath).c_str());
            
            BOOL result = CreateProcessW(
                exePath.c_str(),     // Application path
                nullptr,             // Command line
                nullptr,             // Process security attributes
                nullptr,             // Thread security attributes
                FALSE,               // Inherit handles
                0,                   // Creation flags
                nullptr,             // Environment
                nullptr,             // Current directory
                &si,                 // Startup info
                &pi                  // Process info
            );
            
            if (!result) {
                DWORD error = GetLastError();
                LogMessageF("[-] CreateProcess failed with error: %lu", error);
                return false;
            }
            
            LogMessageF("[+] Main executable launched successfully (PID: %lu)", pi.dwProcessId);
            
            // Close handles - we don't need to wait for the process
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            
            return true;
        }

        bool FileExists(const std::wstring& filePath) {
            DWORD fileAttrib = GetFileAttributesW(filePath.c_str());
            return (fileAttrib != INVALID_FILE_ATTRIBUTES) && 
                   !(fileAttrib & FILE_ATTRIBUTE_DIRECTORY);
        }

        bool CheckForUpdates() {
            try {
                UpdateManager::Release latestRelease;
                
                if (UpdateManager::CheckForUpdates(LOADER_VERSION, latestRelease)) {
                    LogMessage("\n[!] Update Available!"); // Using LogMessage for simple strings
                    LogMessageF("[!] Current Version: %s", LOADER_VERSION);
                    LogMessageF("[!] Latest Version: %s", latestRelease.tagName.c_str());
                    LogMessageF("[!] Release Notes: %s", latestRelease.name.c_str());
                    
                    // Console interaction for update confirmation - keep std::cout and std::cin
                    std::cout << "\nWould you like to update now? (y/n): ";
                    std::string response;
                    std::getline(std::cin, response);
                    
                    if (response == "y" || response == "Y" || response == "yes" || response == "Yes") {
                        return PerformUpdate(latestRelease);
                    } else {
                        LogMessage("[+] Update skipped. Continuing with current version...");
                    }
                }
                
                return true; // Continue with normal operation
            }
            catch (const std::exception& e) {
                LogMessageF("[-] Error checking for updates: %s", e.what());
                LogMessage("[+] Continuing without update check...");
                return true; // Continue even if update check fails
            }
        }

        bool PerformUpdate(const UpdateManager::Release& release) {
            try {
                LogMessage("[+] Starting update process...");
                
                // Get temp directory and create paths
                std::wstring tempDir = GetTempDirectory();
                if (tempDir.empty()) {
                    LogMessage("[-] Failed to get temp directory");
                    return false;
                }
                
                DWORD tickCount = GetTickCount();
                std::wstring newLoaderPath = tempDir + L"\\HatedLoader_" + std::to_wstring(tickCount) + L".exe";
                std::wstring helperPath = tempDir + L"\\update_helper_" + std::to_wstring(tickCount) + L".bat";
                
                // Get current executable path
                wchar_t currentPath[MAX_PATH];
                GetModuleFileNameW(nullptr, currentPath, MAX_PATH);
                std::wstring currentLoaderPath(currentPath);
                
                // Download the update
                if (!UpdateManager::DownloadUpdate(release, newLoaderPath)) {
                    LogMessage("[-] Failed to download update");
                    return false;
                }
                
                // Create update helper script
                if (!UpdateManager::CreateUpdateHelper(helperPath, newLoaderPath, currentLoaderPath)) {
                    LogMessage("[-] Failed to create update helper");
                    DeleteFileW(newLoaderPath.c_str());
                    return false;
                }
                
                LogMessage("[+] Update downloaded successfully!");
                LogMessage("[+] Launching update helper...");
                LogMessage("[+] The loader will restart automatically after update.");
                
                // Launch update helper
                if (UpdateManager::LaunchUpdateHelper(helperPath)) {
                    LogMessage("[+] Update process started. Exiting current loader...");
                    return false; // Signal to exit the current loader
                } else {
                    LogMessage("[-] Failed to launch update helper");
                    DeleteFileW(newLoaderPath.c_str());
                    DeleteFileW(helperPath.c_str());
                    return false;
                }
            }
            catch (const std::exception& e) {
                LogMessageF("[-] Error during update process: %s", e.what());
                return false;
            }
        }

        // ...existing code...
    };

} // namespace Loader

int main() {
    // Set console title
    SetConsoleTitleW(L"Hated Loader");
    
    // Enable UTF-8 console output
    SetConsoleOutputCP(CP_UTF8); // This is good for std::cout if it were used with UTF-8 strings.
                                 // Logging.h should handle its output encoding.

    // These initial messages are fine with std::wcout as they are part of the console UI before Logging might be fully active
    // or if we want them regardless of Logging's _DEBUG state.
    // However, to be consistent with the goal of centralizing, they will be converted.
    // For this subtask, I will convert them.
    LogMessage("=====================================");
    LogMessage("       Hated Loader v1.0"); // LOADER_VERSION could be used here too.
    LogMessage("=====================================");
    LogMessage(""); // For newline

    Loader::LoaderManager loader;
    
    try {
        // Initialize loader components
        if (!loader.Initialize()) {
            LogMessage("[-] Loader initialization failed");
            // Keep console interaction for critical exit
            std::wcout << L"\nPress any key to exit..." << std::endl;
            std::cin.get();
            return 1;
        }

        // Run the main loader process
        if (loader.Run()) {
            LogMessage("[+] Loader completed successfully!");
            LogMessage("[+] Main application should now be running.");
        } else {
            LogMessage("[-] Loader process failed");
            std::wcout << L"\nPress any key to exit..." << std::endl;
            std::cin.get();
            return 1;
        }
    }
    catch (const std::exception& e) {
        LogMessageF("[-] Loader exception: %s", e.what());
        std::wcout << L"\nPress any key to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

    // Cleanup
    loader.Cleanup();
    
    LogMessage("\nLoader will exit in 3 seconds...");
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    return 0;
}
