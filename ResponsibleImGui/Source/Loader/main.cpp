#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
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

namespace Loader {
    
    class LoaderManager {
    public:
        LoaderManager() = default;
        ~LoaderManager() = default;

        bool Initialize() {
            std::wcout << L"[+] Hated Loader Initializing..." << std::endl;
            
            // Initialize KeyAuth
            try {
                KeyAuthManager::Initialize();
                std::wcout << L"[+] KeyAuth initialized successfully" << std::endl;
            }
            catch (const std::exception& e) {
                std::wcerr << L"[-] KeyAuth initialization failed: " << e.what() << std::endl;
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
                std::wcerr << L"[-] Authentication failed" << std::endl;
                return false;
            }

            // Step 3: Map the driver
            if (!MapDriver()) {
                std::wcerr << L"[-] Driver mapping failed" << std::endl;
                return false;
            }

            // Step 4: Extract and launch the main executable
            if (!LaunchMainExecutable()) {
                std::wcerr << L"[-] Failed to launch main executable" << std::endl;
                return false;
            }

            return true;
        }

        void Cleanup() {
            KeyAuthManager::Cleanup();
            DriverMapper::CleanupTempFiles();
        }

    private:        bool AuthenticateUser() {
            std::wcout << L"[+] Starting authentication process..." << std::endl;
            
            // Try to load saved credentials first
            if (!KeyAuthManager::gTriedAuto) {
                KeyAuthManager::gTriedAuto = true;
                char tempLicense[128];
                
                if (KeyAuthManager::LoadCredentials(tempLicense, sizeof(tempLicense))) {
                    std::wcout << L"[+] Found saved credentials, attempting auto-login..." << std::endl;
                    
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
                            std::wcout << L"[+] Auto-login successful!" << std::endl;
                            std::wcout << L"[+] Welcome back, " << KeyAuthManager::KeyAuthApp.user_data.username.c_str() << std::endl;
                            std::wcout << L"[+] Time remaining: " << KeyAuthManager::GetTimeRemaining().c_str() << std::endl;
                            return true;
                        } else {
                            std::wcout << L"[-] HWID mismatch - license locked to another machine" << std::endl;
                            KeyAuthManager::ClearCredentials();
                        }
                    } else {
                        std::wcout << L"[-] Saved license invalid" << std::endl;
                        KeyAuthManager::ClearCredentials();
                    }
                }
            }
            
            // Check if already authenticated
            if (KeyAuthManager::IsAuthenticated()) {
                std::wcout << L"[+] User already authenticated" << std::endl;
                return true;
            }

            // Show console-based login prompt
            return PerformConsoleLogin();
        }

        bool PerformConsoleLogin() {
            std::string licenseKey;
            int maxAttempts = 3;
            int attempts = 0;

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
            std::wcout << L"[+] Starting driver mapping process..." << std::endl;
            
            try {
                if (DriverMapper::MapDriver()) {
                    std::wcout << L"[+] Driver mapped successfully!" << std::endl;
                    return true;
                } else {
                    std::wcerr << L"[-] Driver mapping failed!" << std::endl;
                    return false;
                }
            }
            catch (const std::exception& e) {
                std::wcerr << L"[-] Driver mapping exception: " << e.what() << std::endl;
                return false;
            }
        }

        bool LaunchMainExecutable() {
            std::wcout << L"[+] Extracting and launching main executable..." << std::endl;
            
            try {
                // Create temp directory
                std::wstring tempDir = GetTempDirectory();
                if (tempDir.empty()) {
                    std::wcerr << L"[-] Failed to get temp directory" << std::endl;
                    return false;
                }

                // Generate unique filename
                DWORD tickCount = GetTickCount();
                std::wstring exePath = tempDir + L"\Hated_" + std::to_wstring(tickCount) + L".exe";

                // Extract embedded executable
                if (!ExtractExecutable(exePath)) {
                    std::wcerr << L"[-] Failed to extract executable" << std::endl;
                    return false;
                }

                // Launch the executable
                if (!LaunchExecutable(exePath)) {
                    std::wcerr << L"[-] Failed to launch executable" << std::endl;
                    DeleteFileW(exePath.c_str()); // Clean up on failure
                    return false;
                }

                std::wcout << L"[+] Main executable launched successfully!" << std::endl;
                
                // Optionally wait a bit before cleaning up
                std::this_thread::sleep_for(std::chrono::seconds(2));
                
                // Clean up the extracted file
                if (DeleteFileW(exePath.c_str())) {
                    std::wcout << L"[+] Temporary executable cleaned up" << std::endl;
                } else {
                    std::wcout << L"[!] Warning: Failed to clean up temporary executable" << std::endl;
                }

                return true;
            }
            catch (const std::exception& e) {
                std::wcerr << L"[-] Exception launching executable: " << e.what() << std::endl;
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
                    std::wcerr << L"[-] Failed to create executable file: " << filePath << std::endl;
                    return false;
                }
                
                file.write(reinterpret_cast<const char*>(IUIC_ImGui_exe), IUIC_ImGui_exe_len);
                file.close();
                
                if (!FileExists(filePath)) {
                    std::wcerr << L"[-] Executable extraction verification failed: " << filePath << std::endl;
                    return false;
                }
                
                std::wcout << L"[+] Extracted executable: " << filePath << L" (" << IUIC_ImGui_exe_len << L" bytes)" << std::endl;
                return true;
            }
            catch (const std::exception& e) {
                std::wcerr << L"[-] Exception extracting executable: " << e.what() << std::endl;
                return false;
            }
        }

        bool LaunchExecutable(const std::wstring& exePath) {
            STARTUPINFOW si = {};
            PROCESS_INFORMATION pi = {};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_SHOW; // Show the main application window
            
            std::wcout << L"[+] Launching: " << exePath << std::endl;
            
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
                std::wcerr << L"[-] CreateProcess failed with error: " << error << std::endl;
                return false;
            }
            
            std::wcout << L"[+] Main executable launched successfully (PID: " << pi.dwProcessId << L")" << std::endl;
            
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
                    std::wcout << L"\n[!] Update Available!" << std::endl;
                    std::wcout << L"[!] Current Version: " << LOADER_VERSION << std::endl;
                    std::wcout << L"[!] Latest Version: " << latestRelease.tagName.c_str() << std::endl;
                    std::wcout << L"[!] Release Notes: " << latestRelease.name.c_str() << std::endl;
                    
                    std::cout << "\nWould you like to update now? (y/n): ";
                    std::string response;
                    std::getline(std::cin, response);
                    
                    if (response == "y" || response == "Y" || response == "yes" || response == "Yes") {
                        return PerformUpdate(latestRelease);
                    } else {
                        std::wcout << L"[+] Update skipped. Continuing with current version..." << std::endl;
                    }
                }
                
                return true; // Continue with normal operation
            }
            catch (const std::exception& e) {
                std::wcerr << L"[-] Error checking for updates: " << e.what() << std::endl;
                std::wcout << L"[+] Continuing without update check..." << std::endl;
                return true; // Continue even if update check fails
            }
        }

        bool PerformUpdate(const UpdateManager::Release& release) {
            try {
                std::wcout << L"[+] Starting update process..." << std::endl;
                
                // Get temp directory and create paths
                std::wstring tempDir = GetTempDirectory();
                if (tempDir.empty()) {
                    std::wcerr << L"[-] Failed to get temp directory" << std::endl;
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
                    std::wcerr << L"[-] Failed to download update" << std::endl;
                    return false;
                }
                
                // Create update helper script
                if (!UpdateManager::CreateUpdateHelper(helperPath, newLoaderPath, currentLoaderPath)) {
                    std::wcerr << L"[-] Failed to create update helper" << std::endl;
                    DeleteFileW(newLoaderPath.c_str());
                    return false;
                }
                
                std::wcout << L"[+] Update downloaded successfully!" << std::endl;
                std::wcout << L"[+] Launching update helper..." << std::endl;
                std::wcout << L"[+] The loader will restart automatically after update." << std::endl;
                
                // Launch update helper
                if (UpdateManager::LaunchUpdateHelper(helperPath)) {
                    std::wcout << L"[+] Update process started. Exiting current loader..." << std::endl;
                    return false; // Signal to exit the current loader
                } else {
                    std::wcerr << L"[-] Failed to launch update helper" << std::endl;
                    DeleteFileW(newLoaderPath.c_str());
                    DeleteFileW(helperPath.c_str());
                    return false;
                }
            }
            catch (const std::exception& e) {
                std::wcerr << L"[-] Error during update process: " << e.what() << std::endl;
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
    SetConsoleOutputCP(CP_UTF8);
    
    std::wcout << L"=====================================" << std::endl;
    std::wcout << L"       Hated Loader v1.0" << std::endl;
    std::wcout << L"=====================================" << std::endl;
    std::wcout << std::endl;

    Loader::LoaderManager loader;
    
    try {
        // Initialize loader components
        if (!loader.Initialize()) {
            std::wcerr << L"[-] Loader initialization failed" << std::endl;
            std::wcout << L"\nPress any key to exit..." << std::endl;
            std::cin.get();
            return 1;
        }

        // Run the main loader process
        if (loader.Run()) {
            std::wcout << L"[+] Loader completed successfully!" << std::endl;
            std::wcout << L"[+] Main application should now be running." << std::endl;
        } else {
            std::wcerr << L"[-] Loader process failed" << std::endl;
            std::wcout << L"\nPress any key to exit..." << std::endl;
            std::cin.get();
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::wcerr << L"[-] Loader exception: " << e.what() << std::endl;
        std::wcout << L"\nPress any key to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

    // Cleanup
    loader.Cleanup();
    
    std::wcout << L"\nLoader will exit in 3 seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    return 0;
}
