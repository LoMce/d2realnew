#include "KeyAuthManager.h"
#include <iostream>
// Ensure Windows.h is included before dpapi.h
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <dpapi.h>
#include "json.hpp" // Assumed to be in the same directory
#include <algorithm>
#include <ctime>
#include <cstring> // For strcpy_s, strlen (used by KeyAuth or other parts)
#include <vector> // For std::vector used in updated functions

#pragma comment(lib, "Crypt32.lib")

namespace KeyAuthManager {
    // DEVELOPER TODO: Fill in your actual KeyAuth application details below.
    // IMPORTANT: These are currently placeholders and WILL NOT WORK for real authentication.
    std::string name = skCrypt("").decrypt(); // e.g., skCrypt("MyApplicationName").decrypt();
    std::string ownerid = skCrypt("").decrypt(); // e.g., skCrypt("YourOwnerId").decrypt();
    std::string version = skCrypt("1.0").decrypt();
    std::string url = skCrypt("https://keyauth.win/api/1.3/").decrypt();
    std::string path = skCrypt("").decrypt(); // Optional: path for KeyAuth files, can be empty
    
    // KeyAuth app instance
    KeyAuth::api KeyAuthApp(name, ownerid, version, url, path);
    
    // Authentication state
    bool isAuthenticated = false;
    char License[128] = "Enter Your License Key";
    char statusmsg[128] = "";
    
    // Internal state
    bool gTriedAuto = false;
    bool gHasInitialized = false;
    bool isAuthenticating = false;
    char savedHwid[64] = "";
    
    void Initialize() {
        try {
            if (!gHasInitialized) {
                KeyAuthApp.init();
                gHasInitialized = true;
                std::cout << "[KeyAuth] Initialized successfully\n";
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[KeyAuth] Initialization failed: " << e.what() << "\n";
            strcpy_s(statusmsg, "Failed to initialize KeyAuth");
        }
        catch (...) {
            std::cerr << "[KeyAuth] Initialization failed with unknown error\n";
            strcpy_s(statusmsg, "Failed to initialize KeyAuth");
        }
    }
    
    void Cleanup() {
        // Reset all state variables
        isAuthenticated = false;
        strcpy_s(License, "Enter Your License Key");
        strcpy_s(statusmsg, "");
        savedHwid[0] = '\0';
        gTriedAuto = false;
        gHasInitialized = false;
        isAuthenticating = false;
    }
    
    void SaveCredentials(const char* licenseKey) {
        nlohmann::json creds_json;
        creds_json["license"] = licenseKey;
        
        if (KeyAuthApp.user_data.hwid.empty() && gHasInitialized) {
            if(KeyAuthApp.user_data.hwid.empty()){
                std::cerr << "[KeyAuth] SaveCredentials: HWID is empty. Cannot save credentials." << std::endl;
                strcpy_s(statusmsg, "HWID not available, cannot save.");
                return;
            }
        } else if (KeyAuthApp.user_data.hwid.empty() && !gHasInitialized) {
             std::cerr << "[KeyAuth] SaveCredentials: KeyAuth not initialized, HWID is empty. Cannot save credentials." << std::endl;
             strcpy_s(statusmsg, "KeyAuth not initialized, HWID unavailable.");
             return;
        }
        creds_json["hwid"] = KeyAuthApp.user_data.hwid;
        std::string json_str = creds_json.dump();

        DATA_BLOB in_data;
        DATA_BLOB out_data;
        ZeroMemory(&in_data, sizeof(in_data));
        ZeroMemory(&out_data, sizeof(out_data));

        in_data.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(json_str.c_str()));
        in_data.cbData = static_cast<DWORD>(json_str.length());

        if (CryptProtectData(&in_data, L"Credentials", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out_data)) {
            HKEY hKey;
            LSTATUS status = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\IUIC", 0, nullptr,
                            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
            if (status == ERROR_SUCCESS) {
                status = RegSetValueExA(hKey, "CredsDPAPI", 0, REG_BINARY, out_data.pbData, out_data.cbData);
                if (status != ERROR_SUCCESS) {
                    std::cerr << "[KeyAuth] SaveCredentials: RegSetValueExA failed. Error: " << status << std::endl;
                    strcpy_s(statusmsg, "Failed to save credentials (value set).");
                }
                RegCloseKey(hKey);
            } else {
                std::cerr << "[KeyAuth] SaveCredentials: RegCreateKeyExA failed. Error: " << status << std::endl;
                strcpy_s(statusmsg, "Failed to save credentials (key creation).");
            }
            LocalFree(out_data.pbData);
        } else {
            std::cerr << "[KeyAuth] SaveCredentials: CryptProtectData failed. Error: " << GetLastError() << std::endl;
            strcpy_s(statusmsg, "Failed to encrypt credentials.");
        }
    }
    
    bool LoadCredentials(char* licenseKey, size_t licSz) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\IUIC", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return false;
        }

        DWORD type = REG_BINARY, cbData = 0;
        LSTATUS status = RegQueryValueExA(hKey, "CredsDPAPI", nullptr, &type, nullptr, &cbData);
        if (status != ERROR_SUCCESS || cbData == 0) {
            RegCloseKey(hKey);
            return false;
        }

        std::vector<BYTE> encrypted_data(cbData);
        status = RegQueryValueExA(hKey, "CredsDPAPI", nullptr, nullptr, encrypted_data.data(), &cbData);
        RegCloseKey(hKey);

        if (status != ERROR_SUCCESS) {
            std::cerr << "[KeyAuth] LoadCredentials: Failed to read registry value for CredsDPAPI. Error: " << status << std::endl;
            return false;
        }

        DATA_BLOB in_data;
        DATA_BLOB out_data;
        ZeroMemory(&in_data, sizeof(in_data));
        ZeroMemory(&out_data, sizeof(out_data));
        in_data.pbData = encrypted_data.data();
        in_data.cbData = cbData;

        if (CryptUnprotectData(&in_data, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out_data)) {
            if (out_data.pbData == nullptr || out_data.cbData == 0) {
                std::cerr << "[KeyAuth] LoadCredentials: CryptUnprotectData returned success but no data." << std::endl;
                if(out_data.pbData) LocalFree(out_data.pbData); // Still free if pbData is not null but cbData is 0
                return false;
            }
            std::string decrypted_json_str(reinterpret_cast<char*>(out_data.pbData), out_data.cbData);
            LocalFree(out_data.pbData);

            try {
                nlohmann::json creds_json = nlohmann::json::parse(decrypted_json_str, nullptr, false);
                if (creds_json.is_discarded() || !creds_json.contains("license") || !creds_json.contains("hwid")) {
                    std::cerr << "[KeyAuth] LoadCredentials: Failed to parse JSON or missing keys from CredsDPAPI." << std::endl;
                    return false;
                }
                std::string lic = creds_json["license"].get<std::string>();
                std::string hw  = creds_json["hwid"].get<std::string>();

                strncpy_s(licenseKey, licSz, lic.c_str(), _TRUNCATE);
                strncpy_s(savedHwid, sizeof(savedHwid), hw.c_str(), _TRUNCATE);
                return true;
            } catch (const nlohmann::json::parse_error& e) {
                std::cerr << "[KeyAuth] LoadCredentials: JSON parse error from CredsDPAPI: " << e.what() << std::endl;
                return false;
            } catch (const nlohmann::json::type_error& e) {
                std::cerr << "[KeyAuth] LoadCredentials: JSON type error from CredsDPAPI: " << e.what() << std::endl;
                return false;
            }
        } else {
            DWORD dwError = GetLastError();
            std::cerr << "[KeyAuth] LoadCredentials: CryptUnprotectData failed for CredsDPAPI. Error: " << dwError << std::endl;
            if (dwError == ERROR_INVALID_DATA || dwError == CRYPT_E_ASN1_BADTAG || dwError == ERROR_INVALID_CIPHERTEXT) {
                std::cerr << "[KeyAuth] LoadCredentials: CredsDPAPI data seems corrupted. Clearing it." << std::endl;
                ClearCredentials();
            }
            return false;
        }
    }
    
    void ClearCredentials() {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\IUIC", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            LSTATUS status_dpapi = RegDeleteValueA(hKey, "CredsDPAPI");
            if (status_dpapi != ERROR_SUCCESS && status_dpapi != ERROR_FILE_NOT_FOUND) {
                std::cerr << "[KeyAuth] ClearCredentials: RegDeleteValueA failed for CredsDPAPI. Error: " << status_dpapi << std::endl;
            }
            // Also attempt to delete old XORed creds if they might exist (for cleanup during transition)
            LSTATUS status_xor = RegDeleteValueA(hKey, "Creds");
             if (status_xor != ERROR_SUCCESS && status_xor != ERROR_FILE_NOT_FOUND) {
                std::cerr << "[KeyAuth] ClearCredentials: RegDeleteValueA failed for old Creds. Error: " << status_xor << std::endl;
            }
            RegCloseKey(hKey);
        } else {
             std::cerr << "[KeyAuth] ClearCredentials: RegOpenKeyExA failed. Error: " << GetLastError() << std::endl;
        }
    }
    
    bool IsAuthenticated() {
        return isAuthenticated;
    }
    
    std::string GetTimeRemaining() {
        if (!isAuthenticated || KeyAuthApp.user_data.subscriptions.empty()) {
            return "N/A";
        }
        
        auto &sub = KeyAuthApp.user_data.subscriptions[0]; // Assuming first subscription is relevant

        // Check if expiry is a valid timestamp (all digits)
        bool isNumeric = true;
        for (char c : sub.expiry) {
            if (!isdigit(c)) {
                isNumeric = false;
                break;
            }
        }

        if (isNumeric && !sub.expiry.empty()) {
            try {
                long long expTs = std::stoll(sub.expiry); // Use stoll for potentially large timestamps
                long long now   = static_cast<long long>(std::time(nullptr));
                long long diff  = expTs - now;
                if (diff > 0) {
                    int days    = static_cast<int>(diff / 86400);
                    int hours   = static_cast<int>((diff % 86400) / 3600);
                    int mins    = static_cast<int>((diff % 3600) / 60);

                    std::string time_str = "";
                    if (days > 0) time_str += std::to_string(days) + "d ";
                    if (hours > 0 || days > 0) time_str += std::to_string(hours) + "h "; // Show hours if days are present or hours > 0
                    time_str += std::to_string(mins) + "m";
                    return time_str;
                } else {
                    return "Expired";
                }
            } catch (const std::out_of_range& oor) {
                std::cerr << "[KeyAuth] GetTimeRemaining: Expiry timestamp out of range: " << sub.expiry << std::endl;
                return "Invalid Date";
            } catch (const std::invalid_argument& ia) {
                std::cerr << "[KeyAuth] GetTimeRemaining: Invalid expiry timestamp format: " << sub.expiry << std::endl;
                return "Invalid Date";
            }
        }
        return "Lifetime"; // Or "N/A" if non-numeric expiry should not mean lifetime
    }
    
    void Logout() {
        ClearCredentials();
        isAuthenticated = false;
        strcpy_s(License, "Enter Your License Key");
        strcpy_s(statusmsg, "Logged out."); // Provide feedback
        savedHwid[0] = '\0';
        gTriedAuto = false;
        // gHasInitialized can remain true if KeyAuth itself doesn't need re-init,
        // but user-specific data is cleared. If KeyAuthApp needs full reset, set gHasInitialized = false;
        // For now, assume KeyAuthApp.init() is a one-time setup.
        // KeyAuthApp.user_data clear (if necessary, depends on KeyAuth lib behavior on re-auth)
        KeyAuthApp.user_data = {}; // Reset user_data structure
    }
}
