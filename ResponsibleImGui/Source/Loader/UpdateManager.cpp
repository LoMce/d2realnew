#include "UpdateManager.h"
#include "json.hpp" // Added for nlohmann::json
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <wininet.h>
#include <urlmon.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")

// Using nlohmann::json for convenience
using json = nlohmann::json;

bool UpdateManager::CheckForUpdates(const std::string& currentVersion, Release& latestRelease) {
    try {
        std::wcout << L"[+] Checking for updates..." << std::endl;
        
        std::string response = MakeHttpsRequest(GITHUB_API_URL);
        if (response.empty()) {
            std::wcerr << L"[-] Failed to fetch release information from GitHub API." << std::endl;
            return false;
        }

        json release_data = json::parse(response, nullptr, false); // No exceptions on parse error

        if (release_data.is_discarded()) {
            std::wcerr << L"[-] Failed to parse JSON response from GitHub API." << std::endl;
            // std::wcerr << L"[-] Response was: " << std::wstring(response.begin(), response.end()) << std::endl; // Optional: log raw response
            return false;
        }

        latestRelease.tagName = release_data.value("tag_name", "");
        latestRelease.name = release_data.value("name", "");
        latestRelease.body = release_data.value("body", "");
        latestRelease.prerelease = release_data.value("prerelease", false);

        if (latestRelease.tagName.empty()) {
            std::wcerr << L"[-] Could not find 'tag_name' in release data." << std::endl;
            return false;
        }
        
        latestRelease.version = ParseVersion(latestRelease.tagName);
        Version currentVer = ParseVersion(currentVersion);
        
        if (release_data.contains("assets") && release_data["assets"].is_array()) {
            for (const auto& asset : release_data["assets"]) {
                std::string assetName = asset.value("name", "");
                if (assetName.find("Loader.exe") != std::string::npos ||
                    assetName.find("HatedLoader.exe") != std::string::npos || // Keep existing variations
                    assetName.find("loader.exe") != std::string::npos) {
                    latestRelease.downloadUrl = asset.value("browser_download_url", "");
                    if (!latestRelease.downloadUrl.empty()) {
                        break; // Found our loader asset
                    }
                }
            }
        } else {
            std::wcerr << L"[-] Release data does not contain 'assets' array." << std::endl;
        }
        
        // Note: If downloadUrl is empty here, it means a suitable asset was not found.
        // The logic below will determine if this is an issue based on whether an update is actually available.

        if (latestRelease.version > currentVer) {
            std::wcout << L"[+] Update available: " << std::wstring(latestRelease.tagName.begin(), latestRelease.tagName.end())
                      << L" (Current: " << std::wstring(currentVersion.begin(), currentVersion.end()) << L")" << std::endl;
            if (latestRelease.downloadUrl.empty()) {
                 std::wcerr << L"[-] Update " << std::wstring(latestRelease.tagName.begin(), latestRelease.tagName.end())
                           << L" found, but no download URL for the loader executable." << std::endl;
                return false; // Cannot proceed with update if URL is missing for an actual update
            }
            return true;
        } else {
            std::wcout << L"[+] You have the latest version (" << std::wstring(currentVersion.begin(), currentVersion.end()) << L")" << std::endl;
            return false;
        }
    }
    catch (const json::parse_error& e) {
        std::wcerr << L"[-] JSON parsing error: " << e.what() << std::endl;
        return false;
    }
    catch (const std::exception& e) {
        std::wcerr << L"[-] Error checking for updates: " << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::wcerr << L"[-] Unknown error occurred while checking for updates." << std::endl;
        return false;
    }
}

bool UpdateManager::DownloadUpdate(const Release& release, const std::wstring& downloadPath, 
                                  std::function<void(int)> progressCallback) {
    try {
        std::wcout << L"[+] Downloading update: " << std::wstring(release.name.begin(), release.name.end()) << std::endl;
        
        if (release.downloadUrl.empty()) {
            std::wcerr << L"[-] Download URL is empty. Cannot download update." << std::endl;
            return false;
        }

        std::wstring wideUrl(release.downloadUrl.begin(), release.downloadUrl.end());
        
        UNREFERENCED_PARAMETER(progressCallback);

        HRESULT hr = URLDownloadToFileW(nullptr, wideUrl.c_str(), downloadPath.c_str(), 0, nullptr);
        
        if (SUCCEEDED(hr)) {
            std::wcout << L"[+] Update downloaded successfully to: " << downloadPath << std::endl;
            return true;
        } else {
            std::wcerr << L"[-] Failed to download update (HRESULT: 0x" << std::hex << hr << std::dec << L")" << std::endl;
            return false;
        }
    }
    catch (const std::exception& e) {
        std::wcerr << L"[-] Error downloading update: " << e.what() << std::endl;
        return false;
    }
}

// NOTE: Using a batch script for updates is a basic mechanism.
// It can have issues with permissions, path escaping, and silent failures.
// More robust solutions involve dedicated updater processes or service-based updates.
bool UpdateManager::CreateUpdateHelper(const std::wstring& helperPath, const std::wstring& newLoaderPath, 
                                       const std::wstring& currentLoaderPath) {
    try {
        std::wofstream helperScript(helperPath);
        if (!helperScript.is_open()) {
            std::wcerr << L"[-] Failed to create update helper script at " << helperPath << std::endl;
            return false;
        }
        
        helperScript << L"@echo off" << std::endl;
        helperScript << L"echo [+] Hated Loader Update Helper" << std::endl;
        helperScript << L"echo [+] Waiting for loader to close..." << std::endl;
        helperScript << L"timeout /t 5 /nobreak >nul" << std::endl;
        helperScript << L"" << std::endl;
        helperScript << L"echo [+] Backing up current loader..." << std::endl;
        helperScript << L"copy \"" << currentLoaderPath << L"\" \"" << currentLoaderPath << L".backup\" >nul" << std::endl;
        helperScript << L"" << std::endl;
        helperScript << L"echo [+] Installing update..." << std::endl;
        helperScript << L"copy \"" << newLoaderPath << L"\" \"" << currentLoaderPath << L"\" >nul" << std::endl;
        helperScript << L"if errorlevel 1 (" << std::endl;
        helperScript << L"    echo [-] Update failed! Restoring backup..." << std::endl;
        helperScript << L"    copy \"" << currentLoaderPath << L".backup\" \"" << currentLoaderPath << L"\" >nul" << std::endl;
        helperScript << L"    echo [-] Update failed. Press any key to exit." << std::endl;
        helperScript << L"    pause >nul" << std::endl;
        helperScript << L"    goto cleanup" << std::endl;
        helperScript << L")" << std::endl;
        helperScript << L"" << std::endl;
        helperScript << L"echo [+] Update completed successfully!" << std::endl;
        helperScript << L"echo [+] Starting updated loader..." << std::endl;
        helperScript << L"start \"\" \"" << currentLoaderPath << L"\"" << std::endl;
        helperScript << L"" << std::endl;
        helperScript << L":cleanup" << std::endl;
        helperScript << L"echo [+] Cleaning up..." << std::endl;
        helperScript << L"del \"" << newLoaderPath << L"\" >nul 2>&1" << std::endl;
        helperScript << L"del \"" << currentLoaderPath << L".backup\" >nul 2>&1" << std::endl;
        // Do not delete the helper script itself from within, Windows may lock it.
        
        helperScript.close();
        
        std::wcout << L"[+] Update helper script created: " << helperPath << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::wcerr << L"[-] Error creating update helper: " << e.what() << std::endl;
        return false;
    }
}

bool UpdateManager::LaunchUpdateHelper(const std::wstring& helperPath) {
    try {
        STARTUPINFOW si = {};
        PROCESS_INFORMATION pi = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;
        
        std::wstring cmdLine = L"cmd.exe /c \"" + helperPath + L"\"";
        
        BOOL result = CreateProcessW(
            nullptr,
            const_cast<LPWSTR>(cmdLine.c_str()),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NEW_CONSOLE,
            nullptr,
            nullptr,
            &si,
            &pi
        );
        
        if (result) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            std::wcout << L"[+] Update helper launched successfully" << std::endl;
            return true;
        } else {
            DWORD error = GetLastError();
            std::wcerr << L"[-] Failed to launch update helper (Error: " << error << L")" << std::endl;
            return false;
        }
    }
    catch (const std::exception& e) {
        std::wcerr << L"[-] Error launching update helper: " << e.what() << std::endl;
        return false;
    }
}

UpdateManager::Version UpdateManager::ParseVersion(const std::string& versionStr) {
    Version version = {0, 0, 0};
    
    std::string cleanVersion = versionStr;
    if (!cleanVersion.empty() && (cleanVersion[0] == 'v' || cleanVersion[0] == 'V')) {
        cleanVersion = cleanVersion.substr(1);
    }
    
    std::regex versionRegex(R"((\d+)\.(\d+)\.(\d+))");
    std::smatch matches;
    
    if (std::regex_search(cleanVersion, matches, versionRegex) && matches.size() == 4) {
        try {
            version.major = std::stoi(matches[1].str());
            version.minor = std::stoi(matches[2].str());
            version.patch = std::stoi(matches[3].str());
        } catch (const std::out_of_range& oor) {
            std::wcerr << L"[-] Version string component out of range: " << std::wstring(cleanVersion.begin(), cleanVersion.end()) << L" (" << oor.what() << L")" << std::endl;
             version = {0,0,0};
        } catch (const std::invalid_argument& ia) {
            std::wcerr << L"[-] Invalid argument parsing version string: " << std::wstring(cleanVersion.begin(), cleanVersion.end()) << L" (" << ia.what() << L")" << std::endl;
            version = {0,0,0};
        }
    } else {
         std::wcout << L"[~] Version string format not matched: " << std::wstring(cleanVersion.begin(), cleanVersion.end()) << L". Assuming 0.0.0" << std::endl;
    }
    
    return version;
}

std::string UpdateManager::MakeHttpsRequest(const std::string& url) {
    HINTERNET hInternet = InternetOpenA(USER_AGENT, INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (!hInternet) {
        std::wcerr << L"[-] MakeHttpsRequest: InternetOpenA failed. Error: " << GetLastError() << std::endl;
        return "";
    }
    
    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, 
                                         INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        std::wcerr << L"[-] MakeHttpsRequest: InternetOpenUrlA failed for URL " << url.c_str() << L". Error: " << GetLastError() << std::endl;
        InternetCloseHandle(hInternet);
        return "";
    }
    
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (!HttpQueryInfo(hConnect, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusCodeSize, nullptr)) {
        std::wcerr << L"[-] MakeHttpsRequest: HttpQueryInfo failed. Error: " << GetLastError() << std::endl;
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    if (statusCode != HTTP_STATUS_OK) {
        std::wcerr << L"[-] MakeHttpsRequest: HTTP request failed with status code " << statusCode << std::endl;
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    std::string response;
    char buffer[4096];
    DWORD bytesRead;
    
    while (InternetReadFile(hConnect, buffer, sizeof(buffer) -1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response.append(buffer, bytesRead);
    }
    
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return response;
}
// Old manual parsing functions (ParseJsonString, ParseJsonArray) are no longer needed and have been removed.
// The nlohmann/json library handles this directly within CheckForUpdates.