#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <functional>

class UpdateManager {
public:
    struct Version {
        int major = 0;
        int minor = 0;
        int patch = 0;
        
        Version() = default;
        Version(int maj, int min, int pat) : major(maj), minor(min), patch(pat) {}
        
        bool operator>(const Version& other) const {
            if (major != other.major) return major > other.major;
            if (minor != other.minor) return minor > other.minor;
            return patch > other.patch;
        }
        
        std::string ToString() const {
            return std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);
        }
    };

    struct Release {
        std::string tagName;
        std::string name;
        std::string downloadUrl;
        std::string body;
        Version version;
        bool prerelease = false;
    };

    static bool CheckForUpdates(const std::string& currentVersion, Release& latestRelease);
    static bool DownloadUpdate(const Release& release, const std::wstring& downloadPath, 
                              std::function<void(int)> progressCallback = nullptr);
    static bool CreateUpdateHelper(const std::wstring& helperPath, const std::wstring& newLoaderPath, 
                                  const std::wstring& currentLoaderPath);
    static bool LaunchUpdateHelper(const std::wstring& helperPath);
    
private:
    static Version ParseVersion(const std::string& versionStr);
    static std::string MakeHttpsRequest(const std::string& url);
    static std::string ParseJsonString(const std::string& json, const std::string& key);
    static std::vector<std::string> ParseJsonArray(const std::string& json, const std::string& arrayKey);
      static constexpr const char* GITHUB_API_URL = "https://api.github.com/repos/Anthropicalluv/hatedupdates/releases/latest";
    static constexpr const char* USER_AGENT = "HatedLoader/1.0";
};