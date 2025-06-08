#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include "../../../KM-UM/UM/src/StealthComm.h" // For StealthComm::InitializeStealthComm etc.

class DriverMapper {
public:
    static bool MapDriver();
    static bool IsDriverLoaded();
    // static void CleanupTempFiles(); // Removed

private:
    // static bool ExtractResource(const unsigned char* data, unsigned int size, const std::wstring& filePath); // Removed
    // static bool ExecuteKdmapper(const std::wstring& kdmapperPath, const std::wstring& driverPath); // Modified
    static bool ExecuteKdmapper(const unsigned char* kdmapper_data, unsigned int kdmapper_size, const unsigned char* driver_data, unsigned int driver_size);
    // static std::wstring GetTempDirectory(); // Removed
    // static bool FileExists(const std::wstring& filePath); // Removed
    
    // Static member variables to track temp file paths - Removed
    // static std::wstring s_tempKdmapperPath;
    // static std::wstring s_tempDriverPath;
    // static bool s_tempFilesCreated;
};
