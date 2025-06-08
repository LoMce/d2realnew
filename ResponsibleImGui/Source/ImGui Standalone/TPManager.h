#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <chrono>
#include "json.hpp"

class ImGuiContext;
struct ImGuiIO;
namespace DriverComm {
    struct Request;
}

namespace TPManager {
    struct TPEntry { std::string name; float x, y, z, viewX, viewY; };

    constexpr uintptr_t POS_X = 0x1C0;
    constexpr uintptr_t POS_Y = 0x1C4;
    constexpr uintptr_t POS_Z = 0x1C8;
    constexpr uintptr_t VEL_X = 0x230;
    constexpr uintptr_t VEL_Y = 0x234;
    constexpr uintptr_t VEL_Z = 0x238;
    constexpr intptr_t VIEW_X = (0x1C - 0x4);
    constexpr intptr_t VIEW_Y = 0x1C;

    extern std::filesystem::path folder;
    extern std::vector<std::string> configs;
    extern std::vector<TPEntry> cycleList;
    extern int loadedConfigIdx;
    extern int loadedConfigIdxActive;
    extern int currentCycleIdx;
    extern bool arrowDebounce;
    extern char configNameBuf[64];
    extern char tpNameBuf[64];
    extern std::string lastTPName;
    extern std::string coordsStr;
    extern std::string viewStr;
    extern std::chrono::steady_clock::time_point lastStatusUpdate;

    // Editor State
    extern char editName[64];
    extern float editX, editY, editZ;
    extern float editViewX, editViewY;
    extern int lastEditIdx;

    // Functions
    void InitFolder();
    void RefreshConfigList();
    void ReadConfig(const std::string& name);
    void WriteConfig(const std::string& name);
    void LoadEditorFields(int idx);
    void ClearEditorFields();
    void ApplyEditorChanges();
    void TeleportTo(int idx); // Removed HANDLE driver
    void UpdateStatus();
    void Poll(); // Removed HANDLE driver, DWORD pid

    // Function to render the TP tab in ImGui
    void RenderTPTab(); // Removed HANDLE driver, DWORD pid
}
