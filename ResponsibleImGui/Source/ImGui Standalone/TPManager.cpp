#include "pch.h"
#include "TPManager.h"
#include "DriverComm.h"
#include "FeaturesDecl.h"
#include <iostream>
#include <string>
#include <cstdio> // For std::format if available and used, or alternatives
#include <filesystem> // For std::filesystem
#include <fstream>    // For std::ifstream, std::ofstream
#include <algorithm>  // For std::find, std::remove_if
#include <vector>     // For std::vector
#include <chrono>     // For std::chrono
#include <thread>     // For std::this_thread

// Ensure nlohmann/json.hpp is correctly included if used directly here,
// or ensure Features.h provides it if TPManager relies on json types from there.
// Assuming Features.h or pch.h handles nlohmann::json include.


namespace TPManager {
    std::filesystem::path folder;
    std::vector<std::string> configs;
    std::vector<TPEntry> cycleList;
    int loadedConfigIdx = -1;
    int loadedConfigIdxActive = -1;
    int currentCycleIdx = 0; // Changed from -1 to 0 for initial valid index if list not empty
    bool arrowDebounce = false;
    char configNameBuf[64] = {};
    char tpNameBuf[64] = "";
    std::string lastTPName = "None";
    std::string coordsStr = "N/A";
    std::string viewStr = "N/A";
    std::chrono::steady_clock::time_point lastStatusUpdate{};

    char editName[64] = "";
    float editX = 0.0f, editY = 0.0f, editZ = 0.0f;
    float editViewX = 0.0f, editViewY = 0.0f;
    int lastEditIdx = -1;

    void InitFolder() {
        char* userProfile = nullptr;
        size_t len = 0;
        if (_dupenv_s(&userProfile, &len, "USERPROFILE") != 0 || !userProfile) {
            folder = std::filesystem::current_path() / "Hatemob" / "TPs";
        }
        else {
            folder = std::filesystem::path(userProfile) / "Documents" / "Hatemob" / "TPs";
            free(userProfile);
        }
        std::error_code ec;
        std::filesystem::create_directories(folder, ec);
        if(ec) {
            std::cerr << "[-] TPManager::InitFolder: Failed to create directory " << folder << ". Error: " << ec.message() << std::endl;
        }
    }

    void RefreshConfigList() {
        configs.clear();
        try {
            for (auto& e : std::filesystem::directory_iterator(folder)) {
                if (e.is_regular_file() && e.path().extension() == ".json")
                    configs.push_back(e.path().stem().string());
            }
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "[-] TPManager::RefreshConfigList: Error iterating directory " << folder << ": " << e.what() << std::endl;
        }
        if (configs.empty()) {
            loadedConfigIdx = -1; // No config to select
        } else if (loadedConfigIdx >= static_cast<int>(configs.size()) || loadedConfigIdx < 0) {
            loadedConfigIdx = 0; // Default to first if out of bounds
        }
        // currentCycleIdx should also be reset or validated if a new config is loaded or list becomes empty
        if (cycleList.empty()) currentCycleIdx = 0;
        else if (currentCycleIdx >= static_cast<int>(cycleList.size())) currentCycleIdx = static_cast<int>(cycleList.size()) -1;

    }

    void ReadConfig(const std::string& name) {
        cycleList.clear();
        ClearEditorFields(); // Clear editor when loading new config
        std::ifstream f(folder / (name + ".json"));
        if (!f.is_open()) {
            std::cerr << "[-] TPManager::ReadConfig: Failed to open config file: " << (folder / (name + ".json")) << std::endl;
            lastTPName = "None";
            currentCycleIdx = 0;
            return;
        }
        nlohmann::json j;
        try {
            f >> j;
            for (auto& item : j) {
                TPEntry t;
                t.name = item.value("name", "");
                t.x = item.value("x", 0.0f);
                t.y = item.value("y", 0.0f);
                t.z = item.value("z", 0.0f);
                t.viewX = item.value("viewX", 0.0f);
                t.viewY = item.value("viewY", 0.0f);
                cycleList.push_back(t);
            }
        } catch (const nlohmann::json::exception& e) {
            std::cerr << "[-] TPManager::ReadConfig: JSON parsing error: " << e.what() << std::endl;
        }
        lastTPName = "None";
        currentCycleIdx = cycleList.empty() ? 0 : 0; // Start at index 0 if list has items
        if (!cycleList.empty()) LoadEditorFields(currentCycleIdx); // Load first entry into editor
    }

    void WriteConfig(const std::string& name) {
        if (name.empty()) {
            std::cerr << "[-] TPManager::WriteConfig: Config name cannot be empty." << std::endl;
            return;
        }
        nlohmann::json j = nlohmann::json::array();
        for (auto& t : cycleList) {
            j.push_back({
                {"name",  t.name}, {"x",     t.x}, {"y",     t.y}, {"z",     t.z},
                {"viewX", t.viewX}, {"viewY", t.viewY}
            });
        }
        std::ofstream f(folder / (name + ".json"));
        if (f.is_open()) {
            f << j.dump(4);
            #ifdef _DEBUG
            std::cout << "[+] TPManager::WriteConfig: Config '" << name << "' saved." << std::endl;
            #endif
        } else {
            std::cerr << "[-] TPManager::WriteConfig: Failed to open config file for writing: " << (folder / (name + ".json")) << std::endl;
        }
    }

    void LoadEditorFields(int idx) {
        if (idx < 0 || idx >= static_cast<int>(cycleList.size())) {
            ClearEditorFields(); // Clear if index is invalid
            return;
        }
        const auto& tp = cycleList[idx];
        strncpy_s(editName, tp.name.c_str(), sizeof(editName) - 1);
        editName[sizeof(editName)-1] = '\0'; // Ensure null termination
        editX = tp.x; editY = tp.y; editZ = tp.z;
        editViewX = tp.viewX; editViewY = tp.viewY;
        lastEditIdx = idx;
    }

    void ClearEditorFields() {
        editName[0] = '\0';
        editX = editY = editZ = 0.0f;
        editViewX = editViewY = 0.0f;
        lastEditIdx = -1;
    }

    void ApplyEditorChanges() {
        if (lastEditIdx < 0 || lastEditIdx >= static_cast<int>(cycleList.size())) {
            std::cerr << "[-] TPManager::ApplyEditorChanges: Invalid edit index." << std::endl;
            return;
        }
        if (strlen(editName) == 0) {
             std::cerr << "[-] TPManager::ApplyEditorChanges: Name cannot be empty." << std::endl;
            return; // Should be handled by UI popup as well
        }
        auto& tp = cycleList[lastEditIdx];
        tp.name = editName;
        tp.x = editX; tp.y = editY; tp.z = editZ;
        tp.viewX = editViewX; tp.viewY = editViewY;

        if (loadedConfigIdx >= 0 && loadedConfigIdx < static_cast<int>(configs.size())) {
            WriteConfig(configs[loadedConfigIdx]);
        } else {
            std::cerr << "[-] TPManager::ApplyEditorChanges: No valid config selected to save changes." << std::endl;
        }
    }

    void TeleportTo(int idx) { // Removed HANDLE driver parameter
        if (!LocalPlayer::Enabled) return;

        uintptr_t base = LocalPlayer::realPlayer.load();
        uintptr_t viewBase = ViewAngles::g_viewBase.load(); // Use the cached global from ViewAngles

        float velX = 0.0f, velY = 0.0f, velZ = 10.0f; // Default upward velocity

        if (!base || cycleList.empty() || idx < 0 || idx >= static_cast<int>(cycleList.size())) {
            #ifdef _DEBUG
            std::cerr << "[-] TPManager::TeleportTo: Pre-condition failed. Base: 0x" << std::hex << base
                      << ", ViewBase: 0x" << viewBase << ", ListEmpty: " << cycleList.empty()
                      << ", Idx: " << std::dec << idx << std::endl;
            #endif
            return;
        }
        if (viewBase == 0) { // Critical if view angles need to be set
            #ifdef _DEBUG
            std::cerr << "[-] TPManager::TeleportTo: ViewAngles base is NULL. Cannot set view angles." << std::endl;
            #endif
            // Continue to teleport position if that's desired without view angles.
        }

        const auto& e = cycleList[idx];
        DriverComm::write_memory(base + POS_X, e.x);
        DriverComm::write_memory(base + POS_Y, e.y);
        DriverComm::write_memory(base + POS_Z, e.z);

        if (LocalPlayer::flyEnabled) { // If fly mode is active, use its velocity logic
            // The FlyLoop will handle velocity, so we might not need to set it here,
            // or set a minimal upward nudge to unstick.
            // For simplicity, if fly is on, let FlyLoop manage it. Just ensure Z is set.
            DriverComm::write_memory(base + VEL_Z, velZ); // Give an upward nudge
        } else {
            velZ = 2.0f; // Smaller nudge if not flying
            DriverComm::write_memory(base + VEL_Z, velZ);
            // Zero out X, Y velocity if not flying to prevent sliding
            DriverComm::write_memory(base + VEL_X, 0.0f);
            DriverComm::write_memory(base + VEL_Y, 0.0f);
        }
        
        if (viewBase != 0) { // Only write view angles if base is valid
            DriverComm::write_memory(viewBase + VIEW_X, e.viewX);
            DriverComm::write_memory(viewBase + VIEW_Y, e.viewY);
        }

        lastTPName = e.name;
        #ifdef _DEBUG
        std::cout << "[+] TPManager::TeleportTo: Teleported to '" << e.name << "'." << std::endl;
        #endif
    }

    void UpdateStatus() {
        if (!LocalPlayer::Enabled) {
            coordsStr = "N/A (LocalPlayer OFF)";
            viewStr = "N/A (LocalPlayer OFF)";
            return;
        }
        auto coords = LocalPlayer::g_cachedCoords.load();
        char buf[100];
        snprintf(buf, sizeof(buf), "%.3f, %.3f, %.3f", coords.x, coords.y, coords.z);
        coordsStr = buf;

        if (ViewAngles::g_viewBase.load() != 0) {
            auto angles = ViewAngles::g_cachedAngles.load();
            snprintf(buf, sizeof(buf), "%.3f, %.3f", angles.pitch, angles.yaw);
            viewStr = buf;
        } else {
            viewStr = "N/A (ViewAngles Base NULL)";
        }
    }

    void Poll() { // Removed HANDLE driver, DWORD pid parameters
        if (!LocalPlayer::Enabled || DriverComm::g_pid == 0) return; // Rely on global g_pid

        if (cycleList.empty() || loadedConfigIdxActive < 0) return; // No config loaded or list empty

        bool right = (GetAsyncKeyState(VK_RIGHT) & 0x8000) != 0;
        bool left = (GetAsyncKeyState(VK_LEFT) & 0x8000) != 0;

        if ((right || left) && !arrowDebounce) {
            if (right) {
                currentCycleIdx = (currentCycleIdx + 1) % cycleList.size();
            } else { // left
                currentCycleIdx = (currentCycleIdx - 1 + static_cast<int>(cycleList.size())) % static_cast<int>(cycleList.size());
            }
            TeleportTo(currentCycleIdx); // Pass only index
            LoadEditorFields(currentCycleIdx); // Update editor to current TP
            arrowDebounce = true;
        }
        if (!right && !left) arrowDebounce = false;

        auto now = std::chrono::steady_clock::now();
        if (now - lastStatusUpdate > std::chrono::milliseconds(250)) { // Update status more frequently
            UpdateStatus(); // UpdateStatus will use cached values
            lastStatusUpdate = now;
        }
    }

    void RenderTPTab() { // Removed HANDLE driver, DWORD pid parameters
        // ... (UI rendering logic remains largely the same, but calls to TeleportTo, ReadMem, WriteMem will use updated signatures)
        // Example for "Save TP" button:
        // if (ImGui::Button("Save TP") && loadedConfigIdx >= 0)
        // {
        //     uintptr_t base = LocalPlayer::realPlayer.load();
        //     uintptr_t viewBase = ViewAngles::g_viewBase.load(); // Use cached global
        //     TPManager::TPEntry e;
        //     e.name = tpNameBuf[0] ? std::string(tpNameBuf) : ("TP" + std::to_string(cycleList.size() + 1));
        //
        //     // Use DriverComm::read_memory directly
        //     e.x = DriverComm::read_memory<float>(base + POS_X);
        //     e.y = DriverComm::read_memory<float>(base + POS_Y);
        //     e.z = DriverComm::read_memory<float>(base + POS_Z);
        //     if (viewBase) {
        //         e.viewX = DriverComm::read_memory<float>(viewBase + VIEW_X);
        //         e.viewY = DriverComm::read_memory<float>(viewBase + VIEW_Y);
        //     } else {
        //         e.viewX = e.viewY = 0.0f;
        //     }
        //     // ... rest of logic
        // }
        // The existing TPManager::RenderTPTab already uses ReadMem/WriteMem wrappers from Features.h.
        // Since those wrappers are being removed from Features.h, the calls inside RenderTPTab
        // must be updated to directly use DriverComm::read_memory and DriverComm::write_memory.

        ImVec2 p = ImGui::GetCursorScreenPos();
        ImVec2 size = ImGui::GetContentRegionAvail();
        size.y = 320; // Adjust as needed
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        draw_list->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
        ImGui::Dummy(ImVec2(0, 10));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);
        ImGui::Text("TP Options:");

        if (!LocalPlayer::Enabled) {
            ImGui::TextDisabled("Enable LocalPlayer hook to use Teleports");
        }
        else {
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
            ImGui::SetNextItemWidth(200.0f);
            ImGui::InputText("##Config Name", configNameBuf, sizeof(configNameBuf));
            if (configNameBuf[0] == '\0') {
                ImVec2 pos = ImGui::GetItemRectMin();
                ImVec2 text_pos = ImVec2(pos.x + ImGui::GetStyle().FramePadding.x, pos.y + ImGui::GetStyle().FramePadding.y);
                ImGui::GetWindowDrawList()->AddText(text_pos, ImGui::GetColorU32(ImGuiCol_TextDisabled), "Enter config name...");
            }
            ImGui::PopStyleColor();
            ImGui::SameLine();
            if (ImGui::Button("Create")) {
                std::string nm{ configNameBuf };
                if (!nm.empty()) {
                    cycleList.clear(); WriteConfig(nm); RefreshConfigList();
                    auto it = std::find(configs.begin(), configs.end(), nm);
                    if (it != configs.end()) loadedConfigIdx = static_cast<int>(std::distance(configs.begin(), it));
                    else loadedConfigIdx = -1; // Should not happen if RefreshConfigList is correct
                    loadedConfigIdxActive = loadedConfigIdx; // Activate the new config
                    if(!cycleList.empty()) LoadEditorFields(0); else ClearEditorFields();
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Refresh")) { RefreshConfigList(); }

            const char* curConfig = (loadedConfigIdx >= 0 && loadedConfigIdx < static_cast<int>(configs.size())) ? configs[loadedConfigIdx].c_str() : "Select config";
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
            ImGui::SetNextItemWidth(200.0f);
            if (ImGui::BeginCombo("##Configs", curConfig)) {
                for (int i = 0; i < static_cast<int>(configs.size()); ++i) {
                    bool isSel = (i == loadedConfigIdx);
                    if (ImGui::Selectable(configs[i].c_str(), isSel)) loadedConfigIdx = i;
                    if (isSel) ImGui::SetItemDefaultFocus();
                }
                ImGui::EndCombo();
            }
            ImGui::PopStyleColor();
            ImGui::SameLine();
            ImGui::BeginDisabled(loadedConfigIdx < 0 || loadedConfigIdx >= static_cast<int>(configs.size()));
            if (ImGui::Button("Load")) {
                ReadConfig(configs[loadedConfigIdx]);
                loadedConfigIdxActive = loadedConfigIdx;
            }
            ImGui::SameLine();
            if (ImGui::Button("Unload")) {
                cycleList.clear(); currentCycleIdx = 0; lastTPName = "None"; loadedConfigIdxActive = -1; ClearEditorFields();
            }
            ImGui::SameLine();
            if (ImGui::Button("Reset Index")) { currentCycleIdx = cycleList.empty() ? 0 : 0; if(!cycleList.empty()) LoadEditorFields(currentCycleIdx); }
            ImGui::EndDisabled();

            float rightBlockY = ImGui::GetCursorPosY(); // Get Y after the buttons
            float rightBlockX = ImGui::GetWindowWidth() * 0.5f + 20.0f;
            ImGui::SetCursorPos(ImVec2(rightBlockX, rightBlockY - 100)); // Adjust Y to align better

            ImGui::BeginGroup();
            ImGui::Text("Loaded: %s", (loadedConfigIdxActive >= 0 && loadedConfigIdxActive < static_cast<int>(configs.size())) ? configs[loadedConfigIdxActive].c_str() : "None");
            ImGui::Text("Current TP Index: %d", cycleList.empty() ? -1 : currentCycleIdx); // Show -1 if list empty
            ImGui::Text("Last TP: %s", lastTPName.c_str());
            UpdateStatus(); // This uses cached values
            ImGui::Text("Coords: %s", coordsStr.c_str());
            ImGui::Text("View : %s", viewStr.c_str());
            ImGui::EndGroup();

            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10); // Reset Y to below the group
            ImGui::Separator();
            ImGui::Text("Teleport Entries:");
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0.180f, 0.180f, 0.180f, 1.0f));
            if (ImGui::ListBoxHeader("##Tplist", ImVec2(-FLT_MIN, ImGui::GetTextLineHeightWithSpacing() * 6))) { // Auto-width, 6 items high
                for (int i = 0; i < static_cast<int>(cycleList.size()); ++i) {
                    const bool selected = (i == currentCycleIdx);
                    std::string label = std::to_string(i + 1) + ". " + cycleList[i].name;
                    if (ImGui::Selectable(label.c_str(), selected)) {
                        currentCycleIdx = i;
                        LoadEditorFields(i);
                    }
                }
                ImGui::ListBoxFooter();
            }
            ImGui::PopStyleColor(2);
            ImGui::SameLine();
            ImGui::BeginGroup();
            ImGui::Text("Edit Selected TP");
            if (lastEditIdx >= 0 && lastEditIdx < static_cast<int>(cycleList.size())) {
                ImGui::PushItemWidth(180);
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
                ImGui::InputText("Name", editName, sizeof(editName));
                ImGui::InputFloat("X", &editX); ImGui::InputFloat("Y", &editY); ImGui::InputFloat("Z", &editZ);
                ImGui::InputFloat("ViewX", &editViewX); ImGui::InputFloat("ViewY", &editViewY);
                ImGui::PopStyleColor();
                ImGui::PopItemWidth();
                if (ImGui::Button("Apply Changes")) {
                    if (strlen(editName) == 0) ImGui::OpenPopup("NameError");
                    else ApplyEditorChanges();
                }
                ImGui::SameLine();
                if (ImGui::Button("Reset Fields")) LoadEditorFields(lastEditIdx);

                if (ImGui::BeginPopupModal("NameError", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                    ImGui::Text("Name cannot be empty!"); ImGui::Separator();
                    if (ImGui::Button("OK", ImVec2(120, 0))) { ImGui::CloseCurrentPopup(); }
                    ImGui::EndPopup();
                }
            } else { ImGui::TextDisabled("No TP selected or list empty.");}
            ImGui::EndGroup();

            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
            ImGui::InputText("##NewTPName", tpNameBuf, sizeof(tpNameBuf));
            ImGui::PopStyleColor();
            ImGui::SameLine();
            if (ImGui::Button("Save TP") && loadedConfigIdxActive >= 0 && loadedConfigIdxActive < static_cast<int>(configs.size())) {
                uintptr_t base = LocalPlayer::realPlayer.load();
                uintptr_t viewBase = ViewAngles::g_viewBase.load();
                if (base != 0) { // Ensure player base is valid
                    TPEntry e;
                    e.name = tpNameBuf[0] ? std::string(tpNameBuf) : ("TP" + std::to_string(cycleList.size() + 1));
                    e.x = DriverComm::read_memory<float>(base + POS_X);
                    e.y = DriverComm::read_memory<float>(base + POS_Y);
                    e.z = DriverComm::read_memory<float>(base + POS_Z);
                    if (viewBase != 0) {
                        e.viewX = DriverComm::read_memory<float>(viewBase + VIEW_X);
                        e.viewY = DriverComm::read_memory<float>(viewBase + VIEW_Y);
                    } else { e.viewX = e.viewY = 0.0f; }
                    cycleList.push_back(e);
                    WriteConfig(configs[loadedConfigIdxActive]);
                    tpNameBuf[0] = '\0';
                    currentCycleIdx = static_cast<int>(cycleList.size()) - 1;
                    LoadEditorFields(currentCycleIdx); // Load new TP into editor
                } else { std::cerr << "[-] Save TP: LocalPlayer base is NULL." << std::endl;}
            }
            ImGui::SameLine();
            if (ImGui::Button("Delete TP") && loadedConfigIdxActive >= 0 && currentCycleIdx >= 0 && currentCycleIdx < static_cast<int>(cycleList.size())) {
                cycleList.erase(cycleList.begin() + currentCycleIdx);
                WriteConfig(configs[loadedConfigIdxActive]);
                // ReadConfig(configs[loadedConfigIdxActive]); // Reload to refresh view, or just adjust index
                if (currentCycleIdx >= static_cast<int>(cycleList.size())) {
                    currentCycleIdx = static_cast<int>(cycleList.size()) - 1;
                }
                if (currentCycleIdx >= 0) LoadEditorFields(currentCycleIdx); else ClearEditorFields();

            }

            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 4));
            if (ImGui::ArrowButton("Up##tp", ImGuiDir_Up) && currentCycleIdx > 0) {
                std::swap(cycleList[currentCycleIdx], cycleList[currentCycleIdx - 1]);
                --currentCycleIdx;
                if (loadedConfigIdxActive >=0) WriteConfig(configs[loadedConfigIdxActive]);
                LoadEditorFields(currentCycleIdx);
            }
            ImGui::SameLine();
            if (ImGui::ArrowButton("Down##tp", ImGuiDir_Down) && currentCycleIdx + 1 < static_cast<int>(cycleList.size())) {
                std::swap(cycleList[currentCycleIdx], cycleList[currentCycleIdx + 1]);
                ++currentCycleIdx;
                if (loadedConfigIdxActive >=0) WriteConfig(configs[loadedConfigIdxActive]);
                LoadEditorFields(currentCycleIdx);
            }
            ImGui::PopStyleVar();
        }
    }
}
