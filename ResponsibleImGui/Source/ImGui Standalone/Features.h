#pragma once

#ifndef FEATURES_H_GUARD
#define FEATURES_H_GUARD

#include <Windows.h>
#include <cstdint>
#include <iomanip>
#include <mutex>
#include <filesystem>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic> // Added for std::atomic

#include "Logging.h" // Added for logging functions
#include "ImGui/imgui_custom.h"
#include "DriverComm.h"
#include "aobs.h"

#include "nlohmann/json.hpp"
using json = nlohmann::json;

// Global state
inline std::unordered_map<std::string, bool> FeatureConfig;
inline std::unordered_map<std::string, int> Hotkeys;
inline std::atomic<bool> g_aob_scan_complete_flag{false};
inline std::atomic<bool> g_aob_scan_running{false};

// Forward declarations for helper functions
void LoadHotkeys();
void SaveHotkeys();
void SetHotkeyDefault(const std::string& name, int defaultVK);
std::string GetKeyName(int vkCode);
bool DrawHotkeyPicker(const std::string& name, const std::string& label, bool& listening);
std::vector<BYTE> HexToBytes(const std::string& hex_str);

// Modified InjectCodecave to use NTSTATUS and atomic<uintptr_t>
inline bool InjectCodecave( // Return bool for simplicity in feature logic, but use NTSTATUS internally
    DWORD pid,
    uintptr_t targetAddress,
    const std::vector<BYTE>& shellcodeBytes,
    SIZE_T originalSize,
    std::atomic<uintptr_t>& codecaveAddress_atomic) // Takes atomic by reference
{
    if (shellcodeBytes.empty()) {
        LogMessage("[-] InjectCodecave: Shellcode byte vector is empty.");
        return false; // Changed from FALSE
    }
    if (shellcodeBytes.size() < 5 && originalSize > 0) { // Need 5 bytes for a JMP
        LogMessage("[-] InjectCodecave: Shellcode must be at least 5 bytes for a JMP if originalSize > 0.");
        return false;
    }

    std::vector<BYTE> finalShellcode = shellcodeBytes;
    uintptr_t currentCodecaveAddressVal = codecaveAddress_atomic.load();

    if (currentCodecaveAddressVal == 0) {
        NTSTATUS alloc_status = DriverComm::allocate_memory_ex(pid, finalShellcode.size() + 32, currentCodecaveAddressVal, reinterpret_cast<PVOID>(targetAddress));
        if (!NT_SUCCESS(alloc_status)) {
            LogMessageF("[-] InjectCodecave: DriverComm::allocate_memory_ex failed. PID: %lu, Size: %zu, Status: 0x%lX", pid, finalShellcode.size() + 32, alloc_status);
            return false;
        }
        codecaveAddress_atomic.store(currentCodecaveAddressVal);
        #ifdef _DEBUG
        std::cout << "[+] InjectCodecave: Codecave allocated at: 0x" << std::hex << currentCodecaveAddressVal << std::dec << " for PID " << pid << std::endl;
        #endif
    } else {
        #ifdef _DEBUG
        std::cout << "[+] InjectCodecave: Using provided codecave address: 0x" << std::hex << currentCodecaveAddressVal << std::dec << " for PID " << pid << std::endl;
        #endif
    }

    if (originalSize > 0) {
        if (finalShellcode.size() < 5) {
             LogMessageF("[-] InjectCodecave: Shellcode (size %zu) is too small to append a 5-byte jump.", finalShellcode.size());
             return false;
        }
        SIZE_T jmpPatchOffset = finalShellcode.size() - 5;
        finalShellcode[jmpPatchOffset] = 0xE9; // JMP rel32
        DWORD returnRelativeOffset = static_cast<DWORD>((targetAddress + originalSize) - (currentCodecaveAddressVal + jmpPatchOffset + 5));
        memcpy(&finalShellcode[jmpPatchOffset + 1], &returnRelativeOffset, sizeof(returnRelativeOffset));
    }

    NTSTATUS write_sc_status = DriverComm::write_memory_buffer(currentCodecaveAddressVal, finalShellcode.data(), finalShellcode.size());
    if (!NT_SUCCESS(write_sc_status)) {
        LogMessageF("[-] InjectCodecave: DriverComm::write_memory_buffer for codecave failed at 0x%llX. PID: %lu, Status: 0x%lX", currentCodecaveAddressVal, pid, write_sc_status);
        return false;
    }
    #ifdef _DEBUG
    std::cout << "[+] InjectCodecave: Shellcode (size " << finalShellcode.size() << ") written to codecave at 0x" << std::hex << currentCodecaveAddressVal << std::dec << " for PID " << pid << std::endl;
    #endif

    if (originalSize > 0) {
        std::vector<BYTE> patchBytes(originalSize, 0x90);
        patchBytes[0] = 0xE9; // JMP rel32
        DWORD jumpToCaveRelativeOffset = static_cast<DWORD>(currentCodecaveAddressVal - (targetAddress + 5));
        memcpy(&patchBytes[1], &jumpToCaveRelativeOffset, sizeof(jumpToCaveRelativeOffset));

        NTSTATUS write_hook_status = DriverComm::write_memory_buffer(targetAddress, patchBytes.data(), patchBytes.size());
        if (!NT_SUCCESS(write_hook_status)) {
            LogMessageF("[-] InjectCodecave: DriverComm::write_memory_buffer for hook at 0x%llX. PID: %lu failed. Status: 0x%lX", targetAddress, pid, write_hook_status);
            return false;
        }
        #ifdef _DEBUG
        std::cout << "[+] InjectCodecave: Hook (JMP to cave) written to 0x" << std::hex << targetAddress << std::dec << " for PID " << pid << std::endl;
        #endif
    }
    return true; // Changed from TRUE
}

// Function to release a codecave
static inline void ReleaseCodecave(DWORD pid, std::atomic<uintptr_t>& featureCodecaveAddress, bool& memAllocatedFlag) {
    uintptr_t address_to_free = featureCodecaveAddress.load();
    if (address_to_free != 0 && memAllocatedFlag) {
        NTSTATUS free_status = DriverComm::free_memory_ex(pid, address_to_free, 0); // Size 0 for MEM_RELEASE
        if (NT_SUCCESS(free_status)) {
            LogMessageF("[+] Codecave at 0x%llX freed successfully for PID %lu.", address_to_free, pid);
            featureCodecaveAddress.store(0);
            memAllocatedFlag = false;
        } else {
            LogMessageF("[-] Failed to free codecave at 0x%llX for PID %lu. Status: 0x%lX", address_to_free, pid, free_status);
            // Don't reset flags if free failed, might retry or indicates an issue.
        }
    } else if (address_to_free != 0 && !memAllocatedFlag) {
        // This case could happen if address was set but memAllocatedFlag is false (e.g. shared cave not owned by this feature)
        // For now, we only free if memAllocatedFlag indicates this feature instance allocated it.
        // LogMessageF("[!] ReleaseCodecave: Address 0x%llX present but memAllocatedFlag is false. Not freeing.", address_to_free);
    }
}


// Hotkey and config helpers
inline std::filesystem::path GetHotkeysFilePath() { char* userProfile = nullptr; size_t len = 0; if (_dupenv_s(&userProfile, &len, "USERPROFILE") != 0 || !userProfile) { return std::filesystem::current_path() / "hotkeys.json"; } std::filesystem::path docs = std::filesystem::path(userProfile) / "Documents"; free(userProfile); std::filesystem::path hotkeysDir = docs / "Hatemob" / "Hotkeys"; std::error_code ec; std::filesystem::create_directories(hotkeysDir, ec); if(ec) { LogMessageF("[-] GetHotkeysFilePath: Error creating directory %s: %s", hotkeysDir.string().c_str(), ec.message().c_str());} return hotkeysDir / "hotkeys.json";}
inline void LoadHotkeys() { auto path = GetHotkeysFilePath(); std::ifstream file(path); if (!file.is_open()) { return; } try { json j; file >> j; for (auto& [key, value] : j.items()) { if (value.is_number_integer()) Hotkeys[key] = value.get<int>(); } } catch (const std::exception& e) { LogMessageF("[Hotkeys] Load error: %s", e.what()); }}
inline void SaveHotkeys() { json j; for (auto& [key, value] : Hotkeys) j[key] = value; auto path = GetHotkeysFilePath(); std::ofstream file(path); if (file.is_open()) { file << j.dump(4); }}
inline void SetHotkeyDefault(const std::string& name, int defaultVK) { if (Hotkeys.find(name) == Hotkeys.end() || Hotkeys[name] == 0) Hotkeys[name] = defaultVK; }
inline std::string GetKeyName(int vkCode) { UINT sc = MapVirtualKeyA(vkCode, MAPVK_VK_TO_VSC); switch (vkCode) { case VK_LEFT: case VK_UP: case VK_RIGHT: case VK_DOWN: case VK_PRIOR: case VK_NEXT: case VK_END: case VK_HOME: case VK_INSERT: case VK_DELETE: case VK_DIVIDE: case VK_NUMLOCK: case VK_RCONTROL: case VK_RMENU: sc |= 0x100; } LONG lParam = sc << 16; char buf[128] = {}; if (GetKeyNameTextA(lParam, buf, sizeof(buf))) return buf; return "Unknown";}
inline bool DrawHotkeyPicker(const std::string& name, const std::string& label, bool& listening) { std::string button_label = "Set##" + name; if (!label.empty()) { ImGui::TextUnformatted(label.c_str()); ImGui::SameLine(); } if (ImGui::Button(button_label.c_str())) listening = true; ImGui::SameLine(); int& hotkey = Hotkeys[name]; if (hotkey == 0) hotkey = VK_NONE; ImGui::Text("Key: %s", GetKeyName(hotkey).c_str()); if (listening) { ImGui::Text("Press a key…"); for (int vk = 0x01; vk <= 0xFE; ++vk) { if (vk == VK_ESCAPE || vk == VK_RETURN || vk == VK_TAB) continue; if (GetAsyncKeyState(vk) & 0x8000) { hotkey = vk; listening = false; SaveHotkeys(); return true; } } } return false; }
inline std::vector<BYTE> HexToBytes(const std::string& hex_str) { std::vector<BYTE> bytes; std::string hex = hex_str; hex.erase(std::remove_if(hex.begin(), hex.end(), ::isspace), hex.end()); if (hex.length() % 2 != 0) {LogMessage("[-] HexToBytes: Odd length hex string."); return bytes; } if (hex.empty()){ return bytes; } for (size_t i = 0; i < hex.length(); i += 2) { std::string byteString = hex.substr(i, 2); try { BYTE byte = static_cast<BYTE>(std::stoul(byteString, nullptr, 16)); bytes.push_back(byte); } catch (const std::exception& e) {LogMessageF("[-] HexToBytes: Error parsing '%s': %s", byteString.c_str(), e.what()); bytes.clear(); return bytes; } } return bytes; }

// Feature Namespaces
namespace Killaura { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "F3 0F 10 41 20 32 C0 0F C6 C0 ? 0F 11 02 C3 ? 0F ? ? ? 32"; std::string shellcode_hex = "c7 41 20 00 00 7a 44 f3 0f 10 41 20 e9 00 00 00 00"; BYTE origBytes[5] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace LocalPlayer { struct Vec3 { float x, y, z; }; std::atomic<Vec3> g_cachedCoords{ {0,0,0} }; bool Enabled = false; bool flyEnabled = false; bool FlyHotkeyWasDown = false; inline bool KillKeyEnabled = false; inline bool KillKeyWasDown = false; uintptr_t destinyBase = 0x301F8F0; std::atomic<uintptr_t> realPlayer = 0; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::atomic<uintptr_t> addrMemAllocatedAddress{0}; bool addr_mem_allocated = false; std::string AOB = "0F 10 89 ? ? ? ? 0F 54 0D ? ? ? ? 66 0F 6F ? ? ? ? ? 0F 54 C8 66 0F 72 D2 ? 66 0F 72 F2 ? 0F 55 C2 0F 56 C8 0F 11 0A E9 ? ? ? ? 48 81 C1"; std::string shellcode_hex = "50 48 89 C8 48 A3 FF FF FF FF FF FF FF FF 58 0F 10 89 C0 01 00 00 E9 00 00 00 00"; BYTE origBytes[7] = {}; std::atomic<uintptr_t> InstructionAddress{0}; std::atomic<uintptr_t> disableGravAddress{0}; std::string disableGravAOB = "88 51 79 8B D0"; std::string disableGravShellcode_hex = "C7 41 79 01 00 00 00 8B D0 E9 00 00 00 00"; BYTE disableGravOrigBytes[5] = {}; std::atomic<uintptr_t> disableGravMemAllocatedAddress{0}; bool disableGrav_mem_allocated = false; }
namespace ViewAngles { struct Vec2 { float pitch, yaw; }; std::atomic<uintptr_t> g_viewBase{0}; std::atomic<ViewAngles::Vec2> g_cachedAngles{{0.0f,0.0f}}; std::atomic<bool> g_cacheThreadRunning{false}; bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::atomic<uintptr_t> addrMemAllocatedAddress{0}; bool addr_mem_allocated = false; std::string AOB = "F3 0F 11 47 1C 7A"; std::string shellcode_hex = "50 48 89 F8 48 A3 FF FF FF FF FF FF FF FF 58 F3 0F 11 47 1C E9 00 00 00 00"; BYTE origBytes[5] = {}; std::atomic<uintptr_t> InstructionAddress{0}; inline void CacheLoop(DWORD pid) { g_cacheThreadRunning = true; uintptr_t temp_addr_storage_val = 0; Vec2 angles_val_cache; LocalPlayer::Vec3 coords_val_cache; while (g_cacheThreadRunning.load()) { if (addrMemAllocatedAddress.load() == 0) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); continue; }  NTSTATUS status = DriverComm::read_memory<uintptr_t>(addrMemAllocatedAddress.load(), temp_addr_storage_val); if (NT_SUCCESS(status)) { g_viewBase.store(temp_addr_storage_val); if (temp_addr_storage_val != 0) {  NTSTATUS angle_status = DriverComm::read_memory<Vec2>(temp_addr_storage_val + 0x18, angles_val_cache); if(NT_SUCCESS(angle_status)) g_cachedAngles.store(angles_val_cache); } } if (LocalPlayer::realPlayer.load() != 0) {  NTSTATUS coord_status = DriverComm::read_memory<LocalPlayer::Vec3>(LocalPlayer::realPlayer.load() + 0x1C0, coords_val_cache); if(NT_SUCCESS(coord_status)) LocalPlayer::g_cachedCoords.store(coords_val_cache); } std::this_thread::sleep_for(std::chrono::milliseconds(150)); } } }
namespace Ghostmode { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "F3 0F 11 4C 24 38 B9 DD AD 93 43 8B 5C 24 38 B8 9C 6E 3F 2B 66 66 0F 1F 84 00 00 00 00 00"; BYTE origBytes[6] = {}; std::string shellcode_hex = "b8 00 00 80 bf 66 0f 6e c8 f3 0f 11 4c 24 38 e9 00 00 00 00"; std::atomic<uintptr_t> InstructionAddress{0};}
namespace Godmode { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "33 DA C1 C3 10 E8 ? ? ? ? 48"; std::string shellcode_hex = "6b db 01 e9 00 00 00 00"; BYTE origBytes[5] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace InfAmmo { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "44 0F 28 BD F0 05 00 00 48 83 C3"; std::string shellcode_hex = "81 bd f0 05 00 00 00 00 80 bf 0f 85 00 00 00 00 c7 85 f0 05 00 00 00 00 00 00 44 0f 28 bd f0 05 00 00 e9 00 00 00 00"; BYTE origBytes[8] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace dmgMult { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "F3 44 0F 10 61 24 44 0F 29 68 88 F3 44 0F 10 69 1C"; std::string shellcode_hex = "c7 41 24 00 40 9c 45 f3 44 0f 10 61 24 e9 00 00 00 00"; BYTE origBytes[6] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace FOV { std::string AOB = "30 00 00 00 00 00 00 00 28 C8 0A 00 00 00 00 00 40 01 00 00 00 00 00 00 A0 08"; uint8_t fov = 0; std::atomic<uintptr_t> ptr{0}; uintptr_t offset = 0x530; uintptr_t pointer = 0x5DC;}
namespace RPM { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "F3 0F 11 86 CC 17 00 00 48"; std::string shellcode_hex = "f3 0f 10 86 9c 17 00 00 f3 0f 59 c0 f3 0f 11 86 9c 17 00 00 f3 0f 11 86 cc 17 00 00 e9 00 00 00 00"; BYTE origBytes[8] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace NoRecoil { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "0F 11 8B ? ? ? ? 0F 28 CD";  std::string shellcode_hex = "66 0f ef c9 0f 11 8b 50 10 00 00 e9 00 00 00 00"; BYTE origBytes[7] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace OHK { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "F3 0F 11 44 24 50 33 C0 8B";  std::string shellcode_hex = "0f ef c0 f3 0f 11 44 24 32 e9 00 00 00 00"; BYTE origBytes[6] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace NoJoinAllies { bool Enabled = false; std::string AOB = "48 01 47 ? EB ? 48"; BYTE nops[6] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; BYTE origBytes[6] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace NoTurnBack { bool Enabled = false; std::string AOB = "F3 0F 11 46 ? E9 ? ? ? ? 44 0F B6"; BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90 }; BYTE origBytes[5] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace InfSwordAmmo {  bool Enabled = false; std::string AOB = "0F 28 C7 F3 41 0F 5C C0 0F 2F C6 ? ? 41 0F 28 F8 F3"; BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; BYTE origBytes[8] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace SparrowAnywhere {  bool Enabled = false; std::string AOB = "74 ?? 48 8B C8 48 89 7C 24 30 E8 ?? ?? ?? ?? 48 8B CB 48 8B F8 E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 ?? ?? 80 78 0E 00"; BYTE mybyte[] = { 0x75 }; BYTE origByte[] = { 0x74 }; std::atomic<uintptr_t> InstructionAddress{0};}
namespace InfStacks {bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "89 5F ? 74 ? 8B"; std::string shellcode_hex = "bb 64 00 00 00 89 5f 30 e9 00 00 00 00"; BYTE origBytes[5] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace NoRezTokens {  bool Enabled = false; std::string AOB = "75 08 E8 ?? ?? ?? ?? 89"; BYTE myByte[] = { 0xEB }; BYTE origByte[] = { 0x75 }; std::atomic<uintptr_t> InstructionAddress{0};}
namespace InstaRespawn {  bool Enabled = false; std::string AOB = "49 8B ? ? ? ? ? 48 8B 08 48 3B"; BYTE myBytes[] = { 0x48, 0x31, 0xD2, 0x90, 0x90, 0x90, 0x90 }; BYTE origBytes[7] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace RespawnAnywhere { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "48 89 ? ? ? ? ? ? ? 0F 28 CE 48 8D"; std::string shellcode_hex = "50 48 31 c0 48 89 86 68 08 00 00 58 e9 00 00 00 00"; BYTE origBytes[7] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace ShootThru {  bool Enabled = false; std::string AOB = "0F 11 02 0F 11 4A 10 44 0F 28 0D"; BYTE nops[] = { 0x90, 0x90, 0x90 }; BYTE origBytes[3] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace Chams { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "0F 10 02 48 83 C1 60"; std::string shellcode_hex = "b8 a6 95 80 80 39 42 78 0f 85 06 00 00 00 c7 02 00 00 20 41 0f 10 02 48 83 c1 60 e9 00 00 00 00"; BYTE origBytes[7] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace ImmuneBosses { std::atomic<bool> Enabled = false; std::atomic<bool> ThreadRunning = false; std::atomic<uintptr_t> Address{0}; }
namespace AbilityCharge { bool Enabled = false; bool WasKeyDown = false;  std::string AOB = "0F 10 02 48 83 C1 60"; std::string shellcode_hex = "50 b8 00 00 80 3f f3 0f 2a c0 48 83 c1 60 58 e9 00 00 00 00"; BYTE origBytes[7] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace ImmuneAura {  bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "0F 10 02 48 83 C1 60"; std::string shellcode_hex = "50 b8 e8 03 00 00 f3 0f 2a c0 48 83 c1 60 58 e9 00 00 00 00"; BYTE origBytes[7] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace IcarusDash {  bool Enabled = false; std::string AOB = "89 46 34 89 6E 3C"; BYTE nops[] = { 0x90, 0x90, 0x90 }; BYTE origBytes[3] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace InstantInteract { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::string AOB = "F3 0F 11 43 08 48 83 C4 30 5B C3 48"; std::string shellcode_hex = "c7 43 08 00 00 00 00 e9 00 00 00 00"; BYTE origBytes[5] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace InteractThruWalls { bool Enabled = false; bool mem_allocated1 = false; bool mem_allocated2 = false; std::atomic<uintptr_t> memAllocatedAddress1{0}; std::atomic<uintptr_t> memAllocatedAddress2{0}; std::string AOB1 = "8B 54 01 6C 8B 4F 24"; std::string AOB2 = "0F 11 02 0F 11 4A 10 44 0F 28 0D"; std::string shellcode1_hex = "c7 44 01 6c 00 00 7a 44 8b 54 01 6c 8b 4f 24 e9 00 00 00 00"; std::string shellcode2_hex = "c7 02 10 27 00 00 0f 11 4a 10 e9 00 00 00 00"; BYTE origBytes1[7] = {}; BYTE origBytes2[7] = {}; std::atomic<uintptr_t> InstructionAddress1{0}; std::atomic<uintptr_t> InstructionAddress2{0};}
namespace GameSpeed {  bool Enabled = false; std::string AOB = "00 5B 24 49 00 24 74 49 0A D7 23 3C 0A D7 23 3C 0A D7 23 3C 0A D7 23 3C 00 00 00 00 00 00 00 00 00 00 00"; std::atomic<uintptr_t> Address{0}; float FastValue = 9000.0f; float NormalValue = 673200.0f; bool WasKeyDown = false;}
namespace LobbyCrasher {  bool Enabled = false; std::string AOB = "C7 43 04 FF FF FF FF C6 03 01 48 83 C4 20 5B C3 48 8B"; BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; BYTE origBytes[7] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace GSize {  bool Enabled = false;  std::string AOB = "00 00 80 3F 80 F0 FA 02"; float Value = 0.0f; float inputVal = 0; std::atomic<uintptr_t> Address{0}; }
namespace Oxygen {  bool Enabled = false; std::string AOB = "0F 28 C8 E8 ? ? ? ? 0F B6 43 0C"; BYTE nops[] = { 0x90 ,0x90, 0x90 }; BYTE origBytes[3] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace InfSparrowBoost {  bool Enabled = false; std::string AOB = "72 34 48 8D 4B 50"; BYTE myByte[] = { 0x77 }; BYTE origByte[] = { 0x72 }; std::atomic<uintptr_t> InstructionAddress{0};}
namespace InfBuffTimers {  bool Enabled = false; std::string AOB = "48 89 8B A0 00 00 00 48 8D 4C 24 30 E8 ? ? ? ? 48 8B 08 48 39"; BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; BYTE origBytes[7] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace InfExoticBuffTimers {  bool Enabled = false; std::string AOB = "F3 0F 5C C7 F3 0F 5F C6 0F 2E"; BYTE nops[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}; BYTE origBytes[8] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace AntiFlinch {  bool Enabled = false;  std::string AOB1 = "F3 0F 11 8B E0 16 00 00"; std::string AOB2 = "F3 0F 11 8B E4 16 00 00"; std::string AOB3 = "F3 0F 11 83 E8 16 00 00"; BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; BYTE origBytes1[8] = {}; BYTE origBytes2[8] = {}; BYTE origBytes3[8] = {}; std::atomic<uintptr_t> InstructionAddress1{0}; std::atomic<uintptr_t> InstructionAddress2{0}; std::atomic<uintptr_t> InstructionAddress3{0};}
// ActivityLoader: New shellcode intends to mov RDX into the address pointed to by addrMemAllocatedAddress, then executes original instruction.
// mov rax, <addrMemAllocatedAddress_value> ; mov [rax], rdx ; movzx r9d, word ptr [rdx+2] (original instruction)
namespace ActivityLoader { bool Enabled = false; bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0}; std::atomic<uintptr_t> addrMemAllocatedAddress{0}; bool addr_mem_allocated = false; std::string AOB = "44 0F B7 4A 02 44"; std::string shellcode_hex = "48 B8 00 00 00 00 00 00 00 00 48 89 10 44 0F B7 4A 02"; BYTE origBytes[5] = {}; std::atomic<uintptr_t> InstructionAddress{0};}
namespace Mag999 { bool Enabled = false;  bool mem_allocated = false; std::atomic<uintptr_t> memAllocatedAddress{0};  std::string AOB = "0F 10 04 C1 48 83 C2 10 49"; std::string shellcode_hex = "50 B8 8A 49 FD 79 66 0F 6E D0 58 F3 0F 10 44 C1 B8 0F 2E C2 0F 85 16 00 00 00 50 B8 20 BC BE 4C 66 0F 6E D0 58 F3 0F 11 14 C1 F3 0F 11 54 C1 50 50 B8 02 03 02 34 66 0F 6E D0 58 F3 0F 10 44 C1 B8 0F 2E C2 0F 85 16 00 00 00 50 B8 20 BC BE 4C 66 0F 6E D0 58 F3 0F 11 14 C1 F3 0F 11 54 C1 10 0F 10 04 C1 48 83 C2 10 E9 00 00 00 00"; BYTE origBytes[8] = {}; std::atomic<uintptr_t> InstructionAddress{0};}


const SIZE_T DEFAULT_SCAN_REGION_SIZE = 0x7FFFFFF;
inline void PerformStartupAobScans(DWORD pid, uintptr_t moduleBaseAddress) {
    if (moduleBaseAddress == 0) {
        LogMessage("[-] PerformStartupAobScans: Invalid moduleBaseAddress (0).");
        return;
    }
    auto ScanAndLog = [&](const char* featureName, const std::string& aobPattern, std::atomic<uintptr_t>& instructionAddress_atomic) {
        uintptr_t found_addr = 0;
        NTSTATUS status = DriverComm::aob_scan_info(pid, moduleBaseAddress, DEFAULT_SCAN_REGION_SIZE, aobPattern.c_str(), "", found_addr);
        if(NT_SUCCESS(status) && found_addr != 0) {
            instructionAddress_atomic.store(found_addr);
        } else {
            instructionAddress_atomic.store(0);
            // LogMessageF("[-] PerformStartupAobScans: AOBScan failed for %s or not found. Status: 0x%lX", featureName, status); // Optional: log individual failures
        }
    };
    ScanAndLog("Killaura", Killaura::AOB, Killaura::InstructionAddress); ScanAndLog("LocalPlayer", LocalPlayer::AOB, LocalPlayer::InstructionAddress); ScanAndLog("LocalPlayer Disable Gravity", LocalPlayer::disableGravAOB, LocalPlayer::disableGravAddress); ScanAndLog("ViewAngles", ViewAngles::AOB, ViewAngles::InstructionAddress); ScanAndLog("Ghostmode", Ghostmode::AOB, Ghostmode::InstructionAddress); ScanAndLog("Godmode", Godmode::AOB, Godmode::InstructionAddress); ScanAndLog("InfAmmo", InfAmmo::AOB, InfAmmo::InstructionAddress); ScanAndLog("dmgMult", dmgMult::AOB, dmgMult::InstructionAddress); ScanAndLog("RPM", RPM::AOB, RPM::InstructionAddress); ScanAndLog("NoRecoil", NoRecoil::AOB, NoRecoil::InstructionAddress); ScanAndLog("OHK", OHK::AOB, OHK::InstructionAddress); ScanAndLog("NoJoinAllies", NoJoinAllies::AOB, NoJoinAllies::InstructionAddress); ScanAndLog("NoTurnBack", NoTurnBack::AOB, NoTurnBack::InstructionAddress); ScanAndLog("InfSwordAmmo", InfSwordAmmo::AOB, InfSwordAmmo::InstructionAddress); ScanAndLog("SparrowAnywhere", SparrowAnywhere::AOB, SparrowAnywhere::InstructionAddress); ScanAndLog("InfStacks", InfStacks::AOB, InfStacks::InstructionAddress); ScanAndLog("NoRezTokens", NoRezTokens::AOB, NoRezTokens::InstructionAddress); ScanAndLog("InstaRespawn", InstaRespawn::AOB, InstaRespawn::InstructionAddress); ScanAndLog("RespawnAnywhere", RespawnAnywhere::AOB, RespawnAnywhere::InstructionAddress); ScanAndLog("ShootThru", ShootThru::AOB, ShootThru::InstructionAddress); ScanAndLog("Chams", Chams::AOB, Chams::InstructionAddress); ScanAndLog("AbilityCharge", AbilityCharge::AOB, AbilityCharge::InstructionAddress); ScanAndLog("ImmuneAura", ImmuneAura::AOB, ImmuneAura::InstructionAddress); ScanAndLog("IcarusDash", IcarusDash::AOB, IcarusDash::InstructionAddress); ScanAndLog("InstantInteract", InstantInteract::AOB, InstantInteract::InstructionAddress); ScanAndLog("InteractThruWalls1", InteractThruWalls::AOB1, InteractThruWalls::InstructionAddress1); ScanAndLog("InteractThruWalls2", InteractThruWalls::AOB2, InteractThruWalls::InstructionAddress2); ScanAndLog("GameSpeed", GameSpeed::AOB, GameSpeed::Address); ScanAndLog("LobbyCrasher", LobbyCrasher::AOB, LobbyCrasher::InstructionAddress); ScanAndLog("GSize", GSize::AOB, GSize::Address); ScanAndLog("Oxygen", Oxygen::AOB, Oxygen::InstructionAddress); ScanAndLog("InfSparrowBoost", InfSparrowBoost::AOB, InfSparrowBoost::InstructionAddress); ScanAndLog("InfBuffTimers", InfBuffTimers::AOB, InfBuffTimers::InstructionAddress); ScanAndLog("InfExoticBuffTimers", InfExoticBuffTimers::AOB, InfExoticBuffTimers::InstructionAddress); ScanAndLog("AntiFlinch1", AntiFlinch::AOB1, AntiFlinch::InstructionAddress1); ScanAndLog("AntiFlinch2", AntiFlinch::AOB2, AntiFlinch::InstructionAddress2); ScanAndLog("AntiFlinch3", AntiFlinch::AOB3, AntiFlinch::InstructionAddress3); ScanAndLog("ActivityLoader", ActivityLoader::AOB, ActivityLoader::InstructionAddress); ScanAndLog("Mag999", Mag999::AOB, Mag999::InstructionAddress); ScanAndLog("FOV", FOV::AOB, FOV::ptr);
}

template<size_t N>
inline bool ReadOriginalBytes(std::atomic<uintptr_t>& address_atomic, BYTE(&origBytes_array)[N]) {
    uintptr_t address = address_atomic.load();
    if (address == 0) return false;
    return NT_SUCCESS(DriverComm::read_memory_buffer(address, origBytes_array, N, nullptr));
}

inline void PerformStartupByteReads(DWORD pid, uintptr_t moduleBaseAddress) {
    UNREFERENCED_PARAMETER(moduleBaseAddress); UNREFERENCED_PARAMETER(pid);
    // Using .load() for checking the address before calling ReadOriginalBytes
    if (Killaura::InstructionAddress.load() != 0) ReadOriginalBytes(Killaura::InstructionAddress, Killaura::origBytes);
    if (LocalPlayer::InstructionAddress.load() != 0) ReadOriginalBytes(LocalPlayer::InstructionAddress, LocalPlayer::origBytes);
    if (LocalPlayer::disableGravAddress.load() != 0) ReadOriginalBytes(LocalPlayer::disableGravAddress, LocalPlayer::disableGravOrigBytes);
    if (ViewAngles::InstructionAddress.load() != 0) ReadOriginalBytes(ViewAngles::InstructionAddress, ViewAngles::origBytes);
    if (Ghostmode::InstructionAddress.load() != 0) ReadOriginalBytes(Ghostmode::InstructionAddress, Ghostmode::origBytes);
    if (Godmode::InstructionAddress.load() != 0) ReadOriginalBytes(Godmode::InstructionAddress, Godmode::origBytes);
    if (InfAmmo::InstructionAddress.load() != 0) ReadOriginalBytes(InfAmmo::InstructionAddress, InfAmmo::origBytes);
    if (dmgMult::InstructionAddress.load() != 0) ReadOriginalBytes(dmgMult::InstructionAddress, dmgMult::origBytes);
    if (RPM::InstructionAddress.load() != 0) ReadOriginalBytes(RPM::InstructionAddress, RPM::origBytes);
    if (NoRecoil::InstructionAddress.load() != 0) ReadOriginalBytes(NoRecoil::InstructionAddress, NoRecoil::origBytes);
    if (OHK::InstructionAddress.load() != 0) ReadOriginalBytes(OHK::InstructionAddress, OHK::origBytes);
    if (NoJoinAllies::InstructionAddress.load() != 0) ReadOriginalBytes(NoJoinAllies::InstructionAddress, NoJoinAllies::origBytes);
    if (NoTurnBack::InstructionAddress.load() != 0) ReadOriginalBytes(NoTurnBack::InstructionAddress, NoTurnBack::origBytes);
    if (InfSwordAmmo::InstructionAddress.load() != 0) ReadOriginalBytes(InfSwordAmmo::InstructionAddress, InfSwordAmmo::origBytes);
    if (SparrowAnywhere::InstructionAddress.load() != 0) ReadOriginalBytes(SparrowAnywhere::InstructionAddress, SparrowAnywhere::origByte);
    if (InfStacks::InstructionAddress.load() != 0) ReadOriginalBytes(InfStacks::InstructionAddress, InfStacks::origBytes);
    if (NoRezTokens::InstructionAddress.load() != 0) ReadOriginalBytes(NoRezTokens::InstructionAddress, NoRezTokens::origByte);
    if (InstaRespawn::InstructionAddress.load() != 0) ReadOriginalBytes(InstaRespawn::InstructionAddress, InstaRespawn::origBytes);
    if (RespawnAnywhere::InstructionAddress.load() != 0) ReadOriginalBytes(RespawnAnywhere::InstructionAddress, RespawnAnywhere::origBytes);
    if (ShootThru::InstructionAddress.load() != 0) ReadOriginalBytes(ShootThru::InstructionAddress, ShootThru::origBytes);
    if (Chams::InstructionAddress.load() != 0) ReadOriginalBytes(Chams::InstructionAddress, Chams::origBytes);
    if (AbilityCharge::InstructionAddress.load() != 0) ReadOriginalBytes(AbilityCharge::InstructionAddress, AbilityCharge::origBytes);
    if (ImmuneAura::InstructionAddress.load() != 0) ReadOriginalBytes(ImmuneAura::InstructionAddress, ImmuneAura::origBytes);
    if (IcarusDash::InstructionAddress.load() != 0) ReadOriginalBytes(IcarusDash::InstructionAddress, IcarusDash::origBytes);
    if (InstantInteract::InstructionAddress.load() != 0) ReadOriginalBytes(InstantInteract::InstructionAddress, InstantInteract::origBytes);
    if (InteractThruWalls::InstructionAddress1.load() != 0) ReadOriginalBytes(InteractThruWalls::InstructionAddress1, InteractThruWalls::origBytes1);
    if (InteractThruWalls::InstructionAddress2.load() != 0) ReadOriginalBytes(InteractThruWalls::InstructionAddress2, InteractThruWalls::origBytes2);
    if (LobbyCrasher::InstructionAddress.load() != 0) ReadOriginalBytes(LobbyCrasher::InstructionAddress, LobbyCrasher::origBytes);
    if (Oxygen::InstructionAddress.load() != 0) ReadOriginalBytes(Oxygen::InstructionAddress, Oxygen::origBytes);
    if (InfSparrowBoost::InstructionAddress.load() != 0) ReadOriginalBytes(InfSparrowBoost::InstructionAddress, InfSparrowBoost::origByte);
    if (InfBuffTimers::InstructionAddress.load() != 0) ReadOriginalBytes(InfBuffTimers::InstructionAddress, InfBuffTimers::origBytes);
    if (InfExoticBuffTimers::InstructionAddress.load() != 0) ReadOriginalBytes(InfExoticBuffTimers::InstructionAddress, InfExoticBuffTimers::origBytes);
    if (AntiFlinch::InstructionAddress1.load() != 0) ReadOriginalBytes(AntiFlinch::InstructionAddress1, AntiFlinch::origBytes1);
    if (AntiFlinch::InstructionAddress2.load() != 0) ReadOriginalBytes(AntiFlinch::InstructionAddress2, AntiFlinch::origBytes2);
    if (AntiFlinch::InstructionAddress3.load() != 0) ReadOriginalBytes(AntiFlinch::InstructionAddress3, AntiFlinch::origBytes3);
    if (ActivityLoader::InstructionAddress.load() != 0) ReadOriginalBytes(ActivityLoader::InstructionAddress, ActivityLoader::origBytes);
    if (Mag999::InstructionAddress.load() != 0) ReadOriginalBytes(Mag999::InstructionAddress, Mag999::origBytes);
}


// Hook enabling functions
inline bool EnableLocalPlayerHook(DWORD pid) {
    using namespace LocalPlayer;
    if (InstructionAddress == 0) { LogMessage("[-] EnableLocalPlayerHook: InstructionAddress is 0."); return false; }
    // addrMemAllocatedAddress should be allocated by UpdateFeatureStates when LocalPlayer::Enabled is true.
    if (addrMemAllocatedAddress == 0) { LogMessage("[-] EnableLocalPlayerHook: LocalPlayer::addrMemAllocatedAddress is 0. This should be allocated before enabling the hook."); return false; }

    std::vector<BYTE> scBytes = HexToBytes(shellcode_hex);
    if (scBytes.empty() || scBytes.size() < (6 + sizeof(uintptr_t)) ) {
        LogMessage("[-] EnableLocalPlayerHook: Shellcode invalid or too short for address patch."); return false;
    }
    memcpy(&scBytes[6], &addrMemAllocatedAddress, sizeof(uintptr_t)); // Patch in the address

    // Use LocalPlayer::mem_allocated to track codecave allocation for this specific hook
    if (!LocalPlayer::mem_allocated) {
        if(!DriverComm::allocate_memory(pid, scBytes.size() + 32, LocalPlayer::memAllocatedAddress, reinterpret_cast<PVOID>(InstructionAddress))) {
             LogMessage("[-] EnableLocalPlayerHook: Failed to allocate cave for main shellcode."); return false;
        }
        LocalPlayer::mem_allocated = true; // Mark that this feature's codecave is allocated
    }
    if (!InjectCodecave(pid, InstructionAddress, scBytes, sizeof(origBytes), LocalPlayer::memAllocatedAddress)) {
        LogMessage("[-] EnableLocalPlayerHook: InjectCodecave failed.");
        return false;
    }
    return true;
}

inline bool EnableViewAngleHook(DWORD pid) {
    using namespace ViewAngles;
    if (InstructionAddress == 0) { LogMessage("[-] EnableViewAngleHook: InstructionAddress is 0."); return false; }
    if (addrMemAllocatedAddress == 0) { LogMessage("[-] EnableViewAngleHook: ViewAngles::addrMemAllocatedAddress is 0. Allocate first."); return false; }

    std::vector<BYTE> scBytes = HexToBytes(shellcode_hex);
     if (scBytes.empty() || scBytes.size() < (6 + sizeof(uintptr_t))) {
        LogMessage("[-] EnableViewAngleHook: Shellcode invalid or too short for address patch."); return false;
    }
    memcpy(&scBytes[6], &addrMemAllocatedAddress, sizeof(uintptr_t)); // Patch in the address

    if (!ViewAngles::mem_allocated) {
        if(!DriverComm::allocate_memory(pid, scBytes.size() + 32, ViewAngles::memAllocatedAddress, reinterpret_cast<PVOID>(InstructionAddress))) {
             LogMessage("[-] EnableViewAngleHook: Failed to allocate cave for main shellcode."); return false;
        }
        ViewAngles::mem_allocated = true;
    }
    if (!InjectCodecave(pid, InstructionAddress, scBytes, sizeof(origBytes), ViewAngles::memAllocatedAddress)) {
         LogMessage("[-] EnableViewAngleHook: InjectCodecave failed.");
        return false;
    }
    return true;
}

inline bool EnableInfiniteAmmo(DWORD pid) {
    using namespace InfAmmo;
    if (InstructionAddress == 0) { LogMessage("[-] EnableInfiniteAmmo: InstructionAddress is 0."); return false; }
    std::vector<BYTE> scBytes = HexToBytes(shellcode_hex);
    if (scBytes.empty()){ LogMessage("[-] EnableInfiniteAmmo: shellcode_hex is invalid."); return false; }

    if (!InfAmmo::mem_allocated) { // Use namespace specific mem_allocated
        if(!DriverComm::allocate_memory(pid, scBytes.size() + 20, InfAmmo::memAllocatedAddress, reinterpret_cast<PVOID>(InstructionAddress))) {
            LogMessage("[-] EnableInfiniteAmmo: Failed to allocate cave."); return false;
        }
        InfAmmo::mem_allocated = true;
    }
    if (!InjectCodecave(pid, InstructionAddress, scBytes, sizeof(origBytes), InfAmmo::memAllocatedAddress)) {
        LogMessage("[-] EnableInfiniteAmmo: InjectCodecave failed.");
        DriverComm::write_memory_buffer(InstructionAddress, origBytes, sizeof(origBytes));
        return false;
    }
    return true;
}

inline bool EnableActivityLoaderHook(DWORD pid) {
    using namespace ActivityLoader;
    if (InstructionAddress == 0) {
        LogMessage("[-] EnableActivityLoaderHook: InstructionAddress is 0.");
        return false;
    }

    std::vector<BYTE> scBytes = HexToBytes(shellcode_hex);
    if (scBytes.empty()){
        LogMessage("[-] EnableActivityLoaderHook: shellcode_hex is invalid or resulted in empty byte vector.");
        return false;
    }

    // Ensure ActivityLoader::addrMemAllocatedAddress is valid
    if (ActivityLoader::addrMemAllocatedAddress == 0) {
        if (!DriverComm::allocate_memory(pid, sizeof(uintptr_t), ActivityLoader::addrMemAllocatedAddress, nullptr)) {
            LogMessage("[-] EnableActivityLoaderHook: Failed to allocate memory for address storage (addrMemAllocatedAddress).");
            ActivityLoader::addr_mem_allocated = false; // Explicitly set false on failure
            // ActivityLoader::Enabled = false; // State managed by UpdateFeatureStates
            return false;
        }
        ActivityLoader::addr_mem_allocated = true; // Set true on successful allocation
        #ifdef _DEBUG
        std::cout << "[+] EnableActivityLoaderHook: Allocated addrMemAllocatedAddress at 0x" << std::hex << ActivityLoader::addrMemAllocatedAddress.load() << std::dec << ". addr_mem_allocated set to true." << std::endl;
        #endif
    } else {
        // If address is already non-zero, assume it was allocated and set flag accordingly.
        // This handles cases where the hook might be re-enabled without full cleanup.
        ActivityLoader::addr_mem_allocated = true;
         #ifdef _DEBUG
        std::cout << "[+] EnableActivityLoaderHook: addrMemAllocatedAddress was already set to 0x" << std::hex << ActivityLoader::addrMemAllocatedAddress.load() << std::dec << ". Ensuring addr_mem_allocated is true." << std::endl;
        #endif
    }

    // Patch scBytes with ActivityLoader::addrMemAllocatedAddress
    // Shellcode: "48 B8 <8_byte_addr> 48 89 10 44 0F B7 4A 02"
    // Placeholder for address starts at index 2.
    if (scBytes.size() < 10) { // Minimum size for "48 B8" + 8-byte address
        LogMessageF("[-] EnableActivityLoaderHook: Shellcode too short for patching address. Size: %zu", scBytes.size());
        return false;
    }
    memcpy(&scBytes[2], &ActivityLoader::addrMemAllocatedAddress, sizeof(uintptr_t));

    // Codecave Allocation for Shellcode (if not already done by UpdateFeatureStates - this function might be called directly in some scenarios)
    // Note: UpdateFeatureStates now handles the primary allocation logic for mem_allocated features.
    // This function should ensure the cave exists if it's supposed to be used.
    // For robustness, if mem_allocated is false, attempt allocation.
    if (!ActivityLoader::mem_allocated) {
        if (!DriverComm::allocate_memory(pid, scBytes.size() + 32, ActivityLoader::memAllocatedAddress, reinterpret_cast<PVOID>(InstructionAddress))) {
            LogMessage("[-] EnableActivityLoaderHook: Failed to allocate cave for shellcode.");
            // ActivityLoader::Enabled = false; // State managed by UpdateFeatureStates
            return false;
        }
        // IMPORTANT: Do NOT set ActivityLoader::mem_allocated = true here.
        // This flag is managed by UpdateFeatureStates to indicate a *fully successful* hook placement.
        // This function's role is to prepare and attempt the injection.
        #ifdef _DEBUG
        std::cout << "[+] EnableActivityLoaderHook: Codecave for shellcode allocated by EnableActivityLoaderHook at 0x" << std::hex << ActivityLoader::memAllocatedAddress << std::dec << " (mem_allocated will be set by caller on InjectCodecave success)" << std::endl;
        #endif
    }

    // Call InjectCodecave
    // The last parameter to InjectCodecave (added in a previous refactor for ActivityLoader in Drawing.cpp)
    // is not part of the standard InjectCodecave signature used elsewhere.
    // The standard InjectCodecave takes 5 parameters.
    // If ActivityLoader's shellcode itself *needs* addrMemAllocatedAddress at runtime (e.g. for RIP-relative addressing within the shellcode),
    // then InjectCodecave would need modification, or the shellcode needs to be constructed differently.
    // The current shellcode "48 B8 <addr> 48 89 10 ..." directly uses the patched-in absolute address.
    // So, the standard 5-parameter InjectCodecave is appropriate here.
    if (!InjectCodecave(pid, InstructionAddress, scBytes, sizeof(origBytes), ActivityLoader::memAllocatedAddress)) {
         LogMessage("[-] EnableActivityLoaderHook: InjectCodecave failed.");
         // Attempt to restore original bytes if hook failed. InjectCodecave might not do this if cave allocation succeeded but hook write failed.
         // DriverComm::write_memory_buffer(InstructionAddress, origBytes, sizeof(origBytes)); // Consider if InjectCodecave's failure requires manual restoration here.
        return false;
    }
    ActivityLoader::mem_allocated = true; // Set flag only on full success of InjectCodecave
    // ActivityLoader::Enabled = true; // State is managed by UpdateFeatureStates based on this function's return
    return true;
}

#endif // FEATURES_H_GUARD
