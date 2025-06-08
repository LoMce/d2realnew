#include "Drawing.h"
#include <ctime>
#include <string>
#include <cmath>
#include <chrono>
#include <thread>
#include "DriverComm.h"
#include <algorithm>  // for std::copy_n
#include <iterator>   // for std::begin / std::size

#include <iostream> // Will be removed if all stdio is replaced by Logging
#include "Logging.h" // Added for logging functions

#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>
#include <string.h>
#include <cwchar>
#include <cstdint>
#include <vector>
#include "Features.h"
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <ShlObj.h>
#include "themes.h"
#include "imgui/imgui_custom.h"
#include "TPManager.h"
#include "fonts/font_globals.h"

#include <iomanip>



// Global instruction toggles
// Note: pid and moduleBaseAddress are now global to Drawing.cpp, set during initialization in Drawing::Draw
static DWORD g_current_pid_drawing = 0;
static uintptr_t g_moduleBaseAddress_drawing = 0;

static bool wasKillauraEnabled = false;
static bool wasViewAnglesEnabled = false;
static bool wasLocalPlayerEnabled = false;
static bool wasGhostmodeEnabled = false;
static bool wasGodmodeEnabled = false;
static bool wasInfAmmoEnabled = false;
static bool wasDmgMultEnabled = false;
static bool wasFOVEnabled = false;
static bool wasRPMEnabled = false;
static bool wasNoRecoilEnabled = false;
static bool wasOHKEnabled = false;
static bool wasNoJoiningAlliesEnabled = false;
static bool wasNoTurnBackEnabled = false;
static bool wasSparrowAnywhereEnabled = false;
static bool wasInfStacksEnabled = false;
static bool wasNoRezTokensEnabled = false;
static bool wasInstaRespawnEnabled = false;
static bool wasShootThruWallsEnabled = false;
static bool wasChamsEnabled = false;
static bool wasImmuneBossesEnabled = false;
static bool wasAbilityChargeEnabled = false;
static bool wasImmuneAuraEnabled = false;
static bool wasIcarusDashEnabled = false;
static bool wasInstantInteractEnabled = false;
static bool wasLobbyCrasherEnabled = false;
static bool wasGSizeEnabled = false;
static bool wasOxygenEnabled = false;
static bool wasInfSparrowBoostEnabled = false;
static bool wasInteractThruWallsEnabled = false;
static bool wasAntiFlinchEnabled = false;
static bool wasInfBuffTimersEnabled = false;
static bool wasMag999Enabled = false;
static bool wasInfExoticBuffTimersEnabled = false;
static bool wasActivityLoaderEnabled = false;

// at top of Drawing.cpp
// static bool wasFlyEnabled = false; // Removed
static bool wasFlyKeyDown = false;
uintptr_t moduleBaseAddress = 0; // This seems unused if g_moduleBaseAddress_drawing is primary.

// Global std::thread object for ImmuneBosses feature (declaration already exists if it's global)
// If not, it should be declared here or where Drawing class members are.
// Assuming it's already declared globally as: std::thread ImmuneBossesThread;

// Actual implementation for the ImmuneBossesThread function logic
void ActualImmuneBossesThreadLogic(DWORD pid_param) { // pid_param is passed but g_current_pid_drawing is used by DriverComm
    ImmuneBosses::ThreadRunning.store(true);

    uintptr_t moduleBaseAddress = g_moduleBaseAddress_drawing;

    if (moduleBaseAddress == 0) {
        #ifdef _DEBUG
        LogMessage("[-] [ActualImmuneBossesThreadLogic] Module base address is 0. Cannot perform AOB scan.");
        #endif
        ImmuneBosses::Address = 0;
        ImmuneBosses::Enabled = false;
        ImmuneBosses::ThreadRunning.store(false);
        return;
    }

    std::string boss_health_aob = "F3 0F 5A C0 F3 0F 11 41 ??"; // AOB pattern for boss health
    #ifdef _DEBUG
    LogMessageF("[+] [ActualImmuneBossesThreadLogic] Scanning for Boss Health AOB: %s", boss_health_aob.c_str());
    #endif
    // Ensure DEFAULT_SCAN_REGION_SIZE is accessible. It's defined in Features.h
    uintptr_t found_addr = DriverComm::AOBScan(moduleBaseAddress, DEFAULT_SCAN_REGION_SIZE, boss_health_aob.c_str(), "");

    if (found_addr != 0) {
        ImmuneBosses::Address = found_addr;
        float zero_val = 0.0f;
        #ifdef _DEBUG
        LogMessageF("[+] [ActualImmuneBossesThreadLogic] Boss Health AOB found at 0x%llX. Attempting to write %f.", found_addr, zero_val);
        #endif
        if (DriverComm::write_memory(found_addr, zero_val)) {
            #ifdef _DEBUG
            LogMessageF("[+] [ActualImmuneBossesThreadLogic] Patched successfully at 0x%llX.", found_addr);
            #endif
        } else {
            #ifdef _DEBUG
            LogMessageF("[-] [ActualImmuneBossesThreadLogic] Failed to write to address 0x%llX.", found_addr);
            #endif
            ImmuneBosses::Address = 0;
            ImmuneBosses::Enabled = false; // Disable if write failed
        }
    } else {
        #ifdef _DEBUG
        LogMessage("[-] [ActualImmuneBossesThreadLogic] Boss health AOB not found.");
        #endif
        ImmuneBosses::Address = 0;
        ImmuneBosses::Enabled = false; // Disable if AOB scan failed
    }

    ImmuneBosses::ThreadRunning.store(false);
    #ifdef _DEBUG
    LogMessage("[+] [ActualImmuneBossesThreadLogic] Thread finished.");
    #endif
}


inline void LimitFPS(double targetFPS = 90.0)
{
    using namespace std::chrono;
    static auto lastTime = high_resolution_clock::now();
    constexpr microseconds spinThreshold{ 2000 }; // 2 ms spin-wait threshold

    // how long each frame should take
    const auto frameDuration = microseconds(static_cast<long long>(1e6 / targetFPS));

    auto now = high_resolution_clock::now();
    auto elapsed = duration_cast<microseconds>(now - lastTime);

    if (elapsed < frameDuration)
    {
        auto toSleep = frameDuration - elapsed;
        // sleep for most of the remaining time...
        if (toSleep > spinThreshold)
            std::this_thread::sleep_for(toSleep - spinThreshold);
        // …then spin-wait the rest
        while (duration_cast<microseconds>(high_resolution_clock::now() - lastTime) < frameDuration)
            std::this_thread::yield();
    }

    lastTime = high_resolution_clock::now();
}

// Uses DriverComm::g_pid implicitly via DriverComm calls, and g_moduleBaseAddress_drawing
void PollFly() { // Removed HANDLE driver, DWORD pid parameters. uintptr_t destinyBase is now g_moduleBaseAddress_drawing + LocalPlayer::destinyBase
    static bool previousFlyState = false; // Added
    uintptr_t destinyBaseForFly = g_moduleBaseAddress_drawing + LocalPlayer::destinyBase;

    bool flyKeyDown = (GetAsyncKeyState(Hotkeys["FlyToggle"]) & 0x8000) != 0;
    if (flyKeyDown && !wasFlyKeyDown && LocalPlayer::Enabled) {
        Features::LocalPlayer::flyEnabled = !Features::LocalPlayer::flyEnabled;
        #ifdef _DEBUG
        LogMessageF("[+] [PollFly] Fly Toggled: %s", (Features::LocalPlayer::flyEnabled ? "ON" : "OFF"));
        #endif
    }
    wasFlyKeyDown = flyKeyDown;

    if (Features::LocalPlayer::flyEnabled && !previousFlyState) { // Just enabled Fly
        if (LocalPlayer::disableGravAddress != 0) {
            std::vector<BYTE> disableGravShellcodeBytes = HexToBytes(LocalPlayer::disableGravShellcode_hex);
            uintptr_t temp_cave_addr_grav = LocalPlayer::disableGravMemAllocatedAddress; // Pass existing or 0
            if(!Features::InjectCodecave(g_current_pid_drawing, LocalPlayer::disableGravAddress, disableGravShellcodeBytes, sizeof(LocalPlayer::disableGravOrigBytes), temp_cave_addr_grav)) {
                 LogMessageF("[-] [PollFly] Failed to inject disableGravShellcode at 0x%llX.", LocalPlayer::disableGravAddress);
                 Features::LocalPlayer::flyEnabled = false;
            } else {
                LocalPlayer::disableGravMemAllocatedAddress = temp_cave_addr_grav; // Update if allocated
                LocalPlayer::disableGrav_mem_allocated = true;
                #ifdef _DEBUG
                LogMessageF("[+] [PollFly] Gravity modification (fly) enabled. Cave: 0x%llX.", temp_cave_addr_grav);
                #endif
            }
        } else {
            LogMessage("[-] [PollFly] disableGravAddress is 0, cannot enable fly's gravity modification.");
            Features::LocalPlayer::flyEnabled = false;
        }

        if (Features::LocalPlayer::flyEnabled) {
            StopFlyThread = false;
            if (FlyThread.joinable()) FlyThread.join();
            FlyThread = std::thread(FlyLoop, destinyBaseForFly);
            FlyThread.detach();
            #ifdef _DEBUG
            LogMessage("[+] [PollFly] FlyLoop thread started.");
            #endif
        }
    } else if (!Features::LocalPlayer::flyEnabled && previousFlyState) { // Just disabled Fly
        StopFlyThread = true;
        if (LocalPlayer::disableGravAddress != 0 && LocalPlayer::disableGrav_mem_allocated) {
            if(DriverComm::write_memory_buffer(LocalPlayer::disableGravAddress, LocalPlayer::disableGravOrigBytes, sizeof(LocalPlayer::disableGravOrigBytes))){
                #ifdef _DEBUG
                LogMessageF("[-] [PollFly] Restored original bytes for disable gravity at 0x%llX.", LocalPlayer::disableGravAddress);
                #endif
            } else {
                LogMessageF("[-] [PollFly] Failed to restore original bytes for disable gravity at 0x%llX.", LocalPlayer::disableGravAddress);
            }
            // LocalPlayer::disableGrav_mem_allocated remains true as cave can be reused.
        }
        if (FlyThread.joinable()) {
            FlyThread.join();
            #ifdef _DEBUG
            LogMessage("[+] [PollFly] FlyThread joined on disable.");
            #endif
        }
        #ifdef _DEBUG
        LogMessage("[-] [PollFly] FlyLoop thread signaled to stop and joined."); // Adjusted log
        #endif
    }
    previousFlyState = Features::LocalPlayer::flyEnabled;
}

void PollKillKey() {
    if (!LocalPlayer::Enabled || !LocalPlayer::KillKeyEnabled || LocalPlayer::realPlayer.load() == 0 || DriverComm::g_pid == 0)
        return;

    bool keyNowDown = GetAsyncKeyState(Hotkeys["SuicideKey"]) & 0x8000;

    if (keyNowDown && !LocalPlayer::KillKeyWasDown) {
        uintptr_t playerBase = LocalPlayer::realPlayer.load();
        if (playerBase == 0) {
             #ifdef _DEBUG
             LogMessage("[-] [PollKillKey] playerBase is 0. Cannot perform action.");
             #endif
            return;
        }
        DriverComm::write_memory(playerBase + TPManager::POS_X, -10000.0f);
        DriverComm::write_memory(playerBase + TPManager::POS_Y, -10000.0f);
        DriverComm::write_memory(playerBase + TPManager::VEL_X, 10.0f);
        DriverComm::write_memory(playerBase + TPManager::VEL_Y, 10.0f);
        DriverComm::write_memory(playerBase + TPManager::VEL_Z, 10.0f);
        #ifdef _DEBUG
        LogMessageF("[+] [PollKillKey] Suicide action performed on player at 0x%llX.", playerBase);
        #endif
    }
    LocalPlayer::KillKeyWasDown = keyNowDown;
}

void RenderKillKeyUI() { // No changes needed here as it's UI and hotkey logic
    // 1) Ensure we have a default binding
    if (Hotkeys["SuicideKey"] == 0)
        Hotkeys["SuicideKey"] = LocalPlayer::KillKey;         // Default VK_J

    ImGui::BeginDisabled(!LocalPlayer::Enabled);

    // 2) Checkbox + picker on one line
    ImGui::Toggle("Suicide Key", &LocalPlayer::KillKeyEnabled);
    ImGui::SameLine();
    static bool listening = false;
    DrawHotkeyPicker("SuicideKey", "Key", listening);         // auto-saves to hotkeys.json

    ImGui::EndDisabled();
}

void RenderAbilityChargeUI() {
    // 1. Ensure we have a default binding
    if (Hotkeys["AbilityCharge"] == 0)
        Hotkeys["AbilityCharge"] = VK_5;

    // 2. Checkbox + picker on one line
    ImGui::Toggle("Ability", &AbilityCharge::Enabled);
    ImGui::SameLine();
    static bool listening = false;
    DrawHotkeyPicker("Ability", "Key", listening);
}

// Polls once per frame to inject/restore based on key-hold
void PollAbilityCharge() {
    static bool wasInjected = false; // Tracks if the hook is currently active from this poll function
    static bool currentKeyIsDown = false;
    // Note: AbilityCharge::memAllocatedAddress is used by InjectCodecave.
    // AbilityCharge::Enabled is the global toggle for this hotkey feature.

    int vk = Hotkeys["AbilityCharge"];
    if (vk == 0 || vk == -1) return;

    if (!AbilityCharge::Enabled) { // Global toggle for the hotkey functionality
        if (wasInjected && AbilityCharge::InstructionAddress != 0) {
            if (DriverComm::write_memory_buffer(AbilityCharge::InstructionAddress, AbilityCharge::origBytes, sizeof(AbilityCharge::origBytes))) {
                #ifdef _DEBUG
                LogMessageF("[-] [PollAbilityCharge] Feature disabled globally or key released - original bytes restored at 0x%llX.", AbilityCharge::InstructionAddress);
                #endif
            } else {
                LogMessageF("[-] [PollAbilityCharge] Failed to restore original bytes on global disable for 0x%llX.", AbilityCharge::InstructionAddress);
            }
            wasInjected = false;
        }
        currentKeyIsDown = false; // Reset key state if feature is globally disabled
        return;
    }

    bool keyNowDown = (GetAsyncKeyState(vk) & 0x8000) != 0;

    if (keyNowDown && !currentKeyIsDown) { // Key just pressed
        if (AbilityCharge::InstructionAddress != 0) {
            // AbilityCharge::shellcode is std::vector<BYTE>
            // AbilityCharge::memAllocatedAddress will be used/allocated by InjectCodecave
            uintptr_t temp_cave_addr = AbilityCharge::memAllocatedAddress; // InjectCodecave expects this by ref
            if(Features::InjectCodecave(g_current_pid_drawing, AbilityCharge::InstructionAddress, AbilityCharge::shellcode, sizeof(AbilityCharge::origBytes), temp_cave_addr)){
                AbilityCharge::memAllocatedAddress = temp_cave_addr; // Update if InjectCodecave allocated it
                wasInjected = true;
                #ifdef _DEBUG
                LogMessageF("[+] [PollAbilityCharge] Activated (hooked) at 0x%llX. Codecave: 0x%llX.", AbilityCharge::InstructionAddress, temp_cave_addr);
                #endif
            } else {
                LogMessageF("[-] [PollAbilityCharge] InjectCodecave failed for 0x%llX.", AbilityCharge::InstructionAddress);
            }
        } else {
            LogMessage("[-] [PollAbilityCharge] InstructionAddress is 0. Cannot activate.");
        }
    } else if (!keyNowDown && currentKeyIsDown) { // Key just released
        if (wasInjected && AbilityCharge::InstructionAddress != 0) {
            if (DriverComm::write_memory_buffer(AbilityCharge::InstructionAddress, AbilityCharge::origBytes, sizeof(AbilityCharge::origBytes))) {
                #ifdef _DEBUG
                LogMessageF("[-] [PollAbilityCharge] Deactivated (original bytes restored) at 0x%llX.", AbilityCharge::InstructionAddress);
                #endif
            } else {
                 LogMessageF("[-] [PollAbilityCharge] Failed to restore original bytes on key release for 0x%llX.", AbilityCharge::InstructionAddress);
            }
            wasInjected = false;
        } else if (wasInjected) { // Address is 0 but was injected (should not happen if initial check is done)
            LogMessage("[-] [PollAbilityCharge] InstructionAddress is 0 on key release but was previously injected. Cannot restore bytes.");
            wasInjected = false; // Still mark as not injected
        }
    }
    currentKeyIsDown = keyNowDown;
}

void RenderImmuneBossesUI(DWORD pid_param) { // Added pid_param for consistency, though thread uses global
    bool state = ImmuneBosses::Enabled.load();
    if (ImGui::Toggle("Immune Bosses (Scan)", &state)) {
        ImmuneBosses::Enabled.store(state);
    }
    if (ImmuneBosses::ThreadRunning.load() && ImmuneBosses::Address == 0) {
        ImGui::TextDisabled("Scanning memory...");
    } else if (ImmuneBosses::Enabled.load() && ImmuneBosses::Address != 0){
         ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Active @ 0x%p", (void*)ImmuneBosses::Address);
    }
}

void PollImmuneBosses() { // Removed HANDLE driver, DWORD pid
    bool nowEnabled = ImmuneBosses::Enabled.load();
    if (nowEnabled && !wasImmuneBossesEnabled && !ImmuneBosses::ThreadRunning.load()) {
        ImmuneBosses::Address = 0; // Reset address before starting new scan
        if(ImmuneBossesThread.joinable()) ImmuneBossesThread.join();
        ImmuneBossesThread = std::thread(ActualImmuneBossesThreadLogic, g_current_pid_drawing);
        ImmuneBossesThread.detach();
        #ifdef _DEBUG
        LogMessage("[+] [PollImmuneBosses] Started ActualImmuneBossesThreadLogic due to feature enable.");
        #endif
    } else if (!nowEnabled && wasImmuneBossesEnabled) {
        if (ImmuneBosses::Address != 0) { // Only attempt to restore if an address was found and patched
            float one = 1.0f;
            if (DriverComm::write_memory(ImmuneBosses::Address, one)) {
                #ifdef _DEBUG
                LogMessageF("[-] [PollImmuneBosses] Immune Bosses restored to 1.0f at 0x%llX.", ImmuneBosses::Address);
                #endif
            } else {
                LogMessageF("[-] [PollImmuneBosses] Failed to restore Immune Bosses value at 0x%llX.", ImmuneBosses::Address);
            }
            ImmuneBosses::Address = 0; // Clear address after restoring
        } else {
            #ifdef _DEBUG
            LogMessage("[-] [PollImmuneBosses] Feature disabled, but no valid address was set. No restoration needed.");
            #endif
        }
        // Ensure the thread is signaled to stop if it was running.
        // ActualImmuneBossesThreadLogic sets ThreadRunning to false on completion.
        if (ImmuneBossesThread.joinable()) {
            ImmuneBossesThread.join();
            #ifdef _DEBUG
            LogMessage("[+] [PollImmuneBosses] ImmuneBossesThread joined on disable.");
            #endif
        }
    }
    wasImmuneBossesEnabled = nowEnabled;
}

void RenderGameSpeedUI() {
    SetHotkeyDefault("GameSpeed", VK_CAPITAL);
    ImGui::Toggle("GameSpeed Key", &GameSpeed::Enabled);
    ImGui::SameLine();
    static bool listening = false;
    DrawHotkeyPicker("GameSpeed", "", listening);
}

void PollGameSpeed() {
    if (!GameSpeed::Enabled) { // If globally disabled, ensure key state doesn't linger
        if (GameSpeed::WasKeyDown && GameSpeed::Address != 0) { // If it was active and key was down
             if (!DriverComm::write_memory(GameSpeed::Address, GameSpeed::NormalValue)) {
                LogMessageF("[-] [PollGameSpeed] Write failed for restoring GameSpeed::NormalValue at 0x%llX on global disable.", GameSpeed::Address);
            } else {
                #ifdef _DEBUG
                LogMessageF("[-] [PollGameSpeed] Restored GameSpeed to NormalValue due to global disable. Address: 0x%llX.", GameSpeed::Address);
                #endif
            }
            GameSpeed::WasKeyDown = false; // Reset key state
        }
        return;
    }

    if (GameSpeed::Address == 0) {
        #ifdef _DEBUG
        // This might be spammy if AOB not found yet, only log if explicitly enabled and address is 0
        // static bool initialLogDone = false; if (!initialLogDone && GameSpeed::Enabled) { std::cout << "[-] [PollGameSpeed] GameSpeed::Address is 0. Feature active but cannot modify speed." << std::endl; initialLogDone = true; }
        #endif
        return;
    }

    int vk = Hotkeys["GameSpeed"];
    if (vk == 0 || vk == -1) return;

    bool isDown = (GetAsyncKeyState(vk) & 0x8000) != 0;
    if (isDown != GameSpeed::WasKeyDown) {
        float valueToSet = isDown ? GameSpeed::FastValue : GameSpeed::NormalValue;
        const char* speedState = isDown ? "FastValue" : "NormalValue";
        if (!DriverComm::write_memory(GameSpeed::Address, valueToSet)) {
            LogMessageF("[-] [PollGameSpeed] Write failed for GameSpeed::%s at 0x%llX.", speedState, GameSpeed::Address);
        } else {
            #ifdef _DEBUG
            LogMessageF("[+] [PollGameSpeed] Set to %s (%f) at 0x%llX.", speedState, valueToSet, GameSpeed::Address);
            #endif
        }
        GameSpeed::WasKeyDown = isDown;
    }
}

void DisableViewAngleHook() { // Removed HANDLE driver
    ViewAngles::g_cacheThreadRunning = false;
    if (ViewAngles::InstructionAddress != 0 && ViewAngles::mem_allocated) {
        DriverComm::write_memory_buffer(ViewAngles::InstructionAddress, ViewAngles::origBytes, sizeof(ViewAngles::origBytes));
        #ifdef _DEBUG
        LogMessage("[+] DisableViewAngleHook: Original bytes restored.");
        #endif
    }
}

void UpdateFeatureStates(DWORD pid_param) {
    // Helper lambda for shellcode-based features
    auto toggleShellcodeFeature = [&](
        const char* featureName, bool& enabledFlag, bool& wasEnabledFlag, uintptr_t instrAddr,
        const std::string& shellcodeHex, BYTE* origBytes, size_t origSize,
        bool& cave_allocated_flag, uintptr_t& cave_addr_var)
    {
        if (enabledFlag == wasEnabledFlag) return; // No change in desired state

        if (instrAddr == 0) {
            if (enabledFlag) {
                LogMessageF("[-] [%s] InstructionAddress is 0. Cannot enable.", featureName);
                enabledFlag = false;
            }
            wasEnabledFlag = enabledFlag;
            return;
        }

        if (enabledFlag) { // Try to enable/hook
            std::vector<BYTE> scBytes = HexToBytes(shellcodeHex);
            if (scBytes.empty()) {
                LogMessageF("[-] [%s] Shellcode hex string is invalid or empty. Cannot enable.", featureName);
                enabledFlag = false;
                wasEnabledFlag = enabledFlag; // Sync wasEnabledFlag with the reverted enabledFlag
                return;
            }

            uintptr_t temp_cave_addr = cave_allocated_flag ? cave_addr_var : 0;
            if (Features::InjectCodecave(pid_param, instrAddr, scBytes, origSize, temp_cave_addr)) {
                LogMessageF("[+] [%s] Enabled (hooked) at 0x%llX. Codecave at 0x%llX.", featureName, instrAddr, temp_cave_addr);
                cave_addr_var = temp_cave_addr;
                cave_allocated_flag = true;
            } else {
                LogMessageF("[-] [%s] InjectCodecave failed for address 0x%llX.", featureName, instrAddr);
                enabledFlag = false;
            }
        } else { // Try to disable/unhook
            if (cave_allocated_flag) {
                if (DriverComm::write_memory_buffer(instrAddr, origBytes, origSize)) {
                    LogMessageF("[-] [%s] Disabled (bytes restored) at 0x%llX.", featureName, instrAddr);
                    // cave_allocated_flag remains true, cave_addr_var still holds the address for reuse.
                } else {
                    LogMessageF("[-] [%s] Failed to restore original bytes at 0x%llX.", featureName, instrAddr);
                    enabledFlag = true;
                }
            } else {
                LogMessageF("[-] [%s] Disabled (no active hook/cave to restore) at 0x%llX.", featureName, instrAddr);
            }
        }
        wasEnabledFlag = enabledFlag; // Sync wasEnabledFlag with the final state of enabledFlag
    };

    // Helper lambda for simple NOP/byte patch features
    auto togglePatchFeature = [&](
        const char* featureName, bool& enabledFlag, bool& wasEnabledFlag, uintptr_t instrAddr,
        const auto& patchValue, const auto& originalValue)
    {
        if (enabledFlag == wasEnabledFlag) return;

        if (instrAddr == 0) {
            if (enabledFlag) {
                LogMessageF("[-] [%s] InstructionAddress is 0. Cannot enable.", featureName);
                enabledFlag = false;
            }
            wasEnabledFlag = enabledFlag;
            return;
        }

        if (!DriverComm::write_memory(instrAddr, enabledFlag ? patchValue : originalValue)) {
            LogMessageF("[-] [%s] WriteMemory failed. Addr: 0x%llX.", featureName, instrAddr);
            enabledFlag = !enabledFlag; // Revert toggle on failure
        } else {
            LogMessageF("[%s] [%s] %s at 0x%llX.", (enabledFlag ? "+" : "-"), featureName, (enabledFlag ? "Enabled (patched)" : "Disabled (restored)"), instrAddr);
        }
        wasEnabledFlag = enabledFlag;
    };

    // LOCALPLAYER & VIEANGLES
    if (LocalPlayer::Enabled != wasLocalPlayerEnabled) {
        if (LocalPlayer::Enabled) {
            LogMessage("[+] [LocalPlayer/ViewAngles] Attempting to enable...");
            bool lpAddrOk = LocalPlayer::addrMemAllocatedAddress != 0;
            if (!lpAddrOk) {
                lpAddrOk = DriverComm::allocate_memory(pid_param, sizeof(uintptr_t), LocalPlayer::addrMemAllocatedAddress, nullptr);
                if(lpAddrOk) LogMessageF("[+] [LocalPlayer] Allocated addrMemAllocatedAddress at 0x%llX.", LocalPlayer::addrMemAllocatedAddress);
                else LogMessage("[-] [LocalPlayer] Failed to allocate addrMemAllocatedAddress.");
            }

            bool vaAddrOk = ViewAngles::addrMemAllocatedAddress != 0;
            if (lpAddrOk && !vaAddrOk) { // Only proceed if LP addr is OK
                vaAddrOk = DriverComm::allocate_memory(pid_param, sizeof(uintptr_t), ViewAngles::addrMemAllocatedAddress, nullptr);
                if(vaAddrOk) LogMessageF("[+] [ViewAngles] Allocated addrMemAllocatedAddress at 0x%llX.", ViewAngles::addrMemAllocatedAddress);
                else LogMessage("[-] [ViewAngles] Failed to allocate addrMemAllocatedAddress.");
            }

            if (lpAddrOk && vaAddrOk) {
                bool lpSuccess = Features::EnableLocalPlayerHook(pid_param);
                bool vaSuccess = false;
                if (lpSuccess) { // Only enable VA if LP succeeded
                    vaSuccess = Features::EnableViewAngleHook(pid_param);
                }

                if (lpSuccess && vaSuccess) {
                    g_StopFindThread = false;
                    g_FindPlayerEnabled = true;
                    if(g_FindPlayerThread.joinable()) g_FindPlayerThread.join();
                    g_FindPlayerThread = std::thread(AutoFindPlayerLoop, pid_param, g_moduleBaseAddress_drawing + LocalPlayer::destinyBase, std::ref(LocalPlayer::realPlayer));
                    g_FindPlayerThread.detach();
                    LogMessage("[+] [LocalPlayer/ViewAngles] Hooks enabled, threads started.");
                } else {
                    LogMessage("[-] [LocalPlayer/ViewAngles] Hook enabling failed. Reverting.");
                    if (lpSuccess && LocalPlayer::InstructionAddress != 0 && LocalPlayer::mem_allocated) { // lpSuccess implies mem_allocated is true
                        DriverComm::write_memory_buffer(LocalPlayer::InstructionAddress, LocalPlayer::origBytes, sizeof(LocalPlayer::origBytes));
                    }
                    if (vaSuccess && ViewAngles::InstructionAddress != 0 && ViewAngles::mem_allocated) { // vaSuccess implies mem_allocated is true
                        DriverComm::write_memory_buffer(ViewAngles::InstructionAddress, ViewAngles::origBytes, sizeof(ViewAngles::origBytes));
                    }
                    LocalPlayer::Enabled = false;
                }
            } else {
                LogMessage("[-] [LocalPlayer/ViewAngles] Failed to allocate necessary pointer memory. Feature disabled.");
                LocalPlayer::Enabled = false;
            }
        } else { // Disabling
            LogMessage("[-] [LocalPlayer/ViewAngles] Attempting to disable...");
            if (LocalPlayer::InstructionAddress != 0 && LocalPlayer::mem_allocated) {
                DriverComm::write_memory_buffer(LocalPlayer::InstructionAddress, LocalPlayer::origBytes, sizeof(LocalPlayer::origBytes));
            }
            DisableViewAngleHook(); // This handles its own mem_allocated check for ViewAngles
            g_FindPlayerEnabled = false;
            g_StopFindThread = true;
            if (g_FindPlayerThread.joinable()) g_FindPlayerThread.join();
            LogMessage("[-] [LocalPlayer/ViewAngles] Disabled.");
        }
        wasLocalPlayerEnabled = LocalPlayer::Enabled;
    }

    // Shellcode-based Features
    toggleShellcodeFeature("Killaura", Killaura::Enabled, wasKillauraEnabled, Killaura::InstructionAddress, Killaura::shellcode_hex, Killaura::origBytes, sizeof(Killaura::origBytes), Killaura::mem_allocated, Killaura::memAllocatedAddress);
    toggleShellcodeFeature("Ghostmode", Ghostmode::Enabled, wasGhostmodeEnabled, Ghostmode::InstructionAddress, Ghostmode::shellcode_hex, Ghostmode::origBytes, sizeof(Ghostmode::origBytes), Ghostmode::mem_allocated, Ghostmode::memAllocatedAddress);
    toggleShellcodeFeature("Godmode", Godmode::Enabled, wasGodmodeEnabled, Godmode::InstructionAddress, Godmode::shellcode_hex, Godmode::origBytes, sizeof(Godmode::origBytes), Godmode::mem_allocated, Godmode::memAllocatedAddress);
    toggleShellcodeFeature("dmgMult", dmgMult::Enabled, wasDmgMultEnabled, dmgMult::InstructionAddress, dmgMult::shellcode_hex, dmgMult::origBytes, sizeof(dmgMult::origBytes), dmgMult::mem_allocated, dmgMult::memAllocatedAddress);
    toggleShellcodeFeature("RPM", RPM::Enabled, wasRPMEnabled, RPM::InstructionAddress, RPM::shellcode_hex, RPM::origBytes, sizeof(RPM::origBytes), RPM::mem_allocated, RPM::memAllocatedAddress);
    toggleShellcodeFeature("NoRecoil", NoRecoil::Enabled, wasNoRecoilEnabled, NoRecoil::InstructionAddress, NoRecoil::shellcode_hex, NoRecoil::origBytes, sizeof(NoRecoil::origBytes), NoRecoil::mem_allocated, NoRecoil::memAllocatedAddress);
    toggleShellcodeFeature("OHK", OHK::Enabled, wasOHKEnabled, OHK::InstructionAddress, OHK::shellcode_hex, OHK::origBytes, sizeof(OHK::origBytes), OHK::mem_allocated, OHK::memAllocatedAddress);
    toggleShellcodeFeature("InfStacks", InfStacks::Enabled, wasInfStacksEnabled, InfStacks::InstructionAddress, InfStacks::shellcode_hex, InfStacks::origBytes, sizeof(InfStacks::origBytes), InfStacks::mem_allocated, InfStacks::memAllocatedAddress);
    toggleShellcodeFeature("Chams", Chams::Enabled, wasChamsEnabled, Chams::InstructionAddress, Chams::shellcode_hex, Chams::origBytes, sizeof(Chams::origBytes), Chams::mem_allocated, Chams::memAllocatedAddress);
    toggleShellcodeFeature("InstantInteract", InstantInteract::Enabled, wasInstantInteractEnabled, InstantInteract::InstructionAddress, InstantInteract::shellcode_hex, InstantInteract::origBytes, sizeof(InstantInteract::origBytes), InstantInteract::mem_allocated, InstantInteract::memAllocatedAddress);
    toggleShellcodeFeature("ImmuneAura", ImmuneAura::Enabled, wasImmuneAuraEnabled, ImmuneAura::InstructionAddress, ImmuneAura::shellcode_hex, ImmuneAura::origBytes, sizeof(ImmuneAura::origBytes), ImmuneAura::mem_allocated, ImmuneAura::memAllocatedAddress);
    toggleShellcodeFeature("Mag999", Mag999::Enabled, wasMag999Enabled, Mag999::InstructionAddress, Mag999::shellcode_hex, Mag999::origBytes, sizeof(Mag999::origBytes), Mag999::mem_allocated, Mag999::memAllocatedAddress);

    // InfAmmo & InfSwordAmmo
    if (InfAmmo::Enabled != wasInfAmmoEnabled) {
        if (InfAmmo::Enabled) {
            LogMessage("[+] [InfAmmo/InfSwordAmmo] Attempting to enable...");
            bool mainHookSuccess = Features::EnableInfiniteAmmo(pid_param); // Handles its own mem_allocated & addr
            if (mainHookSuccess) {
                LogMessageF("[+] [InfAmmo] Main hook enabled at 0x%llX.", InfAmmo::InstructionAddress);
                if (InfSwordAmmo::InstructionAddress != 0) {
                    if (DriverComm::write_memory(InfSwordAmmo::InstructionAddress, InfSwordAmmo::nops)) {
                        LogMessageF("[+] [InfSwordAmmo] Patched NOPs at 0x%llX.", InfSwordAmmo::InstructionAddress);
                    } else {
                        LogMessageF("[-] [InfSwordAmmo] Failed NOP patch at 0x%llX.", InfSwordAmmo::InstructionAddress);
                    }
                } else LogMessage("[!] [InfSwordAmmo] InstructionAddress is 0.");
            } else {
                LogMessageF("[-] [InfAmmo] Main hook failed at 0x%llX.", InfAmmo::InstructionAddress);
                InfAmmo::Enabled = false;
            }
        } else { // Disabling
            LogMessage("[-] [InfAmmo/InfSwordAmmo] Attempting to disable...");
            if (InfAmmo::InstructionAddress != 0 && InfAmmo::mem_allocated) {
                DriverComm::write_memory_buffer(InfAmmo::InstructionAddress, InfAmmo::origBytes, sizeof(InfAmmo::origBytes));
            }
            if (InfSwordAmmo::InstructionAddress != 0 && wasInfAmmoEnabled) { // Only restore sword if main was active
                 DriverComm::write_memory(InfSwordAmmo::InstructionAddress, InfSwordAmmo::origBytes);
            }
        }
        wasInfAmmoEnabled = InfAmmo::Enabled;
    }

    // InstaRespawn & RespawnAnywhere
    if (InstaRespawn::Enabled != wasInstaRespawnEnabled) {
        if (InstaRespawn::Enabled) {
            LogMessage("[+] [InstaRespawn/RespawnAnywhere] Attempting to enable...");
            bool instaSuccess = false;
            if (InstaRespawn::InstructionAddress != 0) {
                instaSuccess = DriverComm::write_memory_buffer(InstaRespawn::InstructionAddress, InstaRespawn::myBytes, sizeof(InstaRespawn::myBytes));
                if(instaSuccess) LogMessageF("[+] [InstaRespawn] Patched at 0x%llX.", InstaRespawn::InstructionAddress);
                else LogMessageF("[-] [InstaRespawn] Patch failed at 0x%llX.", InstaRespawn::InstructionAddress);
            } else LogMessage("[-] [InstaRespawn] InstructionAddress is 0.");

            bool raSuccess = false;
            if (instaSuccess) { // Only try RA if Insta succeeded
                std::vector<BYTE> scBytesRA = HexToBytes(RespawnAnywhere::shellcode_hex);
                if (!scBytesRA.empty() && RespawnAnywhere::InstructionAddress != 0) {
                    uintptr_t temp_cave_addr_ra = RespawnAnywhere::mem_allocated ? RespawnAnywhere::memAllocatedAddress : 0;
                    if (Features::InjectCodecave(pid_param, RespawnAnywhere::InstructionAddress, scBytesRA, sizeof(RespawnAnywhere::origBytes), temp_cave_addr_ra)) {
                        RespawnAnywhere::memAllocatedAddress = temp_cave_addr_ra;
                        RespawnAnywhere::mem_allocated = true;
                        raSuccess = true;
                        LogMessageF("[+] [RespawnAnywhere] Hooked at 0x%llX.", RespawnAnywhere::InstructionAddress);
                    } else LogMessageF("[-] [RespawnAnywhere] Hook failed at 0x%llX.", RespawnAnywhere::InstructionAddress);
                } else LogMessageF("[-] [RespawnAnywhere] Invalid shellcode or address 0x%llX.", RespawnAnywhere::InstructionAddress);
            }

            if (! (instaSuccess && raSuccess) ) { // If either failed
                LogMessage("[-] [InstaRespawn/RespawnAnywhere] Enabling failed. Reverting.");
                if (raSuccess && RespawnAnywhere::InstructionAddress != 0 && RespawnAnywhere::mem_allocated) { // raSuccess implies mem_allocated
                    DriverComm::write_memory_buffer(RespawnAnywhere::InstructionAddress, RespawnAnywhere::origBytes, sizeof(RespawnAnywhere::origBytes));
                }
                if (instaSuccess && InstaRespawn::InstructionAddress != 0) {
                    DriverComm::write_memory_buffer(InstaRespawn::InstructionAddress, InstaRespawn::origBytes, sizeof(InstaRespawn::origBytes));
                }
                InstaRespawn::Enabled = false;
            }
        } else { // Disabling
            LogMessage("[-] [InstaRespawn/RespawnAnywhere] Attempting to disable...");
            if (InstaRespawn::InstructionAddress != 0 && wasInstaRespawnEnabled) {
                DriverComm::write_memory_buffer(InstaRespawn::InstructionAddress, InstaRespawn::origBytes, sizeof(InstaRespawn::origBytes));
            }
            if (RespawnAnywhere::InstructionAddress != 0 && RespawnAnywhere::mem_allocated) {
                DriverComm::write_memory_buffer(RespawnAnywhere::InstructionAddress, RespawnAnywhere::origBytes, sizeof(RespawnAnywhere::origBytes));
            }
        }
        wasInstaRespawnEnabled = InstaRespawn::Enabled;
    }

    // Simple NOP/Byte Patch features
    togglePatchFeature("NoJoinAllies", NoJoinAllies::Enabled, wasNoJoiningAlliesEnabled, NoJoinAllies::InstructionAddress, NoJoinAllies::nops, NoJoinAllies::origBytes);
    togglePatchFeature("NoTurnBack", NoTurnBack::Enabled, wasNoTurnBackEnabled, NoTurnBack::InstructionAddress, NoTurnBack::nops, NoTurnBack::origBytes);
    togglePatchFeature("SparrowAnywhere", SparrowAnywhere::Enabled, wasSparrowAnywhereEnabled, SparrowAnywhere::InstructionAddress, SparrowAnywhere::mybyte, SparrowAnywhere::origByte);
    togglePatchFeature("NoRezTokens", NoRezTokens::Enabled, wasNoRezTokensEnabled, NoRezTokens::InstructionAddress, NoRezTokens::myByte, NoRezTokens::origByte);
    togglePatchFeature("ShootThru", ShootThru::Enabled, wasShootThruWallsEnabled, ShootThru::InstructionAddress, ShootThru::nops, ShootThru::origBytes);
    togglePatchFeature("IcarusDash", IcarusDash::Enabled, wasIcarusDashEnabled, IcarusDash::InstructionAddress, IcarusDash::nops, IcarusDash::origBytes);
    togglePatchFeature("LobbyCrasher", LobbyCrasher::Enabled, wasLobbyCrasherEnabled, LobbyCrasher::InstructionAddress, LobbyCrasher::nops, LobbyCrasher::origBytes);
    togglePatchFeature("Oxygen", Oxygen::Enabled, wasOxygenEnabled, Oxygen::InstructionAddress, Oxygen::nops, Oxygen::origBytes);
    togglePatchFeature("InfSparrowBoost", InfSparrowBoost::Enabled, wasInfSparrowBoostEnabled, InfSparrowBoost::InstructionAddress, InfSparrowBoost::myByte, InfSparrowBoost::origByte);
    togglePatchFeature("InfBuffTimers", InfBuffTimers::Enabled, wasInfBuffTimersEnabled, InfBuffTimers::InstructionAddress, InfBuffTimers::nops, InfBuffTimers::origBytes);
    togglePatchFeature("InfExoticBuffTimers", InfExoticBuffTimers::Enabled, wasInfExoticBuffTimersEnabled, InfExoticBuffTimers::InstructionAddress, InfExoticBuffTimers::nops, InfExoticBuffTimers::origBytes);

    // AntiFlinch
    if (AntiFlinch::Enabled != wasAntiFlinchEnabled) {
        bool allAddressesValid = AntiFlinch::InstructionAddress1 != 0 && AntiFlinch::InstructionAddress2 != 0 && AntiFlinch::InstructionAddress3 != 0;
        if (AntiFlinch::Enabled) {
            if (allAddressesValid) {
                bool s1 = DriverComm::write_memory(AntiFlinch::InstructionAddress1, AntiFlinch::nops);
                bool s2 = DriverComm::write_memory(AntiFlinch::InstructionAddress2, AntiFlinch::nops);
                bool s3 = DriverComm::write_memory(AntiFlinch::InstructionAddress3, AntiFlinch::nops);
                if (!s1 || !s2 || !s3) {
                    LogMessage("[-] [AntiFlinch] Patching failed. Reverting.");
                    if(s1) DriverComm::write_memory(AntiFlinch::InstructionAddress1, AntiFlinch::origBytes1);
                    if(s2) DriverComm::write_memory(AntiFlinch::InstructionAddress2, AntiFlinch::origBytes2);
                    if(s3) DriverComm::write_memory(AntiFlinch::InstructionAddress3, AntiFlinch::origBytes3);
                    AntiFlinch::Enabled = false;
                } else LogMessage("[+] [AntiFlinch] Enabled.");
            } else {
                LogMessage("[-] [AntiFlinch] One or more addresses are 0. Cannot enable.");
                AntiFlinch::Enabled = false;
            }
        } else { // Disabling
            if (AntiFlinch::InstructionAddress1 != 0) DriverComm::write_memory(AntiFlinch::InstructionAddress1, AntiFlinch::origBytes1);
            if (AntiFlinch::InstructionAddress2 != 0) DriverComm::write_memory(AntiFlinch::InstructionAddress2, AntiFlinch::origBytes2);
            if (AntiFlinch::InstructionAddress3 != 0) DriverComm::write_memory(AntiFlinch::InstructionAddress3, AntiFlinch::origBytes3);
            LogMessage("[-] [AntiFlinch] Disabled.");
        }
        wasAntiFlinchEnabled = AntiFlinch::Enabled;
    }

    // InteractThruWalls
    if (InteractThruWalls::Enabled != wasInteractThruWallsEnabled) {
        if (InteractThruWalls::Enabled) {
            LogMessage("[+] [InteractThruWalls] Attempting to enable...");
            bool hook1Success = false;
            if (InteractThruWalls::InstructionAddress1 != 0) {
                std::vector<BYTE> sc1 = HexToBytes(InteractThruWalls::shellcode1_hex);
                uintptr_t temp_cave1 = InteractThruWalls::mem_allocated1 ? InteractThruWalls::memAllocatedAddress1 : 0;
                if (!sc1.empty() && Features::InjectCodecave(pid_param, InteractThruWalls::InstructionAddress1, sc1, sizeof(InteractThruWalls::origBytes1), temp_cave1)) {
                    InteractThruWalls::memAllocatedAddress1 = temp_cave1; InteractThruWalls::mem_allocated1 = true; hook1Success = true;
                    LogMessageF("[+] [InteractThruWalls] Hook 1 enabled at 0x%llX", InteractThruWalls::InstructionAddress1);
                } else LogMessageF("[-] [InteractThruWalls] Hook 1 failed at 0x%llX", InteractThruWalls::InstructionAddress1);
            } else LogMessage("[-] [InteractThruWalls] Hook 1 address is 0.");

            bool hook2Success = false;
            if (hook1Success) { // Only try hook2 if hook1 succeeded
                if (InteractThruWalls::InstructionAddress2 != 0) {
                    std::vector<BYTE> sc2 = HexToBytes(InteractThruWalls::shellcode2_hex);
                    uintptr_t temp_cave2 = InteractThruWalls::mem_allocated2 ? InteractThruWalls::memAllocatedAddress2 : 0;
                    if (!sc2.empty() && Features::InjectCodecave(pid_param, InteractThruWalls::InstructionAddress2, sc2, sizeof(InteractThruWalls::origBytes2), temp_cave2)) {
                        InteractThruWalls::memAllocatedAddress2 = temp_cave2; InteractThruWalls::mem_allocated2 = true; hook2Success = true;
                        LogMessageF("[+] [InteractThruWalls] Hook 2 enabled at 0x%llX", InteractThruWalls::InstructionAddress2);
                    } else LogMessageF("[-] [InteractThruWalls] Hook 2 failed at 0x%llX", InteractThruWalls::InstructionAddress2);
                } else LogMessage("[-] [InteractThruWalls] Hook 2 address is 0.");
            }

            if (! (hook1Success && hook2Success) ) {
                LogMessage("[-] [InteractThruWalls] Enabling failed. Reverting.");
                if (hook1Success && InteractThruWalls::InstructionAddress1 != 0 && InteractThruWalls::mem_allocated1) {
                    DriverComm::write_memory_buffer(InteractThruWalls::InstructionAddress1, InteractThruWalls::origBytes1, sizeof(InteractThruWalls::origBytes1));
                }
                // hook2 was only attempted if hook1 succeeded, so no need to check hook2Success for rollback of hook2
                InteractThruWalls::Enabled = false;
            }
        } else { // Disabling
            LogMessage("[-] [InteractThruWalls] Attempting to disable...");
            if (InteractThruWalls::InstructionAddress1 != 0 && InteractThruWalls::mem_allocated1) {
                DriverComm::write_memory_buffer(InteractThruWalls::InstructionAddress1, InteractThruWalls::origBytes1, sizeof(InteractThruWalls::origBytes1));
            }
            if (InteractThruWalls::InstructionAddress2 != 0 && InteractThruWalls::mem_allocated2) {
                DriverComm::write_memory_buffer(InteractThruWalls::InstructionAddress2, InteractThruWalls::origBytes2, sizeof(InteractThruWalls::origBytes2));
            }
        }
        wasInteractThruWallsEnabled = InteractThruWalls::Enabled;
    }
    
    // ActivityLoader
    if (ActivityLoader::Enabled != wasActivityLoaderEnabled) {
        if (ActivityLoader::Enabled) {
            LogMessage("[+] [ActivityLoader] Attempting to enable...");
            if (Features::EnableActivityLoaderHook(pid_param)) { // This function sets mem_allocated on success
                LogMessageF("[+] [ActivityLoader] Hook enabled by EnableActivityLoaderHook for 0x%llX.", ActivityLoader::InstructionAddress);
            } else {
                LogMessageF("[-] [ActivityLoader] EnableActivityLoaderHook failed for 0x%llX.", ActivityLoader::InstructionAddress);
                ActivityLoader::Enabled = false;
            }
        } else { // Disabling
            LogMessage("[-] [ActivityLoader] Attempting to disable...");
            if (ActivityLoader::InstructionAddress != 0 && ActivityLoader::mem_allocated) {
                if (DriverComm::write_memory_buffer(ActivityLoader::InstructionAddress, ActivityLoader::origBytes, sizeof(ActivityLoader::origBytes))) {
                    LogMessageF("[-] [ActivityLoader] Hook disabled, bytes restored at 0x%llX.", ActivityLoader::InstructionAddress);
                    ActivityLoader::mem_allocated = false;
                } else {
                    LogMessageF("[-] [ActivityLoader] Failed to restore bytes at 0x%llX.", ActivityLoader::InstructionAddress);
                    ActivityLoader::Enabled = true; // Failed to disable
                }
            } else LogMessageF("[-] [ActivityLoader] Not active/allocated, no restoration for 0x%llX.", ActivityLoader::InstructionAddress);
        }
        wasActivityLoaderEnabled = ActivityLoader::Enabled;
    }
}

void Drawing::Poll() {
    if (!isInitialized || g_current_pid_drawing == 0) return;

    PollHotkeys();
    PollFly();
    PollAbilityCharge();
    PollImmuneBosses();
    PollGameSpeed();
    PollKillKey();
    TPManager::Poll(); // Assuming TPManager::Poll() is already updated or will be separately
    UpdateFeatureStates(g_current_pid_drawing); // UpdateFeatureStates still takes pid_param
}

void Drawing::Draw() {
    SetCustomTheme();
    // This large block of old feature toggle logic has been removed.
    // It was located here, after SetCustomTheme() and before the new PID/Module init logic.
    // Functionality is now handled by UpdateFeatureStates() and Poll<FeatureName>() functions.

    // NOTE: The large block of old feature toggle logic that was here
    // (from Killaura, Ghostmode, Godmode, etc. up to Mag999)
    // has been removed. This functionality should now be handled by
    // UpdateFeatureStates() and the individual Poll<FeatureName>() functions
    // called from Drawing::Poll().

    // static DWORD oldPid = 0; // No longer needed by this new logic as g_current_pid_drawing tracks it
    static auto lastPidCheckTime = std::chrono::steady_clock::now();
    static auto lastWaitingMessageTime = std::chrono::steady_clock::now();

    if (isInitialized) {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastPidCheckTime).count() >= 2) {
            if (get_process_id_local(g_wModuleName.c_str()) != g_current_pid_drawing) {
                // Convert g_wModuleName to narrow string for logging
                char narrowModuleName[256];
                size_t convertedChars = 0;
                wcstombs_s(&convertedChars, narrowModuleName, sizeof(narrowModuleName), g_wModuleName.c_str(), _TRUNCATE);
                LogMessageF("[!] Drawing::Draw: Target process %s (PID: %lu) lost. Resetting.", narrowModuleName, g_current_pid_drawing);

                if(isInitialized) {
                     LogMessage("[+] Shutting down DriverComm due to process loss...");
                     DriverComm::shutdown();
                     LogMessage("[+] DriverComm shut down.");
                }

                // Signal and join ImmuneBossesThread
                ImmuneBosses::Enabled.store(false);
                ImmuneBosses::ThreadRunning.store(false);
                if (ImmuneBossesThread.joinable()) {
                    LogMessage("[+] Joining ImmuneBossesThread due to process loss...");
                    ImmuneBossesThread.join();
                    LogMessage("[+] ImmuneBossesThread joined.");
                }

                // Signal and join FlyThread
                Features::LocalPlayer::flyEnabled = false;
                StopFlyThread = true;
                if (FlyThread.joinable()) {
                    LogMessage("[+] Joining FlyThread due to process loss...");
                    FlyThread.join();
                    LogMessage("[+] FlyThread joined.");
                }

                isInitialized = false;
                g_current_pid_drawing = 0;
                g_moduleBaseAddress_drawing = 0;

                // Reset relevant feature states
                LocalPlayer::Enabled = false;
                // ... (ensure other features that might hold state or threads are reset)
            }
            lastPidCheckTime = now;
        }
    }

    if (isInitialized == false) {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastPidCheckTime).count() >= 1) {
            lastPidCheckTime = now;

            DWORD currentProcessId = get_process_id_local(g_wModuleName.c_str());

            if (currentProcessId != 0) {
                g_current_pid_drawing = currentProcessId;
                char narrowModuleNameLog[256];
                size_t convertedCharsLog = 0;
                wcstombs_s(&convertedCharsLog, narrowModuleNameLog, sizeof(narrowModuleNameLog), g_wModuleName.c_str(), _TRUNCATE);
                #ifdef _DEBUG
                LogMessageF("[+] Drawing::Draw: %s found! Process ID: %lu", narrowModuleNameLog, g_current_pid_drawing);
                #endif

                if (DriverComm::attach_to_process(g_current_pid_drawing)) {
                    #ifdef _DEBUG
                    LogMessageF("[+] Drawing::Draw: DriverComm::attach_to_process successful for PID %lu", g_current_pid_drawing);
                    #endif
                    g_moduleBaseAddress_drawing = DriverComm::GetModuleBase(g_current_pid_drawing, g_wModuleName.c_str());

                    if (g_moduleBaseAddress_drawing != 0) {
                        #ifdef _DEBUG
                        LogMessageF("[+] Drawing::Draw: Module base address: 0x%llX", g_moduleBaseAddress_drawing);
                        LogMessage("[+] Drawing::Draw: Starting AOB scans...");
                        #endif
                        // These functions will need to be updated to not require driver/pid, or use g_current_pid_drawing and g_moduleBaseAddress_drawing
                        PerformStartupAobScans(g_moduleBaseAddress_drawing);
                        PerformStartupByteReads();

                        LoadHotkeys();
                        SetHotkeyDefault("FlyToggle", VK_F1);
                        SetHotkeyDefault("FlyBoost", VK_F2);
                        SetHotkeyDefault("AbilityCharge", VK_F5);
                        SetHotkeyDefault("SuicideKey", VK_DELETE);
                        SetHotkeyDefault("GameSpeed", VK_CAPITAL);
                        RefreshConfigList();
                        TPManager::InitFolder();
                        TPManager::RefreshConfigList();
                        isInitialized = true;
                        #ifdef _DEBUG
                        LogMessage("[+] Drawing::Draw: Initialization complete.");
                        #endif
                    } else {
                        char narrowModuleNameErr[256];
                        size_t convertedCharsErr = 0;
                        wcstombs_s(&convertedCharsErr, narrowModuleNameErr, sizeof(narrowModuleNameErr), g_wModuleName.c_str(), _TRUNCATE);
                        LogMessageF("[-] Drawing::Draw: Failed to get module base for %s. PID: %lu", narrowModuleNameErr, g_current_pid_drawing);
                        DriverComm::shutdown();
                        g_current_pid_drawing = 0;
                    }
                } else {
                    LogMessageF("[-] Drawing::Draw: DriverComm::attach_to_process failed for PID %lu. Retrying...", g_current_pid_drawing);
                    g_current_pid_drawing = 0;
                }
            } else {
                 static auto lastWaitingMsgTime = std::chrono::steady_clock::now();
                 if (std::chrono::duration_cast<std::chrono::seconds>(now - lastWaitingMsgTime).count() >= 5) {
                    #ifdef _DEBUG
                    char narrowModuleNameWait[256];
                    size_t convertedCharsWait = 0;
                    wcstombs_s(&convertedCharsWait, narrowModuleNameWait, sizeof(narrowModuleNameWait), g_wModuleName.c_str(), _TRUNCATE);
                    LogMessageF("[*] Drawing::Draw: Waiting for %s process...", narrowModuleNameWait);
                    #endif
                    lastWaitingMessageTime = now;
                 }
            }
        }
    }

    if (!isActive())
        return;

    // Set up the main window.
    ImGui::SetNextWindowSize(vWindowSize, ImGuiCond_Once);

    // Add window rounding and shadow for a modern look
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.5f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24, 18));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));


    ImGui::Begin(lpWindowName, &bDraw, WindowFlags);
    // Set up the "X" button at the top-right.
    ImVec2 contentRegion = ImGui::GetWindowContentRegionMax();
    const float padding = 5.0f;
    const float xButtonSize = 20.0f; // adjust to your button size
    float posX = contentRegion.x - xButtonSize - padding;
    float posY = padding;

    // ─── Close Button ───
    ImGui::SetCursorPos(ImVec2(posX, posY));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.7f, 0.1f, 0.1f, 1.0f));
    if (ImGui::Button("X", ImVec2(xButtonSize, xButtonSize))) {
        LogMessage("[+] Application exit requested by user.");

        // Signal and join ImmuneBossesThread
        ImmuneBosses::Enabled.store(false);
        ImmuneBosses::ThreadRunning.store(false);
        if (ImmuneBossesThread.joinable()) {
            LogMessage("[+] Joining ImmuneBossesThread before exit...");
            ImmuneBossesThread.join();
            LogMessage("[+] ImmuneBossesThread joined.");
        }

        // Signal and join FlyThread
        Features::LocalPlayer::flyEnabled = false;
        StopFlyThread = true;
        if (FlyThread.joinable()) {
            LogMessage("[+] Joining FlyThread before exit...");
            FlyThread.join();
            LogMessage("[+] FlyThread joined.");
        }

        if(isInitialized && g_current_pid_drawing != 0) {
             LogMessage("[+] Shutting down DriverComm before exit...");
             DriverComm::shutdown();
             LogMessage("[+] DriverComm shut down.");
        }
        isInitialized = false;

        LogMessage("[+] Exiting application now.");
        exit(0);
    }
    ImGui::PopStyleColor(3);    // ─── Header Text ───
    // Align vertically with the button by setting the same Y
    ImGui::SetCursorPosY(posY);

    // Standardized Failure Indicator Lambda
    auto RenderFeatureStatusIndicator = [&](
        const char* featureName, bool isEnabled,
        uintptr_t pAddr1, bool pNeedsCave = false, bool pCaveAlloc = false,
        uintptr_t pAddr2 = 1, bool sNeedsCave = false, bool sCaveAlloc = false, // Default to 1 (non-zero) to pass checks if not used
        uintptr_t pAddr3 = 1, // For AntiFlinch or similar
        uintptr_t customPtr1 = 1, const char* customPtr1Name = nullptr, // For things like addrMemAllocatedAddress
        uintptr_t customPtr2 = 1, const char* customPtr2Name = nullptr,
        const char* specificFeatureIssue = nullptr) // For very specific pre-checked issues
    {
        if (!isEnabled || g_moduleBaseAddress_drawing == 0) {
            return; // Only show for enabled features when game is active
        }

        std::string tooltipMsg;

        if (specificFeatureIssue) {
            tooltipMsg = specificFeatureIssue;
        } else if (pAddr1 == 0) {
            tooltipMsg = "Failed: Primary AOB/Offset not found for ";
            tooltipMsg += featureName;
        } else if (pNeedsCave && !pCaveAlloc) {
            tooltipMsg = "Failed: Primary memory allocation error for ";
            tooltipMsg += featureName;
        } else if (pAddr2 == 0) { // Check only if pAddr2 was intended to be used (not default 1)
            tooltipMsg = "Failed: Secondary AOB/Offset not found for ";
            tooltipMsg += featureName;
        } else if (sNeedsCave && !sCaveAlloc) { // Check only if sNeedsCave was true
            tooltipMsg = "Failed: Secondary memory allocation error for ";
            tooltipMsg += featureName;
        } else if (pAddr3 == 0) { // Check only if pAddr3 was intended to be used
            tooltipMsg = "Failed: Tertiary AOB/Offset not found for ";
            tooltipMsg += featureName;
        } else if (customPtr1 == 0 && customPtr1Name) {
            tooltipMsg = std::string("Failed: ") + customPtr1Name + " not allocated for ";
            tooltipMsg += featureName;
        } else if (customPtr2 == 0 && customPtr2Name) {
            tooltipMsg = std::string("Failed: ") + customPtr2Name + " not allocated for ";
            tooltipMsg += featureName;
        }

        if (!tooltipMsg.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("(!)");
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
                ImGui::SetTooltip("%s", tooltipMsg.c_str());
            }
        }
    };

    ImGui::SetCursorPosY(posY);
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize(lpWindowName).x) * 0.5f); // Use lpWindowName
    ImGui::TextColored(ImVec4(0.9f, 0.7f, 1.0f, 1.0f), "HATEMOB");    // ─── Divider ───
    ImGui::SetCursorPosY(posY + xButtonSize_local + 23); // Use xButtonSize_local
    ImGui::Separator();

    // Begin the Tab Bar.
    if (ImGui::BeginTabBar("MyTabBar"))
    {
        // Movement Tab
        if (ImGui::BeginTabItem("Player"))
        {
            // Tab background
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImVec2 size = ImGui::GetContentRegionAvail();
            size.y = 180;
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            draw_list->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);

            ImGui::Text("Player Options:");
            ImGui::Spacing();
            // Use lighter color for FOV slider
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_SliderGrab, ImVec4(0.7f, 0.8f, 1.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, ImVec4(0.8f, 0.9f, 1.0f, 1.0f));
            RenderFOVSlider();
            ImGui::Spacing();

            ImGui::Toggle("Hook LocalPlayer", &LocalPlayer::Enabled);
            RenderFeatureStatusIndicator("LocalPlayer/ViewAngles", LocalPlayer::Enabled,
                LocalPlayer::InstructionAddress, true, LocalPlayer::mem_allocated,
                ViewAngles::InstructionAddress, true, ViewAngles::mem_allocated,
                1, LocalPlayer::addrMemAllocatedAddress, "LP Pointer Store", ViewAngles::addrMemAllocatedAddress, "VA Pointer Store");

            RenderKillKeyUI();
            RenderFlyControls();
            ImGui::PopStyleColor(3);
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Combat")) {
            ImVec2 p_combat = ImGui::GetCursorScreenPos(); ImVec2 size_combat = ImGui::GetContentRegionAvail(); size_combat.y = 220;
            ImGui::GetWindowDrawList()->AddRectFilled(p_combat, ImVec2(p_combat.x + size_combat.x, p_combat.y + size_combat.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10)); ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);
            ImGui::Text("Combat Options:"); ImGui::Spacing();

            ImGui::Toggle("Killaura", &Killaura::Enabled);
            RenderFeatureStatusIndicator("Killaura", Killaura::Enabled, Killaura::InstructionAddress, true, Killaura::mem_allocated);
            ImGui::Toggle("Ghostmode", &Ghostmode::Enabled);
            RenderFeatureStatusIndicator("Ghostmode", Ghostmode::Enabled, Ghostmode::InstructionAddress, true, Ghostmode::mem_allocated);
            ImGui::Toggle("Godmode", &Godmode::Enabled);
            RenderFeatureStatusIndicator("Godmode", Godmode::Enabled, Godmode::InstructionAddress, true, Godmode::mem_allocated);

            ImGui::Toggle("Inf Ammo", &InfAmmo::Enabled);
            RenderFeatureStatusIndicator("Inf Ammo", InfAmmo::Enabled, InfAmmo::InstructionAddress, true, InfAmmo::mem_allocated,
                                        (InfSwordAmmo::InstructionAddress == 0 && InfAmmo::Enabled && g_moduleBaseAddress_drawing != 0) ? 0 : 1, // Force fail if sword AOB missing
                                        false, false, 1, 1, nullptr, 1, nullptr,
                                        (InfSwordAmmo::InstructionAddress == 0 && InfAmmo::Enabled && g_moduleBaseAddress_drawing != 0) ? "Warning: InfSwordAmmo offset not found." : nullptr);

            ImGui::Toggle("RPM", &RPM::Enabled);
            RenderFeatureStatusIndicator("RPM", RPM::Enabled, RPM::InstructionAddress, true, RPM::mem_allocated);
            ImGui::Toggle("Dmg Multiplier", &dmgMult::Enabled);
            RenderFeatureStatusIndicator("Dmg Multiplier", dmgMult::Enabled, dmgMult::InstructionAddress, true, dmgMult::mem_allocated);
            ImGui::Toggle("Unshielded Immune Bosses/Aura", &ImmuneAura::Enabled);
            RenderFeatureStatusIndicator("ImmuneAura", ImmuneAura::Enabled, ImmuneAura::InstructionAddress, true, ImmuneAura::mem_allocated);

            RenderAbilityChargeUI();
            RenderFeatureStatusIndicator("AbilityCharge", AbilityCharge::Enabled, AbilityCharge::InstructionAddress, true, AbilityCharge::memAllocatedAddress != 0);

            ImGui::Toggle("No Recoil", &NoRecoil::Enabled);
            RenderFeatureStatusIndicator("No Recoil", NoRecoil::Enabled, NoRecoil::InstructionAddress, true, NoRecoil::mem_allocated);
            ImGui::Toggle("Shoot Thru Walls", &ShootThru::Enabled);
            RenderFeatureStatusIndicator("Shoot Thru Walls", ShootThru::Enabled, ShootThru::InstructionAddress);

            RenderImmuneBossesUI(g_current_pid_drawing); // Handles its own status display ("Scanning...", "Active @ ...")

            ImGui::Toggle("One hit kill", &OHK::Enabled);
            RenderFeatureStatusIndicator("One hit kill", OHK::Enabled, OHK::InstructionAddress, true, OHK::mem_allocated);

            RenderMag999Button(iconFont);
            RenderFeatureStatusIndicator("Mag999", Mag999::Enabled, Mag999::InstructionAddress, true, Mag999::mem_allocated);

            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Misc")) {
            ImVec2 p_misc = ImGui::GetCursorScreenPos(); ImVec2 size_misc = ImGui::GetContentRegionAvail(); size_misc.y = 220;
            ImGui::GetWindowDrawList()->AddRectFilled(p_misc, ImVec2(p_misc.x + size_misc.x, p_misc.y + size_misc.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10)); ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);
            ImGui::Text("Misc Options:"); ImGui::Spacing();

            ImGui::Toggle("No Joining Allies", &NoJoinAllies::Enabled);
            RenderFeatureStatusIndicator("No Joining Allies", NoJoinAllies::Enabled, NoJoinAllies::InstructionAddress);
            ImGui::Toggle("No Turn Back", &NoTurnBack::Enabled);
            RenderFeatureStatusIndicator("No Turn Back", NoTurnBack::Enabled, NoTurnBack::InstructionAddress);
            ImGui::Toggle("Infinite Rez Tokens", &NoRezTokens::Enabled);
            RenderFeatureStatusIndicator("Infinite Rez Tokens", NoRezTokens::Enabled, NoRezTokens::InstructionAddress);

            ImGui::Toggle("Respawn Anywhere", &InstaRespawn::Enabled);
            RenderFeatureStatusIndicator("InstaRespawn/RespawnAnywhere", InstaRespawn::Enabled,
                InstaRespawn::InstructionAddress, false, false,
                RespawnAnywhere::InstructionAddress, true, RespawnAnywhere::mem_allocated);

            ImGui::Toggle("Infinite Stacks", &InfStacks::Enabled);
            RenderFeatureStatusIndicator("Infinite Stacks", InfStacks::Enabled, InfStacks::InstructionAddress, true, InfStacks::mem_allocated);
            ImGui::Toggle("Infinite Buff Timers", &InfBuffTimers::Enabled);
            RenderFeatureStatusIndicator("Infinite Buff Timers", InfBuffTimers::Enabled, InfBuffTimers::InstructionAddress);
            ImGui::Toggle("Infinite Exotic Buff Timers", &InfExoticBuffTimers::Enabled);
            RenderFeatureStatusIndicator("Infinite Exotic Buff Timers", InfExoticBuffTimers::Enabled, InfExoticBuffTimers::InstructionAddress);

            RenderGameSpeedUI();
            RenderFeatureStatusIndicator("GameSpeed", GameSpeed::Enabled, GameSpeed::Address);

            ImGui::Toggle("Instant Interact", &InstantInteract::Enabled);
            RenderFeatureStatusIndicator("Instant Interact", InstantInteract::Enabled, InstantInteract::InstructionAddress, true, InstantInteract::mem_allocated);

            ImGui::Toggle("Interact Thru Walls", &InteractThruWalls::Enabled);
            RenderFeatureStatusIndicator("Interact Thru Walls", InteractThruWalls::Enabled,
                InteractThruWalls::InstructionAddress1, true, InteractThruWalls::mem_allocated1,
                InteractThruWalls::InstructionAddress2, true, InteractThruWalls::mem_allocated2);

            ImGui::Toggle("Sparrow Anywhere", &SparrowAnywhere::Enabled);
            RenderFeatureStatusIndicator("Sparrow Anywhere", SparrowAnywhere::Enabled, SparrowAnywhere::InstructionAddress);
            ImGui::Toggle("Infinite Sparrow Boost", &InfSparrowBoost::Enabled);
            RenderFeatureStatusIndicator("Infinite Sparrow Boost", InfSparrowBoost::Enabled, InfSparrowBoost::InstructionAddress);

            if (GSize::Address == 0 && GSize::Enabled && g_moduleBaseAddress_drawing != 0) {
                GSize::Address = DriverComm::AOBScan(g_moduleBaseAddress_drawing, DEFAULT_SCAN_REGION_SIZE, GSize::AOB.c_str(), "");
                if (GSize::Address == 0) GSize::Enabled = false;
            }
            ImGui::Toggle("Guardian Size", &GSize::Enabled);
            RenderFeatureStatusIndicator("Guardian Size", GSize::Enabled, GSize::Address);

            if (GSize::Enabled && GSize::Address != 0) {
                GSize::Value = DriverComm::read_memory<float>(GSize::Address);
                static float lastReadVal = 0.0f;
                if (lastReadVal != GSize::Value) { GSize::inputVal = GSize::Value; lastReadVal = GSize::Value; }
                ImGui::PushItemWidth(150); ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
                if(ImGui::InputFloat("Size##GSize", &GSize::inputVal, 0.0f, 0.0f, "%.3f")) {}
                ImGui::PopStyleColor(); ImGui::PopItemWidth();
                if (ImGui::Button("Set##GSize")) { DriverComm::write_memory(GSize::Address, GSize::inputVal); lastReadVal = -1.0f; }
            }
            RenderActivityLoaderUI(g_current_pid_drawing);
            RenderFeatureStatusIndicator("ActivityLoader", ActivityLoader::Enabled,
                ActivityLoader::InstructionAddress, true, ActivityLoader::mem_allocated,
                1, false, false, 1,
                ActivityLoader::addrMemAllocatedAddress, "Data Pointer");

            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("TPs")) {
            TPManager::RenderTPTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("PVP")) {
            ImVec2 p_pvp = ImGui::GetCursorScreenPos(); ImVec2 size_pvp = ImGui::GetContentRegionAvail(); size_pvp.y = 120;
            ImGui::GetWindowDrawList()->AddRectFilled(p_pvp, ImVec2(p_pvp.x + size_pvp.x, p_pvp.y + size_pvp.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10)); ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);
            ImGui::Text("PVP Options:"); ImGui::Spacing();

            ImGui::Toggle("Chams", &Chams::Enabled);
            RenderFeatureStatusIndicator("Chams", Chams::Enabled, Chams::InstructionAddress, true, Chams::mem_allocated);
            ImGui::Toggle("Infinite Icarus Dash", &IcarusDash::Enabled);
            RenderFeatureStatusIndicator("Infinite Icarus Dash", IcarusDash::Enabled, IcarusDash::InstructionAddress);
            ImGui::Toggle("Lobby Crasher", &LobbyCrasher::Enabled);
            RenderFeatureStatusIndicator("Lobby Crasher", LobbyCrasher::Enabled, LobbyCrasher::InstructionAddress);
            ImGui::Toggle("No Flinch", &AntiFlinch::Enabled);
            RenderFeatureStatusIndicator("No Flinch", AntiFlinch::Enabled,
                AntiFlinch::InstructionAddress1, false, false,
                AntiFlinch::InstructionAddress2, false, false,
                AntiFlinch::InstructionAddress3);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Random")) {
            ImVec2 p_rand = ImGui::GetCursorScreenPos(); ImVec2 size_rand = ImGui::GetContentRegionAvail(); size_rand.y = 80;
            ImGui::GetWindowDrawList()->AddRectFilled(p_rand, ImVec2(p_rand.x + size_rand.x, p_rand.y + size_rand.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10)); ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);
            ImGui::Text("Random Options:"); ImGui::Spacing();
            if (ImGui::CollapsingHeader("GotD")) {
                ImGui::Toggle("Infinite Oxygen", &Oxygen::Enabled);
                RenderFeatureStatusIndicator("Infinite Oxygen", Oxygen::Enabled, Oxygen::InstructionAddress);
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Config")) {
            RenderConfigTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Logs")) {
            if (ImGui::Button("Clear Log")) {
                std::lock_guard<std::mutex> lock(g_logMutex);
                g_logMessages.clear();
            }
            ImGui::Separator();
            ImGui::BeginChild("LogScrollRegion", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
            {
                std::lock_guard<std::mutex> lock(g_logMutex); // Lock while accessing g_logMessages
                for (const auto& msg : g_logMessages) {
                    ImGui::TextUnformatted(msg.c_str());
                }
                // Optional: Auto-scroll to the bottom if new messages are added
                // if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                // ImGui::SetScrollHereY(1.0f);
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    LimitFPS(185.0);
    ImGui::End();