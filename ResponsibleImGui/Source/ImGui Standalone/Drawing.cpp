﻿#include "Drawing.h"
#include <ctime>
#include <string>
#include <cmath>
#include <chrono>
#include <thread> // Already present, good.
#include <atomic> // Ensure this is present for g_aob_scan_complete_flag etc.
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

// Static global for the target module name
static std::wstring g_wModuleName = L"Destiny 2.exe";

/**
 * @brief Background thread function to initialize feature signatures and byte patterns.
 *
 * This function is designed to run in a separate thread after the target game process
 * is found and its module base address is obtained. Its primary responsibilities are:
 * 1. Calling `Features::PerformStartupAobScans` to perform Array of Bytes (AOB) scans
 *    for all defined features. This populates the `InstructionAddress` for each feature
 *    if the AOB pattern is found in the target process's memory.
 * 2. Calling `Features::PerformStartupByteReads` to read and store the original bytes
 *    at the identified instruction addresses. These original bytes are crucial for
 *    disabling features and restoring the game's original code.
 * 3. Setting the global flag `Features::g_aob_scan_complete_flag` to true upon successful
 *    completion of both scans and byte reads. This flag signals that features are ready
 *    to be activated or have their states updated.
 * 4. Setting `Features::g_aob_scan_running` to false once operations are complete or if
 *    an early exit occurs due to invalid parameters.
 *
 * This asynchronous approach prevents the main UI or game interaction thread from freezing
 * during potentially time-consuming memory scanning operations.
 *
 * @param moduleBase The base address of the target game module in the target process.
 * @param processId The Process ID (PID) of the target game process.
 */
void AsyncInitializeSignaturesAndBytes_ThreadFunc(uintptr_t moduleBase, DWORD processId) {
    if (moduleBase == 0 || processId == 0) {
        LogMessageF("[-] AsyncInitializeSignaturesAndBytes_ThreadFunc: Invalid parameters (moduleBase: 0x%llX, processId: %lu). Aborting scan.", moduleBase, processId);
        Features::g_aob_scan_running = false; // Reset running flag as we are aborting
        Features::g_aob_scan_complete_flag = false; // Ensure it's not mistakenly true
        return;
    }

    LogMessageF("[+] AsyncInitializeSignaturesAndBytes_ThreadFunc: Started for PID %lu, Base 0x%llX.", processId, moduleBase);

    // Ensure that DriverComm::g_pid is set appropriately if PerformStartupAobScans or PerformStartupByteReads implicitly rely on it.
    // The DriverComm functions (AOBScan, read_memory_buffer) use DriverComm::g_pid.
    // Since this thread is detached and DriverComm::g_pid is set in the main thread during attach_to_process,
    // there's a potential reliance on DriverComm::g_pid being valid.
    // For now, we assume DriverComm::g_pid is correctly set by the main thread's initialization logic
    // before this thread performs operations that use it. The passed `processId` parameter is used
    // for logging here but the Features functions might call DriverComm which uses its global g_pid.
    // A safer approach might be to modify Features::PerformStartupAobScans and ::PerformStartupByteReads
    // to explicitly take and use the PID, or ensure DriverComm is thread-safe regarding g_pid if used by these.
    // However, the current Features::PerformStartupAobScans and ::PerformStartupByteReads signatures
    // in Features.h *do* take a PID. So we should use the passed 'processId'.

    Features::PerformStartupAobScans(processId, moduleBase);
    Features::PerformStartupByteReads(processId, moduleBase); // Pass PID here too

    LogMessageF("[+] AsyncInitializeSignaturesAndBytes_ThreadFunc: Completed for PID %lu, Base 0x%llX.", processId, moduleBase);

    Features::g_aob_scan_complete_flag = true;
    Features::g_aob_scan_running = false;
}

/**
 * @brief Disables all active features, restores original game code, and cleans up resources.
 *
 * This function is critical for a safe shutdown or detachment from the target process.
 * It iterates through all managed features and performs the following actions for each:
 * - If the feature is currently `Enabled` and has a valid `InstructionAddress` (meaning it was hooked):
 *   - Restores the original bytes at the `InstructionAddress` to remove the hook.
 *   - If the feature had allocated a codecave (`mem_allocated` is true and `memAllocatedAddress` is valid),
 *     it calls `Features::ReleaseCodecave` to free that memory in the target process.
 * - Sets the feature's `Enabled` flag to `false`.
 *
 * Additionally, this function is responsible for stopping and joining any feature-specific
 * background threads that might be running, such as:
 * - `FlyThread` (for the LocalPlayer Fly feature)
 * - `ImmuneBossesThread` (for the ImmuneBosses feature)
 * - `g_FindPlayerThread` (for automatically finding player data)
 * - Signals the `ViewAngles::CacheLoop` to stop (though it's a detached thread and cannot be joined directly).
 *
 * The goal is to revert all modifications made to the game and terminate all driver-initiated
 * activities related to the features, ensuring the game returns to its original state and
 * no driver resources are left lingering or causing issues.
 *
 * @param pid_param The Process ID of the target game process, used for memory operations.
 */
static void DisableAndCleanupAllFeatures(DWORD pid_param) {
    LogMessage("----------------------------------------------------------");
    LogMessageF("[+] DisableAndCleanupAllFeatures: Starting cleanup for PID %lu...", pid_param);

    // --- Disable Features, Restore Bytes, Free Memory ---

    // Killaura
    if (Killaura::Enabled && Killaura::InstructionAddress.load() != 0) {
        if (Killaura::mem_allocated && Killaura::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(Killaura::InstructionAddress.load(), Killaura::origBytes, sizeof(Killaura::origBytes));
            Features::ReleaseCodecave(pid_param, Killaura::memAllocatedAddress, Killaura::mem_allocated);
            LogMessage("[-] Killaura disabled, bytes restored, codecave released.");
        } else if (Killaura::InstructionAddress.load() != 0) {
            DriverComm::write_memory_buffer(Killaura::InstructionAddress.load(), Killaura::origBytes, sizeof(Killaura::origBytes));
            LogMessage("[-] Killaura disabled, bytes restored (no codecave).");
        }
        Killaura::Enabled = false;
    }

    // Ghostmode
    if (Ghostmode::Enabled && Ghostmode::InstructionAddress.load() != 0) {
        if (Ghostmode::mem_allocated && Ghostmode::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(Ghostmode::InstructionAddress.load(), Ghostmode::origBytes, sizeof(Ghostmode::origBytes));
            Features::ReleaseCodecave(pid_param, Ghostmode::memAllocatedAddress, Ghostmode::mem_allocated);
            LogMessage("[-] Ghostmode disabled, bytes restored, codecave released.");
        }
        Ghostmode::Enabled = false;
    }

    // Godmode
    if (Godmode::Enabled && Godmode::InstructionAddress.load() != 0) {
        if (Godmode::mem_allocated && Godmode::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(Godmode::InstructionAddress.load(), Godmode::origBytes, sizeof(Godmode::origBytes));
            Features::ReleaseCodecave(pid_param, Godmode::memAllocatedAddress, Godmode::mem_allocated);
            LogMessage("[-] Godmode disabled, bytes restored, codecave released.");
        }
        Godmode::Enabled = false;
    }

    // dmgMult
    if (dmgMult::Enabled && dmgMult::InstructionAddress.load() != 0) {
        if (dmgMult::mem_allocated && dmgMult::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(dmgMult::InstructionAddress.load(), dmgMult::origBytes, sizeof(dmgMult::origBytes));
            Features::ReleaseCodecave(pid_param, dmgMult::memAllocatedAddress, dmgMult::mem_allocated);
            LogMessage("[-] dmgMult disabled, bytes restored, codecave released.");
        }
        dmgMult::Enabled = false;
    }

    // RPM
    if (RPM::Enabled && RPM::InstructionAddress.load() != 0) {
        if (RPM::mem_allocated && RPM::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(RPM::InstructionAddress.load(), RPM::origBytes, sizeof(RPM::origBytes));
            Features::ReleaseCodecave(pid_param, RPM::memAllocatedAddress, RPM::mem_allocated);
            LogMessage("[-] RPM disabled, bytes restored, codecave released.");
        }
        RPM::Enabled = false;
    }

    // NoRecoil
    if (NoRecoil::Enabled && NoRecoil::InstructionAddress.load() != 0) {
        if (NoRecoil::mem_allocated && NoRecoil::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(NoRecoil::InstructionAddress.load(), NoRecoil::origBytes, sizeof(NoRecoil::origBytes));
            Features::ReleaseCodecave(pid_param, NoRecoil::memAllocatedAddress, NoRecoil::mem_allocated);
            LogMessage("[-] NoRecoil disabled, bytes restored, codecave released.");
        }
        NoRecoil::Enabled = false;
    }

    // OHK
    if (OHK::Enabled && OHK::InstructionAddress.load() != 0) {
        if (OHK::mem_allocated && OHK::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(OHK::InstructionAddress.load(), OHK::origBytes, sizeof(OHK::origBytes));
            Features::ReleaseCodecave(pid_param, OHK::memAllocatedAddress, OHK::mem_allocated);
            LogMessage("[-] OHK disabled, bytes restored, codecave released.");
        }
        OHK::Enabled = false;
    }

    // InfStacks
    if (InfStacks::Enabled && InfStacks::InstructionAddress.load() != 0) {
        if (InfStacks::mem_allocated && InfStacks::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(InfStacks::InstructionAddress.load(), InfStacks::origBytes, sizeof(InfStacks::origBytes));
            Features::ReleaseCodecave(pid_param, InfStacks::memAllocatedAddress, InfStacks::mem_allocated);
            LogMessage("[-] InfStacks disabled, bytes restored, codecave released.");
        }
        InfStacks::Enabled = false;
    }

    // Chams
    if (Chams::Enabled && Chams::InstructionAddress.load() != 0) {
        if (Chams::mem_allocated && Chams::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(Chams::InstructionAddress.load(), Chams::origBytes, sizeof(Chams::origBytes));
            Features::ReleaseCodecave(pid_param, Chams::memAllocatedAddress, Chams::mem_allocated);
            LogMessage("[-] Chams disabled, bytes restored, codecave released.");
        }
        Chams::Enabled = false;
    }

    // InstantInteract
    if (InstantInteract::Enabled && InstantInteract::InstructionAddress.load() != 0) {
        if (InstantInteract::mem_allocated && InstantInteract::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(InstantInteract::InstructionAddress.load(), InstantInteract::origBytes, sizeof(InstantInteract::origBytes));
            Features::ReleaseCodecave(pid_param, InstantInteract::memAllocatedAddress, InstantInteract::mem_allocated);
            LogMessage("[-] InstantInteract disabled, bytes restored, codecave released.");
        }
        InstantInteract::Enabled = false;
    }

    // ImmuneAura
    if (ImmuneAura::Enabled && ImmuneAura::InstructionAddress.load() != 0) {
        if (ImmuneAura::mem_allocated && ImmuneAura::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(ImmuneAura::InstructionAddress.load(), ImmuneAura::origBytes, sizeof(ImmuneAura::origBytes));
            Features::ReleaseCodecave(pid_param, ImmuneAura::memAllocatedAddress, ImmuneAura::mem_allocated);
            LogMessage("[-] ImmuneAura disabled, bytes restored, codecave released.");
        }
        ImmuneAura::Enabled = false;
    }

    // Mag999
    if (Mag999::Enabled && Mag999::InstructionAddress.load() != 0) {
        if (Mag999::mem_allocated && Mag999::memAllocatedAddress.load() != 0) {
            DriverComm::write_memory_buffer(Mag999::InstructionAddress.load(), Mag999::origBytes, sizeof(Mag999::origBytes));
            Features::ReleaseCodecave(pid_param, Mag999::memAllocatedAddress, Mag999::mem_allocated);
            LogMessage("[-] Mag999 disabled, bytes restored, codecave released.");
        }
        Mag999::Enabled = false;
    }

    // InfAmmo & InfSwordAmmo
    if (InfAmmo::Enabled) {
        if (InfAmmo::InstructionAddress.load() != 0 && InfAmmo::mem_allocated) {
            DriverComm::write_memory_buffer(InfAmmo::InstructionAddress.load(), InfAmmo::origBytes, sizeof(InfAmmo::origBytes));
            Features::ReleaseCodecave(pid_param, InfAmmo::memAllocatedAddress, InfAmmo::mem_allocated);
            LogMessage("[-] InfAmmo main hook disabled, bytes restored, codecave released.");
        }
        if (InfSwordAmmo::InstructionAddress.load() != 0) {
            DriverComm::write_memory_buffer(InfSwordAmmo::InstructionAddress.load(), InfSwordAmmo::origBytes, sizeof(InfSwordAmmo::origBytes));
            LogMessage("[-] InfSwordAmmo NOPs restored.");
        }
        InfAmmo::Enabled = false;
    }

    // InstaRespawn & RespawnAnywhere
    if (InstaRespawn::Enabled) {
        if (InstaRespawn::InstructionAddress.load() != 0) {
            DriverComm::write_memory_buffer(InstaRespawn::InstructionAddress.load(), InstaRespawn::origBytes, sizeof(InstaRespawn::origBytes));
            LogMessage("[-] InstaRespawn direct patch restored.");
        }
        if (RespawnAnywhere::InstructionAddress.load() != 0 && RespawnAnywhere::mem_allocated) {
            DriverComm::write_memory_buffer(RespawnAnywhere::InstructionAddress.load(), RespawnAnywhere::origBytes, sizeof(RespawnAnywhere::origBytes));
            Features::ReleaseCodecave(pid_param, RespawnAnywhere::memAllocatedAddress, RespawnAnywhere::mem_allocated);
            LogMessage("[-] RespawnAnywhere hook disabled, bytes restored, codecave released.");
        }
        InstaRespawn::Enabled = false;
    }

    // InteractThruWalls
    if (InteractThruWalls::Enabled) {
        if (InteractThruWalls::InstructionAddress1.load() != 0 && InteractThruWalls::mem_allocated1) {
            DriverComm::write_memory_buffer(InteractThruWalls::InstructionAddress1.load(), InteractThruWalls::origBytes1, sizeof(InteractThruWalls::origBytes1));
            Features::ReleaseCodecave(pid_param, InteractThruWalls::memAllocatedAddress1, InteractThruWalls::mem_allocated1);
            LogMessage("[-] InteractThruWalls Hook 1 disabled, bytes restored, codecave released.");
        }
        if (InteractThruWalls::InstructionAddress2.load() != 0 && InteractThruWalls::mem_allocated2) {
            DriverComm::write_memory_buffer(InteractThruWalls::InstructionAddress2.load(), InteractThruWalls::origBytes2, sizeof(InteractThruWalls::origBytes2));
            Features::ReleaseCodecave(pid_param, InteractThruWalls::memAllocatedAddress2, InteractThruWalls::mem_allocated2);
            LogMessage("[-] InteractThruWalls Hook 2 disabled, bytes restored, codecave released.");
        }
        InteractThruWalls::Enabled = false;
    }

    // AbilityCharge
    if (AbilityCharge::Enabled && AbilityCharge::InstructionAddress.load() != 0) {
        DriverComm::write_memory_buffer(AbilityCharge::InstructionAddress.load(), AbilityCharge::origBytes, sizeof(AbilityCharge::origBytes));
        LogMessageF("[-] AbilityCharge hook bytes restored at 0x%llX.", AbilityCharge::InstructionAddress.load());
        if (AbilityCharge::mem_allocated && AbilityCharge::memAllocatedAddress.load() != 0) {
            Features::ReleaseCodecave(pid_param, AbilityCharge::memAllocatedAddress, AbilityCharge::mem_allocated);
            LogMessage("[-] AbilityCharge codecave released.");
        } else {
            LogMessage("[-] AbilityCharge (no codecave to release or not allocated by this feature).");
        }
        AbilityCharge::Enabled = false;
    }

    // LocalPlayer and ViewAngles
    if (LocalPlayer::Enabled) {
        if (LocalPlayer::InstructionAddress.load() != 0 && LocalPlayer::mem_allocated) {
            DriverComm::write_memory_buffer(LocalPlayer::InstructionAddress.load(), LocalPlayer::origBytes, sizeof(LocalPlayer::origBytes));
            Features::ReleaseCodecave(pid_param, LocalPlayer::memAllocatedAddress, LocalPlayer::mem_allocated);
        }
        if (Features::LocalPlayer::flyEnabled && LocalPlayer::disableGravAddress.load() != 0 && LocalPlayer::disableGrav_mem_allocated) {
             DriverComm::write_memory_buffer(LocalPlayer::disableGravAddress.load(), LocalPlayer::disableGravOrigBytes, sizeof(LocalPlayer::disableGravOrigBytes));
             Features::ReleaseCodecave(pid_param, LocalPlayer::disableGravMemAllocatedAddress, LocalPlayer::disableGrav_mem_allocated);
             LogMessage("[-] Fly (gravity part) disabled, bytes restored, codecave released.");
        }
        if (LocalPlayer::addrMemAllocatedAddress.load() != 0 && LocalPlayer::addr_mem_allocated) {
            DriverComm::free_memory_ex(pid_param, LocalPlayer::addrMemAllocatedAddress.load(), 0);
            LocalPlayer::addrMemAllocatedAddress.store(0);
            LocalPlayer::addr_mem_allocated = false;
        }
        LocalPlayer::Enabled = false;
        LogMessage("[-] LocalPlayer related features disabled, memory freed.");
    }
    // ViewAngles cleanup
    DisableViewAngleHook();
    if (ViewAngles::addrMemAllocatedAddress.load() != 0 && ViewAngles::addr_mem_allocated) {
        DriverComm::free_memory_ex(pid_param, ViewAngles::addrMemAllocatedAddress.load(), 0);
        ViewAngles::addrMemAllocatedAddress.store(0);
        ViewAngles::addr_mem_allocated = false;
        LogMessage("[-] ViewAngles addrMemAllocatedAddress freed.");
    }
    ViewAngles::Enabled = false;

    // ActivityLoader
    if (ActivityLoader::Enabled) {
        if (ActivityLoader::InstructionAddress.load() != 0 && ActivityLoader::mem_allocated) {
            DriverComm::write_memory_buffer(ActivityLoader::InstructionAddress.load(), ActivityLoader::origBytes, sizeof(ActivityLoader::origBytes));
            Features::ReleaseCodecave(pid_param, ActivityLoader::memAllocatedAddress, ActivityLoader::mem_allocated);
        }
        if (ActivityLoader::addrMemAllocatedAddress.load() != 0 && ActivityLoader::addr_mem_allocated) {
            DriverComm::free_memory_ex(pid_param, ActivityLoader::addrMemAllocatedAddress.load(), 0);
            ActivityLoader::addrMemAllocatedAddress.store(0);
            ActivityLoader::addr_mem_allocated = false;
        }
        ActivityLoader::Enabled = false;
        LogMessage("[-] ActivityLoader disabled, memory freed.");
    }

    // Simple NOP/Byte Patch Features (Restoration)
    if (NoJoinAllies::Enabled && NoJoinAllies::InstructionAddress.load() != 0) { DriverComm::write_memory_buffer(NoJoinAllies::InstructionAddress.load(), NoJoinAllies::origBytes, sizeof(NoJoinAllies::origBytes)); NoJoinAllies::Enabled = false; LogMessage("[-] NoJoinAllies disabled."); }
    if (NoTurnBack::Enabled && NoTurnBack::InstructionAddress.load() != 0) { DriverComm::write_memory_buffer(NoTurnBack::InstructionAddress.load(), NoTurnBack::origBytes, sizeof(NoTurnBack::origBytes)); NoTurnBack::Enabled = false; LogMessage("[-] NoTurnBack disabled."); }
    if (SparrowAnywhere::Enabled && SparrowAnywhere::InstructionAddress.load() != 0) { DriverComm::write_memory(SparrowAnywhere::InstructionAddress.load(), SparrowAnywhere::origByte); SparrowAnywhere::Enabled = false; LogMessage("[-] SparrowAnywhere disabled."); }
    if (NoRezTokens::Enabled && NoRezTokens::InstructionAddress.load() != 0) { DriverComm::write_memory(NoRezTokens::InstructionAddress.load(), NoRezTokens::origByte); NoRezTokens::Enabled = false; LogMessage("[-] NoRezTokens disabled."); }
    if (ShootThru::Enabled && ShootThru::InstructionAddress.load() != 0) { DriverComm::write_memory_buffer(ShootThru::InstructionAddress.load(), ShootThru::origBytes, sizeof(ShootThru::origBytes)); ShootThru::Enabled = false; LogMessage("[-] ShootThruWalls disabled."); }
    if (IcarusDash::Enabled && IcarusDash::InstructionAddress.load() != 0) { DriverComm::write_memory_buffer(IcarusDash::InstructionAddress.load(), IcarusDash::origBytes, sizeof(IcarusDash::origBytes)); IcarusDash::Enabled = false; LogMessage("[-] IcarusDash disabled."); }
    if (LobbyCrasher::Enabled && LobbyCrasher::InstructionAddress.load() != 0) { DriverComm::write_memory_buffer(LobbyCrasher::InstructionAddress.load(), LobbyCrasher::origBytes, sizeof(LobbyCrasher::origBytes)); LobbyCrasher::Enabled = false; LogMessage("[-] LobbyCrasher disabled."); }
    if (Oxygen::Enabled && Oxygen::InstructionAddress.load() != 0) { DriverComm::write_memory_buffer(Oxygen::InstructionAddress.load(), Oxygen::origBytes, sizeof(Oxygen::origBytes)); Oxygen::Enabled = false; LogMessage("[-] Oxygen disabled."); }
    if (InfSparrowBoost::Enabled && InfSparrowBoost::InstructionAddress.load() != 0) { DriverComm::write_memory(InfSparrowBoost::InstructionAddress.load(), InfSparrowBoost::origByte); InfSparrowBoost::Enabled = false; LogMessage("[-] InfSparrowBoost disabled."); }
    if (InfBuffTimers::Enabled && InfBuffTimers::InstructionAddress.load() != 0) { DriverComm::write_memory_buffer(InfBuffTimers::InstructionAddress.load(), InfBuffTimers::origBytes, sizeof(InfBuffTimers::origBytes)); InfBuffTimers::Enabled = false; LogMessage("[-] InfBuffTimers disabled."); }
    if (InfExoticBuffTimers::Enabled && InfExoticBuffTimers::InstructionAddress.load() != 0) { DriverComm::write_memory_buffer(InfExoticBuffTimers::InstructionAddress.load(), InfExoticBuffTimers::origBytes, sizeof(InfExoticBuffTimers::origBytes)); InfExoticBuffTimers::Enabled = false; LogMessage("[-] InfExoticBuffTimers disabled."); }
    if (AntiFlinch::Enabled) {
        if(AntiFlinch::InstructionAddress1.load() != 0) DriverComm::write_memory_buffer(AntiFlinch::InstructionAddress1.load(), AntiFlinch::origBytes1, sizeof(AntiFlinch::origBytes1));
        if(AntiFlinch::InstructionAddress2.load() != 0) DriverComm::write_memory_buffer(AntiFlinch::InstructionAddress2.load(), AntiFlinch::origBytes2, sizeof(AntiFlinch::origBytes2));
        if(AntiFlinch::InstructionAddress3.load() != 0) DriverComm::write_memory_buffer(AntiFlinch::InstructionAddress3.load(), AntiFlinch::origBytes3, sizeof(AntiFlinch::origBytes3));
        AntiFlinch::Enabled = false; LogMessage("[-] AntiFlinch disabled.");
    }
    if (GameSpeed::Enabled && GameSpeed::Address.load() != 0 && GameSpeed::WasKeyDown) {
        DriverComm::write_memory(GameSpeed::Address.load(), GameSpeed::NormalValue);
        LogMessage("[-] GameSpeed restored to normal.");
    }
    GameSpeed::Enabled = false; GameSpeed::WasKeyDown = false;

    if (ImmuneBosses::Enabled.load() && ImmuneBosses::Address.load() != 0) {
        float one = 1.0f; DriverComm::write_memory(ImmuneBosses::Address.load(), one);
        LogMessage("[-] ImmuneBosses restored to normal.");
    }
    ImmuneBosses::Enabled.store(false);

    // --- Stop and Join Threads ---
    if (Features::LocalPlayer::flyEnabled) {
         Features::LocalPlayer::flyEnabled = false;
    }
    StopFlyThread = true;
    if (FlyThread.joinable()) {
        LogMessage("[+] DisableAndCleanupAllFeatures: Joining FlyThread...");
        FlyThread.join();
        LogMessage("[+] DisableAndCleanupAllFeatures: FlyThread joined.");
    } else {
        LogMessage("[!] DisableAndCleanupAllFeatures: FlyThread was not joinable at shutdown (might be normal if never started or already stopped).");
    }

    ImmuneBosses::Enabled.store(false);
    ImmuneBosses::ThreadRunning.store(false);
    if (ImmuneBossesThread.joinable()) {
        LogMessage("[+] Joining ImmuneBossesThread...");
        ImmuneBossesThread.join();
        LogMessage("[+] ImmuneBossesThread joined.");
    } else {
        LogMessage("[!] ImmuneBossesThread was not joinable (already joined or not started).");
    }

    g_FindPlayerEnabled = false;
    g_StopFindThread = true;
    if (g_FindPlayerThread.joinable()) {
        LogMessage("[+] Joining g_FindPlayerThread (AutoFindPlayerLoop)...");
        g_FindPlayerThread.join();
        LogMessage("[+] g_FindPlayerThread joined.");
    } else {
        LogMessage("[!] g_FindPlayerThread was not joinable (already joined or not started).");
    }

    ViewAngles::g_cacheThreadRunning.store(false);
    LogMessage("[+] ViewAngles::CacheLoop signaled to stop (detached thread, cannot join).");

    LogMessage("[+] DisableAndCleanupAllFeatures: Feature cleanup and thread processing complete.");
    LogMessage("----------------------------------------------------------");
}


// Global instruction toggles
// Note: pid and moduleBaseAddress are now global to Drawing.cpp, set during initialization in Drawing::Draw
static std::map<std::string, bool> g_feature_critical_error_flags; // UI error flags
static DWORD g_current_pid_drawing = 0;
static uintptr_t g_moduleBaseAddress_drawing = 0;

/**
 * @brief Resets all feature states and critical global variables to their default/initial values.
 *
 * This function is typically called when the target process is lost or during a full
 * re-initialization of the cheat. Its main responsibilities are:
 * - Setting all feature `Enabled` flags (e.g., `Killaura::Enabled`, `LocalPlayer::Enabled`) to `false`.
 * - Clearing all stored runtime data for each feature. This includes:
 *   - `InstructionAddress`: The resolved memory address of the hooked instruction.
 *   - `memAllocatedAddress`: The address of any codecave allocated for the feature.
 *   - `mem_allocated`: The flag indicating if a codecave was allocated.
 *   - For features with multiple hooks or specific pointer storage (like `LocalPlayer`, `ViewAngles`,
 *     `ActivityLoader`, `InteractThruWalls`), their respective address and allocation flag variables
 *     are also reset (e.g., `LocalPlayer::addrMemAllocatedAddress`, `LocalPlayer::addr_mem_allocated`).
 * - Resetting any other feature-specific state variables to their defaults (e.g., `LocalPlayer::flyEnabled`,
 *   `AbilityCharge::WasKeyDown`).
 * - Clearing global state variables related to the attached game process:
 *   - `isInitialized`: Set to `false`.
 *   - `g_current_pid_drawing`: Set to `0`.
 *   - `g_moduleBaseAddress_drawing`: Set to `0`.
 * - Resetting UI-specific error flags (`g_feature_critical_error_flags`) for all features.
 *
 * This function ensures that the system is in a clean state before attempting a new
 * attachment to a process or when the current attachment is no longer valid.
 */
static void ResetAllFeatureStates() {
    LogMessage("[+] Resetting all feature states, addresses, and flags.");

    // --- Killaura ---
    Killaura::InstructionAddress.store(0); Killaura::memAllocatedAddress.store(0); Killaura::mem_allocated = false; Killaura::Enabled = false; g_feature_critical_error_flags["Killaura"] = false;
    // --- LocalPlayer ---
    LocalPlayer::InstructionAddress.store(0); LocalPlayer::memAllocatedAddress.store(0); LocalPlayer::mem_allocated = false; LocalPlayer::Enabled = false; g_feature_critical_error_flags["LocalPlayer"] = false;
    LocalPlayer::addrMemAllocatedAddress.store(0); LocalPlayer::addr_mem_allocated = false;
    LocalPlayer::disableGravAddress.store(0); LocalPlayer::disableGravMemAllocatedAddress.store(0); LocalPlayer::disableGrav_mem_allocated = false;
    LocalPlayer::realPlayer.store(0); LocalPlayer::flyEnabled = false; LocalPlayer::KillKeyEnabled = false;
    // --- ViewAngles ---
    ViewAngles::InstructionAddress.store(0); ViewAngles::memAllocatedAddress.store(0); ViewAngles::mem_allocated = false; /*ViewAngles::Enabled is tied to LocalPlayer*/ g_feature_critical_error_flags["ViewAngles"] = false;
    ViewAngles::addrMemAllocatedAddress.store(0); ViewAngles::addr_mem_allocated = false;
    ViewAngles::g_viewBase.store(0); ViewAngles::g_cacheThreadRunning.store(false);
    // --- Ghostmode ---
    Ghostmode::InstructionAddress.store(0); Ghostmode::memAllocatedAddress.store(0); Ghostmode::mem_allocated = false; Ghostmode::Enabled = false; g_feature_critical_error_flags["Ghostmode"] = false;
    // --- Godmode ---
    Godmode::InstructionAddress.store(0); Godmode::memAllocatedAddress.store(0); Godmode::mem_allocated = false; Godmode::Enabled = false; g_feature_critical_error_flags["Godmode"] = false;
    // --- InfAmmo & InfSwordAmmo ---
    InfAmmo::InstructionAddress.store(0); InfAmmo::memAllocatedAddress.store(0); InfAmmo::mem_allocated = false; InfAmmo::Enabled = false; g_feature_critical_error_flags["InfAmmo"] = false;
    InfSwordAmmo::InstructionAddress.store(0); // InfSwordAmmo has no Enabled flag of its own or mem_allocated
    // --- dmgMult ---
    dmgMult::InstructionAddress.store(0); dmgMult::memAllocatedAddress.store(0); dmgMult::mem_allocated = false; dmgMult::Enabled = false; g_feature_critical_error_flags["dmgMult"] = false;
    // --- FOV ---
    FOV::ptr.store(0); // FOV::fov is a value, not a flag, reset if needed based on default. FOV::Enabled doesn't exist.
    // --- RPM ---
    RPM::InstructionAddress.store(0); RPM::memAllocatedAddress.store(0); RPM::mem_allocated = false; RPM::Enabled = false; g_feature_critical_error_flags["RPM"] = false;
    // --- NoRecoil ---
    NoRecoil::InstructionAddress.store(0); NoRecoil::memAllocatedAddress.store(0); NoRecoil::mem_allocated = false; NoRecoil::Enabled = false; g_feature_critical_error_flags["NoRecoil"] = false;
    // --- OHK ---
    OHK::InstructionAddress.store(0); OHK::memAllocatedAddress.store(0); OHK::mem_allocated = false; OHK::Enabled = false; g_feature_critical_error_flags["OHK"] = false;
    // --- NoJoinAllies ---
    NoJoinAllies::InstructionAddress.store(0); NoJoinAllies::Enabled = false; g_feature_critical_error_flags["NoJoinAllies"] = false;
    // --- NoTurnBack ---
    NoTurnBack::InstructionAddress.store(0); NoTurnBack::Enabled = false; g_feature_critical_error_flags["NoTurnBack"] = false;
    // --- SparrowAnywhere ---
    SparrowAnywhere::InstructionAddress.store(0); SparrowAnywhere::Enabled = false; g_feature_critical_error_flags["SparrowAnywhere"] = false;
    // --- InfStacks ---
    InfStacks::InstructionAddress.store(0); InfStacks::memAllocatedAddress.store(0); InfStacks::mem_allocated = false; InfStacks::Enabled = false; g_feature_critical_error_flags["InfStacks"] = false;
    // --- NoRezTokens ---
    NoRezTokens::InstructionAddress.store(0); NoRezTokens::Enabled = false; g_feature_critical_error_flags["NoRezTokens"] = false;
    // --- InstaRespawn & RespawnAnywhere ---
    InstaRespawn::InstructionAddress.store(0); InstaRespawn::Enabled = false; g_feature_critical_error_flags["InstaRespawn"] = false;
    RespawnAnywhere::InstructionAddress.store(0); RespawnAnywhere::memAllocatedAddress.store(0); RespawnAnywhere::mem_allocated = false; // RespawnAnywhere::Enabled is tied to InstaRespawn::Enabled
    // --- ShootThru ---
    ShootThru::InstructionAddress.store(0); ShootThru::Enabled = false; g_feature_critical_error_flags["ShootThru"] = false;
    // --- Chams ---
    Chams::InstructionAddress.store(0); Chams::memAllocatedAddress.store(0); Chams::mem_allocated = false; Chams::Enabled = false; g_feature_critical_error_flags["Chams"] = false;
    // --- ImmuneBosses ---
    ImmuneBosses::Address.store(0); ImmuneBosses::Enabled.store(false); ImmuneBosses::ThreadRunning.store(false); // No specific error flag in g_feature_critical_error_flags for this one typically
    // --- AbilityCharge ---
    AbilityCharge::InstructionAddress.store(0); AbilityCharge::memAllocatedAddress.store(0); AbilityCharge::mem_allocated = false; AbilityCharge::Enabled = false; g_feature_critical_error_flags["AbilityCharge"] = false; AbilityCharge::WasKeyDown = false;
    // --- ImmuneAura ---
    ImmuneAura::InstructionAddress.store(0); ImmuneAura::memAllocatedAddress.store(0); ImmuneAura::mem_allocated = false; ImmuneAura::Enabled = false; g_feature_critical_error_flags["ImmuneAura"] = false;
    // --- IcarusDash ---
    IcarusDash::InstructionAddress.store(0); IcarusDash::Enabled = false; g_feature_critical_error_flags["IcarusDash"] = false;
    // --- InstantInteract ---
    InstantInteract::InstructionAddress.store(0); InstantInteract::memAllocatedAddress.store(0); InstantInteract::mem_allocated = false; InstantInteract::Enabled = false; g_feature_critical_error_flags["InstantInteract"] = false;
    // --- InteractThruWalls ---
    InteractThruWalls::InstructionAddress1.store(0); InteractThruWalls::memAllocatedAddress1.store(0); InteractThruWalls::mem_allocated1 = false;
    InteractThruWalls::InstructionAddress2.store(0); InteractThruWalls::memAllocatedAddress2.store(0); InteractThruWalls::mem_allocated2 = false;
    InteractThruWalls::Enabled = false; g_feature_critical_error_flags["InteractThruWalls"] = false;
    // --- GameSpeed ---
    GameSpeed::Address.store(0); GameSpeed::Enabled = false; GameSpeed::WasKeyDown = false; // No specific error flag
    // --- LobbyCrasher ---
    LobbyCrasher::InstructionAddress.store(0); LobbyCrasher::Enabled = false; g_feature_critical_error_flags["LobbyCrasher"] = false;
    // --- GSize ---
    GSize::Address.store(0); GSize::Enabled = false; // GSize::Value and inputVal are UI state, reset if desired, but not critical addresses.
    // --- Oxygen ---
    Oxygen::InstructionAddress.store(0); Oxygen::Enabled = false; g_feature_critical_error_flags["Oxygen"] = false;
    // --- InfSparrowBoost ---
    InfSparrowBoost::InstructionAddress.store(0); InfSparrowBoost::Enabled = false; g_feature_critical_error_flags["InfSparrowBoost"] = false;
    // --- InfBuffTimers ---
    InfBuffTimers::InstructionAddress.store(0); InfBuffTimers::Enabled = false; g_feature_critical_error_flags["InfBuffTimers"] = false;
    // --- InfExoticBuffTimers ---
    InfExoticBuffTimers::InstructionAddress.store(0); InfExoticBuffTimers::Enabled = false; g_feature_critical_error_flags["InfExoticBuffTimers"] = false;
    // --- AntiFlinch ---
    AntiFlinch::InstructionAddress1.store(0); AntiFlinch::InstructionAddress2.store(0); AntiFlinch::InstructionAddress3.store(0); AntiFlinch::Enabled = false; g_feature_critical_error_flags["AntiFlinch"] = false;
    // --- ActivityLoader ---
    ActivityLoader::InstructionAddress.store(0); ActivityLoader::memAllocatedAddress.store(0); ActivityLoader::mem_allocated = false;
    ActivityLoader::addrMemAllocatedAddress.store(0); ActivityLoader::addr_mem_allocated = false;
    ActivityLoader::Enabled = false; g_feature_critical_error_flags["ActivityLoader"] = false;
    // --- Mag999 ---
    Mag999::InstructionAddress.store(0); Mag999::memAllocatedAddress.store(0); Mag999::mem_allocated = false; Mag999::Enabled = false; g_feature_critical_error_flags["Mag999"] = false;

    // Reset main state vars associated with process
    isInitialized = false;
    g_current_pid_drawing = 0;
    g_moduleBaseAddress_drawing = 0;
}

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
        LogMessage("[-] [ActualImmuneBossesThreadLogic] Module base address is 0. Cannot perform AOB scan."); // Kept for release
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
            LogMessageF("[-] [ActualImmuneBossesThreadLogic] Failed to write to address 0x%llX.", found_addr); // Kept for release
            ImmuneBosses::Address = 0;
            ImmuneBosses::Enabled = false; // Disable if write failed
        }
    } else {
        LogMessage("[-] [ActualImmuneBossesThreadLogic] Boss health AOB not found."); // Kept for release
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

/**
 * @brief Polls for the Fly feature hotkey and manages its state.
 *
 * Checks if the FlyToggle hotkey (default F1) is pressed. If so, it toggles `LocalPlayer::flyEnabled`.
 * If fly mode is newly enabled:
 *   - Injects shellcode to disable gravity if `LocalPlayer::disableGravAddress` is valid.
 *   - Starts the `FlyLoop` thread to handle flight mechanics.
 * If fly mode is newly disabled:
 *   - Restores original bytes at `LocalPlayer::disableGravAddress` to re-enable gravity.
 *   - Signals the `FlyLoop` thread to stop and joins it.
 */
void PollFly() {
    static bool previousFlyState = false;
    uintptr_t destinyBaseForFly = g_moduleBaseAddress_drawing + LocalPlayer::destinyBase;

    bool flyKeyDown = (GetAsyncKeyState(Hotkeys["FlyToggle"]) & 0x8000) != 0;
    if (flyKeyDown && !wasFlyKeyDown && LocalPlayer::Enabled) {
        Features::LocalPlayer::flyEnabled = !Features::LocalPlayer::flyEnabled;
        #ifdef _DEBUG
        LogMessageF("[+] [PollFly] Fly Toggled: %s", (Features::LocalPlayer::flyEnabled ? "ON" : "OFF"));
        #endif
    }
    wasFlyKeyDown = flyKeyDown;

    if (Features::LocalPlayer::flyEnabled && !previousFlyState) {
        if (LocalPlayer::disableGravAddress != 0) {
            std::vector<BYTE> disableGravShellcodeBytes = HexToBytes(LocalPlayer::disableGravShellcode_hex);
            uintptr_t temp_cave_addr_grav = LocalPlayer::disableGravMemAllocatedAddress;
            if(!Features::InjectCodecave(g_current_pid_drawing, LocalPlayer::disableGravAddress, disableGravShellcodeBytes, sizeof(LocalPlayer::disableGravOrigBytes), temp_cave_addr_grav)) {
                 LogMessageF("[-] [PollFly] Failed to inject disableGravShellcode at 0x%llX.", LocalPlayer::disableGravAddress);
                 Features::LocalPlayer::flyEnabled = false;
            } else {
                LocalPlayer::disableGravMemAllocatedAddress = temp_cave_addr_grav;
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
            if (FlyThread.joinable()) {
                FlyThread.join();
            }
            FlyThread = std::thread(FlyLoop, destinyBaseForFly);
            #ifdef _DEBUG
            LogMessage("[+] [PollFly] FlyLoop thread started (now joinable).");
            #endif
        }
    } else if (!Features::LocalPlayer::flyEnabled && previousFlyState) {
        StopFlyThread = true;
        if (LocalPlayer::disableGravAddress != 0 && LocalPlayer::disableGrav_mem_allocated) {
            if(DriverComm::write_memory_buffer(LocalPlayer::disableGravAddress, LocalPlayer::disableGravOrigBytes, sizeof(LocalPlayer::disableGravOrigBytes))){
                #ifdef _DEBUG
                LogMessageF("[-] [PollFly] Restored original bytes for disable gravity at 0x%llX.", LocalPlayer::disableGravAddress);
                #endif
            } else {
                LogMessageF("[-] [PollFly] Failed to restore original bytes for disable gravity at 0x%llX.", LocalPlayer::disableGravAddress);
            }
        }
        if (FlyThread.joinable()) {
            FlyThread.join();
            #ifdef _DEBUG
            LogMessage("[+] [PollFly] FlyThread joined on disable.");
            #endif
        }
        #ifdef _DEBUG
        LogMessage("[-] [PollFly] FlyLoop thread signaled to stop and joined.");
        #endif
    }
    previousFlyState = Features::LocalPlayer::flyEnabled;
}

/**
 * @brief Polls for the Suicide Key hotkey and performs the action if enabled.
 *
 * Checks if the SuicideKey hotkey (default VK_DELETE) is pressed.
 * If pressed and the feature `LocalPlayer::KillKeyEnabled` is active and a valid player pointer exists:
 *   - Modifies player coordinates and velocity to simulate a death/fall out of bounds.
 */
void PollKillKey() {
    if (!LocalPlayer::Enabled || !LocalPlayer::KillKeyEnabled || LocalPlayer::realPlayer.load() == 0 || DriverComm::g_pid == 0)
        return;

    bool keyNowDown = GetAsyncKeyState(Hotkeys["SuicideKey"]) & 0x8000;

    if (keyNowDown && !LocalPlayer::KillKeyWasDown) {
        uintptr_t playerBase = LocalPlayer::realPlayer.load();
        if (playerBase == 0) {
             LogMessage("[-] [PollKillKey] playerBase is 0. Cannot perform action.");
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

void RenderKillKeyUI() {
    if (Hotkeys["SuicideKey"] == 0)
        Hotkeys["SuicideKey"] = LocalPlayer::KillKey;

    ImGui::BeginDisabled(!LocalPlayer::Enabled);

    ImGui::Toggle("Suicide Key", &LocalPlayer::KillKeyEnabled);
    ImGui::SameLine();
    static bool listening = false;
    DrawHotkeyPicker("SuicideKey", "Key", listening);

    ImGui::EndDisabled();
}

void RenderAbilityChargeUI() {
    if (Hotkeys["AbilityCharge"] == 0)
        Hotkeys["AbilityCharge"] = VK_5;

    ImGui::Toggle("Ability", &AbilityCharge::Enabled);
    ImGui::SameLine();
    static bool listening = false;
    DrawHotkeyPicker("Ability", "Key", listening);
}

/**
 * @brief Polls for the Ability Charge hotkey and applies/removes the hook.
 *
 * This function implements a "hold-to-activate" mechanism for the AbilityCharge feature.
 * - When the AbilityCharge hotkey (default VK_5) is pressed and `AbilityCharge::Enabled` is true:
 *   - Injects shellcode at `AbilityCharge::InstructionAddress` to modify ability cooldowns/charge.
 * - When the hotkey is released:
 *   - Restores the original bytes at `AbilityCharge::InstructionAddress`.
 *   - Releases the codecave if it was allocated by this feature.
 * If the feature is globally disabled via `AbilityCharge::Enabled`, it ensures any active hook is removed.
 */
void PollAbilityCharge() {
    static bool wasInjected = false;
    static bool currentKeyIsDown = false;

    int vk = Hotkeys["AbilityCharge"];
    if (vk == 0 || vk == -1) return;

    if (!AbilityCharge::Enabled) {
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
        currentKeyIsDown = false;
        return;
    }

    bool keyNowDown = (GetAsyncKeyState(vk) & 0x8000) != 0;

    if (keyNowDown && !currentKeyIsDown) {
        if (AbilityCharge::InstructionAddress != 0) {
            uintptr_t temp_cave_addr = AbilityCharge::memAllocatedAddress.load();
            if(Features::InjectCodecave(g_current_pid_drawing, AbilityCharge::InstructionAddress, AbilityCharge::shellcode, sizeof(AbilityCharge::origBytes), AbilityCharge::memAllocatedAddress)){
                AbilityCharge::mem_allocated = true;
                wasInjected = true;
                #ifdef _DEBUG
                LogMessageF("[+] [PollAbilityCharge] Activated (hooked) at 0x%llX. Codecave: 0x%llX.", AbilityCharge::InstructionAddress.load(), AbilityCharge::memAllocatedAddress.load());
                #endif
            } else {
                LogMessageF("[-] [PollAbilityCharge] InjectCodecave failed for 0x%llX.", AbilityCharge::InstructionAddress);
            }
        } else {
            LogMessage("[-] [PollAbilityCharge] InstructionAddress is 0. Cannot activate.");
        }
    } else if (!keyNowDown && currentKeyIsDown) {
        if (wasInjected && AbilityCharge::InstructionAddress != 0) {
            if (DriverComm::write_memory_buffer(AbilityCharge::InstructionAddress.load(), AbilityCharge::origBytes, sizeof(AbilityCharge::origBytes))) {
                #ifdef _DEBUG
                LogMessageF("[-] [PollAbilityCharge] Deactivated (original bytes restored) at 0x%llX.", AbilityCharge::InstructionAddress.load());
                #endif
                if (AbilityCharge::mem_allocated) {
                    Features::ReleaseCodecave(g_current_pid_drawing, AbilityCharge::memAllocatedAddress, AbilityCharge::mem_allocated);
                }
            } else {
                 LogMessageF("[-] [PollAbilityCharge] Failed to restore original bytes on key release for 0x%llX.", AbilityCharge::InstructionAddress.load());
            }
            wasInjected = false;
        } else if (wasInjected) {
            LogMessage("[-] [PollAbilityCharge] InstructionAddress is 0 on key release but was previously injected. Cannot restore bytes.");
            wasInjected = false;
        }
    }
    currentKeyIsDown = keyNowDown;
}

void RenderImmuneBossesUI(DWORD pid_param) {
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

/**
 * @brief Polls for the Immune Bosses feature toggle and manages its state.
 *
 * If `ImmuneBosses::Enabled` is toggled on:
 *   - Resets `ImmuneBosses::Address`.
 *   - Starts the `ActualImmuneBossesThreadLogic` thread to perform an AOB scan and patch boss health values.
 * If `ImmuneBosses::Enabled` is toggled off:
 *   - If a valid address was patched, restores the boss health value to normal (1.0f).
 *   - Clears the stored address.
 *   - Ensures the `ActualImmuneBossesThreadLogic` thread is joined if it was running.
 */
void PollImmuneBosses() {
    bool nowEnabled = ImmuneBosses::Enabled.load();
    if (nowEnabled && !wasImmuneBossesEnabled && !ImmuneBosses::ThreadRunning.load()) {
        ImmuneBosses::Address = 0;
        if(ImmuneBossesThread.joinable()) ImmuneBossesThread.join();
        ImmuneBossesThread = std::thread(ActualImmuneBossesThreadLogic, g_current_pid_drawing);
        ImmuneBossesThread.detach();
        #ifdef _DEBUG
        LogMessage("[+] [PollImmuneBosses] Started ActualImmuneBossesThreadLogic due to feature enable.");
        #endif
    } else if (!nowEnabled && wasImmuneBossesEnabled) {
        if (ImmuneBosses::Address != 0) {
            float one = 1.0f;
            if (DriverComm::write_memory(ImmuneBosses::Address, one)) {
                #ifdef _DEBUG
                LogMessageF("[-] [PollImmuneBosses] Immune Bosses restored to 1.0f at 0x%llX.", ImmuneBosses::Address);
                #endif
            } else {
                LogMessageF("[-] [PollImmuneBosses] Failed to restore Immune Bosses value at 0x%llX.", ImmuneBosses::Address);
            }
            ImmuneBosses::Address = 0;
        } else {
            #ifdef _DEBUG
            LogMessage("[-] [PollImmuneBosses] Feature disabled, but no valid address was set. No restoration needed.");
            #endif
        }
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

/**
 * @brief Polls for the GameSpeed hotkey and applies speed modifications.
 *
 * This function implements a "hold-to-activate" mechanism for game speed modification.
 * - When the GameSpeed hotkey (default VK_CAPITAL) is pressed and `GameSpeed::Enabled` is true:
 *   - Writes `GameSpeed::FastValue` to `GameSpeed::Address`.
 * - When the hotkey is released:
 *   - Writes `GameSpeed::NormalValue` to `GameSpeed::Address`.
 * If the feature is globally disabled (`GameSpeed::Enabled` is false), it ensures the game speed is restored to normal.
 */
void PollGameSpeed() {
    if (!GameSpeed::Enabled) {
        if (GameSpeed::WasKeyDown && GameSpeed::Address != 0) {
             if (!DriverComm::write_memory(GameSpeed::Address, GameSpeed::NormalValue)) {
                LogMessageF("[-] [PollGameSpeed] Write failed for restoring GameSpeed::NormalValue at 0x%llX on global disable.", GameSpeed::Address);
            } else {
                #ifdef _DEBUG
                LogMessageF("[-] [PollGameSpeed] Restored GameSpeed to NormalValue due to global disable. Address: 0x%llX.", GameSpeed::Address);
                #endif
            }
            GameSpeed::WasKeyDown = false;
        }
        return;
    }

    if (GameSpeed::Address == 0) {
        #ifdef _DEBUG
        // static bool initialLogDone = false; if (!initialLogDone && GameSpeed::Enabled) { /* std::cout removed */ }
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
            #ifdef _DEBUG
            LogMessageF("[-] [PollGameSpeed] Write failed for GameSpeed::%s at 0x%llX.", speedState, GameSpeed::Address);
            #endif
        } else {
            #ifdef _DEBUG
            LogMessageF("[+] [PollGameSpeed] Set to %s (%f) at 0x%llX.", speedState, valueToSet, GameSpeed::Address);
            #endif
        }
        GameSpeed::WasKeyDown = isDown;
    }
}

/**
 * @brief Disables the ViewAngles hook.
 *
 * This function is called to specifically revert the ViewAngles feature.
 * - Sets `ViewAngles::g_cacheThreadRunning` to false to signal the angle caching thread to stop.
 * - If the hook was active (`ViewAngles::InstructionAddress` is valid and `ViewAngles::mem_allocated` is true),
 *   it restores the original bytes at the hooked address using `DriverComm::write_memory_buffer`.
 */
void DisableViewAngleHook() {
    ViewAngles::g_cacheThreadRunning = false;
    if (ViewAngles::InstructionAddress != 0 && ViewAngles::mem_allocated) {
        DriverComm::write_memory_buffer(ViewAngles::InstructionAddress, ViewAngles::origBytes, sizeof(ViewAngles::origBytes));
        #ifdef _DEBUG
        LogMessage("[+] DisableViewAngleHook: Original bytes restored.");
        #endif
    }
}

/**
 * @brief Updates the state of all features based on user configuration.
 *
 * Called every frame via `Drawing::Poll()`, this function is the core logic for
 * enabling or disabling features. It compares the current `Enabled` state of each
 * feature (typically toggled by ImGui checkboxes) with its `wasEnabledFlag` (previous state).
 *
 * Key responsibilities:
 * - For each feature, if its desired state (`Enabled`) has changed:
 *   - It uses helper lambdas (`toggleShellcodeFeature` for complex hooks, `togglePatchFeature`
 *     for simple byte/NOP patches) to manage the actual memory modifications.
 *   - **Enabling a feature**:
 *     - Injects shellcode (for hook-based features) using `Features::InjectCodecave`. This involves
 *       allocating a codecave if one isn't already, writing the feature's shellcode, and
 *       placing a jump from the original game code to the codecave.
 *     - Applies byte patches (for NOP/byte patch features) directly to memory.
 *   - **Disabling a feature**:
 *     - Restores the original game bytes at the hooked/patched address.
 *     - Releases any codecave memory that was allocated specifically for that feature
 *       using `Features::ReleaseCodecave`.
 * - Handles features with multiple parts or dependencies, such as:
 *   - **LocalPlayer/ViewAngles**: Manages allocation of memory for pointers, enables/disables
 *     both LocalPlayer and ViewAngle hooks, and starts/stops associated threads.
 *   - **InfAmmo/InfSwordAmmo**: Enables/disables the main infinite ammo hook and a secondary
 *     patch for sword ammo.
 *   - **InstaRespawn/RespawnAnywhere**: Manages a direct byte patch and a shellcode hook.
 *   - **InteractThruWalls**: Manages two separate shellcode hooks.
 *   - **ActivityLoader**: Manages a shellcode hook and an additional memory allocation for data.
 * - Updates `g_feature_critical_error_flags` for each feature if an operation (enable/disable)
 *   fails critically (e.g., unable to restore original bytes), providing feedback in the UI.
 * - Updates `wasEnabledFlag` to the new `Enabled` state after processing each feature.
 *
 * @param pid_param The Process ID of the target game process.
 */
void UpdateFeatureStates(DWORD pid_param) {
    // Helper lambda for shellcode-based features
    auto toggleShellcodeFeature = [&](
        const char* featureName, bool& enabledFlag, bool& wasEnabledFlag, uintptr_t instrAddr,
        const std::string& shellcodeHex, BYTE* origBytes, size_t origSize,
        bool& cave_allocated_flag, std::atomic<uintptr_t>& cave_addr_var)
    {
        if (enabledFlag == wasEnabledFlag) return;

        if (instrAddr == 0) {
            if (enabledFlag) {
                LogMessageF("[-] [%s] InstructionAddress is 0. Cannot enable.", featureName);
                enabledFlag = false;
            }
            g_feature_critical_error_flags[featureName] = false;
            wasEnabledFlag = enabledFlag;
            return;
        }

        if (enabledFlag) {
            std::vector<BYTE> scBytes = HexToBytes(shellcodeHex);
            if (scBytes.empty()) {
                LogMessageF("[-] [%s] Shellcode hex string is invalid or empty. Cannot enable.", featureName);
                enabledFlag = false;
                g_feature_critical_error_flags[featureName] = false;
                wasEnabledFlag = enabledFlag;
                return;
            }

            if (Features::InjectCodecave(pid_param, instrAddr, scBytes, origSize, cave_addr_var)) {
                #ifdef _DEBUG
                LogMessageF("[+] [%s] Enabled (hooked) at 0x%llX. Codecave at 0x%llX.", featureName, instrAddr, cave_addr_var.load());
                #endif
                cave_allocated_flag = true;
                g_feature_critical_error_flags[featureName] = false;
            } else {
                LogMessageF("[-] [%s] InjectCodecave failed for address 0x%llX.", featureName, instrAddr);
                enabledFlag = false;
            }
        } else {
            if (cave_allocated_flag && cave_addr_var.load() != 0) {
                NTSTATUS restore_status = DriverComm::write_memory_buffer(instrAddr, origBytes, origSize, nullptr);
                if (NT_SUCCESS(restore_status)) {
                    #ifdef _DEBUG
                    LogMessageF("[-] [%s] Disabled (bytes restored) at 0x%llX.", featureName, instrAddr);
                    #endif
                    Features::ReleaseCodecave(pid_param, cave_addr_var, cave_allocated_flag);
                    g_feature_critical_error_flags[featureName] = false;
                } else {
                    LogMessageF("CRITICAL: [%s] Failed to restore original bytes at 0x%llX. Status: 0x%lX. Feature may still be active!", featureName, instrAddr, restore_status);
                    g_feature_critical_error_flags[featureName] = true;
                }
            } else {
                 if (instrAddr != 0) {
                    NTSTATUS restore_status_no_cave = DriverComm::write_memory_buffer(instrAddr, origBytes, origSize, nullptr);
                     if (NT_SUCCESS(restore_status_no_cave)) {
                        #ifdef _DEBUG
                        LogMessageF("[-] [%s] Disabled (bytes restored, no codecave info/already released) at 0x%llX.", featureName, instrAddr);
                        #endif
                        g_feature_critical_error_flags[featureName] = false;
                    } else {
                        LogMessageF("CRITICAL: [%s] Failed to restore original bytes (no codecave info) at 0x%llX. Status: 0x%lX.", featureName, instrAddr, restore_status_no_cave);
                        g_feature_critical_error_flags[featureName] = true;
                    }
                } else {
                     LogMessageF("[-] [%s] Disabled (no valid address or codecave to restore/release).", featureName);
                     g_feature_critical_error_flags[featureName] = false;
                }
            }
        }
        wasEnabledFlag = enabledFlag;
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
            g_feature_critical_error_flags[featureName] = false;
            wasEnabledFlag = enabledFlag;
            return;
        }

        NTSTATUS status = STATUS_UNSUCCESSFUL;
        if constexpr (std::is_array_v<std::remove_reference_t<decltype(patchValue)>>) {
             status = DriverComm::write_memory_buffer(instrAddr, enabledFlag ? patchValue : originalValue, sizeof(originalValue), nullptr);
        } else {
             bool simple_write_success = DriverComm::write_memory(instrAddr, enabledFlag ? patchValue : originalValue);
             status = simple_write_success ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        }

        if (!NT_SUCCESS(status)) {
            if (enabledFlag) {
                LogMessageF("CRITICAL: [%s] Failed to apply patch at 0x%llX. Status: 0x%lX. Feature not enabled.", featureName, instrAddr, status);
                enabledFlag = false;
            } else {
                LogMessageF("CRITICAL: [%s] Failed to restore original value at 0x%llX. Status: 0x%lX. Feature may still be active!", featureName, instrAddr, status);
                g_feature_critical_error_flags[featureName] = true;
            }
        } else {
            #ifdef _DEBUG
            LogMessageF("[%s] [%s] %s at 0x%llX.", (enabledFlag ? "+" : "-"), featureName, (enabledFlag ? "Enabled (patched)" : "Disabled (restored)"), instrAddr);
            #endif
            g_feature_critical_error_flags[featureName] = false;
        }
        wasEnabledFlag = enabledFlag;
    };

    // LOCALPLAYER & VIEANGLES
    if (LocalPlayer::Enabled != wasLocalPlayerEnabled) {
        if (LocalPlayer::Enabled) {
            LogMessage("[+] [LocalPlayer/ViewAngles] Attempting to enable...");
            g_feature_critical_error_flags["LocalPlayer"] = false;
            g_feature_critical_error_flags["ViewAngles"] = false;

            bool lpAddrOk = LocalPlayer::addrMemAllocatedAddress.load() != 0;
            if (!lpAddrOk) {
                if (DriverComm::allocate_memory(pid_param, sizeof(uintptr_t), LocalPlayer::addrMemAllocatedAddress, nullptr)) {
                    LocalPlayer::addr_mem_allocated = true;
                    lpAddrOk = true;
                    #ifdef _DEBUG
                    LogMessageF("[+] [LocalPlayer] Allocated addrMemAllocatedAddress at 0x%llX.", LocalPlayer::addrMemAllocatedAddress.load());
                    #endif
                } else {
                    LocalPlayer::addr_mem_allocated = false;
                    lpAddrOk = false;
                    LogMessage("[-] [LocalPlayer] Failed to allocate addrMemAllocatedAddress.");
                }
            } else {
                 if(LocalPlayer::addrMemAllocatedAddress.load() != 0) LocalPlayer::addr_mem_allocated = true;
            }

            bool vaAddrOk = ViewAngles::addrMemAllocatedAddress.load() != 0;
            if (lpAddrOk && !vaAddrOk) {
                if (DriverComm::allocate_memory(pid_param, sizeof(uintptr_t), ViewAngles::addrMemAllocatedAddress, nullptr)) {
                    ViewAngles::addr_mem_allocated = true;
                    vaAddrOk = true;
                    #ifdef _DEBUG
                    LogMessageF("[+] [ViewAngles] Allocated addrMemAllocatedAddress at 0x%llX.", ViewAngles::addrMemAllocatedAddress.load());
                    #endif
                } else {
                    ViewAngles::addr_mem_allocated = false;
                    vaAddrOk = false;
                    LogMessage("[-] [ViewAngles] Failed to allocate addrMemAllocatedAddress.");
                }
            } else if (lpAddrOk && vaAddrOk) {
                 if(ViewAngles::addrMemAllocatedAddress.load() != 0) ViewAngles::addr_mem_allocated = true;
            }

            if (lpAddrOk && vaAddrOk) {
                bool lpSuccess = Features::EnableLocalPlayerHook(pid_param);
                bool vaSuccess = false;
                if (lpSuccess) {
                    vaSuccess = Features::EnableViewAngleHook(pid_param);
                }

                if (lpSuccess && vaSuccess) {
                    g_StopFindThread = false;
                    g_FindPlayerEnabled = true;
                    if(g_FindPlayerThread.joinable()) g_FindPlayerThread.join();
                    g_FindPlayerThread = std::thread(AutoFindPlayerLoop, pid_param, g_moduleBaseAddress_drawing + LocalPlayer::destinyBase, std::ref(LocalPlayer::realPlayer));
                    g_FindPlayerThread.detach();
                    #ifdef _DEBUG
                    LogMessage("[+] [LocalPlayer/ViewAngles] Hooks enabled, threads started.");
                    #endif
                    g_feature_critical_error_flags["LocalPlayer"] = false;
                    g_feature_critical_error_flags["ViewAngles"] = false;
                } else {
                    LogMessage("[-] [LocalPlayer/ViewAngles] Hook enabling failed. Reverting.");
                    if (lpSuccess && LocalPlayer::InstructionAddress.load() != 0 && LocalPlayer::mem_allocated) {
                        DriverComm::write_memory_buffer(LocalPlayer::InstructionAddress.load(), LocalPlayer::origBytes, sizeof(LocalPlayer::origBytes), nullptr);
                        Features::ReleaseCodecave(pid_param, LocalPlayer::memAllocatedAddress, LocalPlayer::mem_allocated);
                    }
                    if (vaSuccess && ViewAngles::InstructionAddress.load() != 0 && ViewAngles::mem_allocated) {
                        DriverComm::write_memory_buffer(ViewAngles::InstructionAddress.load(), ViewAngles::origBytes, sizeof(ViewAngles::origBytes), nullptr);
                        Features::ReleaseCodecave(pid_param, ViewAngles::memAllocatedAddress, ViewAngles::mem_allocated);
                    }
                    LocalPlayer::Enabled = false;
                }
            } else {
                LogMessage("[-] [LocalPlayer/ViewAngles] Failed to allocate necessary pointer memory. Feature disabled.");
                LocalPlayer::Enabled = false;
            }
        } else {
            LogMessage("[-] [LocalPlayer/ViewAngles] Attempting to disable...");
            bool lp_disable_ok = true;
            bool va_disable_ok = true;

            if (LocalPlayer::InstructionAddress.load() != 0 && LocalPlayer::mem_allocated) {
                NTSTATUS lp_restore_status = DriverComm::write_memory_buffer(LocalPlayer::InstructionAddress.load(), LocalPlayer::origBytes, sizeof(LocalPlayer::origBytes), nullptr);
                if (NT_SUCCESS(lp_restore_status)) {
                    Features::ReleaseCodecave(pid_param, LocalPlayer::memAllocatedAddress, LocalPlayer::mem_allocated);
                } else {
                    LogMessageF("CRITICAL: [LocalPlayer] Failed to restore bytes at 0x%llX. Status: 0x%lX", LocalPlayer::InstructionAddress.load(), lp_restore_status);
                    g_feature_critical_error_flags["LocalPlayer"] = true;
                    lp_disable_ok = false;
                }
            }
            if (LocalPlayer::addrMemAllocatedAddress.load() != 0 && LocalPlayer::addr_mem_allocated) {
                NTSTATUS lp_free_status = DriverComm::free_memory_ex(pid_param, LocalPlayer::addrMemAllocatedAddress.load(), 0);
                if (NT_SUCCESS(lp_free_status)) {
                    LocalPlayer::addrMemAllocatedAddress.store(0);
                    LocalPlayer::addr_mem_allocated = false;
                } else {
                    LogMessageF("CRITICAL: [LocalPlayer] Failed to free addrMemAllocatedAddress at 0x%llX. Status: 0x%lX", LocalPlayer::addrMemAllocatedAddress.load(), lp_free_status);
                    g_feature_critical_error_flags["LocalPlayer"] = true;
                    lp_disable_ok = false;
                }
            }
             if (lp_disable_ok) g_feature_critical_error_flags["LocalPlayer"] = false;

            ViewAngles::g_cacheThreadRunning.store(false);
            if (ViewAngles::InstructionAddress.load() != 0 && ViewAngles::mem_allocated) {
                NTSTATUS va_restore_status = DriverComm::write_memory_buffer(ViewAngles::InstructionAddress.load(), ViewAngles::origBytes, sizeof(ViewAngles::origBytes), nullptr);
                if (NT_SUCCESS(va_restore_status)) {
                    Features::ReleaseCodecave(pid_param, ViewAngles::memAllocatedAddress, ViewAngles::mem_allocated);
                } else {
                    LogMessageF("CRITICAL: [ViewAngles] Failed to restore bytes at 0x%llX. Status: 0x%lX", ViewAngles::InstructionAddress.load(), va_restore_status);
                    g_feature_critical_error_flags["ViewAngles"] = true;
                    va_disable_ok = false;
                }
            }
            if (ViewAngles::addrMemAllocatedAddress.load() != 0 && ViewAngles::addr_mem_allocated) {
                NTSTATUS va_free_status = DriverComm::free_memory_ex(pid_param, ViewAngles::addrMemAllocatedAddress.load(), 0);
                if (NT_SUCCESS(va_free_status)) {
                    ViewAngles::addrMemAllocatedAddress.store(0);
                    ViewAngles::addr_mem_allocated = false;
                } else {
                    LogMessageF("CRITICAL: [ViewAngles] Failed to free addrMemAllocatedAddress at 0x%llX. Status: 0x%lX", ViewAngles::addrMemAllocatedAddress.load(), va_free_status);
                    g_feature_critical_error_flags["ViewAngles"] = true;
                    va_disable_ok = false;
                }
            }
            if (va_disable_ok) g_feature_critical_error_flags["ViewAngles"] = false;

            g_FindPlayerEnabled = false;
            g_StopFindThread = true;
            if (g_FindPlayerThread.joinable()) {
                g_FindPlayerThread.join();
            }
            LogMessage("[-] [LocalPlayer/ViewAngles] Disabled. Threads stopped.");
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
            g_feature_critical_error_flags["InfAmmo"] = false;
            bool mainHookSuccess = Features::EnableInfiniteAmmo(pid_param);
            if (mainHookSuccess) {
                #ifdef _DEBUG
                LogMessageF("[+] [InfAmmo] Main hook enabled at 0x%llX.", InfAmmo::InstructionAddress.load());
                #endif
                if (InfSwordAmmo::InstructionAddress.load() != 0) {
                    if (DriverComm::write_memory(InfSwordAmmo::InstructionAddress.load(), InfSwordAmmo::nops)) {
                        #ifdef _DEBUG
                        LogMessageF("[+] [InfSwordAmmo] Patched NOPs at 0x%llX.", InfSwordAmmo::InstructionAddress.load());
                        #endif
                    } else {
                        LogMessageF("[-] [InfSwordAmmo] Failed NOP patch at 0x%llX.", InfSwordAmmo::InstructionAddress.load());
                    }
                } else LogMessage("[!] [InfSwordAmmo] InstructionAddress is 0.");
            } else {
                LogMessageF("[-] [InfAmmo] Main hook failed at 0x%llX.", InfAmmo::InstructionAddress.load());
                InfAmmo::Enabled = false;
            }
        } else {
            LogMessage("[-] [InfAmmo/InfSwordAmmo] Attempting to disable...");
            bool infAmmo_disable_ok = true;
            if (InfAmmo::InstructionAddress.load() != 0 && InfAmmo::mem_allocated) {
                NTSTATUS restore_status = DriverComm::write_memory_buffer(InfAmmo::InstructionAddress.load(), InfAmmo::origBytes, sizeof(InfAmmo::origBytes), nullptr);
                if (NT_SUCCESS(restore_status)) {
                    Features::ReleaseCodecave(pid_param, InfAmmo::memAllocatedAddress, InfAmmo::mem_allocated);
                } else {
                    LogMessageF("CRITICAL: [InfAmmo] Failed to restore bytes at 0x%llX. Status: 0x%lX", InfAmmo::InstructionAddress.load(), restore_status);
                    g_feature_critical_error_flags["InfAmmo"] = true;
                    infAmmo_disable_ok = false;
                }
            }
            if (InfSwordAmmo::InstructionAddress.load() != 0 && wasInfAmmoEnabled) {
                NTSTATUS sword_restore_status = DriverComm::write_memory_buffer(InfSwordAmmo::InstructionAddress.load(), InfSwordAmmo::origBytes, sizeof(InfSwordAmmo::origBytes), nullptr);
                if (!NT_SUCCESS(sword_restore_status)) {
                    LogMessageF("CRITICAL: [InfSwordAmmo] Failed to restore bytes at 0x%llX. Status: 0x%lX", InfSwordAmmo::InstructionAddress.load(), sword_restore_status);
                    g_feature_critical_error_flags["InfAmmo"] = true;
                    infAmmo_disable_ok = false;
                }
            }
            if (infAmmo_disable_ok) g_feature_critical_error_flags["InfAmmo"] = false;
        }
        wasInfAmmoEnabled = InfAmmo::Enabled;
    }

    // InstaRespawn & RespawnAnywhere
    if (InstaRespawn::Enabled != wasInstaRespawnEnabled) {
        if (InstaRespawn::Enabled) {
            LogMessage("[+] [InstaRespawn/RespawnAnywhere] Attempting to enable...");
            g_feature_critical_error_flags["InstaRespawn"] = false;

            bool instaSuccess = false;
            if (InstaRespawn::InstructionAddress.load() != 0) {
                NTSTATUS patch_status = DriverComm::write_memory_buffer(InstaRespawn::InstructionAddress.load(), InstaRespawn::myBytes, sizeof(InstaRespawn::myBytes), nullptr);
                instaSuccess = NT_SUCCESS(patch_status);
                #ifdef _DEBUG
                if(instaSuccess) LogMessageF("[+] [InstaRespawn] Patched at 0x%llX.", InstaRespawn::InstructionAddress.load());
                #endif
                if(!instaSuccess) LogMessageF("[-] [InstaRespawn] Patch failed at 0x%llX. Status: 0x%lX", InstaRespawn::InstructionAddress.load(), patch_status);
            } else LogMessage("[-] [InstaRespawn] InstructionAddress is 0.");

            bool raSuccess = false;
            if (instaSuccess) {
                std::vector<BYTE> scBytesRA = HexToBytes(RespawnAnywhere::shellcode_hex);
                if (!scBytesRA.empty() && RespawnAnywhere::InstructionAddress.load() != 0) {
                    if (Features::InjectCodecave(pid_param, RespawnAnywhere::InstructionAddress.load(), scBytesRA, sizeof(RespawnAnywhere::origBytes), RespawnAnywhere::memAllocatedAddress)) {
                        RespawnAnywhere::mem_allocated = true;
                        raSuccess = true;
                        #ifdef _DEBUG
                        LogMessageF("[+] [RespawnAnywhere] Hooked at 0x%llX.", RespawnAnywhere::InstructionAddress.load());
                        #endif
                    } else LogMessageF("[-] [RespawnAnywhere] Hook failed at 0x%llX.", RespawnAnywhere::InstructionAddress.load());
                } else LogMessageF("[-] [RespawnAnywhere] Invalid shellcode or address 0x%llX.", RespawnAnywhere::InstructionAddress.load());
            }

            if (! (instaSuccess && raSuccess) ) {
                LogMessage("[-] [InstaRespawn/RespawnAnywhere] Enabling failed. Reverting.");
                if (raSuccess && RespawnAnywhere::InstructionAddress.load() != 0 && RespawnAnywhere::mem_allocated) {
                    DriverComm::write_memory_buffer(RespawnAnywhere::InstructionAddress.load(), RespawnAnywhere::origBytes, sizeof(RespawnAnywhere::origBytes), nullptr);
                    Features::ReleaseCodecave(pid_param, RespawnAnywhere::memAllocatedAddress, RespawnAnywhere::mem_allocated);
                }
                if (instaSuccess && InstaRespawn::InstructionAddress.load() != 0) {
                    DriverComm::write_memory_buffer(InstaRespawn::InstructionAddress.load(), InstaRespawn::origBytes, sizeof(InstaRespawn::origBytes), nullptr);
                }
                InstaRespawn::Enabled = false;
            }
        } else {
            LogMessage("[-] [InstaRespawn/RespawnAnywhere] Attempting to disable...");
            bool insta_disable_ok = true;
            if (InstaRespawn::InstructionAddress.load() != 0 && wasInstaRespawnEnabled) {
                NTSTATUS restore_status = DriverComm::write_memory_buffer(InstaRespawn::InstructionAddress.load(), InstaRespawn::origBytes, sizeof(InstaRespawn::origBytes), nullptr);
                if(!NT_SUCCESS(restore_status)) {
                    LogMessageF("CRITICAL: [InstaRespawn] Failed to restore bytes at 0x%llX. Status: 0x%lX", InstaRespawn::InstructionAddress.load(), restore_status);
                    g_feature_critical_error_flags["InstaRespawn"] = true;
                    insta_disable_ok = false;
                }
            }
            if (RespawnAnywhere::InstructionAddress.load() != 0 && RespawnAnywhere::mem_allocated) {
                NTSTATUS ra_restore_status = DriverComm::write_memory_buffer(RespawnAnywhere::InstructionAddress.load(), RespawnAnywhere::origBytes, sizeof(RespawnAnywhere::origBytes), nullptr);
                if (NT_SUCCESS(ra_restore_status)) {
                    Features::ReleaseCodecave(pid_param, RespawnAnywhere::memAllocatedAddress, RespawnAnywhere::mem_allocated);
                } else {
                    LogMessageF("CRITICAL: [RespawnAnywhere] Failed to restore bytes at 0x%llX. Status: 0x%lX", RespawnAnywhere::InstructionAddress.load(), ra_restore_status);
                    g_feature_critical_error_flags["InstaRespawn"] = true;
                    insta_disable_ok = false;
                }
            }
            if (insta_disable_ok) g_feature_critical_error_flags["InstaRespawn"] = false;
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
                } else {
                    #ifdef _DEBUG
                    LogMessage("[+] [AntiFlinch] Enabled.");
                    #endif
                }
            } else {
                LogMessage("[-] [AntiFlinch] One or more addresses are 0. Cannot enable.");
                AntiFlinch::Enabled = false;
            }
        } else { // Disabling
            if (AntiFlinch::InstructionAddress1 != 0) DriverComm::write_memory(AntiFlinch::InstructionAddress1, AntiFlinch::origBytes1);
            if (AntiFlinch::InstructionAddress2 != 0) DriverComm::write_memory(AntiFlinch::InstructionAddress2, AntiFlinch::origBytes2);
            if (AntiFlinch::InstructionAddress3 != 0) DriverComm::write_memory(AntiFlinch::InstructionAddress3, AntiFlinch::origBytes3);
            #ifdef _DEBUG
            LogMessage("[-] [AntiFlinch] Disabled.");
            #endif
        }
        wasAntiFlinchEnabled = AntiFlinch::Enabled;
    }

    // InteractThruWalls
    if (InteractThruWalls::Enabled != wasInteractThruWallsEnabled) {
        if (InteractThruWalls::Enabled) {
            LogMessage("[+] [InteractThruWalls] Attempting to enable...");
            g_feature_critical_error_flags["InteractThruWalls"] = false;
            bool hook1Success = false;
            if (InteractThruWalls::InstructionAddress1.load() != 0) {
                std::vector<BYTE> sc1 = HexToBytes(InteractThruWalls::shellcode1_hex);
                if (!sc1.empty() && Features::InjectCodecave(pid_param, InteractThruWalls::InstructionAddress1.load(), sc1, sizeof(InteractThruWalls::origBytes1), InteractThruWalls::memAllocatedAddress1)) {
                    InteractThruWalls::mem_allocated1 = true; hook1Success = true;
                    #ifdef _DEBUG
                    LogMessageF("[+] [InteractThruWalls] Hook 1 enabled at 0x%llX", InteractThruWalls::InstructionAddress1.load());
                    #endif
                } else LogMessageF("[-] [InteractThruWalls] Hook 1 failed at 0x%llX", InteractThruWalls::InstructionAddress1.load());
            } else LogMessage("[-] [InteractThruWalls] Hook 1 address is 0.");

            bool hook2Success = false;
            if (hook1Success) {
                if (InteractThruWalls::InstructionAddress2.load() != 0) {
                    std::vector<BYTE> sc2 = HexToBytes(InteractThruWalls::shellcode2_hex);
                    if (!sc2.empty() && Features::InjectCodecave(pid_param, InteractThruWalls::InstructionAddress2.load(), sc2, sizeof(InteractThruWalls::origBytes2), InteractThruWalls::memAllocatedAddress2)) {
                        InteractThruWalls::mem_allocated2 = true; hook2Success = true;
                        #ifdef _DEBUG
                        LogMessageF("[+] [InteractThruWalls] Hook 2 enabled at 0x%llX", InteractThruWalls::InstructionAddress2.load());
                        #endif
                    } else LogMessageF("[-] [InteractThruWalls] Hook 2 failed at 0x%llX", InteractThruWalls::InstructionAddress2.load());
                } else LogMessage("[-] [InteractThruWalls] Hook 2 address is 0.");
            }

            if (! (hook1Success && hook2Success) ) {
                LogMessage("[-] [InteractThruWalls] Enabling failed. Reverting.");
                if (hook1Success && InteractThruWalls::InstructionAddress1.load() != 0 && InteractThruWalls::mem_allocated1) {
                    DriverComm::write_memory_buffer(InteractThruWalls::InstructionAddress1.load(), InteractThruWalls::origBytes1, sizeof(InteractThruWalls::origBytes1), nullptr);
                    Features::ReleaseCodecave(pid_param, InteractThruWalls::memAllocatedAddress1, InteractThruWalls::mem_allocated1);
                }
                InteractThruWalls::Enabled = false;
            }
        } else {
            LogMessage("[-] [InteractThruWalls] Attempting to disable...");
            bool disable_ok = true;
            if (InteractThruWalls::InstructionAddress1.load() != 0 && InteractThruWalls::mem_allocated1) {
                NTSTATUS r1 = DriverComm::write_memory_buffer(InteractThruWalls::InstructionAddress1.load(), InteractThruWalls::origBytes1, sizeof(InteractThruWalls::origBytes1), nullptr);
                if(NT_SUCCESS(r1)) {
                    Features::ReleaseCodecave(pid_param, InteractThruWalls::memAllocatedAddress1, InteractThruWalls::mem_allocated1);
                } else {
                    LogMessageF("CRITICAL: [InteractThruWalls] Failed to restore Hook1 bytes. Status: 0x%lX", r1);
                    g_feature_critical_error_flags["InteractThruWalls"] = true; disable_ok = false;
                }
            }
            if (InteractThruWalls::InstructionAddress2.load() != 0 && InteractThruWalls::mem_allocated2) {
                 NTSTATUS r2 = DriverComm::write_memory_buffer(InteractThruWalls::InstructionAddress2.load(), InteractThruWalls::origBytes2, sizeof(InteractThruWalls::origBytes2), nullptr);
                 if(NT_SUCCESS(r2)) {
                    Features::ReleaseCodecave(pid_param, InteractThruWalls::memAllocatedAddress2, InteractThruWalls::mem_allocated2);
                 } else {
                    LogMessageF("CRITICAL: [InteractThruWalls] Failed to restore Hook2 bytes. Status: 0x%lX", r2);
                    g_feature_critical_error_flags["InteractThruWalls"] = true; disable_ok = false;
                 }
            }
            if(disable_ok) g_feature_critical_error_flags["InteractThruWalls"] = false;
        }
        wasInteractThruWallsEnabled = InteractThruWalls::Enabled;
    }
    
    // ActivityLoader
    if (ActivityLoader::Enabled != wasActivityLoaderEnabled) {
        if (ActivityLoader::Enabled) {
            LogMessage("[+] [ActivityLoader] Attempting to enable...");
            g_feature_critical_error_flags["ActivityLoader"] = false;
            if (Features::EnableActivityLoaderHook(pid_param)) {
                #ifdef _DEBUG
                LogMessageF("[+] [ActivityLoader] Hook enabled by EnableActivityLoaderHook for 0x%llX.", ActivityLoader::InstructionAddress.load());
                #endif
            } else {
                LogMessageF("[-] [ActivityLoader] EnableActivityLoaderHook failed for 0x%llX.", ActivityLoader::InstructionAddress.load());
                ActivityLoader::Enabled = false;
            }
        } else {
            LogMessage("[-] [ActivityLoader] Attempting to disable...");
            bool disable_main_hook_ok = true;
            if (ActivityLoader::InstructionAddress.load() != 0 && ActivityLoader::mem_allocated) {
                NTSTATUS restore_status = DriverComm::write_memory_buffer(ActivityLoader::InstructionAddress.load(), ActivityLoader::origBytes, sizeof(ActivityLoader::origBytes), nullptr);
                if (NT_SUCCESS(restore_status)) {
                    Features::ReleaseCodecave(pid_param, ActivityLoader::memAllocatedAddress, ActivityLoader::mem_allocated);
                } else {
                    LogMessageF("CRITICAL: [ActivityLoader] Failed to restore bytes at 0x%llX. Status: 0x%lX", ActivityLoader::InstructionAddress.load(), restore_status);
                    g_feature_critical_error_flags["ActivityLoader"] = true;
                    disable_main_hook_ok = false;
                }
            } else if (ActivityLoader::InstructionAddress.load() != 0 && !ActivityLoader::mem_allocated && wasActivityLoaderEnabled) {
                 NTSTATUS restore_status = DriverComm::write_memory_buffer(ActivityLoader::InstructionAddress.load(), ActivityLoader::origBytes, sizeof(ActivityLoader::origBytes), nullptr);
                 if(!NT_SUCCESS(restore_status)) {
                    LogMessageF("CRITICAL: [ActivityLoader] Fallback restore bytes failed at 0x%llX. Status: 0x%lX", ActivityLoader::InstructionAddress.load(), restore_status);
                    g_feature_critical_error_flags["ActivityLoader"] = true;
                    disable_main_hook_ok = false;
                 }
            }


            bool disable_addr_mem_ok = true;
            if (ActivityLoader::addrMemAllocatedAddress.load() != 0 && ActivityLoader::addr_mem_allocated) {
                NTSTATUS free_status = DriverComm::free_memory_ex(pid_param, ActivityLoader::addrMemAllocatedAddress.load(), 0);
                if (NT_SUCCESS(free_status)) {
                    ActivityLoader::addrMemAllocatedAddress.store(0);
                    ActivityLoader::addr_mem_allocated = false;
                } else {
                    LogMessageF("CRITICAL: [ActivityLoader] Failed to free addrMemAllocatedAddress at 0x%llX. Status: 0x%lX", ActivityLoader::addrMemAllocatedAddress.load(), free_status);
                    g_feature_critical_error_flags["ActivityLoader"] = true;
                    disable_addr_mem_ok = false;
                }
            }

            if (disable_main_hook_ok && disable_addr_mem_ok) {
                g_feature_critical_error_flags["ActivityLoader"] = false;
            }
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

// static bool Drawing::bDraw = true; // Controls the visibility of the main ImGui window and the active state of the drawing loop.
                                   // Set to false when the main window is closed by the user.
static bool Drawing::bDraw = true;


// bool Drawing::isActive() {
//     // Returns the current state of bDraw, indicating if the main ImGui window is considered active/open.
//     return bDraw;
// }
bool Drawing::isActive() {
    return bDraw;
}

// void Drawing::Active() {
//     // Toggles the active state of the drawing/UI. This affects the visibility of the main ImGui window.
//     bDraw = !bDraw;
// }
void Drawing::Active() {
    bDraw = !bDraw;
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

                DWORD pid_on_loss = g_current_pid_drawing; // Capture PID before it's reset

                // Call the centralized cleanup function BEFORE resetting globals like g_current_pid_drawing
                // and before DriverComm::shutdown() if that function relies on the PID.
                // DisableAndCleanupAllFeatures will handle logging its actions.
                if (isInitialized && pid_on_loss != 0) { // Ensure we had a valid PID and were initialized
                    DisableAndCleanupAllFeatures(pid_on_loss);
                }

                if(isInitialized) { // This check might be redundant if DisableAndCleanupAllFeatures handles DriverComm::shutdown
                                     // but kept for safety to ensure driver comms are attempted to be closed.
                                     // DriverComm::shutdown() should be safe to call multiple times or if already shutdown.
                     LogMessage("[+] Ensuring DriverComm is shut down due to process loss (called from Draw)...");
                     DriverComm::shutdown(); // This will also reset DriverComm::g_pid
                     LogMessage("[+] DriverComm shut down after process loss (called from Draw).");
                }

                // Signal and join ImmuneBossesThread
                ImmuneBosses::Enabled.store(false); // Disable feature
                ImmuneBosses::ThreadRunning.store(false); // Signal thread to stop (if it checks this)
                if (ImmuneBossesThread.joinable()) {
                    LogMessage("[+] Joining ImmuneBossesThread due to process loss...");
                    ImmuneBossesThread.join();
                    LogMessage("[+] ImmuneBossesThread joined.");
                }

                // Signal and join FlyThread
                Features::LocalPlayer::flyEnabled = false; // Disable feature
                StopFlyThread = true; // Signal thread to stop
                if (FlyThread.joinable()) {
                    LogMessage("[+] Drawing::Draw (Process Loss): Joining FlyThread...");
                    FlyThread.join();
                    LogMessage("[+] Drawing::Draw (Process Loss): FlyThread joined.");
                } else {
                    LogMessage("[!] Drawing::Draw (Process Loss): FlyThread was not joinable.");
                }

                // Stop any ongoing AOB scan
                if (Features::g_aob_scan_running.load()) {
                    // There's no direct cancellation mechanism for the detached AOB thread.
                    // It will complete, but its results might be for an old session.
                    // The g_aob_scan_complete_flag will be set by it eventually.
                    // When a new process is found, InitializeStealthComm logic will run again,
                    // and a new AOB scan thread will be launched if conditions are met.
                    // The primary safeguard is that g_current_pid_drawing and g_moduleBaseAddress_drawing are reset.
                    LogMessage("[!] Drawing::Draw: AOB scan might be running for the lost process. It will complete but results will be discarded on next init.");
                    // We can reset g_aob_scan_running here, so a new scan can start if a new process is found quickly.
                    // The old detached thread will still run to completion but won't re-trigger.
                    Features::g_aob_scan_running = false;
                    // g_aob_scan_complete_flag will be reset when a new scan is launched.
                }

                ResetAllFeatureStates(); // Call the new refactored function

                // Reset AOB scan flags
                Features::g_aob_scan_complete_flag.store(false);
                Features::g_aob_scan_running.store(false);

                // Reset main state vars
                isInitialized = false; // This should be set after all resets
                g_current_pid_drawing = 0;
                g_moduleBaseAddress_drawing = 0;
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
                LogMessageF("[+] Drawing::Draw: %s found! Process ID: %lu", narrowModuleNameLog, g_current_pid_drawing); // Kept for release

                if (DriverComm::attach_to_process(g_current_pid_drawing)) {
                    #ifdef _DEBUG
                    LogMessageF("[+] Drawing::Draw: DriverComm::attach_to_process successful for PID %lu", g_current_pid_drawing);
                    #endif
                    g_moduleBaseAddress_drawing = DriverComm::GetModuleBase(g_current_pid_drawing, g_wModuleName.c_str());

                    if (g_moduleBaseAddress_drawing != 0) {
                        #ifdef _DEBUG
                        LogMessageF("[+] Drawing::Draw: Module base address: 0x%llX", g_moduleBaseAddress_drawing);
                        #endif
                        // These functions will need to be updated to not require driver/pid, or use g_current_pid_drawing and g_moduleBaseAddress_drawing
                        // PerformStartupAobScans(g_moduleBaseAddress_drawing); // Will be called in background
                        // PerformStartupByteReads(); // Will be called in background

                        if (!Features::g_aob_scan_complete_flag.load() && !Features::g_aob_scan_running.load()) {
                            Features::g_aob_scan_running = true; // Set before starting thread
                            Features::g_aob_scan_complete_flag = false; // Reset if re-attaching
                            std::thread sigThread(AsyncInitializeSignaturesAndBytes_ThreadFunc, g_moduleBaseAddress_drawing, g_current_pid_drawing);
                            sigThread.detach();
                            #ifdef _DEBUG
                            LogMessage("[+] Drawing::Draw: Launched AsyncInitializeSignaturesAndBytes_ThreadFunc.");
                            #endif
                        }

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
                    char narrowModuleNameWait[256];
                    size_t convertedCharsWait = 0;
                    wcstombs_s(&convertedCharsWait, narrowModuleNameWait, sizeof(narrowModuleNameWait), g_wModuleName.c_str(), _TRUNCATE);
                    LogMessageF("[*] Drawing::Draw: Waiting for %s process...", narrowModuleNameWait); // Kept for release
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
        LogMessage("----------------------------------------------------------");
        LogMessage("[+] Application exit requested by user via X button.");

        DisableAndCleanupAllFeatures(g_current_pid_drawing); // Call the new centralized cleanup function

        // --- Existing Shutdown for Driver and UI ---
        // Note: DriverComm::shutdown() is now called within DisableAndCleanupAllFeatures if pid is valid.
        // However, to ensure it's called even if pid was 0 at the time DisableAndCleanupAllFeatures was invoked,
        // or if DisableAndCleanupAllFeatures might not cover all shutdown scenarios for DriverComm,
        // it's safer to call it here as well, if isInitialized suggests it was active.
        if(isInitialized && g_current_pid_drawing != 0) { // Check g_current_pid_drawing to ensure it was valid
            LogMessage("[+] Ensuring DriverComm is shut down (called from X button)...");
            DriverComm::shutdown();
            LogMessage("[+] DriverComm shut down (called from X button).");
        }
        isInitialized = false; // Ensure this is set after all cleanup and driver comms

        LogMessage("[+] Exiting application now.");
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        UI::CleanupDeviceD3D();
        PostQuitMessage(0);
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

    // Display AOB scan status
    if (Features::g_aob_scan_running.load() && !Features::g_aob_scan_complete_flag.load()) {
        ImGui::SetCursorPosY(posY + xButtonSize + 10); // Adjust position as needed
        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize("Scanning features...").x) * 0.5f);
        ImGui::TextDisabled("Scanning features...");
    }

    ImGui::SetCursorPosY(posY + xButtonSize + 23); // Use xButtonSize
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
            if (g_feature_critical_error_flags["LocalPlayer"] || g_feature_critical_error_flags["ViewAngles"]) {
                ImGui::SameLine(); ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "(!) MODIFY FAIL");
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("CRITICAL: LocalPlayer/ViewAngles failed to correctly apply/revert last state change!\nGame memory may be inconsistent. Try toggling again or restart.");
            }
            RenderFeatureStatusIndicator("LocalPlayer/ViewAngles", LocalPlayer::Enabled,
                LocalPlayer::InstructionAddress.load(), true, LocalPlayer::mem_allocated,
                ViewAngles::InstructionAddress.load(), true, ViewAngles::mem_allocated,
                1, LocalPlayer::addrMemAllocatedAddress.load(), "LP Pointer Store", ViewAngles::addrMemAllocatedAddress.load(), "VA Pointer Store");

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
            if (g_feature_critical_error_flags["Killaura"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Killaura failed to disable correctly."); }
            RenderFeatureStatusIndicator("Killaura", Killaura::Enabled, Killaura::InstructionAddress.load(), true, Killaura::mem_allocated);

            ImGui::Toggle("Ghostmode", &Ghostmode::Enabled);
            if (g_feature_critical_error_flags["Ghostmode"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Ghostmode failed to disable correctly."); }
            RenderFeatureStatusIndicator("Ghostmode", Ghostmode::Enabled, Ghostmode::InstructionAddress.load(), true, Ghostmode::mem_allocated);

            ImGui::Toggle("Godmode", &Godmode::Enabled);
            if (g_feature_critical_error_flags["Godmode"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Godmode failed to disable correctly."); }
            RenderFeatureStatusIndicator("Godmode", Godmode::Enabled, Godmode::InstructionAddress.load(), true, Godmode::mem_allocated);

            ImGui::Toggle("Inf Ammo", &InfAmmo::Enabled);
            if (g_feature_critical_error_flags["InfAmmo"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("InfAmmo/InfSwordAmmo failed to disable correctly."); }
            RenderFeatureStatusIndicator("Inf Ammo", InfAmmo::Enabled, InfAmmo::InstructionAddress.load(), true, InfAmmo::mem_allocated,
                                        (InfSwordAmmo::InstructionAddress.load() == 0 && InfAmmo::Enabled && g_moduleBaseAddress_drawing != 0) ? 0 : 1,
                                        false, false, 1, 1, nullptr, 1, nullptr,
                                        (InfSwordAmmo::InstructionAddress.load() == 0 && InfAmmo::Enabled && g_moduleBaseAddress_drawing != 0) ? "Warning: InfSwordAmmo offset not found." : nullptr);

            ImGui::Toggle("RPM", &RPM::Enabled);
            if (g_feature_critical_error_flags["RPM"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("RPM failed to disable correctly."); }
            RenderFeatureStatusIndicator("RPM", RPM::Enabled, RPM::InstructionAddress.load(), true, RPM::mem_allocated);

            ImGui::Toggle("Dmg Multiplier", &dmgMult::Enabled);
            if (g_feature_critical_error_flags["dmgMult"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Dmg Multiplier failed to disable correctly."); }
            RenderFeatureStatusIndicator("Dmg Multiplier", dmgMult::Enabled, dmgMult::InstructionAddress.load(), true, dmgMult::mem_allocated);

            ImGui::Toggle("Unshielded Immune Bosses/Aura", &ImmuneAura::Enabled);
            if (g_feature_critical_error_flags["ImmuneAura"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("ImmuneAura failed to disable correctly."); }
            RenderFeatureStatusIndicator("ImmuneAura", ImmuneAura::Enabled, ImmuneAura::InstructionAddress.load(), true, ImmuneAura::mem_allocated);

            RenderAbilityChargeUI(); // Hotkey only, no direct error state displayed here for toggle itself
            RenderFeatureStatusIndicator("AbilityCharge", AbilityCharge::Enabled, AbilityCharge::InstructionAddress.load(), true, AbilityCharge::mem_allocated); // Use AbilityCharge::mem_allocated

            ImGui::Toggle("No Recoil", &NoRecoil::Enabled);
            if (g_feature_critical_error_flags["NoRecoil"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("No Recoil failed to disable correctly."); }
            RenderFeatureStatusIndicator("No Recoil", NoRecoil::Enabled, NoRecoil::InstructionAddress.load(), true, NoRecoil::mem_allocated);

            ImGui::Toggle("Shoot Thru Walls", &ShootThru::Enabled);
            if (g_feature_critical_error_flags["ShootThru"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Shoot Thru Walls failed to disable correctly."); }
            RenderFeatureStatusIndicator("Shoot Thru Walls", ShootThru::Enabled, ShootThru::InstructionAddress.load());

            RenderImmuneBossesUI(g_current_pid_drawing);

            ImGui::Toggle("One hit kill", &OHK::Enabled);
            if (g_feature_critical_error_flags["OHK"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("One hit kill failed to disable correctly."); }
            RenderFeatureStatusIndicator("One hit kill", OHK::Enabled, OHK::InstructionAddress.load(), true, OHK::mem_allocated);

            RenderMag999Button(iconFont);
            if (g_feature_critical_error_flags["Mag999"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Mag999 failed to disable correctly."); }
            RenderFeatureStatusIndicator("Mag999", Mag999::Enabled, Mag999::InstructionAddress.load(), true, Mag999::mem_allocated);

            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Misc")) {
            ImVec2 p_misc = ImGui::GetCursorScreenPos(); ImVec2 size_misc = ImGui::GetContentRegionAvail(); size_misc.y = 220;
            ImGui::GetWindowDrawList()->AddRectFilled(p_misc, ImVec2(p_misc.x + size_misc.x, p_misc.y + size_misc.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10)); ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);
            ImGui::Text("Misc Options:"); ImGui::Spacing();

            ImGui::Toggle("No Joining Allies", &NoJoinAllies::Enabled);
            if (g_feature_critical_error_flags["NoJoinAllies"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("No Joining Allies failed to disable correctly."); }
            RenderFeatureStatusIndicator("No Joining Allies", NoJoinAllies::Enabled, NoJoinAllies::InstructionAddress.load());

            ImGui::Toggle("No Turn Back", &NoTurnBack::Enabled);
            if (g_feature_critical_error_flags["NoTurnBack"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("No Turn Back failed to disable correctly."); }
            RenderFeatureStatusIndicator("No Turn Back", NoTurnBack::Enabled, NoTurnBack::InstructionAddress.load());

            ImGui::Toggle("Infinite Rez Tokens", &NoRezTokens::Enabled);
            if (g_feature_critical_error_flags["NoRezTokens"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Infinite Rez Tokens failed to disable correctly."); }
            RenderFeatureStatusIndicator("Infinite Rez Tokens", NoRezTokens::Enabled, NoRezTokens::InstructionAddress.load());

            ImGui::Toggle("Respawn Anywhere", &InstaRespawn::Enabled); // Main toggle for composite feature
            if (g_feature_critical_error_flags["InstaRespawn"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("InstaRespawn/RespawnAnywhere failed to disable correctly."); }
            RenderFeatureStatusIndicator("InstaRespawn/RespawnAnywhere", InstaRespawn::Enabled,
                InstaRespawn::InstructionAddress.load(), false, false,
                RespawnAnywhere::InstructionAddress.load(), true, RespawnAnywhere::mem_allocated);

            ImGui::Toggle("Infinite Stacks", &InfStacks::Enabled);
            if (g_feature_critical_error_flags["InfStacks"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Infinite Stacks failed to disable correctly."); }
            RenderFeatureStatusIndicator("Infinite Stacks", InfStacks::Enabled, InfStacks::InstructionAddress.load(), true, InfStacks::mem_allocated);

            ImGui::Toggle("Infinite Buff Timers", &InfBuffTimers::Enabled);
            if (g_feature_critical_error_flags["InfBuffTimers"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Infinite Buff Timers failed to disable correctly."); }
            RenderFeatureStatusIndicator("Infinite Buff Timers", InfBuffTimers::Enabled, InfBuffTimers::InstructionAddress.load());

            ImGui::Toggle("Infinite Exotic Buff Timers", &InfExoticBuffTimers::Enabled);
            if (g_feature_critical_error_flags["InfExoticBuffTimers"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Infinite Exotic Buff Timers failed to disable correctly."); }
            RenderFeatureStatusIndicator("Infinite Exotic Buff Timers", InfExoticBuffTimers::Enabled, InfExoticBuffTimers::InstructionAddress.load());

            RenderGameSpeedUI(); // UI for hotkey, direct memory write, no critical error flag for toggle itself
            RenderFeatureStatusIndicator("GameSpeed", GameSpeed::Enabled, GameSpeed::Address.load());

            ImGui::Toggle("Instant Interact", &InstantInteract::Enabled);
            if (g_feature_critical_error_flags["InstantInteract"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Instant Interact failed to disable correctly."); }
            RenderFeatureStatusIndicator("Instant Interact", InstantInteract::Enabled, InstantInteract::InstructionAddress.load(), true, InstantInteract::mem_allocated);

            ImGui::Toggle("Interact Thru Walls", &InteractThruWalls::Enabled);
            if (g_feature_critical_error_flags["InteractThruWalls"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Interact Thru Walls failed to disable correctly."); }
            RenderFeatureStatusIndicator("Interact Thru Walls", InteractThruWalls::Enabled,
                InteractThruWalls::InstructionAddress1.load(), true, InteractThruWalls::mem_allocated1,
                InteractThruWalls::InstructionAddress2.load(), true, InteractThruWalls::mem_allocated2);

            ImGui::Toggle("Sparrow Anywhere", &SparrowAnywhere::Enabled);
            if (g_feature_critical_error_flags["SparrowAnywhere"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Sparrow Anywhere failed to disable correctly."); }
            RenderFeatureStatusIndicator("Sparrow Anywhere", SparrowAnywhere::Enabled, SparrowAnywhere::InstructionAddress.load());

            ImGui::Toggle("Infinite Sparrow Boost", &InfSparrowBoost::Enabled);
            if (g_feature_critical_error_flags["InfSparrowBoost"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Infinite Sparrow Boost failed to disable correctly."); }
            RenderFeatureStatusIndicator("Infinite Sparrow Boost", InfSparrowBoost::Enabled, InfSparrowBoost::InstructionAddress.load());

            if (GSize::Address == 0 && GSize::Enabled && g_moduleBaseAddress_drawing != 0) {
                GSize::Address = DriverComm::AOBScan(g_moduleBaseAddress_drawing, DEFAULT_SCAN_REGION_SIZE, GSize::AOB.c_str(), "");
                if (GSize::Address == 0) GSize::Enabled = false;
            }
            ImGui::Toggle("Guardian Size", &GSize::Enabled); // Direct memory write, no critical error flag for toggle
            RenderFeatureStatusIndicator("Guardian Size", GSize::Enabled, GSize::Address.load());

            if (GSize::Enabled && GSize::Address.load() != 0) {
                GSize::Value = DriverComm::read_memory<float>(GSize::Address.load());
                static float lastReadVal = 0.0f;
                if (lastReadVal != GSize::Value) { GSize::inputVal = GSize::Value; lastReadVal = GSize::Value; }
                ImGui::PushItemWidth(150); ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.157f, 0.157f, 0.157f, 1.0f));
                if(ImGui::InputFloat("Size##GSize", &GSize::inputVal, 0.0f, 0.0f, "%.3f")) {}
                ImGui::PopStyleColor(); ImGui::PopItemWidth();
                if (ImGui::Button("Set##GSize")) { DriverComm::write_memory(GSize::Address.load(), GSize::inputVal); lastReadVal = -1.0f; }
            }
            RenderActivityLoaderUI(g_current_pid_drawing);
            if (g_feature_critical_error_flags["ActivityLoader"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("ActivityLoader failed to disable correctly."); }
            RenderFeatureStatusIndicator("ActivityLoader", ActivityLoader::Enabled,
                ActivityLoader::InstructionAddress.load(), true, ActivityLoader::mem_allocated,
                1, false, false, 1,
                ActivityLoader::addrMemAllocatedAddress.load(), "Data Pointer");

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
            if (g_feature_critical_error_flags["Chams"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Chams failed to disable correctly."); }
            RenderFeatureStatusIndicator("Chams", Chams::Enabled, Chams::InstructionAddress.load(), true, Chams::mem_allocated);

            ImGui::Toggle("Infinite Icarus Dash", &IcarusDash::Enabled);
            if (g_feature_critical_error_flags["IcarusDash"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Infinite Icarus Dash failed to disable correctly."); }
            RenderFeatureStatusIndicator("Infinite Icarus Dash", IcarusDash::Enabled, IcarusDash::InstructionAddress.load());

            ImGui::Toggle("Lobby Crasher", &LobbyCrasher::Enabled);
            if (g_feature_critical_error_flags["LobbyCrasher"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Lobby Crasher failed to disable correctly."); }
            RenderFeatureStatusIndicator("Lobby Crasher", LobbyCrasher::Enabled, LobbyCrasher::InstructionAddress.load());

            ImGui::Toggle("No Flinch", &AntiFlinch::Enabled);
            if (g_feature_critical_error_flags["AntiFlinch"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("AntiFlinch failed to disable correctly."); }
            RenderFeatureStatusIndicator("No Flinch", AntiFlinch::Enabled,
                AntiFlinch::InstructionAddress1.load(), false, false,
                AntiFlinch::InstructionAddress2.load(), false, false,
                AntiFlinch::InstructionAddress3.load());
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Random")) {
            ImVec2 p_rand = ImGui::GetCursorScreenPos(); ImVec2 size_rand = ImGui::GetContentRegionAvail(); size_rand.y = 80;
            ImGui::GetWindowDrawList()->AddRectFilled(p_rand, ImVec2(p_rand.x + size_rand.x, p_rand.y + size_rand.y), ImGui::GetColorU32(ImGuiCol_FrameBg), 8.0f);
            ImGui::Dummy(ImVec2(0, 10)); ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 16);
            ImGui::Text("Random Options:"); ImGui::Spacing();
            if (ImGui::CollapsingHeader("GotD")) {
                ImGui::Toggle("Infinite Oxygen", &Oxygen::Enabled);
                if (g_feature_critical_error_flags["Oxygen"]) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1.f,0.f,0.f,1.f), "(!) MODIFY FAIL"); if (ImGui::IsItemHovered()) ImGui::SetTooltip("Infinite Oxygen failed to disable correctly."); }
                RenderFeatureStatusIndicator("Infinite Oxygen", Oxygen::Enabled, Oxygen::InstructionAddress.load());
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

        // Config Tab (or a new "Driver" tab if preferred)
        if (ImGui::BeginTabItem("Config")) { // Assuming "Config" tab exists, or choose/create another
            RenderConfigTab(); // Render existing config tab content first

            ImGui::Separator(); // Add a separator before the new button
            ImGui::Spacing();

            if (ImGui::Button("Request Driver Unload", ImVec2(200, 25))) { // Made button a bit wider
                if (isInitialized && g_current_pid_drawing != 0) {
                    LogMessage("[UI] 'Request Driver Unload' button clicked. Attempting IOCTL.");
                    // Optional: Confirmation Dialog (Skipped for brevity here, but good for UX)
                    // ImGui::OpenPopup("Confirm Unload");

                    NTSTATUS unload_status = DriverComm::RequestDriverUnload();
                    if (NT_SUCCESS(unload_status)) {
                        LogMessage("[UI] Driver unload request IOCTL sent successfully. Driver should prepare for unload.");
                        ImGui::OpenPopup("Unload Info");
                    } else {
                        LogMessageF("[UI] Failed to send driver unload request. Status: 0x%lX", unload_status);
                        ImGui::OpenPopup("Unload Fail Info");
                    }
                } else {
                    LogMessage("[UI] Cannot request driver unload: Not attached to game process or driver not initialized.");
                    ImGui::OpenPopup("Unload Fail Info Not Attached");
                }
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Attempts to send an IOCTL to the driver to request it to unload itself.\nThis is an advanced/debug feature. Use with caution.");
            }

            // Popups for feedback (should be defined once, outside the button's if block, but within Draw scope)
            // These are defined below, near other popups, or can be here. For this diff, assume they are defined elsewhere if this is not the only place.
            // For safety, defining them here if not present.
            if (ImGui::BeginPopupModal("Unload Info", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::Text("Driver unload request sent to kernel.\nThe driver will prepare for unload.\nActual unload may depend on system state or require a reboot.\n\nThis application should likely be closed now.");
                if (ImGui::Button("OK", ImVec2(120, 0))) { ImGui::CloseCurrentPopup(); }
                ImGui::EndPopup();
            }
            if (ImGui::BeginPopupModal("Unload Fail Info", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::Text("Failed to send driver unload request.\nEnsure the application is run with administrator privileges\nand the driver was loaded correctly.");
                if (ImGui::Button("OK", ImVec2(120, 0))) { ImGui::CloseCurrentPopup(); }
                ImGui::EndPopup();
            }
            if (ImGui::BeginPopupModal("Unload Fail Info Not Attached", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::Text("Cannot request driver unload.\nThe UI is not currently attached to the game process,\nor the driver communication is not initialized.");
                if (ImGui::Button("OK", ImVec2(120, 0))) { ImGui::CloseCurrentPopup(); }
                ImGui::EndPopup();
            }

            ImGui::EndTabItem();
        } // End of Config Tab

        ImGui::EndTabBar();
    }
    LimitFPS(185.0);
    ImGui::End();