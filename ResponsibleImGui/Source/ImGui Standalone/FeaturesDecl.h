#pragma once

//simple declarations for features bc importing features.h was causing weird ass issues

#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <string>
#include "DriverComm.h"

namespace LocalPlayer {
    struct Vec3 {
        float x, y, z;
    };

    extern std::atomic<Vec3> g_cachedCoords;
    extern std::atomic<uintptr_t> realPlayer;
    extern bool Enabled;
    extern bool flyEnabled;
    extern uintptr_t destinyBase;
    extern std::atomic<Vec3> g_cachedCoords;
}

namespace ViewAngles {
    struct Vec2 {
        float pitch, yaw;
    };

    // Note: The actual atomic definitions for g_viewBase and g_cachedAngles
    // are located in Features.h to avoid multiple definition errors.
    // FeaturesDecl.h is for extern declarations if they were to be shared across multiple .cpp files
    // without including the full Features.h, but in this project structure,
    // Features.h is included where needed.
}

// Removed template function declarations for ReadMem and WriteMem as they are not defined/used.
// DriverComm.h provides the necessary communication functions.
