#pragma once

#include "auth.hpp"
#include "skStr.h"
#include <string>
#include <vector>

namespace KeyAuthManager {
    // KeyAuth app instance
    extern KeyAuth::api KeyAuthApp;
    
    // Authentication state
    extern bool isAuthenticated;
    extern char License[128];
    extern char statusmsg[128];
    
    // Internal state
    extern bool gTriedAuto;
    extern bool gHasInitialized;
    extern bool isAuthenticating;
    extern char savedHwid[64];
    
    // Core functions
    void Initialize();
    void Cleanup();
    
    // Credential management
    void SaveCredentials(const char* licenseKey);
    bool LoadCredentials(char* licenseKey, size_t licSz);
    void ClearCredentials();
    
    // Authentication utility functions
    bool IsAuthenticated();
    std::string GetTimeRemaining();
    void Logout();
}
