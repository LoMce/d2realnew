#pragma once
#include "ImGui/imgui.h"
#include <vector>
#include <string>

namespace Themes {    enum class ThemeType {
        CATPPUCCIN = 0,
        DARK_BLUE,
        GREEN_MATRIX,
        CYBERPUNK,
        NORD,
        DRACULA,
        GRUVBOX,
        SOLARIZED_DARK,
        DREAM,
        HATED,
        HATEMOB,
        COUNT
    };

    struct ThemeInfo {
        ThemeType type;
        std::string name;
        std::string description;
    };    // Theme functions
    void SetCatppuccin();
    void SetDarkBlue();
    void SetGreenMatrix();
    void SetCyberpunk();
    void SetNord();
    void SetDracula();
    void SetGruvbox();
    void SetSolarizedDark();
    void SetDream();
    void SetHated();
    void SetHatemob();    // Theme management
    void ApplyTheme(ThemeType theme);
    std::vector<ThemeInfo> GetAvailableThemes();
    const char* GetThemeName(ThemeType theme);
    
    // Toggle color helpers
    ImVec4 GetToggleOnColor();
    ImVec4 GetToggleOffColor();
    ImVec4 GetToggleKnobColor();
    ImVec4 GetToggleTextColor();
    
    // Current theme tracking
    extern ThemeType currentTheme;
}