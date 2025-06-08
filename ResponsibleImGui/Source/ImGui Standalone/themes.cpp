#include "Themes.h"

namespace Themes {
    ThemeType currentTheme = ThemeType::CATPPUCCIN;

    void SetCatppuccin() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        // Catppuccin theme colors
        const ImVec4 rosewater = ImVec4(0.937f, 0.880f, 0.859f, 1.0f);
        const ImVec4 flamingo  = ImVec4(0.937f, 0.816f, 0.835f, 1.0f);
        const ImVec4 pink      = ImVec4(0.937f, 0.757f, 0.816f, 1.0f);
        const ImVec4 mauve     = ImVec4(0.788f, 0.678f, 0.957f, 1.0f);
        const ImVec4 red       = ImVec4(0.937f, 0.639f, 0.639f, 1.0f);
        const ImVec4 maroon    = ImVec4(0.937f, 0.678f, 0.718f, 1.0f);
        const ImVec4 peach     = ImVec4(0.937f, 0.757f, 0.616f, 1.0f);
        const ImVec4 yellow    = ImVec4(0.937f, 0.878f, 0.639f, 1.0f);
        const ImVec4 green     = ImVec4(0.639f, 0.937f, 0.639f, 1.0f);
        const ImVec4 teal      = ImVec4(0.639f, 0.937f, 0.757f, 1.0f);
        const ImVec4 sky       = ImVec4(0.639f, 0.937f, 0.878f, 1.0f);
        const ImVec4 sapphire  = ImVec4(0.639f, 0.878f, 0.937f, 1.0f);
        const ImVec4 blue      = ImVec4(0.639f, 0.757f, 0.937f, 1.0f);
        const ImVec4 lavender  = ImVec4(0.718f, 0.718f, 0.937f, 1.0f);
        const ImVec4 text      = ImVec4(0.937f, 0.937f, 0.937f, 1.0f);
        const ImVec4 subtext1  = ImVec4(0.937f, 0.937f, 0.937f, 0.8f);
        const ImVec4 subtext0  = ImVec4(0.937f, 0.937f, 0.937f, 0.6f);
        const ImVec4 overlay2  = ImVec4(0.698f, 0.698f, 0.698f, 1.0f);
        const ImVec4 overlay1  = ImVec4(0.424f, 0.424f, 0.424f, 1.0f);
        const ImVec4 overlay0  = ImVec4(0.243f, 0.243f, 0.243f, 1.0f);
        const ImVec4 surface2  = ImVec4(0.180f, 0.180f, 0.180f, 1.0f);
        const ImVec4 surface1  = ImVec4(0.157f, 0.157f, 0.157f, 1.0f);
        const ImVec4 surface0  = ImVec4(0.110f, 0.110f, 0.110f, 1.0f);
        const ImVec4 base      = ImVec4(0.063f, 0.063f, 0.063f, 1.0f);
        const ImVec4 mantle    = ImVec4(0.039f, 0.039f, 0.039f, 1.0f);
        const ImVec4 crust     = ImVec4(0.016f, 0.016f, 0.016f, 1.0f);

        // Window and background colors
        colors[ImGuiCol_WindowBg]           = base;
        colors[ImGuiCol_PopupBg]            = surface0;
        colors[ImGuiCol_ChildBg]            = base;

        // Text colors
        colors[ImGuiCol_Text]               = text;
        colors[ImGuiCol_TextDisabled]       = subtext0;

        // Headers
        colors[ImGuiCol_Header]             = surface0;
        colors[ImGuiCol_HeaderHovered]      = surface1;
        colors[ImGuiCol_HeaderActive]       = surface2;

        // Buttons
        colors[ImGuiCol_Button]             = mauve;
        colors[ImGuiCol_ButtonHovered]      = pink;
        colors[ImGuiCol_ButtonActive]       = flamingo;

        // Frame colors
        colors[ImGuiCol_FrameBg]            = surface0;
        colors[ImGuiCol_FrameBgHovered]     = surface1;
        colors[ImGuiCol_FrameBgActive]      = surface2;

        // Tabs
        colors[ImGuiCol_Tab]                = surface0;
        colors[ImGuiCol_TabHovered]         = mauve;
        colors[ImGuiCol_TabActive]          = surface2;
        colors[ImGuiCol_TabUnfocused]       = surface0;
        colors[ImGuiCol_TabUnfocusedActive] = surface1;

        // Title
        colors[ImGuiCol_TitleBg]            = crust;
        colors[ImGuiCol_TitleBgActive]      = base;
        colors[ImGuiCol_TitleBgCollapsed]   = mantle;

        // Slider/ScrollBar
        colors[ImGuiCol_ScrollbarBg]        = surface0;
        colors[ImGuiCol_ScrollbarGrab]      = mauve;
        colors[ImGuiCol_ScrollbarGrabHovered] = pink;
        colors[ImGuiCol_ScrollbarGrabActive]  = flamingo;
        colors[ImGuiCol_SliderGrab]         = mauve;
        colors[ImGuiCol_SliderGrabActive]   = flamingo;

        // Style
        style.FrameRounding    = 4.0f;
        style.WindowRounding   = 6.0f;
        style.TabRounding      = 4.0f;
        style.ScrollbarRounding = 6.0f;
        style.GrabRounding     = 4.0f;
        style.PopupRounding    = 4.0f;
        style.ChildRounding    = 4.0f;
    }    void SetDarkBlue() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        const ImVec4 darkBlue   = ImVec4(0.051f, 0.106f, 0.165f, 1.00f);
        const ImVec4 navy       = ImVec4(0.106f, 0.149f, 0.231f, 1.00f);
        const ImVec4 slate      = ImVec4(0.255f, 0.349f, 0.467f, 1.00f);
        const ImVec4 lightSlate = ImVec4(0.467f, 0.537f, 0.659f, 1.00f);
        const ImVec4 silver     = ImVec4(0.878f, 0.886f, 0.871f, 1.00f);

        // Window and background colors
        colors[ImGuiCol_WindowBg]           = darkBlue;
        colors[ImGuiCol_PopupBg]            = navy;
        colors[ImGuiCol_ChildBg]            = darkBlue;

        // Text colors
        colors[ImGuiCol_Text]               = silver;
        colors[ImGuiCol_TextDisabled]       = ImVec4(0.5f, 0.5f, 0.5f, 1.0f);

        // Headers
        colors[ImGuiCol_Header]             = slate;
        colors[ImGuiCol_HeaderHovered]      = lightSlate;
        colors[ImGuiCol_HeaderActive]       = ImVec4(0.6f, 0.7f, 0.8f, 1.0f);

        // Buttons
        colors[ImGuiCol_Button]             = slate;
        colors[ImGuiCol_ButtonHovered]      = lightSlate;
        colors[ImGuiCol_ButtonActive]       = ImVec4(0.6f, 0.7f, 0.8f, 1.0f);

        // Frame colors
        colors[ImGuiCol_FrameBg]            = navy;
        colors[ImGuiCol_FrameBgHovered]     = slate;
        colors[ImGuiCol_FrameBgActive]      = lightSlate;

        // Tabs
        colors[ImGuiCol_Tab]                = navy;
        colors[ImGuiCol_TabHovered]         = slate;
        colors[ImGuiCol_TabActive]          = lightSlate;
        colors[ImGuiCol_TabUnfocused]       = navy;
        colors[ImGuiCol_TabUnfocusedActive] = slate;

        // Title
        colors[ImGuiCol_TitleBg]            = darkBlue;
        colors[ImGuiCol_TitleBgActive]      = navy;
        colors[ImGuiCol_TitleBgCollapsed]   = darkBlue;

        // Slider/ScrollBar
        colors[ImGuiCol_ScrollbarBg]        = darkBlue;
        colors[ImGuiCol_ScrollbarGrab]      = slate;
        colors[ImGuiCol_ScrollbarGrabHovered] = lightSlate;
        colors[ImGuiCol_ScrollbarGrabActive]  = ImVec4(0.6f, 0.7f, 0.8f, 1.0f);
        colors[ImGuiCol_SliderGrab]         = slate;
        colors[ImGuiCol_SliderGrabActive]   = lightSlate;

        // Style
        style.FrameRounding    = 2.0f;
        style.WindowRounding   = 4.0f;
        style.TabRounding      = 2.0f;
        style.ScrollbarRounding = 4.0f;
        style.GrabRounding     = 2.0f;
        style.PopupRounding    = 2.0f;
        style.ChildRounding    = 2.0f;
    }

    void SetGreenMatrix() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        const ImVec4 black      = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
        const ImVec4 darkGreen  = ImVec4(0.0f, 0.2f, 0.0f, 1.0f);
        const ImVec4 green      = ImVec4(0.0f, 0.8f, 0.0f, 1.0f);
        const ImVec4 brightGreen = ImVec4(0.0f, 1.0f, 0.0f, 1.0f);

        // Window and background colors
        colors[ImGuiCol_WindowBg]           = black;
        colors[ImGuiCol_PopupBg]            = darkGreen;
        colors[ImGuiCol_ChildBg]            = black;

        // Text colors
        colors[ImGuiCol_Text]               = green;
        colors[ImGuiCol_TextDisabled]       = ImVec4(0.0f, 0.4f, 0.0f, 1.0f);

        // Headers
        colors[ImGuiCol_Header]             = darkGreen;
        colors[ImGuiCol_HeaderHovered]      = ImVec4(0.0f, 0.3f, 0.0f, 1.0f);
        colors[ImGuiCol_HeaderActive]       = ImVec4(0.0f, 0.5f, 0.0f, 1.0f);

        // Buttons
        colors[ImGuiCol_Button]             = darkGreen;
        colors[ImGuiCol_ButtonHovered]      = green;
        colors[ImGuiCol_ButtonActive]       = brightGreen;

        // Frame colors
        colors[ImGuiCol_FrameBg]            = ImVec4(0.0f, 0.15f, 0.0f, 1.0f);
        colors[ImGuiCol_FrameBgHovered]     = darkGreen;
        colors[ImGuiCol_FrameBgActive]      = ImVec4(0.0f, 0.3f, 0.0f, 1.0f);

        // Tabs
        colors[ImGuiCol_Tab]                = darkGreen;
        colors[ImGuiCol_TabHovered]         = green;
        colors[ImGuiCol_TabActive]          = ImVec4(0.0f, 0.4f, 0.0f, 1.0f);
        colors[ImGuiCol_TabUnfocused]       = darkGreen;
        colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.0f, 0.3f, 0.0f, 1.0f);

        // Title
        colors[ImGuiCol_TitleBg]            = black;
        colors[ImGuiCol_TitleBgActive]      = darkGreen;
        colors[ImGuiCol_TitleBgCollapsed]   = black;

        // Slider/ScrollBar
        colors[ImGuiCol_ScrollbarBg]        = black;
        colors[ImGuiCol_ScrollbarGrab]      = green;
        colors[ImGuiCol_ScrollbarGrabHovered] = brightGreen;
        colors[ImGuiCol_ScrollbarGrabActive]  = brightGreen;
        colors[ImGuiCol_SliderGrab]         = green;
        colors[ImGuiCol_SliderGrabActive]   = brightGreen;

        // Style
        style.FrameRounding    = 0.0f;
        style.WindowRounding   = 0.0f;
        style.TabRounding      = 0.0f;
        style.ScrollbarRounding = 0.0f;
        style.GrabRounding     = 0.0f;
        style.PopupRounding    = 0.0f;
        style.ChildRounding    = 0.0f;
    }

    void SetCyberpunk() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        const ImVec4 black      = ImVec4(0.05f, 0.05f, 0.05f, 1.0f);
        const ImVec4 darkPurple = ImVec4(0.2f, 0.05f, 0.3f, 1.0f);
        const ImVec4 purple     = ImVec4(0.5f, 0.0f, 0.8f, 1.0f);
        const ImVec4 cyan       = ImVec4(0.0f, 0.8f, 1.0f, 1.0f);
        const ImVec4 pink       = ImVec4(1.0f, 0.0f, 0.8f, 1.0f);

        // Window and background colors
        colors[ImGuiCol_WindowBg]           = black;
        colors[ImGuiCol_PopupBg]            = darkPurple;
        colors[ImGuiCol_ChildBg]            = black;

        // Text colors
        colors[ImGuiCol_Text]               = cyan;
        colors[ImGuiCol_TextDisabled]       = ImVec4(0.4f, 0.4f, 0.4f, 1.0f);

        // Headers
        colors[ImGuiCol_Header]             = darkPurple;
        colors[ImGuiCol_HeaderHovered]      = purple;
        colors[ImGuiCol_HeaderActive]       = pink;

        // Buttons
        colors[ImGuiCol_Button]             = darkPurple;
        colors[ImGuiCol_ButtonHovered]      = purple;
        colors[ImGuiCol_ButtonActive]       = pink;

        // Frame colors
        colors[ImGuiCol_FrameBg]            = ImVec4(0.1f, 0.02f, 0.15f, 1.0f);
        colors[ImGuiCol_FrameBgHovered]     = darkPurple;
        colors[ImGuiCol_FrameBgActive]      = purple;

        // Tabs
        colors[ImGuiCol_Tab]                = darkPurple;
        colors[ImGuiCol_TabHovered]         = purple;
        colors[ImGuiCol_TabActive]          = pink;
        colors[ImGuiCol_TabUnfocused]       = darkPurple;
        colors[ImGuiCol_TabUnfocusedActive] = purple;

        // Title
        colors[ImGuiCol_TitleBg]            = black;
        colors[ImGuiCol_TitleBgActive]      = darkPurple;
        colors[ImGuiCol_TitleBgCollapsed]   = black;

        // Slider/ScrollBar
        colors[ImGuiCol_ScrollbarBg]        = black;
        colors[ImGuiCol_ScrollbarGrab]      = purple;
        colors[ImGuiCol_ScrollbarGrabHovered] = pink;
        colors[ImGuiCol_ScrollbarGrabActive]  = cyan;
        colors[ImGuiCol_SliderGrab]         = purple;
        colors[ImGuiCol_SliderGrabActive]   = pink;

        // Style
        style.FrameRounding    = 8.0f;
        style.WindowRounding   = 10.0f;
        style.TabRounding      = 6.0f;
        style.ScrollbarRounding = 8.0f;
        style.GrabRounding     = 6.0f;
        style.PopupRounding    = 8.0f;
        style.ChildRounding    = 8.0f;
    }

    void SetNord() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        const ImVec4 nord0  = ImVec4(0.180f, 0.204f, 0.251f, 1.0f); // #2E3440
        const ImVec4 nord1  = ImVec4(0.231f, 0.259f, 0.322f, 1.0f); // #3B4252
        const ImVec4 nord2  = ImVec4(0.263f, 0.298f, 0.368f, 1.0f); // #434C5E
        const ImVec4 nord3  = ImVec4(0.298f, 0.337f, 0.416f, 1.0f); // #4C566A
        const ImVec4 nord4  = ImVec4(0.847f, 0.871f, 0.914f, 1.0f); // #D8DEE9
        const ImVec4 nord5  = ImVec4(0.898f, 0.914f, 0.941f, 1.0f); // #E5E9F0
        const ImVec4 nord6  = ImVec4(0.925f, 0.937f, 0.957f, 1.0f); // #ECEFF4
        const ImVec4 nord7  = ImVec4(0.565f, 0.737f, 0.733f, 1.0f); // #8FBCBB
        const ImVec4 nord8  = ImVec4(0.533f, 0.753f, 0.816f, 1.0f); // #88C0D0
        const ImVec4 nord9  = ImVec4(0.506f, 0.631f, 0.757f, 1.0f); // #81A1C1
        const ImVec4 nord10 = ImVec4(0.369f, 0.506f, 0.675f, 1.0f); // #5E81AC

        // Window and background colors
        colors[ImGuiCol_WindowBg]           = nord0;
        colors[ImGuiCol_PopupBg]            = nord1;
        colors[ImGuiCol_ChildBg]            = nord0;

        // Text colors
        colors[ImGuiCol_Text]               = nord4;
        colors[ImGuiCol_TextDisabled]       = nord3;

        // Headers
        colors[ImGuiCol_Header]             = nord1;
        colors[ImGuiCol_HeaderHovered]      = nord2;
        colors[ImGuiCol_HeaderActive]       = nord3;

        // Buttons
        colors[ImGuiCol_Button]             = nord9;
        colors[ImGuiCol_ButtonHovered]      = nord8;
        colors[ImGuiCol_ButtonActive]       = nord10;

        // Frame colors
        colors[ImGuiCol_FrameBg]            = nord1;
        colors[ImGuiCol_FrameBgHovered]     = nord2;
        colors[ImGuiCol_FrameBgActive]      = nord3;

        // Tabs
        colors[ImGuiCol_Tab]                = nord1;
        colors[ImGuiCol_TabHovered]         = nord9;
        colors[ImGuiCol_TabActive]          = nord2;
        colors[ImGuiCol_TabUnfocused]       = nord1;
        colors[ImGuiCol_TabUnfocusedActive] = nord2;

        // Title
        colors[ImGuiCol_TitleBg]            = nord0;
        colors[ImGuiCol_TitleBgActive]      = nord1;
        colors[ImGuiCol_TitleBgCollapsed]   = nord0;

        // Slider/ScrollBar
        colors[ImGuiCol_ScrollbarBg]        = nord1;
        colors[ImGuiCol_ScrollbarGrab]      = nord9;
        colors[ImGuiCol_ScrollbarGrabHovered] = nord8;
        colors[ImGuiCol_ScrollbarGrabActive]  = nord10;
        colors[ImGuiCol_SliderGrab]         = nord9;
        colors[ImGuiCol_SliderGrabActive]   = nord8;

        // Style
        style.FrameRounding    = 3.0f;
        style.WindowRounding   = 5.0f;
        style.TabRounding      = 3.0f;
        style.ScrollbarRounding = 5.0f;
        style.GrabRounding     = 3.0f;
        style.PopupRounding    = 3.0f;
        style.ChildRounding    = 3.0f;
    }

    void SetDracula() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        const ImVec4 background = ImVec4(0.157f, 0.165f, 0.212f, 1.0f); // #282a36
        const ImVec4 currentLine = ImVec4(0.173f, 0.180f, 0.231f, 1.0f); // #44475a
        const ImVec4 selection  = ImVec4(0.173f, 0.180f, 0.231f, 1.0f); // #44475a
        const ImVec4 foreground = ImVec4(0.945f, 0.980f, 1.0f, 1.0f); // #f8f8f2
        const ImVec4 comment    = ImVec4(0.412f, 0.439f, 0.518f, 1.0f); // #6272a4
        const ImVec4 cyan       = ImVec4(0.549f, 0.941f, 0.941f, 1.0f); // #8be9fd
        const ImVec4 green      = ImVec4(0.314f, 0.980f, 0.482f, 1.0f); // #50fa7b
        const ImVec4 orange     = ImVec4(1.0f, 0.725f, 0.424f, 1.0f); // #ffb86c
        const ImVec4 pink       = ImVec4(1.0f, 0.475f, 0.776f, 1.0f); // #ff79c6
        const ImVec4 purple     = ImVec4(0.741f, 0.576f, 0.976f, 1.0f); // #bd93f9
        const ImVec4 red        = ImVec4(1.0f, 0.333f, 0.333f, 1.0f); // #ff5555
        const ImVec4 yellow     = ImVec4(0.945f, 0.980f, 0.549f, 1.0f); // #f1fa8c

        // Window and background colors
        colors[ImGuiCol_WindowBg]           = background;
        colors[ImGuiCol_PopupBg]            = currentLine;
        colors[ImGuiCol_ChildBg]            = background;

        // Text colors
        colors[ImGuiCol_Text]               = foreground;
        colors[ImGuiCol_TextDisabled]       = comment;

        // Headers
        colors[ImGuiCol_Header]             = currentLine;
        colors[ImGuiCol_HeaderHovered]      = selection;
        colors[ImGuiCol_HeaderActive]       = purple;

        // Buttons
        colors[ImGuiCol_Button]             = purple;
        colors[ImGuiCol_ButtonHovered]      = pink;
        colors[ImGuiCol_ButtonActive]       = cyan;

        // Frame colors
        colors[ImGuiCol_FrameBg]            = currentLine;
        colors[ImGuiCol_FrameBgHovered]     = selection;
        colors[ImGuiCol_FrameBgActive]      = purple;

        // Tabs
        colors[ImGuiCol_Tab]                = currentLine;
        colors[ImGuiCol_TabHovered]         = purple;
        colors[ImGuiCol_TabActive]          = pink;
        colors[ImGuiCol_TabUnfocused]       = currentLine;
        colors[ImGuiCol_TabUnfocusedActive] = selection;

        // Title
        colors[ImGuiCol_TitleBg]            = background;
        colors[ImGuiCol_TitleBgActive]      = currentLine;
        colors[ImGuiCol_TitleBgCollapsed]   = background;

        // Slider/ScrollBar
        colors[ImGuiCol_ScrollbarBg]        = background;
        colors[ImGuiCol_ScrollbarGrab]      = purple;
        colors[ImGuiCol_ScrollbarGrabHovered] = pink;
        colors[ImGuiCol_ScrollbarGrabActive]  = cyan;
        colors[ImGuiCol_SliderGrab]         = purple;
        colors[ImGuiCol_SliderGrabActive]   = pink;

        // Style
        style.FrameRounding    = 4.0f;
        style.WindowRounding   = 6.0f;
        style.TabRounding      = 4.0f;
        style.ScrollbarRounding = 6.0f;
        style.GrabRounding     = 4.0f;
        style.PopupRounding    = 4.0f;
        style.ChildRounding    = 4.0f;
    }

    void SetGruvbox() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        const ImVec4 bg0_h      = ImVec4(0.106f, 0.102f, 0.094f, 1.0f); // #1d2021
        const ImVec4 bg0        = ImVec4(0.157f, 0.157f, 0.137f, 1.0f); // #282828
        const ImVec4 bg1        = ImVec4(0.235f, 0.218f, 0.178f, 1.0f); // #3c3836
        const ImVec4 bg2        = ImVec4(0.322f, 0.286f, 0.216f, 1.0f); // #504945
        const ImVec4 bg3        = ImVec4(0.427f, 0.369f, 0.259f, 1.0f); // #665c54
        const ImVec4 bg4        = ImVec4(0.514f, 0.427f, 0.275f, 1.0f); // #7c6f64
        const ImVec4 fg0        = ImVec4(0.984f, 0.937f, 0.827f, 1.0f); // #fbf1c7
        const ImVec4 fg1        = ImVec4(0.922f, 0.859f, 0.698f, 1.0f); // #ebdbb2
        const ImVec4 fg2        = ImVec4(0.827f, 0.757f, 0.631f, 1.0f); // #d3c6a1
        const ImVec4 fg3        = ImVec4(0.741f, 0.663f, 0.557f, 1.0f); // #bdae93
        const ImVec4 fg4        = ImVec4(0.659f, 0.573f, 0.486f, 1.0f); // #a89984
        const ImVec4 red        = ImVec4(0.812f, 0.271f, 0.271f, 1.0f); // #cc241d
        const ImVec4 green      = ImVec4(0.596f, 0.592f, 0.102f, 1.0f); // #98971a
        const ImVec4 yellow     = ImVec4(0.843f, 0.600f, 0.129f, 1.0f); // #d79921
        const ImVec4 blue       = ImVec4(0.271f, 0.522f, 0.533f, 1.0f); // #458588
        const ImVec4 purple     = ImVec4(0.694f, 0.384f, 0.525f, 1.0f); // #b16286
        const ImVec4 aqua       = ImVec4(0.408f, 0.616f, 0.416f, 1.0f); // #689d6a
        const ImVec4 orange     = ImVec4(0.851f, 0.373f, 0.059f, 1.0f); // #d65d0e

        // Window and background colors
        colors[ImGuiCol_WindowBg]           = bg0;
        colors[ImGuiCol_PopupBg]            = bg1;
        colors[ImGuiCol_ChildBg]            = bg0;

        // Text colors
        colors[ImGuiCol_Text]               = fg1;
        colors[ImGuiCol_TextDisabled]       = fg4;

        // Headers
        colors[ImGuiCol_Header]             = bg1;
        colors[ImGuiCol_HeaderHovered]      = bg2;
        colors[ImGuiCol_HeaderActive]       = bg3;

        // Buttons
        colors[ImGuiCol_Button]             = yellow;
        colors[ImGuiCol_ButtonHovered]      = orange;
        colors[ImGuiCol_ButtonActive]       = red;

        // Frame colors
        colors[ImGuiCol_FrameBg]            = bg1;
        colors[ImGuiCol_FrameBgHovered]     = bg2;
        colors[ImGuiCol_FrameBgActive]      = bg3;

        // Tabs
        colors[ImGuiCol_Tab]                = bg1;
        colors[ImGuiCol_TabHovered]         = yellow;
        colors[ImGuiCol_TabActive]          = bg2;
        colors[ImGuiCol_TabUnfocused]       = bg1;
        colors[ImGuiCol_TabUnfocusedActive] = bg2;

        // Title
        colors[ImGuiCol_TitleBg]            = bg0_h;
        colors[ImGuiCol_TitleBgActive]      = bg1;
        colors[ImGuiCol_TitleBgCollapsed]   = bg0_h;

        // Slider/ScrollBar
        colors[ImGuiCol_ScrollbarBg]        = bg1;
        colors[ImGuiCol_ScrollbarGrab]      = yellow;
        colors[ImGuiCol_ScrollbarGrabHovered] = orange;
        colors[ImGuiCol_ScrollbarGrabActive]  = red;
        colors[ImGuiCol_SliderGrab]         = yellow;
        colors[ImGuiCol_SliderGrabActive]   = orange;

        // Style
        style.FrameRounding    = 2.0f;
        style.WindowRounding   = 4.0f;
        style.TabRounding      = 2.0f;
        style.ScrollbarRounding = 4.0f;
        style.GrabRounding     = 2.0f;
        style.PopupRounding    = 2.0f;
        style.ChildRounding    = 2.0f;
    }

    void SetSolarizedDark() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        const ImVec4 base03  = ImVec4(0.0f, 0.169f, 0.212f, 1.0f);      // #002b36
        const ImVec4 base02  = ImVec4(0.027f, 0.212f, 0.259f, 1.0f);    // #073642
        const ImVec4 base01  = ImVec4(0.345f, 0.431f, 0.459f, 1.0f);    // #586e75
        const ImVec4 base00  = ImVec4(0.396f, 0.482f, 0.514f, 1.0f);    // #657b83
        const ImVec4 base0   = ImVec4(0.514f, 0.580f, 0.588f, 1.0f);    // #839496
        const ImVec4 base1   = ImVec4(0.576f, 0.631f, 0.631f, 1.0f);    // #93a1a1
        const ImVec4 base2   = ImVec4(0.933f, 0.910f, 0.835f, 1.0f);    // #eee8d5
        const ImVec4 base3   = ImVec4(0.992f, 0.965f, 0.890f, 1.0f);    // #fdf6e3
        const ImVec4 yellow  = ImVec4(0.710f, 0.537f, 0.0f, 1.0f);      // #b58900
        const ImVec4 orange  = ImVec4(0.796f, 0.294f, 0.086f, 1.0f);    // #cb4b16
        const ImVec4 red     = ImVec4(0.863f, 0.196f, 0.184f, 1.0f);    // #dc322f
        const ImVec4 magenta = ImVec4(0.827f, 0.212f, 0.510f, 1.0f);    // #d33682
        const ImVec4 violet  = ImVec4(0.424f, 0.443f, 0.769f, 1.0f);    // #6c71c4
        const ImVec4 blue    = ImVec4(0.149f, 0.545f, 0.824f, 1.0f);    // #268bd2
        const ImVec4 cyan    = ImVec4(0.165f, 0.631f, 0.596f, 1.0f);    // #2aa198
        const ImVec4 green   = ImVec4(0.522f, 0.600f, 0.0f, 1.0f);      // #859900

        // Window and background colors
        colors[ImGuiCol_WindowBg]           = base03;
        colors[ImGuiCol_PopupBg]            = base02;
        colors[ImGuiCol_ChildBg]            = base03;

        // Text colors
        colors[ImGuiCol_Text]               = base0;
        colors[ImGuiCol_TextDisabled]       = base01;

        // Headers
        colors[ImGuiCol_Header]             = base02;
        colors[ImGuiCol_HeaderHovered]      = base01;
        colors[ImGuiCol_HeaderActive]       = base00;

        // Buttons
        colors[ImGuiCol_Button]             = blue;
        colors[ImGuiCol_ButtonHovered]      = cyan;
        colors[ImGuiCol_ButtonActive]       = green;

        // Frame colors
        colors[ImGuiCol_FrameBg]            = base02;
        colors[ImGuiCol_FrameBgHovered]     = base01;
        colors[ImGuiCol_FrameBgActive]      = base00;

        // Tabs
        colors[ImGuiCol_Tab]                = base02;
        colors[ImGuiCol_TabHovered]         = blue;
        colors[ImGuiCol_TabActive]          = base01;
        colors[ImGuiCol_TabUnfocused]       = base02;
        colors[ImGuiCol_TabUnfocusedActive] = base01;

        // Title
        colors[ImGuiCol_TitleBg]            = base03;
        colors[ImGuiCol_TitleBgActive]      = base02;
        colors[ImGuiCol_TitleBgCollapsed]   = base03;

        // Slider/ScrollBar
        colors[ImGuiCol_ScrollbarBg]        = base02;
        colors[ImGuiCol_ScrollbarGrab]      = blue;
        colors[ImGuiCol_ScrollbarGrabHovered] = cyan;
        colors[ImGuiCol_ScrollbarGrabActive]  = green;
        colors[ImGuiCol_SliderGrab]         = blue;
        colors[ImGuiCol_SliderGrabActive]   = cyan;

        // Style        style.FrameRounding    = 3.0f;
        style.WindowRounding   = 5.0f;
        style.TabRounding      = 3.0f;
        style.ScrollbarRounding = 5.0f;
        style.GrabRounding     = 3.0f;
        style.PopupRounding    = 3.0f;
        style.ChildRounding    = 3.0f;

    }

    void SetDream() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        // Dream color palette - soft pastels
        const ImVec4 lavender   = ImVec4(0.804f, 0.706f, 0.859f, 1.0f); // #CDB4DB
        const ImVec4 pinkLight  = ImVec4(1.0f, 0.784f, 0.867f, 1.0f);   // #FFC8DD
        const ImVec4 pinkSoft   = ImVec4(1.0f, 0.686f, 0.8f, 1.0f);     // #FFAFCC
        const ImVec4 blueLight  = ImVec4(0.741f, 0.878f, 0.996f, 1.0f); // #BDE0FE
        const ImVec4 blueSky    = ImVec4(0.635f, 0.824f, 1.0f, 1.0f);   // #A2D2FF
        
        // Derived colors for better contrast
        const ImVec4 background = ImVec4(0.05f, 0.05f, 0.08f, 1.0f);    // Very dark purple
        const ImVec4 surface    = ImVec4(0.1f, 0.08f, 0.12f, 1.0f);     // Dark purple surface
        const ImVec4 text       = ImVec4(0.95f, 0.95f, 0.98f, 1.0f);    // Light text
        const ImVec4 textDim    = ImVec4(0.7f, 0.7f, 0.8f, 1.0f);       // Dimmed text

        // Window and background colors
        colors[ImGuiCol_WindowBg]           = background;
        colors[ImGuiCol_PopupBg]            = surface;
        colors[ImGuiCol_ChildBg]            = background;

        // Text colors
        colors[ImGuiCol_Text]               = text;
        colors[ImGuiCol_TextDisabled]       = textDim;

        // Headers
        colors[ImGuiCol_Header]             = lavender;
        colors[ImGuiCol_HeaderHovered]      = pinkLight;
        colors[ImGuiCol_HeaderActive]       = pinkSoft;

        // Buttons
        colors[ImGuiCol_Button]             = lavender;
        colors[ImGuiCol_ButtonHovered]      = pinkLight;
        colors[ImGuiCol_ButtonActive]       = pinkSoft;

        // Frame colors
        colors[ImGuiCol_FrameBg]            = surface;
        colors[ImGuiCol_FrameBgHovered]     = lavender;
        colors[ImGuiCol_FrameBgActive]      = pinkLight;

        // Tabs
        colors[ImGuiCol_Tab]                = surface;
        colors[ImGuiCol_TabHovered]         = lavender;
        colors[ImGuiCol_TabActive]          = pinkLight;
        colors[ImGuiCol_TabUnfocused]       = surface;
        colors[ImGuiCol_TabUnfocusedActive] = lavender;

        // Title
        colors[ImGuiCol_TitleBg]            = background;
        colors[ImGuiCol_TitleBgActive]      = surface;
        colors[ImGuiCol_TitleBgCollapsed]   = background;

        // Slider/ScrollBar
        colors[ImGuiCol_ScrollbarBg]        = surface;
        colors[ImGuiCol_ScrollbarGrab]      = blueLight;
        colors[ImGuiCol_ScrollbarGrabHovered] = blueSky;
        colors[ImGuiCol_ScrollbarGrabActive]  = pinkSoft;
        colors[ImGuiCol_SliderGrab]         = blueLight;
        colors[ImGuiCol_SliderGrabActive]   = blueSky;

        // Checkmarks and selection
        colors[ImGuiCol_CheckMark]          = pinkSoft;
        colors[ImGuiCol_TextSelectedBg]     = lavender;

        // Borders and separators
        colors[ImGuiCol_Border]             = lavender;
        colors[ImGuiCol_Separator]          = lavender;
        colors[ImGuiCol_SeparatorHovered]   = pinkLight;
        colors[ImGuiCol_SeparatorActive]    = pinkSoft;

        // Resize grip
        colors[ImGuiCol_ResizeGrip]         = lavender;
        colors[ImGuiCol_ResizeGripHovered]  = pinkLight;
        colors[ImGuiCol_ResizeGripActive]   = pinkSoft;

        // Style - soft and rounded for dreamy feel        style.FrameRounding    = 6.0f;
        style.WindowRounding   = 8.0f;
        style.TabRounding      = 6.0f;
        style.ScrollbarRounding = 8.0f;
        style.GrabRounding     = 6.0f;
        style.PopupRounding    = 6.0f;
        style.ChildRounding    = 6.0f;
    }

    void SetHated() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        // Hated color palette - grayscale progression from light to dark
        const ImVec4 gray1      = ImVec4(0.973f, 0.976f, 0.980f, 1.0f); // #f8f9fa - lightest
        const ImVec4 gray2      = ImVec4(0.914f, 0.925f, 0.937f, 1.0f); // #e9ecef
        const ImVec4 gray3      = ImVec4(0.871f, 0.886f, 0.902f, 1.0f); // #dee2e6
        const ImVec4 gray4      = ImVec4(0.808f, 0.831f, 0.855f, 1.0f); // #ced4da
        const ImVec4 gray5      = ImVec4(0.678f, 0.710f, 0.741f, 1.0f); // #adb5bd
        const ImVec4 gray6      = ImVec4(0.424f, 0.459f, 0.490f, 1.0f); // #6c757d
        const ImVec4 gray7      = ImVec4(0.286f, 0.314f, 0.341f, 1.0f); // #495057
        const ImVec4 gray8      = ImVec4(0.204f, 0.227f, 0.251f, 1.0f); // #343a40
        const ImVec4 gray9      = ImVec4(0.129f, 0.145f, 0.161f, 1.0f); // #212529 - darkest

        // Window and background colors
        colors[ImGuiCol_WindowBg]           = gray9;     // Darkest background
        colors[ImGuiCol_PopupBg]            = gray8;     // Popup background
        colors[ImGuiCol_ChildBg]            = gray9;     // Child window background

        // Text colors
        colors[ImGuiCol_Text]               = gray1;     // Light text on dark background
        colors[ImGuiCol_TextDisabled]       = gray5;     // Disabled text

        // Headers
        colors[ImGuiCol_Header]             = gray7;     // Header background
        colors[ImGuiCol_HeaderHovered]      = gray6;     // Header hovered
        colors[ImGuiCol_HeaderActive]       = gray5;     // Header active

        // Buttons
        colors[ImGuiCol_Button]             = gray7;     // Button background
        colors[ImGuiCol_ButtonHovered]      = gray6;     // Button hovered
        colors[ImGuiCol_ButtonActive]       = gray5;     // Button active

        // Frame colors (inputs, etc.)
        colors[ImGuiCol_FrameBg]            = gray8;     // Frame background
        colors[ImGuiCol_FrameBgHovered]     = gray7;     // Frame hovered
        colors[ImGuiCol_FrameBgActive]      = gray6;     // Frame active

        // Tabs
        colors[ImGuiCol_Tab]                = gray8;     // Inactive tab
        colors[ImGuiCol_TabHovered]         = gray6;     // Tab hovered
        colors[ImGuiCol_TabActive]          = gray7;     // Active tab
        colors[ImGuiCol_TabUnfocused]       = gray8;     // Unfocused tab
        colors[ImGuiCol_TabUnfocusedActive] = gray7;     // Unfocused active tab

        // Title
        colors[ImGuiCol_TitleBg]            = gray9;     // Title background
        colors[ImGuiCol_TitleBgActive]      = gray8;     // Active title background
        colors[ImGuiCol_TitleBgCollapsed]   = gray9;     // Collapsed title background

        // Slider/ScrollBar
        colors[ImGuiCol_ScrollbarBg]        = gray8;     // Scrollbar background
        colors[ImGuiCol_ScrollbarGrab]      = gray6;     // Scrollbar grab
        colors[ImGuiCol_ScrollbarGrabHovered] = gray5;   // Scrollbar grab hovered
        colors[ImGuiCol_ScrollbarGrabActive]  = gray4;   // Scrollbar grab active
        colors[ImGuiCol_SliderGrab]         = gray6;     // Slider grab
        colors[ImGuiCol_SliderGrabActive]   = gray5;     // Slider grab active

        // Checkmarks and selection
        colors[ImGuiCol_CheckMark]          = gray3;     // Checkmark color
        colors[ImGuiCol_TextSelectedBg]     = gray6;     // Selected text background

        // Borders and separators
        colors[ImGuiCol_Border]             = gray6;     // Border color
        colors[ImGuiCol_Separator]          = gray6;     // Separator color
        colors[ImGuiCol_SeparatorHovered]   = gray5;     // Separator hovered
        colors[ImGuiCol_SeparatorActive]    = gray4;     // Separator active

        // Resize grip
        colors[ImGuiCol_ResizeGrip]         = gray6;     // Resize grip
        colors[ImGuiCol_ResizeGripHovered]  = gray5;     // Resize grip hovered
        colors[ImGuiCol_ResizeGripActive]   = gray4;     // Resize grip active

        // Menu bar
        colors[ImGuiCol_MenuBarBg]          = gray8;     // Menu bar background

        // Navigation
        colors[ImGuiCol_NavHighlight]       = gray5;     // Navigation highlight
        colors[ImGuiCol_NavWindowingHighlight] = gray3;  // Navigation windowing highlight
        colors[ImGuiCol_NavWindowingDimBg]  = gray7;     // Navigation windowing dim background

        // Modal window
        colors[ImGuiCol_ModalWindowDimBg]   = ImVec4(gray9.x, gray9.y, gray9.z, 0.6f); // Modal dim background        // Style - sharp and minimal for harsh aesthetic
        style.FrameRounding    = 1.0f;       // Minimal rounding
        style.WindowRounding   = 2.0f;       // Slight window rounding
        style.TabRounding      = 1.0f;       // Minimal tab rounding
        style.ScrollbarRounding = 2.0f;      // Slight scrollbar rounding
        style.GrabRounding     = 1.0f;       // Minimal grab rounding
        style.PopupRounding    = 2.0f;       // Slight popup rounding
        style.ChildRounding    = 1.0f;       // Minimal child rounding
    }

    void SetHatemob() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        // Hatemob color palette - deep purple gradient from dark to light
        const ImVec4 purple1    = ImVec4(0.063f, 0.0f, 0.169f, 1.0f);   // #10002b - deepest dark
        const ImVec4 purple2    = ImVec4(0.141f, 0.0f, 0.275f, 1.0f);   // #240046 
        const ImVec4 purple3    = ImVec4(0.235f, 0.024f, 0.424f, 1.0f); // #3c096c
        const ImVec4 purple4    = ImVec4(0.353f, 0.098f, 0.604f, 1.0f); // #5a189a
        const ImVec4 purple5    = ImVec4(0.482f, 0.173f, 0.749f, 1.0f); // #7b2cbf
        const ImVec4 purple6    = ImVec4(0.616f, 0.306f, 0.867f, 1.0f); // #9d4edd
        const ImVec4 purple7    = ImVec4(0.780f, 0.490f, 1.0f, 1.0f);   // #c77dff
        const ImVec4 purple8    = ImVec4(0.878f, 0.667f, 1.0f, 1.0f);   // #e0aaff - lightest

        // Derived colors for better contrast
        const ImVec4 text       = ImVec4(0.95f, 0.95f, 1.0f, 1.0f);     // Almost white with purple tint
        const ImVec4 textDim    = ImVec4(0.7f, 0.6f, 0.8f, 1.0f);       // Dimmed purple-tinted text

        // Window and background colors
        colors[ImGuiCol_WindowBg]           = purple1;   // Deepest purple background
        colors[ImGuiCol_PopupBg]            = purple2;   // Popup background
        colors[ImGuiCol_ChildBg]            = purple1;   // Child window background

        // Text colors
        colors[ImGuiCol_Text]               = text;      // Light text on dark background
        colors[ImGuiCol_TextDisabled]       = textDim;   // Disabled text

        // Headers
        colors[ImGuiCol_Header]             = purple3;   // Header background
        colors[ImGuiCol_HeaderHovered]      = purple4;   // Header hovered
        colors[ImGuiCol_HeaderActive]       = purple5;   // Header active

        // Buttons
        colors[ImGuiCol_Button]             = purple4;   // Button background
        colors[ImGuiCol_ButtonHovered]      = purple5;   // Button hovered
        colors[ImGuiCol_ButtonActive]       = purple6;   // Button active

        // Frame colors (inputs, etc.)
        colors[ImGuiCol_FrameBg]            = purple2;   // Frame background
        colors[ImGuiCol_FrameBgHovered]     = purple3;   // Frame hovered
        colors[ImGuiCol_FrameBgActive]      = purple4;   // Frame active

        // Tabs
        colors[ImGuiCol_Tab]                = purple2;   // Inactive tab
        colors[ImGuiCol_TabHovered]         = purple4;   // Tab hovered
        colors[ImGuiCol_TabActive]          = purple5;   // Active tab
        colors[ImGuiCol_TabUnfocused]       = purple2;   // Unfocused tab
        colors[ImGuiCol_TabUnfocusedActive] = purple3;   // Unfocused active tab

        // Title
        colors[ImGuiCol_TitleBg]            = purple1;   // Title background
        colors[ImGuiCol_TitleBgActive]      = purple2;   // Active title background
        colors[ImGuiCol_TitleBgCollapsed]   = purple1;   // Collapsed title background

        // Slider/ScrollBar
        colors[ImGuiCol_ScrollbarBg]        = purple2;   // Scrollbar background
        colors[ImGuiCol_ScrollbarGrab]      = purple5;   // Scrollbar grab
        colors[ImGuiCol_ScrollbarGrabHovered] = purple6; // Scrollbar grab hovered
        colors[ImGuiCol_ScrollbarGrabActive]  = purple7; // Scrollbar grab active
        colors[ImGuiCol_SliderGrab]         = purple5;   // Slider grab
        colors[ImGuiCol_SliderGrabActive]   = purple6;   // Slider grab active

        // Checkmarks and selection
        colors[ImGuiCol_CheckMark]          = purple7;   // Checkmark color
        colors[ImGuiCol_TextSelectedBg]     = purple4;   // Selected text background

        // Borders and separators
        colors[ImGuiCol_Border]             = purple4;   // Border color
        colors[ImGuiCol_Separator]          = purple4;   // Separator color
        colors[ImGuiCol_SeparatorHovered]   = purple5;   // Separator hovered
        colors[ImGuiCol_SeparatorActive]    = purple6;   // Separator active

        // Resize grip
        colors[ImGuiCol_ResizeGrip]         = purple4;   // Resize grip
        colors[ImGuiCol_ResizeGripHovered]  = purple5;   // Resize grip hovered
        colors[ImGuiCol_ResizeGripActive]   = purple6;   // Resize grip active

        // Menu bar
        colors[ImGuiCol_MenuBarBg]          = purple2;   // Menu bar background

        // Navigation
        colors[ImGuiCol_NavHighlight]       = purple6;   // Navigation highlight
        colors[ImGuiCol_NavWindowingHighlight] = purple7; // Navigation windowing highlight
        colors[ImGuiCol_NavWindowingDimBg]  = purple3;   // Navigation windowing dim background

        // Modal window
        colors[ImGuiCol_ModalWindowDimBg]   = ImVec4(purple1.x, purple1.y, purple1.z, 0.7f); // Modal dim background

        // Style - modern and sleek for premium feel
        style.FrameRounding    = 4.0f;       // Modern rounding
        style.WindowRounding   = 6.0f;       // Smooth window rounding
        style.TabRounding      = 4.0f;       // Tab rounding
        style.ScrollbarRounding = 6.0f;      // Scrollbar rounding
        style.GrabRounding     = 4.0f;       // Grab rounding
        style.PopupRounding    = 6.0f;       // Popup rounding
        style.ChildRounding    = 4.0f;       // Child rounding
    }

    // Theme management functions
    void ApplyTheme(ThemeType theme) {
        currentTheme = theme;
        
        switch (theme) {
            case ThemeType::CATPPUCCIN:
                SetCatppuccin();
                break;
            case ThemeType::DARK_BLUE:
                SetDarkBlue();
                break;
            case ThemeType::GREEN_MATRIX:
                SetGreenMatrix();
                break;
            case ThemeType::CYBERPUNK:
                SetCyberpunk();
                break;
            case ThemeType::NORD:
                SetNord();
                break;
            case ThemeType::DRACULA:
                SetDracula();
                break;
            case ThemeType::GRUVBOX:
                SetGruvbox();
                break;            case ThemeType::SOLARIZED_DARK:
                SetSolarizedDark();
                break;            case ThemeType::DREAM:
                SetDream();
                break;            case ThemeType::HATED:
                SetHated();
                break;
            case ThemeType::HATEMOB:
                SetHatemob();
                break;
            default:
                SetCatppuccin(); // Fallback to default
                break;
        }
    }    std::vector<ThemeInfo> GetAvailableThemes() {
        return {
            { ThemeType::CATPPUCCIN, "Catppuccin", "Pastel colorscheme inspired by cats" },
            { ThemeType::DARK_BLUE, "Dark Blue", "Professional blue theme" },
            { ThemeType::GREEN_MATRIX, "Green Matrix", "Classic hacker aesthetic" },
            { ThemeType::CYBERPUNK, "Cyberpunk", "Neon purple and cyan vibes" },
            { ThemeType::NORD, "Nord", "Arctic color palette" },
            { ThemeType::DRACULA, "Dracula", "Dark theme with vibrant colors" },
            { ThemeType::GRUVBOX, "Gruvbox", "Retro groove colors" },
            { ThemeType::SOLARIZED_DARK, "Solarized Dark", "Precision colors for machines and people" },
            { ThemeType::DREAM, "Dream", "Soft pastel colors for a dreamy aesthetic" },
            { ThemeType::HATED, "Hated", "Monochromatic grayscale theme with harsh contrasts" },
            { ThemeType::HATEMOB, "Hatemob", "Deep purple gradient theme with premium feel" }
        };
    }

    const char* GetThemeName(ThemeType theme) {
        switch (theme) {
            case ThemeType::CATPPUCCIN: return "Catppuccin";
            case ThemeType::DARK_BLUE: return "Dark Blue";
            case ThemeType::GREEN_MATRIX: return "Green Matrix";
            case ThemeType::CYBERPUNK: return "Cyberpunk";
            case ThemeType::NORD: return "Nord";
            case ThemeType::DRACULA: return "Dracula";            case ThemeType::GRUVBOX: return "Gruvbox";            case ThemeType::SOLARIZED_DARK: return "Solarized Dark";            case ThemeType::DREAM: return "Dream";
            case ThemeType::HATED: return "Hated";
            case ThemeType::HATEMOB: return "Hatemob";            default: return "Unknown";
        }
    }

    // Helper functions to get toggle colors from current theme
    ImVec4 GetToggleOnColor() {
        // Use ButtonActive color for "on" state (active/enabled)
        return ImGui::GetStyle().Colors[ImGuiCol_ButtonActive];
    }

    ImVec4 GetToggleOffColor() {
        // Use Button color for "off" state (inactive/disabled)
        return ImGui::GetStyle().Colors[ImGuiCol_Button];
    }

    ImVec4 GetToggleKnobColor() {
        // Use Text color for the knob so it's always visible
        return ImGui::GetStyle().Colors[ImGuiCol_Text];
    }

    ImVec4 GetToggleTextColor() {
        // Use Text color for labels
        return ImGui::GetStyle().Colors[ImGuiCol_Text];
    }
} // namespace Themes