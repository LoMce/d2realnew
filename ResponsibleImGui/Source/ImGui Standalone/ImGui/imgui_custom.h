#pragma once
#include "imgui.h"
#include "imgui_internal.h"
#include "../themes.h"

namespace ImGui {
    // Toggle switch with animated transitions and modern styling
    inline bool Toggle(const char* label, bool* v) {
        ImGuiWindow* window = GetCurrentWindow();
        if (window->SkipItems)
            return false;

        ImGuiContext& g = *GImGui;
        const ImGuiStyle& style = g.Style;
        const ImGuiID id = window->GetID(label);
        const ImVec2 label_size = CalcTextSize(label, NULL, true);

        // Toggle switch dimensions - LARGER SWITCHES
        float height = GetFrameHeight() * 1.05f; // Increased height by 20%
        float width = height * 2.0f;            // Wider proportion for better visibility
        
        const ImVec2 pos = window->DC.CursorPos;
        const ImRect total_bb(
            pos,
            ImVec2(pos.x + width + (label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f), pos.y + height)
        );

        ItemSize(total_bb, style.FramePadding.y);
        if (!ItemAdd(total_bb, id))
            return false;

        bool hovered, held;
        bool pressed = ButtonBehavior(total_bb, id, &hovered, &held);
        
        // Smooth animation
        static ImGuiID last_toggled_id = 0;
        static float anim_progress = 0.0f;
        
        // Only set the animation when actually toggled
        if (pressed) {
            *v = !(*v);
            MarkItemEdited(id);
            last_toggled_id = id;
            anim_progress = 0.0f;
        }
        
        // Animate only the currently animating toggle
        if (last_toggled_id == id && anim_progress < 1.0f) {
            anim_progress = ImMin(anim_progress + ImGui::GetIO().DeltaTime * 5.0f, 1.0f);
        }
          // Calculate t based on animation state
        float t;
        if (last_toggled_id == id && anim_progress < 1.0f) {
            t = *v ? anim_progress : (1.0f - anim_progress);
        } else {
            t = *v ? 1.0f : 0.0f;
        }

        // Theme-aware colors instead of hardcoded Catppuccin colors
        const ImVec4 bg_on = Themes::GetToggleOnColor();
        const ImVec4 bg_off = Themes::GetToggleOffColor();
        
        ImVec4 bg_color = ImLerp(bg_off, bg_on, t);
        
        // Hover and hold effects
        if (hovered) {
            bg_color.w = 0.9f;
        }
        if (held) {
            bg_color.w = 0.8f;
        }

        ImDrawList* draw_list = window->DrawList;
        // Background with rounded corners
        const ImU32 bg_col = GetColorU32(bg_color);
        const float corner_radius = height * 0.5f;
        draw_list->AddRectFilled(
            ImVec2(pos.x, pos.y),
            ImVec2(pos.x + width, pos.y + height),
            bg_col,
            corner_radius
        );        // Draw knob with position animation - LARGER KNOB
        const float knob_size = height - 4.0f; // Slightly larger knob relative to height
        const float knob_x = ImLerp(pos.x + 2.0f, pos.x + width - knob_size - 2.0f, t);
        
        // Theme-aware knob color
        ImVec4 knob_color = Themes::GetToggleKnobColor();
        
        if (hovered) knob_color.w = 0.95f;
        if (held) knob_color.w = 0.9f;
        
        // Add subtle shadow under the knob for depth
        draw_list->AddCircleFilled(
            ImVec2(knob_x + knob_size * 0.5f, pos.y + height * 0.5f + 1.0f),
            knob_size * 0.5f,
            IM_COL32(0, 0, 0, 40)
        );
        
        draw_list->AddCircleFilled(
            ImVec2(knob_x + knob_size * 0.5f, pos.y + height * 0.5f),
            knob_size * 0.5f,
            GetColorU32(knob_color)
        );        // Draw label
        if (label_size.x > 0.0f) {
            PushStyleColor(ImGuiCol_Text, Themes::GetToggleTextColor());
            RenderText(ImVec2(pos.x + width + style.ItemInnerSpacing.x, pos.y + (height - label_size.y) * 0.5f), label);
            PopStyleColor();
        }

        return pressed;
    }
}
