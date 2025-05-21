#include "ImGuiStyleManager.h"
#include <cassert>

void ImGuiStyleManager::ApplyCustomDarkTheme() {
	ImGuiStyle &style = ImGui::GetStyle();
	SetupStyle(style);
	SetupColors(style.Colors);
	clear_color_ = ImVec4(0.07f, 0.07f, 0.10f, 1.00f);
}

void ImGuiStyleManager::SetupStyle(ImGuiStyle &style) {
	style.WindowRounding = 0.0f;
	style.FrameRounding = 3.0f;
	style.ScrollbarRounding = 2.0f;
	style.FramePadding = ImVec2(8, 6);
	style.ItemSpacing = ImVec2(10, 8);
	style.WindowPadding = ImVec2(16, 12);
	style.PopupRounding = 5.0f;
}

void ImGuiStyleManager::SetupColors(ImVec4 *colors) {
	colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
	colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
	colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.06f, 0.06f, 0.94f);
	colors[ImGuiCol_ChildBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
	colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.08f, 0.94f);
	colors[ImGuiCol_Border] = ImVec4(0.43f, 0.43f, 0.50f, 0.50f);
	colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
	colors[ImGuiCol_FrameBg] = ImVec4(0.19f, 0.19f, 0.19f, 0.54f);
	colors[ImGuiCol_FrameBgHovered] = ImVec4(0.60f, 0.26f, 0.98f, 0.40f);
	colors[ImGuiCol_FrameBgActive] = ImVec4(0.60f, 0.26f, 0.98f, 0.67f);
	colors[ImGuiCol_TitleBg] = ImVec4(0.04f, 0.04f, 0.04f, 1.00f);
	colors[ImGuiCol_TitleBgActive] = ImVec4(0.31f, 0.16f, 0.48f, 1.00f);
	colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.51f);
	colors[ImGuiCol_MenuBarBg] = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
	colors[ImGuiCol_ScrollbarBg] = ImVec4(0.02f, 0.02f, 0.02f, 0.53f);
	colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.31f, 0.31f, 0.31f, 1.00f);
	colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.41f, 0.41f, 0.41f, 1.00f);
	colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.51f, 0.51f, 0.51f, 1.00f);
	colors[ImGuiCol_CheckMark] = ImVec4(0.60f, 0.26f, 0.98f, 1.00f);
	colors[ImGuiCol_SliderGrab] = ImVec4(0.54f, 0.24f, 0.88f, 1.00f);
	colors[ImGuiCol_SliderGrabActive] = ImVec4(0.60f, 0.26f, 0.98f, 1.00f);
	colors[ImGuiCol_Button] = ImVec4(0.60f, 0.26f, 0.98f, 0.40f);
	colors[ImGuiCol_ButtonHovered] = ImVec4(0.60f, 0.26f, 0.98f, 1.00f);
	colors[ImGuiCol_ButtonActive] = ImVec4(0.49f, 0.06f, 0.98f, 1.00f);
	colors[ImGuiCol_Header] = ImVec4(0.60f, 0.26f, 0.98f, 0.31f);
	colors[ImGuiCol_HeaderHovered] = ImVec4(0.60f, 0.26f, 0.98f, 0.80f);
	colors[ImGuiCol_HeaderActive] = ImVec4(0.60f, 0.26f, 0.98f, 1.00f);
	colors[ImGuiCol_TextSelectedBg] = ImVec4(0.53f, 0.53f, 0.53f, 0.45f);
	// Add more ImGuiCol_ if needed...
}

void ImGuiStyleManager::LoadDefaultFont() {
	ImFontConfig config;
	config.OversampleH = 3;
	config.OversampleV = 3;
	config.PixelSnapH = false;

	ImGuiIO &io = ImGui::GetIO();
	io.FontDefault = io.Fonts->AddFontDefault(&config);
	io.Fonts->Build();

	assert(io.FontDefault && "Default font loading failed");
}

void ImGuiStyleManager::LoadFontFromPath(const std::string &path, float size) {
	ImFontConfig config;
	config.OversampleH = 3;
	config.OversampleV = 3;
	config.PixelSnapH = false;

	ImGuiIO &io = ImGui::GetIO();
	ImFont *font = io.Fonts->AddFontFromFileTTF(path.c_str(), size, &config, io.Fonts->GetGlyphRangesDefault());
	io.FontDefault = font;
	io.Fonts->Build();

	assert(font && "Custom font loading failed");
}

ImVec4 ImGuiStyleManager::GetClearColor() const {
	return clear_color_;
}
