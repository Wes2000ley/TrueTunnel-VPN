#include "ImGuiStyleManager.h"
#include <cassert>

void ImGuiStyleManager::ApplyCustomDarkTheme(const float scale) {
	ImGuiStyle &style = ImGui::GetStyle();
	SetupStyle(style, scale);
	SetupColors(style.Colors);
	clear_color_ = ImVec4(0.014f, 0.019f, 0.028f, 1.00f);
}

void ImGuiStyleManager::SetupStyle(ImGuiStyle& style, const float scale) {
	// A restrained eight-point spacing system keeps the production window and
	// the visual-test executable pixel-identical at the same DPI.
	style = ImGuiStyle{};
	style.WindowRounding = 16.0f;
	style.ChildRounding = 16.0f;
	style.FrameRounding = 10.0f;
	style.PopupRounding = 14.0f;
	style.ScrollbarRounding = 12.0f;
	style.GrabRounding = 9.0f;
	style.TabRounding = 10.0f;
	style.FramePadding = ImVec2(12.0f, 9.0f);
	style.ItemSpacing = ImVec2(10.0f, 9.0f);
	style.ItemInnerSpacing = ImVec2(8.0f, 6.0f);
	style.WindowPadding = ImVec2(24.0f, 20.0f);
	style.IndentSpacing = 18.0f;
	style.ScrollbarSize = 9.0f;
	style.GrabMinSize = 12.0f;
	style.DisabledAlpha = 0.47f;
	style.WindowBorderSize = 0.0f;
	style.ChildBorderSize = 1.0f;
	style.FrameBorderSize = 1.0f;
	style.PopupBorderSize = 1.0f;
	style.ButtonTextAlign = ImVec2(0.5f, 0.5f);
	style.SelectableTextAlign = ImVec2(0.0f, 0.5f);
	style.AntiAliasedLines = true;
	style.AntiAliasedLinesUseTex = true;
	style.AntiAliasedFill = true;
	if (scale > 0.0f && scale != 1.0f) style.ScaleAllSizes(scale);
}

void ImGuiStyleManager::SetupColors(ImVec4 *colors) {
	const ImVec4 background(0.014f, 0.019f, 0.028f, 1.00f);
	const ImVec4 panel(0.052f, 0.067f, 0.091f, 0.91f);
	const ImVec4 panel_hover(0.076f, 0.101f, 0.139f, 0.97f);
	const ImVec4 panel_active(0.093f, 0.127f, 0.178f, 1.00f);
	const ImVec4 accent(0.286f, 0.604f, 1.000f, 1.00f);
	const ImVec4 accent_hover(0.386f, 0.675f, 1.000f, 1.00f);
	const ImVec4 accent_active(0.220f, 0.506f, 0.914f, 1.00f);
	const ImVec4 border(0.235f, 0.278f, 0.345f, 0.68f);

	colors[ImGuiCol_Text] = ImVec4(0.930f, 0.956f, 0.990f, 1.00f);
	colors[ImGuiCol_TextDisabled] = ImVec4(0.570f, 0.650f, 0.755f, 1.00f);
	colors[ImGuiCol_WindowBg] = background;
	colors[ImGuiCol_ChildBg] = ImVec4(0.034f, 0.046f, 0.065f, 0.90f);
	colors[ImGuiCol_PopupBg] = ImVec4(0.030f, 0.040f, 0.057f, 0.99f);
	colors[ImGuiCol_Border] = border;
	colors[ImGuiCol_BorderShadow] = ImVec4(0.000f, 0.000f, 0.000f, 0.28f);
	colors[ImGuiCol_FrameBg] = panel;
	colors[ImGuiCol_FrameBgHovered] = panel_hover;
	colors[ImGuiCol_FrameBgActive] = panel_active;
	colors[ImGuiCol_TitleBg] = background;
	colors[ImGuiCol_TitleBgActive] = background;
	colors[ImGuiCol_TitleBgCollapsed] = background;
	colors[ImGuiCol_MenuBarBg] = ImVec4(0.035f, 0.046f, 0.064f, 0.92f);
	colors[ImGuiCol_ScrollbarBg] = ImVec4(0.008f, 0.016f, 0.031f, 0.22f);
	colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.235f, 0.300f, 0.400f, 0.72f);
	colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.34f, 0.56f, 0.82f, 0.92f);
	colors[ImGuiCol_ScrollbarGrabActive] = accent;
	colors[ImGuiCol_CheckMark] = accent;
	colors[ImGuiCol_SliderGrab] = accent;
	colors[ImGuiCol_SliderGrabActive] = accent_hover;
	colors[ImGuiCol_Button] = ImVec4(0.070f, 0.094f, 0.130f, 0.96f);
	colors[ImGuiCol_ButtonHovered] = accent;
	colors[ImGuiCol_ButtonActive] = accent_active;
	colors[ImGuiCol_Header] = ImVec4(0.145f, 0.300f, 0.510f, 0.76f);
	colors[ImGuiCol_HeaderHovered] = ImVec4(0.28f, 0.52f, 0.82f, 0.78f);
	colors[ImGuiCol_HeaderActive] = accent;
	colors[ImGuiCol_Separator] = ImVec4(0.218f, 0.258f, 0.322f, 0.55f);
	colors[ImGuiCol_SeparatorHovered] = ImVec4(0.35f, 0.62f, 0.93f, 0.65f);
	colors[ImGuiCol_SeparatorActive] = accent;
	colors[ImGuiCol_TextSelectedBg] = ImVec4(0.24f, 0.51f, 0.83f, 0.42f);
	colors[ImGuiCol_NavHighlight] = ImVec4(0.38f, 0.71f, 1.00f, 0.82f);
	colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.005f, 0.012f, 0.025f, 0.78f);
	colors[ImGuiCol_TableBorderStrong] = border;
	colors[ImGuiCol_TableBorderLight] = ImVec4(0.22f, 0.26f, 0.32f, 0.34f);
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

ImFont* ImGuiStyleManager::LoadFontFromPath(
		const std::string& path,
		const float size,
		const bool make_default) {
	if (path.empty() || size <= 0.0f) return nullptr;
	ImFontConfig config;
	config.OversampleH = 3;
	config.OversampleV = 3;
	config.PixelSnapH = false;

	ImGuiIO &io = ImGui::GetIO();
	ImFont *font = io.Fonts->AddFontFromFileTTF(path.c_str(), size, &config, io.Fonts->GetGlyphRangesDefault());
	if (make_default && font != nullptr) io.FontDefault = font;
	return font;
}

ImVec4 ImGuiStyleManager::GetClearColor() const {
	return clear_color_;
}
