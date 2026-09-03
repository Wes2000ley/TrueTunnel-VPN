#ifndef IMGUI_STYLE_MANAGER_H_
#define IMGUI_STYLE_MANAGER_H_

#include "imgui.h"
#include <string>

class ImGuiStyleManager final {
public:
	void ApplyCustomDarkTheme(float scale = 1.0f);

	static void LoadDefaultFont();

	[[nodiscard]] ImFont* LoadFontFromPath(
		const std::string& path,
		float size = 18.0f,
		bool make_default = true);

	ImVec4 GetClearColor() const;

private:
	void SetupStyle(ImGuiStyle& style, float scale);

	void SetupColors(ImVec4 *colors);

	ImVec4 clear_color_ = ImVec4(0.07f, 0.07f, 0.10f, 1.00f);
};

#endif  // IMGUI_STYLE_MANAGER_H_
