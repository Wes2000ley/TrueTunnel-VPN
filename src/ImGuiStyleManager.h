#ifndef IMGUI_STYLE_MANAGER_H_
#define IMGUI_STYLE_MANAGER_H_

#include "imgui.h"
#include <string>

class ImGuiStyleManager final {
public:
	void ApplyCustomDarkTheme();

	static void LoadDefaultFont();

	void LoadFontFromPath(const std::string &path, float size = 18.0f);

	ImVec4 GetClearColor() const;

private:
	void SetupStyle(ImGuiStyle &style);

	void SetupColors(ImVec4 *colors);

	ImVec4 clear_color_ = ImVec4(0.07f, 0.07f, 0.10f, 1.00f);
};

#endif  // IMGUI_STYLE_MANAGER_H_
