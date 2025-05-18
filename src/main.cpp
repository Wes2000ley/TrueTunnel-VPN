#include <cstdio>
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>
#include "VpnController.h"
#include "utils.hpp"




static std::unique_ptr<VpnController> g_vpn_controller;


// Data
static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;

// Forward declarations of helper functions
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Main code
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
    // Create application window
    //ImGui_ImplWin32_EnableDpiAwareness();
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"True Tunnel VPN", nullptr };
    ::RegisterClassExW(&wc);
    RECT screen;
    GetWindowRect(GetDesktopWindow(), &screen);
    int screen_width = screen.right;
    int screen_height = screen.bottom;
    int width  = static_cast<int>(screen_width / 4.0);
    int height = static_cast<int>(screen_height / 1.5);
    int pos_x  = (screen_width - width) / 2;
    int pos_y  = (screen_height - height) / 2;

    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"True Tunnel VPN", WS_OVERLAPPEDWINDOW,
                                pos_x ,pos_y, width, height, nullptr, nullptr, wc.hInstance, nullptr);

    populate_real_adapters();

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show the window
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
   //io.ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleFonts;
   // io.ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleViewports;
    io.Framerate = 60.0f;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls
   // io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;         // Enable Docking
   // io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;       // Enable Multi-Viewport / Platform Windows
    //io.ConfigViewportsNoAutoMerge = true;
    //io.ConfigViewportsNoTaskBarIcon = true;
    //io.ConfigViewportsNoDefaultParent = true;
    //io.ConfigDockingAlwaysTabBar = true;
    //io.ConfigDockingTransparentPayload = true;
    //io.ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleFonts;     // FIXME-DPI: Experimental. THIS CURRENTLY DOESN'T WORK AS EXPECTED. DON'T USE IN USER APP!
    //io.ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleViewports; // FIXME-DPI: Experimental.

    // Setup Dear ImGui style
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.FrameRounding = 3.0f;
    style.ScrollbarRounding = 2.0f;
    style.FramePadding = ImVec2(8, 6);
    style.ItemSpacing = ImVec2(10, 8);
    style.WindowPadding = ImVec2(16, 12);

    ImVec4 *colors = ImGui::GetStyle().Colors;
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
        colors[ImGuiCol_Separator] = ImVec4(0.43f, 0.43f, 0.50f, 0.50f);
        colors[ImGuiCol_SeparatorHovered] = ImVec4(0.41f, 0.10f, 0.75f, 0.78f);
        colors[ImGuiCol_SeparatorActive] = ImVec4(0.41f, 0.10f, 0.75f, 1.00f);
        colors[ImGuiCol_ResizeGrip] = ImVec4(0.60f, 0.26f, 0.98f, 0.20f);
        colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.60f, 0.26f, 0.98f, 0.67f);
        colors[ImGuiCol_ResizeGripActive] = ImVec4(0.60f, 0.26f, 0.98f, 0.95f);
        colors[ImGuiCol_TabHovered] = ImVec4(0.60f, 0.26f, 0.98f, 0.80f);
        colors[ImGuiCol_Tab] = ImVec4(0.37f, 0.18f, 0.58f, 0.86f);
        colors[ImGuiCol_TabSelected] = ImVec4(0.42f, 0.20f, 0.68f, 1.00f);
        colors[ImGuiCol_TabSelectedOverline] = ImVec4(0.60f, 0.26f, 0.98f, 1.00f);
        colors[ImGuiCol_TabDimmed] = ImVec4(0.11f, 0.07f, 0.15f, 0.97f);
        colors[ImGuiCol_TabDimmedSelected] = ImVec4(0.27f, 0.14f, 0.42f, 1.00f);
        colors[ImGuiCol_TabDimmedSelectedOverline] = ImVec4(0.50f, 0.50f, 0.50f, 0.00f);
        colors[ImGuiCol_DockingPreview] = ImVec4(0.60f, 0.26f, 0.98f, 0.70f);
        colors[ImGuiCol_DockingEmptyBg] = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
        colors[ImGuiCol_PlotLines] = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);
        colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
        colors[ImGuiCol_PlotHistogram] = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
        colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
        colors[ImGuiCol_TableHeaderBg] = ImVec4(0.19f, 0.19f, 0.20f, 1.00f);
        colors[ImGuiCol_TableBorderStrong] = ImVec4(0.31f, 0.31f, 0.35f, 1.00f);
        colors[ImGuiCol_TableBorderLight] = ImVec4(0.23f, 0.23f, 0.25f, 1.00f);
        colors[ImGuiCol_TableRowBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
        colors[ImGuiCol_TableRowBgAlt] = ImVec4(1.00f, 1.00f, 1.00f, 0.06f);
        colors[ImGuiCol_TextLink] = ImVec4(0.60f, 0.26f, 0.98f, 1.00f);
        colors[ImGuiCol_TextSelectedBg] = ImVec4(0.53f, 0.53f, 0.53f, 0.45f);
        colors[ImGuiCol_DragDropTarget] = ImVec4(1.00f, 1.00f, 0.00f, 0.90f);
        colors[ImGuiCol_NavCursor] = ImVec4(0.60f, 0.26f, 0.98f, 1.00f);
        colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
        colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.20f);
        colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);




    // When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
   // ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowRounding = 0.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // Load Fonts
    // - If no fonts are loaded, dear imgui will use the default font. You can also load multiple fonts and use ImGui::PushFont()/PopFont() to select them.
    // - AddFontFromFileTTF() will return the ImFont* so you can store it if you need to select the font among multiple.
    // - If the file cannot be loaded, the function will return a nullptr. Please handle those errors in your application (e.g. use an assertion, or display an error and quit).
    // - The fonts will be rasterized at a given size (w/ oversampling) and stored into a texture when calling ImFontAtlas::Build()/GetTexDataAsXXXX(), which ImGui_ImplXXXX_NewFrame below will call.
    // - Use '#define IMGUI_ENABLE_FREETYPE' in your imconfig file to use Freetype for higher quality font rendering.
    // - Read 'docs/FONTS.md' for more instructions and details.
    // - Remember that in C/C++ if you want to include a backslash \ in a string literal you need to write a double backslash \\ !
    //io.Fonts->AddFontDefault();
    //io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\segoeui.ttf", 18.0f);
    //io.Fonts->AddFontFromFileTTF("../../misc/fonts/DroidSans.ttf", 16.0f);
    //io.Fonts->AddFontFromFileTTF("../../misc/fonts/Roboto-Medium.ttf", 16.0f);
    //io.Fonts->AddFontFromFileTTF("../../misc/fonts/Cousine-Regular.ttf", 15.0f);
    //ImFont* font = io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\ArialUni.ttf", 18.0f, nullptr, io.Fonts->GetGlyphRangesJapanese());
    //IM_ASSERT(font != nullptr);

    ImVec4 clear_color = ImVec4(0.00f, 0.00f, 0.05f, 1.00f);

    ImFontConfig font_cfg;
    font_cfg.OversampleH = 3;
    font_cfg.OversampleV = 3;
    font_cfg.PixelSnapH = false;

    ImFont* customFont = io.Fonts->AddFontFromFileTTF(
        "C:/Windows/Fonts/segoeui.ttf", 19.0f, &font_cfg, io.Fonts->GetGlyphRangesDefault());

    IM_ASSERT(customFont != nullptr);
    io.FontDefault = customFont;


    // Main loop
    bool done = false;
    while (!done)
    {
        // Poll and handle messages (inputs, window resize, etc.)
        // See the WndProc() function below for our to dispatch events to the Win32 backend.
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        // Handle window being minimized or screen locked
        if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
        {
            ::Sleep(10);
            continue;
        }
        g_SwapChainOccluded = false;

        // Handle window resize (we don't resize directly in the WM_SIZE handler)
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();


        // // Main DockSpace
        // ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoDocking;
        // const ImGuiViewport* viewport = ImGui::GetMainViewport();
        // ImGui::SetNextWindowPos(viewport->WorkPos);
        // ImGui::SetNextWindowSize(viewport->WorkSize);
        // ImGui::SetNextWindowViewport(viewport->ID);
        // window_flags |= ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove;
        // window_flags |= ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoBackground;
        //
        // ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
        // ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        //
        // ImGui::Begin("DockSpace_Window", nullptr, window_flags);
        // ImGui::PopStyleVar(2);
        //
        // // Optional: DockSpace flags
        // ImGuiDockNodeFlags dockspace_flags = ImGuiDockNodeFlags_PassthruCentralNode;
        // ImGui::DockSpace(ImGui::GetID("MyDockSpace"), ImVec2(0.0f, 0.0f), dockspace_flags);
        //
        // ImGui::End();
        //
        // ImGui::SetNextWindowDockID(ImGui::GetID("MyDockSpace"), ImGuiCond_FirstUseEver);
        // ImGui::SetNextWindowPos(viewport->WorkPos, ImGuiCond_FirstUseEver);
        // ImGui::SetNextWindowSize(viewport->WorkSize, ImGuiCond_FirstUseEver);


        // 2. Show a simple window that we create ourselves. We use a Begin/End pair to create a named window.
        {
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 6));
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8, 6));

            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImVec2 window_size;
            ::RECT rect;
            if (::GetClientRect(hwnd, &rect))
                window_size = ImVec2(static_cast<float>(rect.right), static_cast<float>(rect.bottom));
            else
                window_size = io.DisplaySize;

            ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
            ImGui::SetNextWindowSize(window_size, ImGuiCond_Always);

            // Apply padding styles
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 16));  // Space inside window
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 6));    // Space around text inside widgets
            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(10, 8));     // Space between widgets

            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);


            ImGui::Begin("##MainPanel", nullptr,
                         ImGuiWindowFlags_NoTitleBar |
                         ImGuiWindowFlags_NoResize |
                         ImGuiWindowFlags_NoMove |
                         ImGuiWindowFlags_NoCollapse |
                         ImGuiWindowFlags_NoBringToFrontOnFocus |
                         ImGuiWindowFlags_NoNavFocus |
                         ImGuiWindowFlags_NoBackground);







    static char mode[16] = "server";
    static char server_ip[64] = "";
    static char port[16] = "5555";
    static char local_ip[64] = "will decide of type choice";
    static char adapter_name[64] = "TrueTunnel VPN Adapter";
    static char subnet_mask[64] = "will decide of type choice";
    static char gateway[64] = "will decide of type choice";
    static char password[64] = "SuperStrongPassword123";
    static char public_ip[64] = "192.168.1.10";
    static int  real_adapter_index = 0;

            static const char* mode_options[] = { "server", "client" };
            static int selected_mode = 0;

            // Start combo
            if (ImGui::Combo("##mode", &selected_mode, mode_options, IM_ARRAYSIZE(mode_options))) {
                strncpy_s(mode, mode_options[selected_mode], sizeof(mode) - 1);
            }

            // Label placed to the right of the combo
            ImGui::SameLine();
            ImGui::Text("Mode:");





          //  ImGui::InputText("Server IP", server_ip, IM_ARRAYSIZE(server_ip));
    ImGui::InputText("Port", port, IM_ARRAYSIZE(port));
   // ImGui::InputText("Local IP", local_ip, IM_ARRAYSIZE(local_ip));
    ImGui::InputText("Adapter Name", adapter_name, IM_ARRAYSIZE(adapter_name));
   // ImGui::InputText("Subnet Mask", subnet_mask, IM_ARRAYSIZE(subnet_mask));
   // ImGui::InputText("Gateway", gateway, IM_ARRAYSIZE(gateway));
    ImGui::InputText("Password", password, IM_ARRAYSIZE(password), ImGuiInputTextFlags_Password);
    ImGui::InputText("Server Public IP", public_ip, IM_ARRAYSIZE(public_ip));

            // Show adapter dropdown
            if (!adapter_labels_.empty()) {
                ImGui::Combo("##real_adapter", &current_adapter_idx_, adapter_labels_.data(), static_cast<int>(adapter_labels_.size()));
                ImGui::SameLine();
                ImGui::Text("Tethered Adapter:");
            } else {
                ImGui::Text("No network adapters found.");
            }

            // Static buffers for logging and message input
            static char vpn_log[2048] = "";
            static char message_input[256] = "";

            // Connect button
            if (ImGui::Button("Connect")) {
                strcat_s(vpn_log, "[System] Connect button pressed\n");

                if (g_vpn_controller) g_vpn_controller->stop();
                g_vpn_controller = std::make_unique<VpnController>();

                g_vpn_controller->set_log_callback([](const std::string& msg) {
                    // Append log to ImGui buffer
                    strncat_s(vpn_log, msg.c_str(), sizeof(vpn_log) - strlen(vpn_log) - 2);
                    strncat_s(vpn_log, "\n", sizeof(vpn_log) - strlen(vpn_log) - 1);
                });

                std::string mode_str = mode;

                // Get selected adapter name (safe fallback)
                std::string real_adapter_str = (current_adapter_idx_ >= 0 && current_adapter_idx_ < static_cast<int>(real_adapters_.size()))
                    ? real_adapters_[current_adapter_idx_].name
                    : "Unknown";

                g_vpn_controller->start(
                    mode_str,
                    server_ip,
                    std::stoi(port),
                    local_ip,
                    gateway,
                    password,
                    adapter_name,
                    subnet_mask,
                    public_ip,
                    real_adapter_str
                );
            }

    ImGui::Separator();
ImGui::Text("Log:");
            // Reserve space for log box height dynamically
            float available_height = ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing() * 2.0f;

            ImGui::BeginChild("log_box", ImVec2(0, available_height), true,
                              ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_AlwaysHorizontalScrollbar);
            ImGui::TextUnformatted(vpn_log);
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                ImGui::SetScrollHereY(1.0f);
            ImGui::EndChild();


            ImGui::InputText("Message", message_input, IM_ARRAYSIZE(message_input));
            if (ImGui::Button("Send Message")) {
                if (strlen(message_input) > 0) {
                    if (g_vpn_controller && g_vpn_controller->is_running()) {
                        g_vpn_controller->send_manual_message(message_input);
                    }

                    char formatted[256];
                    snprintf(formatted, sizeof(formatted), "[You] %s\n", message_input);
                    strcat_s(vpn_log, formatted);
                    message_input[0] = '\0';
                }
            }

    ImGui::End();
            ImGui::PopStyleVar(3);
            ImGui::PopStyleVar(3); // Restore padding
}





        // Rendering
        ImGui::Render();
        const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        // Update and Render additional Platform Windows
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        // Present
        HRESULT hr = g_pSwapChain->Present(1, 0);   // Present with vsync
        //HRESULT hr = g_pSwapChain->Present(0, 0); // Present without vsync
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    // Cleanup
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    if (g_vpn_controller) {
        g_vpn_controller->stop();
        g_vpn_controller.reset();
    }

    return 0;
}

// Helper functions
bool CreateDeviceD3D(HWND hWnd)
{
    // Setup swap chain
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 4;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    //createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0,
        D3D_FEATURE_LEVEL_9_3
    };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0 // From Windows SDK 8.1+ headers
#endif

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Win32 message handler
// You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
// - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
// - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
// Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam); // Queue resize
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    case WM_DPICHANGED:
        if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_DpiEnableScaleViewports)
        {
            //const int dpi = HIWORD(wParam);
            //printf("WM_DPICHANGED to %d (%.0f%%)\n", dpi, (float)dpi / 96.0f * 100.0f);
            const RECT* suggested_rect = (RECT*)lParam;
            ::SetWindowPos(hWnd, nullptr, suggested_rect->left, suggested_rect->top, suggested_rect->right - suggested_rect->left, suggested_rect->bottom - suggested_rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        break;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
