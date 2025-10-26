#include <cstdio>
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <mutex>
#include <memory>
#include <mmsystem.h>   // timeBeginPeriod/timeEndPeriod
#pragma comment(lib, "winmm.lib")

#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <thread>
#include <vector>
#include <stdexcept>
#include <tchar.h>
#include "core/VpnDaemon.h"
#include "secure/CipherSuite.h"
#include "utils.hpp"
#include "ImGuiStyleManager.h"
#include "Networking.h"
#include "TransportProtocol.h"
#define IDI_VPN_ICON 101


static std::unique_ptr<VpnDaemon> g_vpn_daemon;


// Data
static ID3D11Device *g_pd3dDevice = nullptr;
static ID3D11DeviceContext *g_pd3dDeviceContext = nullptr;
static IDXGISwapChain *g_pSwapChain = nullptr;
static bool g_SwapChainOccluded = false;
static UINT g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView *g_mainRenderTargetView = nullptr;

namespace {
class ScopedTimerResolution {
public:
	explicit ScopedTimerResolution(UINT period_ms) : period_(period_ms) {
		if (timeBeginPeriod(period_) == TIMERR_NOERROR) {
			active_ = true;
		}
	}
	ScopedTimerResolution(const ScopedTimerResolution&) = delete;
	ScopedTimerResolution& operator=(const ScopedTimerResolution&) = delete;
	ScopedTimerResolution(ScopedTimerResolution&&) = delete;
	ScopedTimerResolution& operator=(ScopedTimerResolution&&) = delete;
	~ScopedTimerResolution() {
		if (active_) {
			timeEndPeriod(period_);
		}
	}
	[[nodiscard]] bool active() const noexcept { return active_; }
private:
	UINT period_{1};
	bool active_{false};
};
} // namespace

// Forward declarations of helper functions
bool CreateDeviceD3D(HWND hWnd);

void CleanupDeviceD3D();

void CreateRenderTarget();

void CleanupRenderTarget();

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001
#define ID_TRAY_RESTORE 1002

NOTIFYICONDATA nid = {};
HMENU h_tray_menu = nullptr;
bool in_tray = false;


// Main code
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
	// Create application window
	//ImGui_ImplWin32_EnableDpiAwareness();
	HICON h_icon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_VPN_ICON));
	HICON h_icon_small = (HICON) LoadImage(hInstance, MAKEINTRESOURCE(IDI_VPN_ICON),
	                                       IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);

	WNDCLASSEXW wc = {
		sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
		hInstance, h_icon, LoadCursor(nullptr, IDC_ARROW),
		nullptr, nullptr, L"True Tunnel VPN", h_icon_small
	};
	::RegisterClassExW(&wc);
	RECT screen;
	GetWindowRect(GetDesktopWindow(), &screen);
	int screen_width = screen.right;
	int screen_height = screen.bottom;
	int width = static_cast<int>(screen_width / 4.0);
	int height = static_cast<int>(screen_height / 1.5);
	int pos_x = (screen_width - width) / 2;
	int pos_y = (screen_height - height) / 2;

	HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"True Tunnel VPN", WS_OVERLAPPEDWINDOW,
	                            pos_x, pos_y, width, height, nullptr, nullptr, wc.hInstance, nullptr);

	// Improve timer granularity for lower end-to-end latency
	ScopedTimerResolution timer_res(1);

	populate_real_adapters();
	SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM) h_icon);
	SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM) h_icon_small);


	// Initialize Direct3D
	if (!CreateDeviceD3D(hwnd)) {
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
	ImGuiIO &io = ImGui::GetIO();
	(void) io;
	//io.ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleFonts;
	// io.ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleViewports;
	io.Framerate = 60.0f;
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad; // Enable Gamepad Controls
	// io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;         // Enable Docking
	// io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;       // Enable Multi-Viewport / Platform Windows
	//io.ConfigViewportsNoAutoMerge = true;
	//io.ConfigViewportsNoTaskBarIcon = true;
	//io.ConfigViewportsNoDefaultParent = true;
	//io.ConfigDockingAlwaysTabBar = true;
	//io.ConfigDockingTransparentPayload = true;
	//io.ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleFonts;     // FIXME-DPI: Experimental. THIS CURRENTLY DOESN'T WORK AS EXPECTED. DON'T USE IN USER APP!
	//io.ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleViewports; // FIXME-DPI: Experimental.


	// When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
	// ImGuiStyle& style = ImGui::GetStyle();

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

	ImGuiStyleManager style_mgr;
	style_mgr.ApplyCustomDarkTheme();
	style_mgr.LoadFontFromPath("C:/Windows/Fonts/segoeui.ttf", 19.0f);
	ImVec4 clear_color = style_mgr.GetClearColor();

	// Main loop
	bool done = false;
	while (!done) {
		// Poll and handle messages (inputs, window resize, etc.)
		// See the WndProc() function below for our to dispatch events to the Win32 backend.
		MSG msg;
		while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
			::TranslateMessage(&msg);
			::DispatchMessage(&msg);
			if (msg.message == WM_QUIT)
				done = true;
		}
		if (done)
			break;

		// Handle window being minimized or screen locked
		if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED) {
			::Sleep(10);
			continue;
		}
		g_SwapChainOccluded = false;

		// Handle window resize (we don't resize directly in the WM_SIZE handler)
		if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
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
			ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(5, 5)); // Space inside window
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 6)); // Space around text inside widgets
			ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(10, 8)); // Space between widgets

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
			static char public_ip[64] = "192.168.50.10";
			static int real_adapter_index = 0;

		static const char *mode_options[] = {"server", "client"};
		static int selected_mode = 0;
		static const char *cipher_labels[] = {"AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"};
		static const secure::CipherSuite cipher_values[] = {
			secure::CipherSuite::Aes256Gcm,
			secure::CipherSuite::Aes128Gcm,
			secure::CipherSuite::ChaCha20Poly1305
		};
		static int selected_cipher = 0;
		static const char *transport_labels[] = {"TCP", "UDP"};
		static int selected_transport = 0;


			ImGui::Text("Mode:");
			if (ImGui::IsItemHovered())
				ImGui::SetTooltip(
					"Select the VPN role:\n"
					"* Server: Listens for an incoming connection (requires port forwarding or a public IP).\n"
					"* Client: Initiates the connection to the server (can operate behind NAT)."
				);

			ImGui::SameLine();
			// Start combo
			if (ImGui::Combo("##mode", &selected_mode, mode_options, IM_ARRAYSIZE(mode_options))) {
				strncpy_s(mode, mode_options[selected_mode], sizeof(mode) - 1);
			}


			ImGui::SameLine(ImGui::GetWindowContentRegionMax().x - 25.0f);
			if (ImGui::Button("?", ImVec2(25, 25)))
				ImGui::OpenPopup("Help Me");
			if (ImGui::BeginPopup("Help Me")) {
				ImGui::TextColored(ImVec4(0.98f, 0.8f, 0.2f, 1.0f), "TrueTunnel VPN");
				ImGui::Separator();

				ImGui::TextWrapped(
					"TrueTunnel VPN is a secure point-to-point TLS VPN with a focus on speed, privacy, and reliability.");
				ImGui::Spacing();

				ImGui::BulletText("Double-click the tray icon to restore the app.");
				ImGui::BulletText("Click 'Connect' to establish a VPN tunnel.");
				ImGui::BulletText("Supports client and server mode.");
				ImGui::BulletText("Minimizes to system tray when closed or minimized.");
				ImGui::BulletText("Stores adapter binding and password securely in memory.");

				ImGui::Spacing();
				ImGui::Separator();

				ImGui::Text("Developer: Wesley Atwell");
				ImGui::Text("License:  MIT or GPLv2 ");

				ImGui::Spacing();
				if (ImGui::Button("Close")) {
					ImGui::CloseCurrentPopup();
				}

				ImGui::EndPopup();
			}


			// ImGui::Text("Server IP:");
			// ImGui::SameLine();
			// if (ImGui::IsItemHovered())
			//     ImGui::SetTooltip("This is the IP clients will connect to (internal or external).");
			// ImGui::InputText("##server_ip", server_ip, IM_ARRAYSIZE(server_ip));

			ImGui::Text("Port:");
			ImGui::SameLine();
			if (ImGui::IsItemHovered())
				ImGui::SetTooltip("The TCP port to use for this VPN connection.");
			ImGui::InputText("##port", port, IM_ARRAYSIZE(port));

			// ImGui::Text("Local IP:");
			// ImGui::SameLine();
			// if (ImGui::IsItemHovered())
			//     ImGui::SetTooltip("The internal IP assigned to this node (e.g., 10.x.x.x).");
			// ImGui::InputText("##local_ip", local_ip, IM_ARRAYSIZE(local_ip));

			ImGui::Text("Adapter Name:");
			ImGui::SameLine();
			if (ImGui::IsItemHovered())
				ImGui::SetTooltip("The display name of your virtual adapter.");
			ImGui::InputText("##adapter_name", adapter_name, IM_ARRAYSIZE(adapter_name));

			// ImGui::Text("Subnet Mask:");
			// ImGui::SameLine();
			// if (ImGui::IsItemHovered())
			//     ImGui::SetTooltip("The subnet mask for the VPN adapter (e.g., 255.255.255.0).");
			// ImGui::InputText("##subnet_mask", subnet_mask, IM_ARRAYSIZE(subnet_mask));

			// ImGui::Text("Gateway:");
			// ImGui::SameLine();
			// if (ImGui::IsItemHovered())
			//     ImGui::SetTooltip("The gateway address to reach external networks.");
			// ImGui::InputText("##gateway", gateway, IM_ARRAYSIZE(gateway));

			ImGui::Text("Password:");
			ImGui::SameLine();
			if (ImGui::IsItemHovered())
				ImGui::SetTooltip("This pre-shared password will be used for authentication.");
			ImGui::InputText("##password", password, IM_ARRAYSIZE(password), ImGuiInputTextFlags_Password);

		ImGui::Text("Cipher Suite:");
		ImGui::SameLine();
		if (ImGui::IsItemHovered())
			ImGui::SetTooltip("Choose the AEAD used to protect transport records.");
		ImGui::Combo("##cipher_suite", &selected_cipher, cipher_labels, IM_ARRAYSIZE(cipher_labels));

		ImGui::Text("Transport:");
		ImGui::SameLine();
		if (ImGui::IsItemHovered())
			ImGui::SetTooltip("Select the underlying transport protocol for the secure tunnel.");
		ImGui::Combo("##transport", &selected_transport, transport_labels, IM_ARRAYSIZE(transport_labels));

			ImGui::Text("Server Public IP:");
			ImGui::SameLine();
			if (ImGui::IsItemHovered())
				ImGui::SetTooltip("This is the routable IP of your server.");
			ImGui::InputText("##public_ip", public_ip, IM_ARRAYSIZE(public_ip));

			// Show adapter dropdown
			if (!adapter_labels_.empty()) {
				ImGui::Text("Tethered Adapter:");
				if (ImGui::IsItemHovered())
					ImGui::SetTooltip("This is adapter you bind Wintun to.");
				ImGui::SameLine();
				ImGui::Combo("##real_adapter", &current_adapter_idx_, adapter_cstrs_.data(),
							 static_cast<int>(adapter_cstrs_.size()));
			} else {
				ImGui::Text("No network adapters found.");
			}
                        // Static buffers for logging and message input
                        static std::vector<std::string> log_lines;
                        static std::mutex log_mutex;
                        static char message_input[256] = "";
                        const size_t max_log_lines = 5000;

                        // Connect button
                        if (ImGui::Button("Connect")) {
                                const auto format_with_timestamp = [](const std::string &message,
                                                                       std::chrono::system_clock::time_point when) {
                                        std::time_t tt = std::chrono::system_clock::to_time_t(when);
                                        std::tm tm_buf{};
#ifdef _WIN32
                                        localtime_s(&tm_buf, &tt);
#else
                                        localtime_r(&tt, &tm_buf);
#endif
                                        std::ostringstream oss;
                                        oss << "[" << std::put_time(&tm_buf, "%H:%M:%S") << "] " << message;
                                        return oss.str();
                                };

                                auto append_line = [&, format_with_timestamp](const std::string &message,
                                                                              std::chrono::system_clock::time_point when =
                                                                                  std::chrono::system_clock::now()) {
                                        std::lock_guard<std::mutex> lock(log_mutex);
                                        log_lines.emplace_back(format_with_timestamp(message, when));
                                        if (log_lines.size() > max_log_lines) {
                                                log_lines.erase(log_lines.begin(), log_lines.begin() + 100);
                                        }
                                };

                                append_line("[System] Connect button pressed");

                                if (g_vpn_daemon) {
                                        g_vpn_daemon->stop();
                                        g_vpn_daemon.reset();
                                }

                                g_vpn_daemon = std::make_unique<VpnDaemon>();

                                g_vpn_daemon->set_event_callback([format_with_timestamp, max_log_lines](
                                                                     const VpnDaemon::TelemetryEvent &event) {
                                        std::string payload;
                                        switch (event.type) {
                                                case VpnDaemon::EventType::Log:
                                                        payload = event.message;
                                                        break;
                                                case VpnDaemon::EventType::Started:
                                                        payload = "[*] " + event.message;
                                                        break;
                                                case VpnDaemon::EventType::Stopped:
                                                        payload = "[*] " + event.message;
                                                        break;
                                                case VpnDaemon::EventType::Error:
                                                        payload = "[!] " + event.message;
                                                        break;
                                        }
                                        std::lock_guard<std::mutex> lock(log_mutex);
                                        log_lines.emplace_back(format_with_timestamp(payload, event.timestamp));
                                        if (log_lines.size() > max_log_lines) {
                                                log_lines.erase(log_lines.begin(), log_lines.begin() + 100);
                                        }
                                });

                                int port_num = 0;
                                try {
                                        port_num = std::stoi(port);
                                        if (port_num < 1 || port_num > 65535)
                                                throw std::out_of_range("Invalid port range");
                                } catch (...) {
                                        append_line("[!] Invalid port entered");
                                        port_num = 0; // or abort connection
                                }

                                VpnDaemon::SessionConfig config{};
                                config.mode = mode;
                                config.server_ip = server_ip;
                                config.port = port_num;
                                config.local_ip = local_ip;
                                config.gateway = gateway;
                                config.password = password;
                                config.adapter_name = adapter_name;
                                config.subnet_mask = subnet_mask;
                                config.public_ip = public_ip;
                                config.real_adapter = (current_adapter_idx_ >= 0 &&
                                                      current_adapter_idx_ < static_cast<int>(real_adapters_.size()))
                                                     ? real_adapters_[current_adapter_idx_].name
                                                     : "Unknown";
                                const int cipher_count = static_cast<int>(IM_ARRAYSIZE(cipher_labels));
                                int cipher_index = (selected_cipher >= 0 && selected_cipher < cipher_count)
                                                   ? selected_cipher
                                                   : 0;
                                const secure::CipherSuite chosen_cipher = cipher_values[cipher_index];
                                config.cipher_suite = chosen_cipher;
                                append_line(std::string("[*] Cipher suite: ") + cipher_labels[cipher_index]);
                                config.transport = (selected_transport == 0)
                                                   ? TransportProtocol::Tcp
                                                   : TransportProtocol::Udp;
                                append_line(std::string("[*] Transport: ") + transport_labels[selected_transport]);

                                if (port_num == 0) {
                                        append_line("[!] Aborting connection attempt due to invalid port");
                                } else {
                                        g_vpn_daemon->start(config);
                                }
                        }
			ImGui::SameLine();
			if (ImGui::Button("Disconnect")) {
				ImGui::OpenPopup("ConfirmDisconnect");
			}

			if (ImGui::BeginPopupModal("ConfirmDisconnect", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
				ImGui::Text("Are you sure you want to disconnect and quit?");
				if (ImGui::Button("Yes, Disconnect")) {
                                        if (g_vpn_daemon && g_vpn_daemon->is_running()) {
                                                //g_vpn_daemon->send_manual_message("/quit");
                                                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                                        }
                                        if (g_vpn_daemon) {
                                                g_vpn_daemon->stop();
                                                g_vpn_daemon.reset();
                                        }
					::ExitProcess(EXIT_SUCCESS);
				}
				ImGui::SameLine();
				if (ImGui::Button("Cancel")) {
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}

			ImGui::Separator();
			ImGui::Text("Connection Log");
			ImGui::SameLine();
			if (ImGui::Button("Clear")) {
				log_lines.clear();
			}
			ImGui::SameLine();
			static bool auto_scroll = true;
			ImGui::Checkbox("Auto-scroll", &auto_scroll);

			float available_height = ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing() * 2.0f;
			ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.69f, 0.51f, 0.89f, 1.00f));

			// Track previous content size
			static int last_log_length = 0;
			int current_log_length = static_cast<int>(log_lines.size());
			// Begin log display
			ImGui::BeginChild("log_box", ImVec2(0, available_height), true,
			                  ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_AlwaysHorizontalScrollbar);

			for (const auto &line: log_lines)
				ImGui::TextUnformatted(line.c_str());

			if (auto_scroll && log_lines.size() > last_log_length) {
				ImGui::SetScrollHereY(1.0f);
				last_log_length = static_cast<int>(log_lines.size());
			}

			ImGui::EndChild();

			ImGui::PopStyleColor();

			static bool focus_message_input = true; // <- new flag

			ImGui::Text("Message:");
			ImGui::SameLine();
			if (ImGui::IsItemHovered())
				ImGui::SetTooltip("Enter a message to send through the VPN tunnel.");

			// Focus box if requested
			if (focus_message_input) {
				ImGui::SetKeyboardFocusHere();
				focus_message_input = false;
			}

			// Input box
			bool enter_pressed = ImGui::InputText(
				"##message",
				message_input,
				IM_ARRAYSIZE(message_input),
				ImGuiInputTextFlags_EnterReturnsTrue
			);

			// Send button
			bool send_requested = enter_pressed || ImGui::Button("Send Message");

			// Send logic
			if (send_requested && strlen(message_input) > 0) {
                                if (g_vpn_daemon && g_vpn_daemon->is_running()) {
                                        //g_vpn_daemon->send_manual_message(message_input);
                                }

				// Append to log
				char formatted[256];
				snprintf(formatted, sizeof(formatted), "[You] %s\n", message_input);
				log_lines.emplace_back(formatted);

				// Clear input
				message_input[0] = '\0';

				// Refocus input box on next frame
				focus_message_input = true;
			}


			ImGui::End();
			ImGui::PopStyleVar(3);
			ImGui::PopStyleVar(3); // Restore padding
		}


		// Rendering
		ImGui::Render();
		const float clear_color_with_alpha[4] = {
			clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w
		};
		g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
		g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

		// Update and Render additional Platform Windows
		if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
			ImGui::UpdatePlatformWindows();
			ImGui::RenderPlatformWindowsDefault();
		}

		// Present
		HRESULT hr = g_pSwapChain->Present(1, 0); // Present with vsync
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

        if (g_vpn_daemon) {
                g_vpn_daemon->stop();
                g_vpn_daemon.reset();
        }

	return 0;
}

// Helper functions
bool CreateDeviceD3D(HWND hWnd) {
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
	HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
	                                            featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
	                                            &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
	if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
		res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags,
		                                    featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice,
		                                    &featureLevel, &g_pd3dDeviceContext);
	if (res != S_OK)
		return false;

	CreateRenderTarget();
	return true;
}

void CleanupDeviceD3D() {
	CleanupRenderTarget();
	if (g_pSwapChain) {
		g_pSwapChain->Release();
		g_pSwapChain = nullptr;
	}
	if (g_pd3dDeviceContext) {
		g_pd3dDeviceContext->Release();
		g_pd3dDeviceContext = nullptr;
	}
	if (g_pd3dDevice) {
		g_pd3dDevice->Release();
		g_pd3dDevice = nullptr;
	}
}

void CreateRenderTarget() {
	ID3D11Texture2D *pBackBuffer;
	g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
	g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
	pBackBuffer->Release();
}

void CleanupRenderTarget() {
	if (g_mainRenderTargetView) {
		g_mainRenderTargetView->Release();
		g_mainRenderTargetView = nullptr;
	}
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
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
		return true;

	switch (msg) {
		case WM_SIZE:
			if (wParam == SIZE_MINIMIZED && !in_tray) {
				// Add tray icon
				in_tray = true;
				nid.cbSize = sizeof(NOTIFYICONDATA);
				nid.uVersion = NOTIFYICON_VERSION_4;
				Shell_NotifyIcon(NIM_SETVERSION, &nid);
				nid.hWnd = hWnd;
				nid.uID = 1;
				nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
				nid.uCallbackMessage = WM_TRAYICON;
				nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_VPN_ICON));
				strcpy_s(nid.szTip, "TrueTunnel VPN");
				Shell_NotifyIcon(NIM_ADD, &nid);
				nid.uFlags |= NIF_INFO;
				strcpy_s(nid.szInfoTitle, "TrueTunnel VPN");
				strcpy_s(nid.szInfo, "App minimized to system tray.\nDouble-click tray icon to restore.");
				nid.dwInfoFlags = NIIF_INFO;
				Shell_NotifyIcon(NIM_MODIFY, &nid);


				ShowWindow(hWnd, SW_HIDE);
				return 0;
			}

			g_ResizeWidth = LOWORD(lParam);
			g_ResizeHeight = HIWORD(lParam);
			return 0;

		case WM_SYSCOMMAND:
			if ((wParam & 0xfff0) == SC_KEYMENU)
				return 0;
			break;

		case WM_COMMAND:
			switch (LOWORD(wParam)) {
				case ID_TRAY_EXIT:
					Shell_NotifyIcon(NIM_DELETE, &nid);
					PostQuitMessage(0);
					break;

				case ID_TRAY_RESTORE:
					ShowWindow(hWnd, SW_RESTORE);
					Shell_NotifyIcon(NIM_DELETE, &nid);
					in_tray = false;

					break;
			}
			return 0;

		case WM_TRAYICON:
			switch (LOWORD(lParam)) {
				case WM_LBUTTONDBLCLK: // <- double-click left
					ShowWindow(hWnd, SW_RESTORE);
					Shell_NotifyIcon(NIM_DELETE, &nid);
					in_tray = false;

					break;

				case WM_RBUTTONUP: {
					POINT pt;
					GetCursorPos(&pt);

					if (!h_tray_menu) {
						h_tray_menu = CreatePopupMenu();
						AppendMenu(h_tray_menu, MF_STRING, ID_TRAY_RESTORE, "Restore");
						AppendMenu(h_tray_menu, MF_STRING, ID_TRAY_EXIT, "Exit");
					}

					SetForegroundWindow(hWnd);
					TrackPopupMenu(h_tray_menu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hWnd, NULL);
				}
				break;
			}
			break;


		case WM_DESTROY:
			Shell_NotifyIcon(NIM_DELETE, &nid);
			PostQuitMessage(0);
			return 0;

		case WM_DPICHANGED:
			if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_DpiEnableScaleViewports) {
				const RECT *suggested_rect = (RECT *) lParam;
				::SetWindowPos(hWnd, nullptr,
				               suggested_rect->left, suggested_rect->top,
				               suggested_rect->right - suggested_rect->left,
				               suggested_rect->bottom - suggested_rect->top,
				               SWP_NOZORDER | SWP_NOACTIVATE);
			}
			break;
	}

	return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
