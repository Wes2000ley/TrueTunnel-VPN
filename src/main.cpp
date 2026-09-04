#include <cstdio>
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <dwmapi.h>
#include <shellapi.h>
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
#include "imgui_internal.h"
#include <wincodec.h>
#include <wrl/client.h>
#endif
#include <mutex>
#include <memory>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <mmsystem.h>   // timeBeginPeriod/timeEndPeriod
#pragma comment(lib, "winmm.lib")

#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <thread>
#include <vector>
#include <filesystem>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tchar.h>
#include <algorithm>
#include "core/VpnDaemon.h"
#include "secure/CipherSuite.h"
#include "utils.hpp"
#include "ImGuiStyleManager.h"
#include "Networking.h"
#include "TransportProtocol.h"
#include "secure/SharedSecret.h"
#define IDI_VPN_ICON 101


static std::unique_ptr<VpnDaemon> g_vpn_daemon;

namespace {
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
constexpr bool kGuiVisualTestBuild = true;
#else
constexpr bool kGuiVisualTestBuild = false;
#endif
constexpr std::size_t kMaxLogLines    = 5000;
constexpr std::size_t kLogPruneBatch  = 100;
constexpr char kSessionStartFailureLog[] = "[!] Failed to start VPN session";
constexpr std::chrono::seconds kClipboardSecretLifetime{30};

using SharedSecretBuffer = std::array<char, 64>;

struct GuiSmokeOptions {
        bool enabled{false};
        bool valid{true};
        std::filesystem::path log_path;
};

std::optional<std::filesystem::path> executable_directory() noexcept {
	try {
		std::vector<wchar_t> module_path(32'768U, L'\0');
		const DWORD length = ::GetModuleFileNameW(
			nullptr, module_path.data(),
			static_cast<DWORD>(module_path.size()));
		if (length == 0U || length >= module_path.size()) return std::nullopt;
		return std::filesystem::path(
			std::wstring(module_path.data(), length)).parent_path();
	} catch (...) {
		return std::nullopt;
	}
}

GuiSmokeOptions parse_gui_smoke_options() noexcept {
        GuiSmokeOptions options{};
        int argc = 0;
        LPWSTR* argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
        if (argv == nullptr) {
                return options;
        }

        for (int index = 1; index < argc; ++index) {
                const std::wstring argument(argv[index] == nullptr ? L"" : argv[index]);
                if (argument == L"--gui-smoke-test") {
                        options.enabled = true;
                } else if (argument == L"--gui-smoke-log") {
                        // The GUI runs elevated. Never let command-line input
                        // select a privileged write/truncation target.
                        options.enabled = true;
                        options.valid = false;
                        break;
                }
        }
        ::LocalFree(argv);

        if (!options.enabled || !options.valid) return options;

	try {
		const auto module_directory = executable_directory();
		if (!module_directory) {
			options.valid = false;
			return options;
		}
		options.log_path = *module_directory / L"vpn-gui-smoke.log";
                if (options.log_path.empty()) options.valid = false;
        } catch (...) {
                options.valid = false;
        }
        return options;
}

std::string_view shared_secret_text(const SharedSecretBuffer& value) noexcept {
        std::size_t length = 0U;
        while (length < value.size() && value[length] != '\0') ++length;
        return {value.data(), length};
}

bool shared_secret_invariants_hold(const SharedSecretBuffer& value) noexcept {
        return secure::is_valid_shared_secret(shared_secret_text(value));
}

bool generate_shared_secret(SharedSecretBuffer& destination) noexcept {
        static constexpr char alphabet[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (unsigned int attempt = 0U; attempt < 8U; ++attempt) {
                std::array<std::uint8_t, secure::kSharedSecretBytes> random_bytes{};
                const NTSTATUS status = ::BCryptGenRandom(
                        nullptr,
                        random_bytes.data(),
                        static_cast<ULONG>(random_bytes.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                if (status < 0) {
                        ::SecureZeroMemory(destination.data(), destination.size());
                        return false;
                }

                destination.fill('\0');
                std::size_t input = 0U;
                std::size_t output = 0U;
                while (input + 3U <= random_bytes.size()) {
                        const std::uint32_t block =
                                (static_cast<std::uint32_t>(random_bytes[input]) << 16U) |
                                (static_cast<std::uint32_t>(random_bytes[input + 1U]) << 8U) |
                                static_cast<std::uint32_t>(random_bytes[input + 2U]);
                        destination[output++] = alphabet[(block >> 18U) & 0x3FU];
                        destination[output++] = alphabet[(block >> 12U) & 0x3FU];
                        destination[output++] = alphabet[(block >> 6U) & 0x3FU];
                        destination[output++] = alphabet[block & 0x3FU];
                        input += 3U;
                }

                const std::size_t remaining = random_bytes.size() - input;
                if (remaining == 2U) {
                        const std::uint32_t block =
                                (static_cast<std::uint32_t>(random_bytes[input]) << 16U) |
                                (static_cast<std::uint32_t>(random_bytes[input + 1U]) << 8U);
                        destination[output++] = alphabet[(block >> 18U) & 0x3FU];
                        destination[output++] = alphabet[(block >> 12U) & 0x3FU];
                        destination[output++] = alphabet[(block >> 6U) & 0x3FU];
                }

                destination[output] = '\0';
                ::SecureZeroMemory(random_bytes.data(), random_bytes.size());
                if (output == secure::kSharedSecretTextLength &&
                    shared_secret_invariants_hold(destination)) {
                        return true;
                }
        }
        ::SecureZeroMemory(destination.data(), destination.size());
        return false;
}

class SecretClipboardLease final {
public:
        [[nodiscard]] bool copy_secret(
                HWND owner,
                const SharedSecretBuffer& secret) noexcept {
                const int wide_characters = ::MultiByteToWideChar(
                        CP_UTF8, MB_ERR_INVALID_CHARS, secret.data(), -1,
                        nullptr, 0);
                if (owner == nullptr || wide_characters <= 1) return false;

                const SIZE_T secret_bytes =
                        static_cast<SIZE_T>(wide_characters) * sizeof(wchar_t);
                HGLOBAL secret_memory =
                        ::GlobalAlloc(GMEM_MOVEABLE, secret_bytes);
                if (secret_memory == nullptr) return false;

                auto* const secret_text = static_cast<wchar_t*>(
                        ::GlobalLock(secret_memory));
                if (secret_text == nullptr) {
                        ::GlobalFree(secret_memory);
                        return false;
                }
                const int converted = ::MultiByteToWideChar(
                        CP_UTF8, MB_ERR_INVALID_CHARS, secret.data(), -1,
                        secret_text, wide_characters);
                if (converted != wide_characters) {
                        ::SecureZeroMemory(secret_text, secret_bytes);
                        ::GlobalUnlock(secret_memory);
                        ::GlobalFree(secret_memory);
                        return false;
                }
                ::GlobalUnlock(secret_memory);

                const UINT exclusion_format = ::RegisterClipboardFormatW(
                        L"ExcludeClipboardContentFromMonitorProcessing");
                HGLOBAL exclusion_memory =
                        ::GlobalAlloc(GMEM_MOVEABLE, sizeof(DWORD));
                if (exclusion_format == 0U || exclusion_memory == nullptr) {
                        wipe_and_free(secret_memory, secret_bytes);
                        if (exclusion_memory != nullptr) {
                                ::GlobalFree(exclusion_memory);
                        }
                        return false;
                }
                auto* const exclusion_value = static_cast<DWORD*>(
                        ::GlobalLock(exclusion_memory));
                if (exclusion_value == nullptr) {
                        wipe_and_free(secret_memory, secret_bytes);
                        ::GlobalFree(exclusion_memory);
                        return false;
                }
                *exclusion_value = 0U;
                ::GlobalUnlock(exclusion_memory);

                if (!::OpenClipboard(owner)) {
                        wipe_and_free(secret_memory, secret_bytes);
                        ::GlobalFree(exclusion_memory);
                        return false; // Preserve any earlier active lease.
                }
                if (!::EmptyClipboard()) {
                        ::CloseClipboard();
                        wipe_and_free(secret_memory, secret_bytes);
                        ::GlobalFree(exclusion_memory);
                        return false;
                }

                // The previous owned value is now gone. From this point a
                // partial failure must leave the clipboard empty and inactive.
                active_ = false;
                if (::SetClipboardData(exclusion_format, exclusion_memory) ==
                    nullptr) {
                        ::EmptyClipboard();
                        ::CloseClipboard();
                        wipe_and_free(secret_memory, secret_bytes);
                        ::GlobalFree(exclusion_memory);
                        return false;
                }
                exclusion_memory = nullptr; // The system owns it now.

                if (::SetClipboardData(CF_UNICODETEXT, secret_memory) ==
                    nullptr) {
                        ::EmptyClipboard();
                        ::CloseClipboard();
                        wipe_and_free(secret_memory, secret_bytes);
                        return false;
                }
                secret_memory = nullptr; // The system owns and will free it.

                // No other process can mutate the clipboard while it is open,
                // so this sequence number belongs to the successful write.
                const DWORD sequence = ::GetClipboardSequenceNumber();
                const bool ownership_confirmed =
                        sequence != 0U && ::GetClipboardOwner() == owner;
                if (!ownership_confirmed) {
                        ::EmptyClipboard();
                        ::CloseClipboard();
                        return false;
                }

                sequence_ = sequence;
                owner_ = owner;
                expires_ = std::chrono::steady_clock::now() +
                           kClipboardSecretLifetime;
                active_ = true;
                if (!::CloseClipboard()) {
                        // Retain the lease. A later clear attempt will retry
                        // after the system releases the clipboard.
                        return false;
                }
                return true;
        }

        void clear_if_expired(HWND owner) noexcept {
                if (active_ && std::chrono::steady_clock::now() >= expires_) {
                        clear_if_owned(owner);
                }
        }

        void clear_now_if_owned(HWND owner) noexcept {
                if (active_) clear_if_owned(owner);
        }

        [[nodiscard]] bool clear_before_shutdown(HWND owner) noexcept {
                while (active_) {
                        const auto retry_deadline =
                                std::chrono::steady_clock::now() +
                                std::chrono::seconds{2};
                        do {
                                clear_if_owned(owner);
                                if (!active_) return true;
                                ::Sleep(10U);
                        } while (std::chrono::steady_clock::now() <
                                 retry_deadline);

                        const int choice = ::MessageBoxW(
                                owner,
                                L"The clipboard is busy, so TrueTunnel could "
                                L"not clear the copied shared key. Close the "
                                L"application using the clipboard, then choose "
                                L"Retry. Cancel exits without clearing it.",
                                L"TrueTunnel clipboard protection",
                                MB_RETRYCANCEL | MB_ICONWARNING | MB_DEFBUTTON1 |
                                    MB_TASKMODAL);
                        if (choice != IDRETRY) return false;
                }
                return true;
        }

private:
        void clear_if_owned(HWND owner) noexcept {
                const DWORD before_open = ::GetClipboardSequenceNumber();
                if (owner != owner_ || before_open == 0U ||
                    before_open != sequence_ ||
                    ::GetClipboardOwner() != owner_) {
                        // Another application replaced the clipboard. Never
                        // erase content that TrueTunnel no longer owns.
                        active_ = false;
                        return;
                }
                if (!::OpenClipboard(owner)) {
                        return; // Keep the lease and retry on a later frame.
                }
                const DWORD after_open = ::GetClipboardSequenceNumber();
                if (after_open == sequence_ &&
                    ::GetClipboardOwner() == owner_ && ::EmptyClipboard()) {
                        active_ = false;
                } else if (after_open != sequence_ ||
                           ::GetClipboardOwner() != owner_) {
                        active_ = false;
                }
                ::CloseClipboard();
        }

        static void wipe_and_free(HGLOBAL memory,
                                  const SIZE_T bytes) noexcept {
                if (memory == nullptr) return;
                void* const data = ::GlobalLock(memory);
                if (data != nullptr) {
                        ::SecureZeroMemory(data, bytes);
                        ::GlobalUnlock(memory);
                }
                ::GlobalFree(memory);
        }

        DWORD sequence_{0U};
        HWND owner_{nullptr};
        std::chrono::steady_clock::time_point expires_{};
        bool active_{false};
};

std::mutex g_log_mutex;
std::vector<std::string> g_log_lines;
HANDLE g_gui_smoke_log = INVALID_HANDLE_VALUE;
bool g_gui_smoke_log_write_failed = false;

std::string format_with_timestamp(const std::string& message,
                                  std::chrono::system_clock::time_point when = std::chrono::system_clock::now()) {
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
}

void write_gui_test_log_locked(const std::string& formatted) noexcept {
	if (g_gui_smoke_log == INVALID_HANDLE_VALUE) return;
	const std::string line = formatted + "\r\n";
	DWORD written = 0U;
	const bool size_valid = line.size() <= static_cast<std::size_t>(
		(std::numeric_limits<DWORD>::max)());
	if (!size_valid ||
		!::WriteFile(
			g_gui_smoke_log, line.data(), static_cast<DWORD>(line.size()),
			&written, nullptr) ||
		written != line.size() || !::FlushFileBuffers(g_gui_smoke_log)) {
		g_gui_smoke_log_write_failed = true;
	}
}

void append_log(const std::string& message,
                std::chrono::system_clock::time_point when = std::chrono::system_clock::now()) {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        const std::string formatted = format_with_timestamp(message, when);
        g_log_lines.emplace_back(formatted);
		write_gui_test_log_locked(formatted);
        if (g_log_lines.size() > kMaxLogLines) {
                auto excess = g_log_lines.size() - kMaxLogLines;
                auto prune  = std::max<std::size_t>(excess, kLogPruneBatch);
                prune = std::min(prune, g_log_lines.size());
                g_log_lines.erase(g_log_lines.begin(), g_log_lines.begin() + static_cast<std::ptrdiff_t>(prune));
        }
}

#ifdef TRUETUNNEL_GUI_VISUAL_TEST
void append_visual_report(const std::string& message) noexcept {
	try {
		std::lock_guard<std::mutex> lock(g_log_mutex);
		write_gui_test_log_locked(format_with_timestamp(message));
	} catch (...) {
		g_gui_smoke_log_write_failed = true;
	}
}
#endif

bool open_gui_smoke_log(const std::filesystem::path& path) noexcept {
        if (path.empty()) return false;
        try {
                HANDLE handle = ::CreateFileW(
                    path.c_str(),
                    GENERIC_WRITE,
                    FILE_SHARE_READ,
                    nullptr,
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
                if (handle == INVALID_HANDLE_VALUE) return false;

                BY_HANDLE_FILE_INFORMATION information{};
                const bool safe_target =
                    ::GetFileInformationByHandle(handle, &information) &&
                    (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U &&
                    (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U &&
                    information.nNumberOfLinks == 1U;
                LARGE_INTEGER beginning{};
                if (!safe_target ||
                    !::SetFilePointerEx(handle, beginning, nullptr, FILE_BEGIN) ||
                    !::SetEndOfFile(handle)) {
                        ::CloseHandle(handle);
                        return false;
                }
                g_gui_smoke_log = handle;
                return true;
        } catch (...) {
                return false;
        }
}

void close_gui_smoke_log() noexcept {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        if (g_gui_smoke_log != INVALID_HANDLE_VALUE) {
                ::CloseHandle(g_gui_smoke_log);
                g_gui_smoke_log = INVALID_HANDLE_VALUE;
        }
}

std::vector<std::string> snapshot_logs() {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        return g_log_lines;
}

void clear_logs() {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        g_log_lines.clear();
}

void handle_daemon_event(const VpnDaemon::TelemetryEvent& event) {
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
        append_log(payload, event.timestamp);
}

void ensure_daemon() {
        if (!g_vpn_daemon) {
                g_vpn_daemon = std::make_unique<VpnDaemon>();
                g_vpn_daemon->set_event_callback(handle_daemon_event);
        }
}
} // namespace


// Data
static ID3D11Device *g_pd3dDevice = nullptr;
static ID3D11DeviceContext *g_pd3dDeviceContext = nullptr;
static IDXGISwapChain *g_pSwapChain = nullptr;
static bool g_SwapChainOccluded = false;
static UINT g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView *g_mainRenderTargetView = nullptr;
static float g_ui_scale = 1.0f;
static UINT g_pending_dpi = 0U;

namespace {
struct GuiFonts {
	ImFont* body{nullptr};
	ImFont* semibold{nullptr};
	ImFont* title{nullptr};
};

std::string utf8_path(const std::filesystem::path& path) {
	const std::wstring native = path.native();
	if (native.empty()) return {};
	const int byte_count = ::WideCharToMultiByte(
		CP_UTF8, WC_ERR_INVALID_CHARS, native.data(),
		static_cast<int>(native.size()), nullptr, 0, nullptr, nullptr);
	if (byte_count <= 0) return {};
	std::string encoded(static_cast<std::size_t>(byte_count), '\0');
	if (::WideCharToMultiByte(
			CP_UTF8, WC_ERR_INVALID_CHARS, native.data(),
			static_cast<int>(native.size()), encoded.data(), byte_count,
			nullptr, nullptr) != byte_count) {
		return {};
	}
	return encoded;
}

std::string windows_font_path(const wchar_t* filename) {
	std::array<wchar_t, 32'768U> windows_directory{};
	const UINT length = ::GetWindowsDirectoryW(
		windows_directory.data(), static_cast<UINT>(windows_directory.size()));
	if (length == 0U ||
		length >= static_cast<UINT>(windows_directory.size())) {
		return {};
	}
	return utf8_path(
		std::filesystem::path(std::wstring(windows_directory.data(), length)) /
		L"Fonts" / filename);
}

GuiFonts load_gui_fonts(ImGuiStyleManager& style_manager, const float scale) {
	ImGuiIO& io = ImGui::GetIO();
	io.Fonts->Clear();
	GuiFonts fonts{};
	fonts.body = style_manager.LoadFontFromPath(
		windows_font_path(L"segoeui.ttf"), 17.0f * scale, true);
	if (fonts.body == nullptr) {
		style_manager.LoadDefaultFont();
		fonts.body = io.FontDefault;
	}
	fonts.semibold = style_manager.LoadFontFromPath(
		windows_font_path(L"seguisb.ttf"), 18.0f * scale, false);
	if (fonts.semibold == nullptr) fonts.semibold = fonts.body;
	fonts.title = style_manager.LoadFontFromPath(
		windows_font_path(L"segoeuib.ttf"), 26.0f * scale, false);
	if (fonts.title == nullptr) fonts.title = fonts.semibold;
	(void)io.Fonts->Build();
	return fonts;
}

enum class UiErrorField {
	None,
	Endpoint,
	Port,
	SharedSecret,
	Adapter,
	General
};

struct GuiRenderMetrics {
	struct Bounds {
		ImVec2 minimum{};
		ImVec2 maximum{};
		bool valid{false};
	};

	float content_scroll_y{0.0f};
	float content_scroll_max{0.0f};
	float requested_content_scroll_y{0.0f};
	float network_anchor_y{0.0f};
	float secret_anchor_y{0.0f};
	float activity_anchor_y{0.0f};
	float recovery_anchor_y{0.0f};
	float security_anchor_y{0.0f};
	float activity_scroll_y{0.0f};
	float activity_scroll_max{0.0f};
	float requested_activity_scroll_y{0.0f};
	bool connect_action_visible{false};
	bool disconnect_action_visible{false};
	bool endpoint_focused{false};
	bool port_focused{false};
	bool primary_action_focused{false};
	bool validation_error_visible{false};
	bool activity_error_visible{false};
	bool help_visible{false};
	bool disconnect_confirmation_visible{false};
	bool partial_control_visible{false};
	bool partial_activity_row_visible{false};
	bool help_button_available{false};
	bool endpoint_input_available{false};
	bool disconnect_button_available{false};
	bool recovery_control_present{false};
	bool recovery_toggle_visible{false};
	bool recovery_toggle_enabled{false};
	bool recovery_toggle_focused{false};
	bool recovery_status_visible{false};
	bool configuration_controls_locked{false};
	bool secure_session_indicators_active{false};
	bool status_endpoint_port_visible{false};
	bool wide_layout{false};
	bool role_server_control_available{false};
	bool transport_tcp_control_available{false};
	bool secret_action_available{false};
	ImVec2 help_button_center{};
	ImVec2 endpoint_input_center{};
	ImVec2 disconnect_button_center{};
	ImVec2 role_server_control_center{};
	ImVec2 transport_tcp_control_center{};
	ImVec2 secret_action_center{};
	ImVec2 dashboard_clip_minimum{};
	ImVec2 dashboard_clip_maximum{};
	Bounds header_surface{};
	Bounds help_button{};
	Bounds status_card{};
	Bounds status_context{};
	Bounds status_endpoint{};
	Bounds connection_card{};
	Bounds recovery_card{};
	Bounds endpoint_field{};
	Bounds port_field{};
	Bounds network_card{};
	Bounds secret_card{};
	Bounds activity_card{};
	Bounds security_card{};
};

ImVec2 last_item_center() noexcept {
	const ImVec2 minimum = ImGui::GetItemRectMin();
	const ImVec2 maximum = ImGui::GetItemRectMax();
	return ImVec2(
		(minimum.x + maximum.x) * 0.5f,
		(minimum.y + maximum.y) * 0.5f);
}

void observe_last_control(
		GuiRenderMetrics& metrics,
		const ImVec2& clip_minimum,
		const ImVec2& clip_maximum) noexcept {
	const ImVec2 minimum = ImGui::GetItemRectMin();
	const ImVec2 maximum = ImGui::GetItemRectMax();
	const bool intersects =
		maximum.x > clip_minimum.x && maximum.y > clip_minimum.y &&
		minimum.x < clip_maximum.x && minimum.y < clip_maximum.y;
	const bool contained =
		minimum.x >= clip_minimum.x && minimum.y >= clip_minimum.y &&
		maximum.x <= clip_maximum.x && maximum.y <= clip_maximum.y;
	if (intersects && !contained) metrics.partial_control_visible = true;
}

void record_last_item_bounds(GuiRenderMetrics::Bounds& bounds) noexcept {
	bounds.minimum = ImGui::GetItemRectMin();
	bounds.maximum = ImGui::GetItemRectMax();
	bounds.valid = bounds.maximum.x > bounds.minimum.x &&
		bounds.maximum.y > bounds.minimum.y;
}

std::string ellipsize_text_to_width(
		const std::string_view text,
		const float maximum_width) {
	if (text.empty() || maximum_width <= 0.0f) return {};
	if (ImGui::CalcTextSize(text.data(), text.data() + text.size()).x <=
		maximum_width) {
		return std::string{text};
	}

	constexpr std::string_view ellipsis{"..."};
	std::string_view preserved_suffix{};
	std::size_t prefix_limit = text.size();
	const std::size_t port_separator = text.rfind(':');
	if (port_separator != std::string_view::npos &&
		port_separator + 1U < text.size()) {
		preserved_suffix = text.substr(port_separator);
		prefix_limit = port_separator;
	}
	std::string fixed_tail{ellipsis};
	fixed_tail.append(preserved_suffix);
	if (ImGui::CalcTextSize(fixed_tail.c_str()).x > maximum_width) {
		preserved_suffix = {};
		prefix_limit = text.size();
		fixed_tail.assign(ellipsis);
	}
	if (ImGui::CalcTextSize(fixed_tail.c_str()).x > maximum_width) {
		return {};
	}

	// Remove complete UTF-8 code points from the host while retaining the port.
	// Endpoint input is bounded to 63 bytes, so this simple loop is predictable.
	std::size_t prefix_size = prefix_limit;
	while (prefix_size > 0U) {
		--prefix_size;
		while (prefix_size > 0U &&
			(static_cast<unsigned char>(text[prefix_size]) & 0xC0U) == 0x80U) {
			--prefix_size;
		}
		std::string candidate{text.substr(0U, prefix_size)};
		candidate.append(fixed_tail);
		if (ImGui::CalcTextSize(candidate.c_str()).x <= maximum_width) {
			return candidate;
		}
	}
	return fixed_tail;
}

void push_validation_frame(const bool invalid) {
	if (!invalid) return;
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.16f, 0.055f, 0.064f, 0.96f));
	ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.21f, 0.068f, 0.077f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0.18f, 0.060f, 0.071f, 1.0f));
	ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1.0f, 0.35f, 0.37f, 0.90f));
}

void pop_validation_frame(const bool invalid) {
	if (invalid) ImGui::PopStyleColor(4);
}

void inline_validation_error(
		GuiRenderMetrics& metrics,
		const std::string& message) {
	if (message.empty()) return;
	ImGui::PushTextWrapPos(0.0f);
	ImGui::TextColored(
		ImVec4(1.0f, 0.58f, 0.58f, 1.0f), "%s", message.c_str());
	ImGui::PopTextWrapPos();
	if (ImGui::IsItemVisible()) metrics.validation_error_visible = true;
}

bool apply_dark_window_frame(HWND window) noexcept {
	if (window == nullptr) return false;
	const BOOL enabled = TRUE;
	constexpr DWORD immersive_dark_mode = 20U;
	constexpr DWORD immersive_dark_mode_legacy = 19U;
	HRESULT dark_result = ::DwmSetWindowAttribute(
		window, immersive_dark_mode, &enabled, sizeof(enabled));
	if (FAILED(dark_result)) {
		dark_result = ::DwmSetWindowAttribute(
			window, immersive_dark_mode_legacy, &enabled, sizeof(enabled));
	}
	// Windows 11 uses value 2 for DWMWCP_ROUND. Older systems simply reject
	// the unknown attribute and keep their native frame behavior.
	constexpr DWORD window_corner_preference = 33U;
	const DWORD rounded = 2U;
	(void)::DwmSetWindowAttribute(
		window, window_corner_preference, &rounded, sizeof(rounded));
	// Integrate the standard Windows frame with the app palette. Unsupported
	// attributes are deliberately best-effort on Windows 10.
	constexpr DWORD border_color_attribute = 34U;
	constexpr DWORD caption_color_attribute = 35U;
	constexpr DWORD text_color_attribute = 36U;
	constexpr DWORD system_backdrop_attribute = 38U;
	const COLORREF border_color = RGB(50, 59, 73);
	const COLORREF caption_color = RGB(12, 17, 25);
	const COLORREF text_color = RGB(229, 240, 252);
	const DWORD mica_backdrop = 2U;
	(void)::DwmSetWindowAttribute(
		window, border_color_attribute, &border_color, sizeof(border_color));
	(void)::DwmSetWindowAttribute(
		window, caption_color_attribute, &caption_color, sizeof(caption_color));
	(void)::DwmSetWindowAttribute(
		window, text_color_attribute, &text_color, sizeof(text_color));
	(void)::DwmSetWindowAttribute(
		window, system_backdrop_attribute, &mica_backdrop, sizeof(mica_backdrop));
	return SUCCEEDED(dark_result);
}

bool resize_client_area(
		HWND window,
		const int logical_width,
		const int logical_height,
		const float scale) noexcept {
	if (window == nullptr || logical_width <= 0 || logical_height <= 0 ||
		scale <= 0.0f) {
		return false;
	}

	const auto width = static_cast<LONG>(std::lround(
		static_cast<double>(logical_width) * scale));
	const auto height = static_cast<LONG>(std::lround(
		static_cast<double>(logical_height) * scale));
	RECT outer{0, 0, width, height};
	const DWORD style = static_cast<DWORD>(::GetWindowLongPtrW(window, GWL_STYLE));
	const DWORD extended_style = static_cast<DWORD>(
		::GetWindowLongPtrW(window, GWL_EXSTYLE));
	const UINT dpi = (std::max)(96U, ::GetDpiForWindow(window));

	using AdjustForDpi = BOOL(WINAPI*)(LPRECT, DWORD, BOOL, DWORD, UINT);
	const HMODULE user32 = ::GetModuleHandleW(L"user32.dll");
	const auto adjust_for_dpi = user32 == nullptr ? nullptr :
		reinterpret_cast<AdjustForDpi>(
			::GetProcAddress(user32, "AdjustWindowRectExForDpi"));
	const BOOL adjusted = adjust_for_dpi != nullptr
		? adjust_for_dpi(&outer, style, FALSE, extended_style, dpi)
		: ::AdjustWindowRectEx(&outer, style, FALSE, extended_style);
	if (!adjusted) return false;

	MONITORINFO monitor_info{sizeof(monitor_info)};
	const HMONITOR monitor = ::MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST);
	if (!::GetMonitorInfoW(monitor, &monitor_info)) return false;
	const int outer_width = outer.right - outer.left;
	const int outer_height = outer.bottom - outer.top;
	const int x = monitor_info.rcWork.left +
		((monitor_info.rcWork.right - monitor_info.rcWork.left) - outer_width) / 2;
	const int y = monitor_info.rcWork.top +
		((monitor_info.rcWork.bottom - monitor_info.rcWork.top) - outer_height) / 2;
	return ::SetWindowPos(
		window, nullptr, x, y, outer_width, outer_height,
		SWP_NOACTIVATE | SWP_NOZORDER) != FALSE;
}

void draw_brand_mark(const float scale) {
	const ImVec2 origin = ImGui::GetCursorScreenPos();
	const ImVec2 size(38.0f * scale, 38.0f * scale);
	ImGui::Dummy(size);
	ImDrawList* draw = ImGui::GetWindowDrawList();
	const ImVec2 maximum(origin.x + size.x, origin.y + size.y);
	draw->AddRectFilled(
		ImVec2(origin.x, origin.y + 4.0f * scale),
		ImVec2(maximum.x, maximum.y + 5.0f * scale),
		ImGui::GetColorU32(ImVec4(0.00f, 0.08f, 0.22f, 0.42f)),
		11.0f * scale);
	draw->AddRectFilled(
		origin, maximum,
		ImGui::GetColorU32(ImVec4(0.15f, 0.43f, 0.92f, 1.0f)),
		10.0f * scale);
	draw->AddRectFilledMultiColor(
		ImVec2(origin.x + 6.0f * scale, origin.y + 1.0f * scale),
		ImVec2(maximum.x - 6.0f * scale, origin.y + 16.0f * scale),
		ImGui::GetColorU32(ImVec4(0.48f, 0.78f, 1.00f, 0.64f)),
		ImGui::GetColorU32(ImVec4(0.28f, 0.66f, 1.00f, 0.26f)),
		ImGui::GetColorU32(ImVec4(0.22f, 0.46f, 0.94f, 0.00f)),
		ImGui::GetColorU32(ImVec4(0.34f, 0.62f, 1.00f, 0.00f)));
	draw->AddRect(
		origin, maximum,
		ImGui::GetColorU32(ImVec4(0.56f, 0.82f, 1.00f, 0.72f)),
		10.0f * scale, 0, 1.0f * scale);
	const ImVec2 center(origin.x + size.x * 0.5f, origin.y + size.y * 0.5f);
	const ImU32 glyph = ImGui::GetColorU32(ImVec4(0.94f, 0.98f, 1.0f, 0.98f));
	// A compact shield/T mark reads as security and avoids looking like a
	// window's minus button at small sizes.
	draw->PathLineTo(ImVec2(center.x, center.y - 10.0f * scale));
	draw->PathLineTo(ImVec2(center.x + 9.0f * scale, center.y - 6.0f * scale));
	draw->PathLineTo(ImVec2(center.x + 7.0f * scale, center.y + 6.0f * scale));
	draw->PathLineTo(ImVec2(center.x, center.y + 11.0f * scale));
	draw->PathLineTo(ImVec2(center.x - 7.0f * scale, center.y + 6.0f * scale));
	draw->PathLineTo(ImVec2(center.x - 9.0f * scale, center.y - 6.0f * scale));
	draw->PathLineTo(ImVec2(center.x, center.y - 10.0f * scale));
	draw->PathStroke(glyph, 0, 1.8f * scale);
	draw->AddLine(
		ImVec2(center.x - 5.0f * scale, center.y - 3.5f * scale),
		ImVec2(center.x + 5.0f * scale, center.y - 3.5f * scale),
		glyph, 1.8f * scale);
	draw->AddLine(
		ImVec2(center.x, center.y - 3.5f * scale),
		ImVec2(center.x, center.y + 5.5f * scale),
		glyph, 1.8f * scale);
}

void draw_glass_surface(
		const ImVec2& origin,
		const ImVec2& size,
		const ImVec4& accent,
		const float scale,
		const bool emphasized = false) {
	if (size.x <= 0.0f || size.y <= 0.0f) return;
	ImDrawList* draw = ImGui::GetWindowDrawList();
	const ImVec2 maximum(origin.x + size.x, origin.y + size.y);
	const float rounding = (emphasized ? 18.0f : 16.0f) * scale;

	// Layered low-alpha edges provide depth without turning the utility into a
	// glowing game overlay.
	draw->AddRectFilled(
		ImVec2(origin.x + 1.0f * scale, origin.y + 7.0f * scale),
		ImVec2(maximum.x + 1.0f * scale, maximum.y + 9.0f * scale),
		ImGui::GetColorU32(ImVec4(0.0f, 0.0f, 0.0f, 0.20f)),
		rounding + 2.0f * scale);

	const ImVec4 glass = emphasized
		? ImVec4(0.046f, 0.071f, 0.106f, 0.96f)
		: ImVec4(0.033f, 0.050f, 0.074f, 0.94f);
	draw->AddRectFilled(origin, maximum, ImGui::GetColorU32(glass), rounding);

	// The hairline and top highlight imply a laminated
	// glass edge while remaining crisp at non-integer Windows DPI scales.
	draw->AddRect(
		origin, maximum,
		ImGui::GetColorU32(ImVec4(0.30f, 0.42f, 0.57f, 0.78f)),
		rounding, 0, 1.0f * scale);
	draw->AddRect(
		ImVec2(origin.x + 1.0f * scale, origin.y + 1.0f * scale),
		ImVec2(maximum.x - 1.0f * scale, maximum.y - 1.0f * scale),
		ImGui::GetColorU32(ImVec4(0.80f, 0.91f, 1.00f, 0.055f)),
		rounding - 1.0f * scale, 0, 1.0f * scale);
	draw->AddLine(
		ImVec2(origin.x + rounding, origin.y + 1.0f * scale),
		ImVec2(maximum.x - rounding, origin.y + 1.0f * scale),
		ImGui::GetColorU32(ImVec4(0.93f, 0.96f, 1.00f, 0.10f)),
		1.0f * scale);
	if (emphasized) {
		ImVec4 accent_edge = accent;
		accent_edge.w = 0.92f;
		draw->AddLine(
			ImVec2(origin.x + rounding, origin.y + 1.0f * scale),
			ImVec2(origin.x + rounding + 104.0f * scale,
			       origin.y + 1.0f * scale),
			ImGui::GetColorU32(accent_edge), 2.0f * scale);
	}
}

bool begin_card(
		const char* id,
		const float scale,
		const bool emphasized = false,
		const float vertical_padding = 18.0f) {
	ImGui::PushStyleColor(
		ImGuiCol_ChildBg,
		emphasized ? ImVec4(0.046f, 0.071f, 0.106f, 0.96f)
		           : ImVec4(0.036f, 0.052f, 0.075f, 0.94f));
	ImGui::PushStyleColor(
		ImGuiCol_Border, ImVec4(0.29f, 0.35f, 0.43f, 0.78f));
	ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 16.0f * scale);
	ImGui::PushStyleVar(
		ImGuiStyleVar_WindowPadding,
		ImVec2(20.0f * scale, vertical_padding * scale));
	const bool visible = ImGui::BeginChild(
		id, ImVec2(0.0f, 0.0f),
		ImGuiChildFlags_Borders |
		ImGuiChildFlags_AlwaysUseWindowPadding |
		ImGuiChildFlags_AutoResizeY |
		ImGuiChildFlags_AlwaysAutoResize,
		ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	// Cards auto-size to their content and must never retain an internal scroll
	// offset when a prior viewport clipped them.
	ImGui::SetScrollX(0.0f);
	ImGui::SetScrollY(0.0f);
	return visible;
}

void end_card(
		const float scale,
		const ImVec4 accent = ImVec4(0.28f, 0.61f, 1.00f, 1.0f),
		const bool emphasized = false) {
	ImGui::EndChild();
	const ImVec2 item_min = ImGui::GetItemRectMin();
	const ImVec2 item_max = ImGui::GetItemRectMax();
	ImDrawList* draw = ImGui::GetWindowDrawList();
	const float rounding = 16.0f * scale;
	// Repaint a precise outer hairline and a restrained inner reflection after
	// the child is laid out. This keeps every card edge identical at any DPI.
	draw->AddRect(
		item_min, item_max,
		ImGui::GetColorU32(ImVec4(0.30f, 0.36f, 0.45f, 0.78f)),
		rounding, 0, 1.0f * scale);
	draw->AddRect(
		ImVec2(item_min.x + 1.0f * scale, item_min.y + 1.0f * scale),
		ImVec2(item_max.x - 1.0f * scale, item_max.y - 1.0f * scale),
		ImGui::GetColorU32(ImVec4(0.82f, 0.91f, 1.00f, 0.045f)),
		rounding - 1.0f * scale, 0, 1.0f * scale);
	draw->AddLine(
		ImVec2(item_min.x + 16.0f * scale, item_min.y + 1.0f * scale),
		ImVec2(item_max.x - 16.0f * scale, item_min.y + 1.0f * scale),
		ImGui::GetColorU32(ImVec4(0.94f, 0.97f, 1.00f, 0.12f)),
		1.0f * scale);
	draw->AddLine(
		ImVec2(item_min.x + rounding, item_max.y + 2.0f * scale),
		ImVec2(item_max.x - rounding, item_max.y + 2.0f * scale),
		ImGui::GetColorU32(ImVec4(0.0f, 0.0f, 0.0f, 0.30f)),
		2.0f * scale);
	if (emphasized) {
		ImVec4 accent_edge = accent;
		accent_edge.w = 0.94f;
		draw->AddLine(
			ImVec2(item_min.x + 1.5f * scale, item_min.y + 18.0f * scale),
			ImVec2(item_min.x + 1.5f * scale, item_max.y - 18.0f * scale),
			ImGui::GetColorU32(accent_edge), 3.0f * scale);
	}
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(2);
}

void card_heading(
		ImFont* font,
		const char* title,
		const char* subtitle) {
	if (font != nullptr) ImGui::PushFont(font);
	ImGui::TextUnformatted(title);
	if (font != nullptr) ImGui::PopFont();
	if (subtitle != nullptr && subtitle[0] != '\0') {
		ImGui::PushStyleColor(
			ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
		ImGui::PushTextWrapPos(0.0f);
		ImGui::TextWrapped("%s", subtitle);
		ImGui::PopTextWrapPos();
		ImGui::PopStyleColor();
	}
	ImGui::Spacing();
}

bool segment_button(
		const char* label,
		const bool selected,
		const ImVec2& size,
		const float scale,
		const bool read_only = false) {
	ImGui::PushStyleColor(
		ImGuiCol_Button,
		selected ? (read_only
			? ImVec4(0.105f, 0.235f, 0.410f, 0.98f)
			: ImVec4(0.145f, 0.390f, 0.790f, 0.98f))
		         : ImVec4(0.047f, 0.086f, 0.145f, 0.90f));
	ImGui::PushStyleColor(
		ImGuiCol_ButtonHovered,
		selected ? ImVec4(0.200f, 0.490f, 0.930f, 1.0f)
		         : ImVec4(0.080f, 0.145f, 0.235f, 0.96f));
	ImGui::PushStyleColor(
		ImGuiCol_ButtonActive, ImVec4(0.145f, 0.349f, 0.659f, 1.0f));
	ImGui::PushStyleColor(
		ImGuiCol_Text,
		selected ? (read_only
			? ImVec4(0.76f, 0.83f, 0.91f, 1.0f)
			: ImVec4(0.98f, 0.99f, 1.0f, 1.0f))
		         : ImVec4(0.63f, 0.70f, 0.79f, 1.0f));
	ImGui::PushStyleColor(
		ImGuiCol_Border,
		selected ? (read_only
			? ImVec4(0.30f, 0.50f, 0.71f, 0.68f)
			: ImVec4(0.38f, 0.70f, 1.00f, 0.76f))
		         : ImVec4(0.21f, 0.34f, 0.51f, 0.58f));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f * scale);
	const bool clicked = ImGui::Button(label, size);
	const ImVec2 item_min = ImGui::GetItemRectMin();
	const ImVec2 item_max = ImGui::GetItemRectMax();
	if (selected && !read_only) {
		ImGui::GetWindowDrawList()->AddLine(
			ImVec2(item_min.x + 12.0f * scale, item_min.y + 1.0f * scale),
			ImVec2(item_max.x - 12.0f * scale, item_min.y + 1.0f * scale),
			ImGui::GetColorU32(ImVec4(0.72f, 0.89f, 1.00f, 0.34f)),
			1.0f * scale);
	}
	ImGui::PopStyleVar();
	ImGui::PopStyleColor(5);
	return clicked;
}

void decorate_popup_surface(const float scale, const ImVec4& accent) {
	const ImVec2 minimum = ImGui::GetWindowPos();
	const ImVec2 maximum(
		minimum.x + ImGui::GetWindowWidth(),
		minimum.y + ImGui::GetWindowHeight());
	const float rounding = ImGui::GetStyle().PopupRounding;
	ImDrawList* draw = ImGui::GetWindowDrawList();
	draw->AddRect(
		minimum, maximum,
		ImGui::GetColorU32(ImVec4(0.35f, 0.52f, 0.72f, 0.88f)),
		rounding, 0, 1.0f * scale);
	draw->AddRect(
		ImVec2(minimum.x + 1.0f * scale, minimum.y + 1.0f * scale),
		ImVec2(maximum.x - 1.0f * scale, maximum.y - 1.0f * scale),
		ImGui::GetColorU32(ImVec4(0.86f, 0.94f, 1.0f, 0.08f)),
		rounding - 1.0f * scale, 0, 1.0f * scale);
	ImVec4 top_accent = accent;
	top_accent.w = 0.90f;
	draw->AddLine(
		ImVec2(minimum.x + rounding, minimum.y + 1.0f * scale),
		ImVec2(minimum.x + rounding + 76.0f * scale,
		       minimum.y + 1.0f * scale),
		ImGui::GetColorU32(top_accent), 2.0f * scale);
}

void decorate_last_button_surface(
		const float scale,
		const ImVec4& accent,
		const bool enabled = true) {
	if (!enabled || !ImGui::IsItemVisible() ||
		(!ImGui::IsItemHovered() && !ImGui::IsItemFocused() &&
		 !ImGui::IsItemActive())) {
		return;
	}
	const ImVec2 minimum = ImGui::GetItemRectMin();
	const ImVec2 maximum = ImGui::GetItemRectMax();
	const float rounding = ImGui::GetStyle().FrameRounding;
	ImDrawList* draw = ImGui::GetWindowDrawList();
	ImVec4 edge = accent;
	edge.w *= 0.72f;
	draw->AddRect(
		ImVec2(minimum.x + 1.0f * scale, minimum.y + 1.0f * scale),
		ImVec2(maximum.x - 1.0f * scale, maximum.y - 1.0f * scale),
		ImGui::GetColorU32(edge), rounding - 1.0f * scale,
		0, 1.0f * scale);
	ImVec4 sheen = accent;
	sheen.w = 0.28f;
	draw->AddLine(
		ImVec2(minimum.x + rounding, minimum.y + 1.0f * scale),
		ImVec2(maximum.x - rounding, minimum.y + 1.0f * scale),
		ImGui::GetColorU32(sheen), 1.0f * scale);
}

bool toggle_switch(
		const char* id,
		bool& value,
		const bool enabled,
		const float scale,
		bool* focused = nullptr) {
	const ImVec2 size(48.0f * scale, 27.0f * scale);
	ImGui::PushID(id);
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
	ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, size.y * 0.5f);
	ImGui::BeginDisabled(!enabled);
	const bool pressed = ImGui::Button("##Control", size);
	const bool hovered = enabled && ImGui::IsItemHovered();
	const bool keyboard_focused = enabled && ImGui::IsItemFocused();
	const ImVec2 minimum = ImGui::GetItemRectMin();
	const ImVec2 maximum = ImGui::GetItemRectMax();
	ImGui::EndDisabled();
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(4);
	const bool keyboard_activation = enabled && keyboard_focused &&
		ImGui::IsKeyPressed(ImGuiKey_Space, false);
	const bool activated = enabled && (pressed || keyboard_activation);
	if (activated) value = !value;
	if (focused != nullptr) *focused = keyboard_focused;

	// Persist a tiny amount of visual state in the current window so the thumb
	// glides between positions without adding product-level state or timers.
	const ImGuiID animation_id = ImGui::GetID("##Animation");
	ImGuiStorage* storage = ImGui::GetStateStorage();
	const float target = value ? 1.0f : 0.0f;
	float position = storage->GetFloat(animation_id, target);
	const float response = 1.0f - std::exp(
		-24.0f * (std::max)(0.0f, ImGui::GetIO().DeltaTime));
	position += (target - position) * response;
	if (std::abs(target - position) < 0.002f) position = target;
	storage->SetFloat(animation_id, position);

	ImDrawList* draw = ImGui::GetWindowDrawList();
	const float radius = size.y * 0.5f;
	const ImVec4 track = value
		? (enabled ? ImVec4(0.13f, 0.46f, 0.91f, 1.0f)
		           : ImVec4(0.11f, 0.29f, 0.49f, 1.0f))
		: (enabled ? ImVec4(0.070f, 0.096f, 0.135f, 1.0f)
		           : ImVec4(0.055f, 0.073f, 0.100f, 1.0f));
	const ImVec4 edge = value
		? (enabled ? ImVec4(0.43f, 0.76f, 1.0f, 0.82f)
		           : ImVec4(0.31f, 0.53f, 0.72f, 0.72f))
		: ImVec4(0.28f, 0.34f, 0.43f, enabled ? 0.84f : 0.64f);
	draw->AddRectFilled(
		ImVec2(minimum.x, minimum.y + 2.0f * scale),
		ImVec2(maximum.x, maximum.y + 3.0f * scale),
		ImGui::GetColorU32(ImVec4(0.0f, 0.0f, 0.0f, 0.30f)), radius);
	draw->AddRectFilled(minimum, maximum, ImGui::GetColorU32(track), radius);
	draw->AddRect(
		minimum, maximum, ImGui::GetColorU32(edge), radius, 0, 1.0f * scale);
	draw->AddLine(
		ImVec2(minimum.x + radius, minimum.y + 1.0f * scale),
		ImVec2(maximum.x - radius, minimum.y + 1.0f * scale),
		ImGui::GetColorU32(ImVec4(0.86f, 0.94f, 1.0f, value ? 0.24f : 0.10f)),
		1.0f * scale);
	if (hovered) {
		draw->AddRect(
			ImVec2(minimum.x + 1.0f * scale, minimum.y + 1.0f * scale),
			ImVec2(maximum.x - 1.0f * scale, maximum.y - 1.0f * scale),
			ImGui::GetColorU32(ImVec4(0.68f, 0.86f, 1.0f, 0.30f)),
			radius, 0, 1.0f * scale);
	}
	const float thumb_radius = 10.0f * scale;
	const float thumb_x = minimum.x + radius +
		(maximum.x - minimum.x - 2.0f * radius) * position;
	const ImVec2 thumb_center(thumb_x, minimum.y + radius);
	draw->AddCircleFilled(
		ImVec2(thumb_center.x, thumb_center.y + 1.5f * scale),
		thumb_radius + 0.7f * scale,
		ImGui::GetColorU32(ImVec4(0.0f, 0.0f, 0.0f, 0.30f)));
	draw->AddCircleFilled(
		thumb_center, thumb_radius,
		ImGui::GetColorU32(enabled
			? ImVec4(0.96f, 0.98f, 1.0f, 1.0f)
			: ImVec4(0.67f, 0.72f, 0.79f, 1.0f)));
	draw->AddCircle(
		thumb_center, thumb_radius,
		ImGui::GetColorU32(ImVec4(0.13f, 0.19f, 0.27f, 0.42f)),
		0, 1.0f * scale);
	if (keyboard_focused) {
		draw->AddRect(
			ImVec2(minimum.x - 3.0f * scale, minimum.y - 3.0f * scale),
			ImVec2(maximum.x + 3.0f * scale, maximum.y + 3.0f * scale),
			ImGui::GetColorU32(ImVec4(0.48f, 0.78f, 1.0f, 0.92f)),
			radius + 3.0f * scale, 0, 1.5f * scale);
	}
	ImGui::PopID();
	return activated;
}

void posture_row(
		const char* title,
		const char* detail,
		const float scale,
		const bool active) {
	const ImVec2 origin = ImGui::GetCursorScreenPos();
	ImDrawList* draw = ImGui::GetWindowDrawList();
	const ImVec2 badge_min(origin.x, origin.y + 1.0f * scale);
	const ImVec2 badge_max(
		origin.x + 18.0f * scale, origin.y + 19.0f * scale);
	draw->AddRectFilled(
		badge_min, badge_max,
		ImGui::GetColorU32(active
			? ImVec4(0.08f, 0.27f, 0.22f, 0.92f)
			: ImVec4(0.08f, 0.18f, 0.31f, 0.92f)),
		6.0f * scale);
	draw->AddRect(
		badge_min, badge_max,
		ImGui::GetColorU32(active
			? ImVec4(0.35f, 0.94f, 0.69f, 0.52f)
			: ImVec4(0.40f, 0.72f, 1.00f, 0.52f)),
		6.0f * scale, 0, 1.0f * scale);
	const ImU32 indicator = ImGui::GetColorU32(active
		? ImVec4(0.42f, 0.96f, 0.72f, 1.0f)
		: ImVec4(0.46f, 0.76f, 1.00f, 1.0f));
	if (active) {
		draw->AddLine(
			ImVec2(origin.x + 4.5f * scale, origin.y + 10.0f * scale),
			ImVec2(origin.x + 7.8f * scale, origin.y + 13.0f * scale),
			indicator, 1.6f * scale);
		draw->AddLine(
			ImVec2(origin.x + 7.8f * scale, origin.y + 13.0f * scale),
			ImVec2(origin.x + 14.0f * scale, origin.y + 6.5f * scale),
			indicator, 1.6f * scale);
	} else {
		draw->AddCircleFilled(
			ImVec2(origin.x + 9.0f * scale, origin.y + 10.0f * scale),
			2.5f * scale, indicator);
	}
	ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 30.0f * scale);
	ImGui::TextUnformatted(title);
	float widest_title = ImGui::CalcTextSize("Protocol").x;
	widest_title = (std::max)(widest_title, ImGui::CalcTextSize("Provider").x);
	widest_title = (std::max)(widest_title, ImGui::CalcTextSize("Cipher").x);
	widest_title = (std::max)(widest_title, ImGui::CalcTextSize("Key lifecycle").x);
	const float detail_screen_x = origin.x + 30.0f * scale +
		widest_title + 16.0f * scale;
	ImGui::SameLine(detail_screen_x - ImGui::GetWindowPos().x);
	ImGui::TextDisabled("%s", detail);
	ImGui::Dummy(ImVec2(0.0f, 3.0f * scale));
}

ImVec4 activity_line_color(const std::string& line) noexcept {
	if (line.find("[!]") != std::string::npos ||
		line.find("FAIL") != std::string::npos) {
		return ImVec4(1.00f, 0.56f, 0.48f, 1.0f);
	}
	if (line.find("[PASS]") != std::string::npos ||
		line.find("ready") != std::string::npos ||
		line.find("connected") != std::string::npos ||
		line.find("rotated") != std::string::npos) {
		return ImVec4(0.42f, 0.88f, 0.66f, 1.0f);
	}
	return ImVec4(0.36f, 0.67f, 1.00f, 1.0f);
}

std::string_view activity_timestamp(const std::string& line) noexcept {
	const std::string_view view(line);
	if (view.empty() || view.front() != '[') return {};
	const std::size_t closing = view.find(']');
	if (closing == std::string_view::npos || closing > 12U) return {};
	return view.substr(0U, closing + 1U);
}

std::string_view activity_message(const std::string& line) noexcept {
	std::string_view view(line);
	const std::string_view timestamp = activity_timestamp(line);
	if (!timestamp.empty()) view.remove_prefix(timestamp.size());
	while (!view.empty() && view.front() == ' ') view.remove_prefix(1U);
	constexpr std::array<std::string_view, 6> prefixes{{
		"[PASS] ", "[System] ", "[Network] ", "[Security] ", "[Session] ", "[*] "
	}};
	for (const std::string_view prefix : prefixes) {
		if (view.starts_with(prefix)) {
			view.remove_prefix(prefix.size());
			break;
		}
	}
	if (view.starts_with("[!] ")) view.remove_prefix(4U);
	return view;
}

#ifdef TRUETUNNEL_GUI_VISUAL_TEST
enum class VisualContentTarget {
	Top,
	Network,
	Secret,
	Activity,
	Recovery,
	Bottom
};

struct BackBufferCaptureStats {
	UINT width{0U};
	UINT height{0U};
	std::uint8_t minimum_luma{255U};
	std::uint8_t maximum_luma{0U};
};

struct VisualCaptureCase {
	const wchar_t* filename;
	const char* label;
	int role;
	int transport;
	VpnDaemon::State daemon_state;
	int logical_width;
	int logical_height;
	VisualContentTarget content_target;
	float content_scroll_ratio;
	float activity_scroll_ratio;
	bool require_content_scroll;
	bool require_activity_scroll;
	UiErrorField validation_field;
	const char* validation_error;
	bool focus_endpoint;
	bool open_help;
	bool open_disconnect;
	bool tab_endpoint_to_port;
	bool activate_primary_with_keyboard;
	bool dismiss_help_with_escape;
	int connection_phase;
	bool recovery_enabled;
	bool activate_recovery_with_keyboard;
	bool attempt_locked_configuration;
	const char* server_address_override;
	bool capture_full_viewport;
};

constexpr VisualCaptureCase visual_case(
		const wchar_t* filename,
		const char* label,
		const int role,
		const int transport,
		const VpnDaemon::State daemon_state,
		const int logical_width = 1180,
		const int logical_height = 820,
		const VisualContentTarget content_target = VisualContentTarget::Top,
		const float content_scroll_ratio = 0.0f,
		const float activity_scroll_ratio = 0.0f,
		const bool require_content_scroll = false,
		const bool require_activity_scroll = false,
		const UiErrorField validation_field = UiErrorField::None,
		const char* validation_error = nullptr,
		const bool focus_endpoint = false,
		const bool open_help = false,
		const bool open_disconnect = false,
		const bool tab_endpoint_to_port = false,
		const bool activate_primary_with_keyboard = false,
		const bool dismiss_help_with_escape = false,
		const int connection_phase = -1,
		const bool recovery_enabled = false,
		const bool activate_recovery_with_keyboard = false,
		const bool attempt_locked_configuration = false,
		const char* server_address_override = nullptr,
		const bool capture_full_viewport = false) noexcept {
	return {
		filename, label, role, transport, daemon_state,
		logical_width, logical_height, content_target,
		content_scroll_ratio, activity_scroll_ratio,
		require_content_scroll, require_activity_scroll,
		validation_field, validation_error, focus_endpoint,
		open_help, open_disconnect, tab_endpoint_to_port,
		activate_primary_with_keyboard, dismiss_help_with_escape,
		connection_phase, recovery_enabled, activate_recovery_with_keyboard,
		attempt_locked_configuration, server_address_override,
		capture_full_viewport
	};
}

constexpr std::array<VisualCaptureCase, 33> kVisualCaptureCases{{
	visual_case(L"01-server-tcp-overview.png", "server TCP desktop",
		0, 0, VpnDaemon::State::Idle),
	visual_case(L"02-server-udp-overview.png", "server UDP desktop",
		0, 1, VpnDaemon::State::Idle),
	visual_case(L"03-client-tcp-overview.png", "client TCP desktop",
		1, 0, VpnDaemon::State::Idle),
	visual_case(L"04-client-udp-log-bottom.png", "client UDP activity bottom",
		1, 1, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 1.0f, false, true),
	visual_case(L"05-client-udp-connected.png", "connected client action state",
		1, 1, VpnDaemon::State::Running, 1180, 820,
		VisualContentTarget::Top, 0.0f, 1.0f, false, true),
	visual_case(L"06-medium-client-activity.png", "medium-width activity section",
		1, 1, VpnDaemon::State::Idle, 1020, 820,
		VisualContentTarget::Activity, 0.0f, 1.0f, true, true),
	visual_case(L"07-compact-client-connection.png", "compact connection section",
		1, 1, VpnDaemon::State::Idle, 780, 700,
		VisualContentTarget::Top, 0.0f, 0.0f, true),
	visual_case(L"08-compact-client-network.png", "compact network card",
		1, 1, VpnDaemon::State::Idle, 780, 700,
		VisualContentTarget::Network, 0.0f, 0.0f, true),
	visual_case(L"09-compact-client-secret.png", "compact credentials card",
		1, 1, VpnDaemon::State::Idle, 780, 700,
		VisualContentTarget::Secret, 0.0f, 0.0f, true),
	visual_case(L"10-compact-client-activity.png", "compact activity card",
		1, 1, VpnDaemon::State::Running, 780, 700,
		VisualContentTarget::Activity, 0.0f, 0.72f, true, true),
	visual_case(L"11-compact-client-bottom.png", "compact security card",
		1, 1, VpnDaemon::State::Idle, 780, 700,
		VisualContentTarget::Bottom, 1.0f, 1.0f, true, true),
	visual_case(L"12-validation-address.png", "focused server-address validation",
		1, 1, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::Endpoint, "Enter the server address.", true),
	visual_case(L"13-validation-port.png", "port validation",
		1, 1, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::Port, "Enter a port from 1 to 65535."),
	visual_case(L"14-validation-secret.png", "shared-secret validation",
		1, 1, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::SharedSecret,
		"The shared key must be exactly 43 characters (a generated 256-bit key)."),
	visual_case(L"15-validation-adapter.png", "network-adapter validation",
		1, 1, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::Adapter, "Select an available physical network adapter."),
	visual_case(L"16-start-failure.png", "daemon start failure",
		1, 1, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::General,
		"The tunnel could not start. Check Activity for details."),
	visual_case(L"17-help.png", "connection help modal",
		1, 1, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::None, nullptr, false, true),
	visual_case(L"18-client-connecting.png", "connecting action state",
		1, 1, VpnDaemon::State::Starting),
	visual_case(L"19-client-stopping.png", "stopping action state",
		1, 1, VpnDaemon::State::Stopping),
	visual_case(L"20-disconnect-confirmation.png", "disconnect confirmation modal",
		1, 1, VpnDaemon::State::Running, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::None, nullptr, false, false, true),
	visual_case(L"21-keyboard-tab-order.png", "keyboard Tab moves endpoint to port",
		1, 1, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::None, nullptr, true, false, false, true),
	visual_case(L"22-keyboard-primary-action.png", "keyboard Enter activates primary action",
		1, 1, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::None, nullptr, false, false, false, false, true),
	visual_case(L"23-keyboard-escape-dialog.png", "keyboard Escape dismisses Help",
		1, 1, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::None, nullptr, false, true, false, false, false, true),
	visual_case(L"24-client-recovery-enabled.png", "client automatic recovery enabled",
		1, 0, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::None, nullptr, false, false, false, false, false, false, 0, true),
	visual_case(L"25-client-reconnecting.png", "client reconnecting status",
		1, 0, VpnDaemon::State::Running, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::None, nullptr, false, false, false, false, false, false, 3, true),
	visual_case(L"26-compact-client-recovery.png", "compact recovery settings",
		1, 1, VpnDaemon::State::Idle, 780, 700,
		VisualContentTarget::Recovery, 0.0f, 0.0f, true, false,
		UiErrorField::None, nullptr, false, false, false, false, false, false, 0, true),
	visual_case(L"27-compact-client-reconnecting.png", "compact reconnecting status",
		1, 1, VpnDaemon::State::Running, 780, 700,
		VisualContentTarget::Recovery, 0.0f, 0.0f, true, false,
		UiErrorField::None, nullptr, false, false, false, false, false, false, 3, true),
	visual_case(L"28-client-recovery-connected.png", "armed recovery on a connected client",
		1, 1, VpnDaemon::State::Running, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::None, nullptr, false, false, false, false, false, false, 2, true),
	visual_case(L"29-keyboard-recovery-toggle.png", "keyboard Space toggles recovery",
		1, 0, VpnDaemon::State::Idle, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::None, nullptr, false, false, false, false, false, false, 0, false, true),
	visual_case(L"30-keyboard-locked-recovery.png", "keyboard cannot change locked recovery",
		1, 1, VpnDaemon::State::Running, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::None, nullptr, false, false, false, false, false, false, 2, false, true),
	visual_case(L"31-locked-configuration.png", "active configuration rejects input",
		1, 1, VpnDaemon::State::Running, 1180, 820,
		VisualContentTarget::Top, 0.0f, 0.0f, false, false,
		UiErrorField::None, nullptr, false, false, false, false, false, false, 2, false, false, true),
	visual_case(L"32-minimum-window-recovery.png", "minimum supported window",
		1, 1, VpnDaemon::State::Idle, 760, 640,
		VisualContentTarget::Recovery, 0.0f, 0.0f, true, false,
		UiErrorField::None, nullptr, false, false, false, false, false, false, 0, true),
	visual_case(L"33-minimum-long-hostname.png", "minimum window long endpoint",
		1, 1, VpnDaemon::State::Idle, 760, 640,
		VisualContentTarget::Recovery, 0.0f, 0.0f, true, false,
		UiErrorField::None, nullptr, false, false, false, false, false, false,
		0, true, false, false,
		"vpn-gateway-012345678901234567890123456789012345678901x.example", true),
}};

bool process_is_elevated() noexcept {
	HANDLE token = nullptr;
	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
		return true; // Fail closed: the visual test must prove it is unelevated.
	}
	TOKEN_ELEVATION elevation{};
	DWORD returned = 0U;
	const bool queried = ::GetTokenInformation(
		token, TokenElevation, &elevation,
		static_cast<DWORD>(sizeof(elevation)), &returned) != FALSE;
	::CloseHandle(token);
	return !queried || elevation.TokenIsElevated != 0U;
}

bool capture_back_buffer_png(
	const std::filesystem::path& path,
	BackBufferCaptureStats& stats,
	const RECT* capture_region = nullptr) noexcept;
#endif

class ScopedComInitialization final {
public:
	explicit ScopedComInitialization(const bool enabled) noexcept {
		if (!enabled) {
			usable_ = true;
			return;
		}
		const HRESULT result = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
		usable_ = SUCCEEDED(result) || result == RPC_E_CHANGED_MODE;
		uninitialize_ = SUCCEEDED(result);
	}

	ScopedComInitialization(const ScopedComInitialization&) = delete;
	ScopedComInitialization& operator=(const ScopedComInitialization&) = delete;
	~ScopedComInitialization() {
		if (uninitialize_) ::CoUninitialize();
	}

	[[nodiscard]] bool usable() const noexcept { return usable_; }

private:
	bool usable_{false};
	bool uninitialize_{false};
};

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
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
	HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

void CleanupDeviceD3D();

bool CreateRenderTarget();

void CleanupRenderTarget();

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001
#define ID_TRAY_RESTORE 1002

NOTIFYICONDATA nid = {};
HMENU h_tray_menu = nullptr;
bool in_tray = false;


// Main code
int WINAPI WinMain(_In_ HINSTANCE hInstance,
                   _In_opt_ HINSTANCE,
                   _In_ LPSTR,
                   _In_ int) {
	GuiSmokeOptions gui_smoke_options = parse_gui_smoke_options();
	std::filesystem::path visual_output_directory;
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
	const auto module_directory = executable_directory();
	if (!module_directory) return 1;
	visual_output_directory = *module_directory / L"gui-visual-test";
	try {
		std::filesystem::create_directories(visual_output_directory);
		for (const auto& entry :
				std::filesystem::directory_iterator(visual_output_directory)) {
			if (entry.is_regular_file() && entry.path().extension() == L".png") {
				std::filesystem::remove(entry.path());
			}
		}
	} catch (...) {
		return 1;
	}
	gui_smoke_options.enabled = true;
	gui_smoke_options.valid = true;
	gui_smoke_options.log_path =
		visual_output_directory / L"gui-visual-test.log";
#endif
	const bool gui_smoke_test = gui_smoke_options.enabled;
	bool gui_smoke_failed = false;
	std::size_t rendered_smoke_frames = 0U;
	bool smoke_connect_rendered = false;
	bool smoke_disconnect_rendered = false;
	bool smoke_password_rendered = false;
	bool smoke_regenerate_rendered = false;
	bool smoke_transport_rendered = false;
	bool smoke_cipher_rendered = false;
	bool smoke_message_rendered = false;
	bool smoke_recovery_rendered = false;
	bool smoke_main_panel_visible = false;
	const auto gui_smoke_deadline = std::chrono::steady_clock::now() +
		std::chrono::seconds(kGuiVisualTestBuild ? 45 : 10);
	ScopedComInitialization visual_com(kGuiVisualTestBuild);

	if (gui_smoke_test) {
		if (!gui_smoke_options.valid || !visual_com.usable() ||
		    !open_gui_smoke_log(gui_smoke_options.log_path)) {
			return 1;
		}
		append_log("[SMOKE] GUI smoke log initialized");
	} else if (!gui_smoke_options.valid) {
		return 1;
	}

#ifdef TRUETUNNEL_GUI_VISUAL_TEST
	if (process_is_elevated()) {
		append_visual_report("[VISUAL] FAIL: visual-test process is elevated");
		close_gui_smoke_log();
		return 1;
	}
	append_visual_report("[VISUAL] PASS: process is unelevated; no UAC is required");
#endif

	// Create application window
	// Match Dear ImGui's official Win32 example: opt into per-monitor DPI
	// awareness before creating the HWND, then scale both style and fonts.
	ImGui_ImplWin32_EnableDpiAwareness();
	HICON h_icon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_VPN_ICON));
	HICON h_icon_small = (HICON) LoadImage(hInstance, MAKEINTRESOURCE(IDI_VPN_ICON),
	                                       IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);

	WNDCLASSEXW wc = {
		sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
		hInstance, h_icon, LoadCursor(nullptr, IDC_ARROW),
		nullptr, nullptr, L"TrueTunnel VPN", h_icon_small
	};
	if (::RegisterClassExW(&wc) == 0) return 1;
	HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"TrueTunnel VPN", WS_OVERLAPPEDWINDOW,
	                            CW_USEDEFAULT, CW_USEDEFAULT, 1180, 820,
	                            nullptr, nullptr, wc.hInstance, nullptr);
	if (hwnd == nullptr) {
		::UnregisterClassW(wc.lpszClassName, wc.hInstance);
		return 1;
	}
	const UINT window_dpi = (std::max)(96U, ::GetDpiForWindow(hwnd));
	g_ui_scale = static_cast<float>(window_dpi) / 96.0f;
	if (!resize_client_area(hwnd, 1180, 820, g_ui_scale)) {
		::DestroyWindow(hwnd);
		::UnregisterClassW(wc.lpszClassName, wc.hInstance);
		return 1;
	}
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
	if (!apply_dark_window_frame(hwnd)) {
		append_visual_report("[VISUAL] FAIL: Windows rejected dark title-bar styling");
		close_gui_smoke_log();
		::DestroyWindow(hwnd);
		::UnregisterClassW(wc.lpszClassName, wc.hInstance);
		return 1;
	}
	append_visual_report("[VISUAL] PASS: dark native title-bar styling applied");
#else
	(void)apply_dark_window_frame(hwnd);
#endif

	// Improve timer granularity for lower end-to-end latency
	ScopedTimerResolution timer_res(1);

#ifdef TRUETUNNEL_GUI_VISUAL_TEST
	real_adapters_ = {{"Ethernet", "Intel Ethernet Controller", "192.0.2.20", 1U}};
	adapter_labels_ = {"Ethernet  -  Intel Ethernet Controller"};
	adapter_cstrs_ = {adapter_labels_.front().c_str()};
	current_adapter_idx_ = 0;
	if (g_vpn_daemon) {
		append_visual_report("[VISUAL] FAIL: preview constructed the VPN daemon");
		close_gui_smoke_log();
		::DestroyWindow(hwnd);
		::UnregisterClassW(wc.lpszClassName, wc.hInstance);
		return 1;
	}
	append_visual_report("[VISUAL] PASS: VPN daemon and network setup are disabled");
#else
	populate_real_adapters();
	ensure_daemon();
#endif
	SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM) h_icon);
	SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM) h_icon_small);


	// Initialize Direct3D
	if (!CreateDeviceD3D(hwnd)) {
		if (gui_smoke_test) append_log("[SMOKE] D3D initialization: FAIL");
		CleanupDeviceD3D();
		::DestroyWindow(hwnd);
		::UnregisterClassW(wc.lpszClassName, wc.hInstance);
		return 1;
	}
	if (gui_smoke_test) append_log("[SMOKE] D3D initialization: PASS");

	// Show the window
	::ShowWindow(hwnd, kGuiVisualTestBuild ? SW_SHOWNOACTIVATE : SW_SHOWDEFAULT);
	::UpdateWindow(hwnd);

	// Setup Dear ImGui context
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	const bool imgui_context_ok = ImGui::GetCurrentContext() != nullptr;
	if (gui_smoke_test) {
		append_log(std::string("[SMOKE] ImGui context: ") +
		           (imgui_context_ok ? "PASS" : "FAIL"));
	}
	if (!imgui_context_ok) {
		CleanupDeviceD3D();
		::DestroyWindow(hwnd);
		::UnregisterClassW(wc.lpszClassName, wc.hInstance);
		return 1;
	}
	ImGuiIO &io = ImGui::GetIO();
	io.IniFilename = nullptr;
	io.Framerate = 60.0f;
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;

	// Setup Platform/Renderer backends
	const bool win32_backend_ok = ImGui_ImplWin32_Init(hwnd);
	const bool dx11_backend_ok = ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
	if (gui_smoke_test) {
		append_log(std::string("[SMOKE] ImGui Win32 backend: ") +
		           (win32_backend_ok ? "PASS" : "FAIL"));
		append_log(std::string("[SMOKE] ImGui DX11 backend: ") +
		           (dx11_backend_ok ? "PASS" : "FAIL"));
	}
	if (!win32_backend_ok || !dx11_backend_ok) {
		if (dx11_backend_ok) ImGui_ImplDX11_Shutdown();
		if (win32_backend_ok) ImGui_ImplWin32_Shutdown();
		ImGui::DestroyContext();
		CleanupDeviceD3D();
		::DestroyWindow(hwnd);
		::UnregisterClassW(wc.lpszClassName, wc.hInstance);
		return 1;
	}

	ImGuiStyleManager style_mgr;
	style_mgr.ApplyCustomDarkTheme(g_ui_scale);
	GuiFonts fonts = load_gui_fonts(style_mgr, g_ui_scale);
	ImVec4 clear_color = style_mgr.GetClearColor();

	SharedSecretBuffer password{};
	bool password_generated = generate_shared_secret(password);
	SecretClipboardLease secret_clipboard;
	const bool secret_invariants_ok =
		password_generated && shared_secret_invariants_hold(password);
	if (gui_smoke_test) {
		append_log(std::string("[SMOKE] generated secret invariant: ") +
		           (secret_invariants_ok ? "PASS" : "FAIL"));
		if (!secret_invariants_ok) gui_smoke_failed = true;
	}
	if (!password_generated) {
		append_log("[!] Windows CSPRNG failed; shared key is empty");
	}

	char mode[16] = "server";
	char port[16] = "5555";
	char local_ip[64] = "will decide of type choice";
	char adapter_name[64] = "TrueTunnel VPN Adapter";
	char subnet_mask[64] = "will decide of type choice";
	char gateway[64] = "will decide of type choice";
	char server_address[64] = "";
	constexpr const char* mode_options[] = {"server", "client"};
	constexpr const char* mode_labels[] = {"Server", "Client"};
	int selected_mode = 0;
	constexpr const char* transport_labels[] = {"TCP", "UDP"};
	int selected_transport = 0;
	char message_input[256] = "";
	ConnectionRecoveryOptions recovery_options{};
	#ifndef TRUETUNNEL_GUI_VISUAL_TEST
	if (gui_smoke_test) {
		// Exercise the optional client-only recovery surface in the shipping
		// executable without creating a tunnel or requiring elevation.
		selected_mode = 1;
		strncpy_s(mode, mode_options[selected_mode], sizeof(mode) - 1U);
		recovery_options.enabled = true;
	}
	#endif
	bool auto_scroll = true;
	int last_log_length = 0;
	bool focus_message_input = false;
	float requested_content_scroll_ratio = -1.0f;
	float requested_activity_scroll_ratio = -1.0f;
	std::string ui_error;
	UiErrorField ui_error_field = UiErrorField::None;
	const auto clear_ui_error = [&ui_error, &ui_error_field]() noexcept {
		ui_error.clear();
		ui_error_field = UiErrorField::None;
	};
	[[maybe_unused]] GuiRenderMetrics render_metrics{};

#ifdef TRUETUNNEL_GUI_VISUAL_TEST
	auto_scroll = false;
	VpnDaemon::State visual_daemon_state = VpnDaemon::State::Idle;
	VisualContentTarget visual_content_target = VisualContentTarget::Top;
	bool visual_help_open = false;
	bool visual_disconnect_open = false;
	bool visual_focus_endpoint = false;
	bool visual_tab_endpoint_to_port = false;
	bool visual_activate_primary_with_keyboard = false;
	bool visual_activate_recovery_with_keyboard = false;
	bool visual_attempt_locked_configuration = false;
	bool visual_dismiss_help_with_escape = false;
	bool visual_help_popup_opened_once = false;
	bool visual_help_was_visible = false;
	bool visual_keyboard_primary_activated = false;
	bool visual_keyboard_recovery_activated = false;
	bool visual_locked_endpoint_activated = false;
	unsigned int visual_input_stage = 0U;
	bool visual_focus_reset_pending = false;
	ConnectionStatus visual_connection_status{};
	strncpy_s(server_address, "vpn.example.net", sizeof(server_address) - 1U);
	clear_logs();
	constexpr std::array<const char*, 18> visual_activity{{
		"[System] Configuration ready",
		"[Network] Ethernet selected",
		"[Network] Virtual adapter identity verified",
		"[Security] Secure transport profile loaded",
		"[Session] Secure endpoint ready on port 5555",
		"[Session] Peer handshake started",
		"[Session] Peer authenticated",
		"[Session] Tunnel connected",
		"[Network] IPv4 route installed",
		"[Network] Encrypted data path active",
		"[Security] Traffic key rotated",
		"[Session] Keepalive acknowledged",
		"[Network] 24 packets sent",
		"[Network] 19 packets received",
		"[Session] Peer latency 4 ms",
		"[Security] Replay window healthy",
		"[Session] Session policy loaded",
		"[System] Ready",
	}};
	std::size_t visual_case_index = 0U;
	std::size_t visual_settle_frames = 0U;
	bool visual_case_configured = false;
#endif

	// Main loop
	bool done = false;
	while (!done) {
		if (gui_smoke_test &&
		    std::chrono::steady_clock::now() >= gui_smoke_deadline) {
			append_log("[SMOKE] FAIL: GUI test deadline exceeded");
			gui_smoke_failed = true;
			done = true;
		}

#ifdef TRUETUNNEL_GUI_VISUAL_TEST
		if (!done && !visual_case_configured &&
			visual_case_index < kVisualCaptureCases.size()) {
			const VisualCaptureCase& capture_case =
				kVisualCaptureCases[visual_case_index];
			selected_mode = capture_case.role;
			selected_transport = capture_case.transport;
			visual_daemon_state = capture_case.daemon_state;
			recovery_options = {};
			recovery_options.enabled = capture_case.recovery_enabled;
			visual_connection_status = {};
			visual_connection_status.phase = capture_case.connection_phase >= 0
				? static_cast<ConnectionPhase>(capture_case.connection_phase)
				: (capture_case.daemon_state == VpnDaemon::State::Starting
					? ConnectionPhase::Connecting
					: capture_case.daemon_state == VpnDaemon::State::Running
						? (capture_case.role == 0
							? ConnectionPhase::Listening : ConnectionPhase::Connected)
						: ConnectionPhase::Idle);
			if (visual_connection_status.phase == ConnectionPhase::Reconnecting) {
				visual_connection_status.retry_attempt = 2U;
				visual_connection_status.retry_delay = std::chrono::seconds{4};
			}
			visual_content_target = capture_case.content_target;
			visual_help_open = capture_case.open_help;
			visual_disconnect_open = capture_case.open_disconnect;
			visual_focus_endpoint = capture_case.focus_endpoint;
			visual_tab_endpoint_to_port = capture_case.tab_endpoint_to_port;
			visual_activate_primary_with_keyboard =
				capture_case.activate_primary_with_keyboard;
			visual_activate_recovery_with_keyboard =
				capture_case.activate_recovery_with_keyboard;
			visual_attempt_locked_configuration =
				capture_case.attempt_locked_configuration;
			visual_dismiss_help_with_escape =
				capture_case.dismiss_help_with_escape;
			visual_help_popup_opened_once = false;
			visual_help_was_visible = false;
			visual_keyboard_primary_activated = false;
			visual_keyboard_recovery_activated = false;
			visual_locked_endpoint_activated = false;
			visual_input_stage = 0U;
			visual_focus_reset_pending = true;
			ui_error = capture_case.validation_error == nullptr
				? std::string{} : capture_case.validation_error;
			ui_error_field = capture_case.validation_field;
			clear_logs();
			if (capture_case.validation_field == UiErrorField::General) {
				append_log("[System] Connect requested");
				append_log("[Network] Preparing the virtual adapter");
				append_log(kSessionStartFailureLog);
			} else {
				if (visual_connection_status.phase == ConnectionPhase::Reconnecting) {
					append_log("[Session] Heartbeat timeout · retry scheduled in 4s");
				}
				for (const char* entry : visual_activity) append_log(entry);
			}
			strncpy_s(mode, mode_options[selected_mode], sizeof(mode) - 1U);
			strncpy_s(port, "5555", sizeof(port) - 1U);
			current_adapter_idx_ = capture_case.validation_field == UiErrorField::Adapter
				? -1 : 0;
			if (capture_case.validation_field == UiErrorField::Endpoint) {
				server_address[0] = '\0';
			} else if (capture_case.server_address_override != nullptr) {
				strncpy_s(
					server_address, capture_case.server_address_override,
					sizeof(server_address) - 1U);
			} else {
				strncpy_s(
					server_address, "vpn.example.net",
					sizeof(server_address) - 1U);
			}
			if (capture_case.validation_field == UiErrorField::Port) {
				strncpy_s(port, "70000", sizeof(port) - 1U);
			}
			if (capture_case.validation_field == UiErrorField::SharedSecret) {
				password.fill('\0');
				strncpy_s(password.data(), password.size(), "short", 5U);
				password_generated = false;
			} else {
				password_generated = generate_shared_secret(password);
				if (!password_generated) {
					append_visual_report(
						"[VISUAL] FAIL: could not refresh the scripted shared key");
					gui_smoke_failed = true;
					done = true;
				}
			}
			if (visual_daemon_state == VpnDaemon::State::Running) {
				strncpy_s(message_input, "Status check", sizeof(message_input) - 1U);
			} else {
				message_input[0] = '\0';
			}
			requested_content_scroll_ratio =
				capture_case.content_scroll_ratio;
			requested_activity_scroll_ratio =
				capture_case.activity_scroll_ratio;
			if (!resize_client_area(
					hwnd,
					capture_case.logical_width,
					capture_case.logical_height,
					g_ui_scale)) {
				append_visual_report("[VISUAL] FAIL: could not resize the capture viewport");
				gui_smoke_failed = true;
				done = true;
			} else {
				visual_settle_frames = 0U;
				visual_case_configured = true;
				append_visual_report(
					std::string("[VISUAL] Preparing ") + capture_case.label);
			}
		}
#endif

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
		secret_clipboard.clear_if_expired(hwnd);

		// Handle window being minimized or screen locked
		if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED) {
			::Sleep(10);
			continue;
		}
		g_SwapChainOccluded = false;

		// Handle window resize (we don't resize directly in the WM_SIZE handler)
		if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
			CleanupRenderTarget();
			const HRESULT resize_result = g_pSwapChain->ResizeBuffers(
				0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
			g_ResizeWidth = g_ResizeHeight = 0;
			if (FAILED(resize_result) || !CreateRenderTarget()) {
				append_log("[!] Direct3D swap-chain resize failed");
				gui_smoke_failed = true;
				done = true;
				continue;
			}
		}
		if (g_pending_dpi != 0U) {
			const UINT pending_dpi = g_pending_dpi;
			g_pending_dpi = 0U;
			const float pending_scale =
				static_cast<float>((std::max)(96U, pending_dpi)) / 96.0f;
			if (std::abs(pending_scale - g_ui_scale) > 0.001f) {
				g_ui_scale = pending_scale;
				ImGui_ImplDX11_InvalidateDeviceObjects();
				style_mgr.ApplyCustomDarkTheme(g_ui_scale);
				fonts = load_gui_fonts(style_mgr, g_ui_scale);
				clear_color = style_mgr.GetClearColor();
				if (!ImGui_ImplDX11_CreateDeviceObjects()) {
					append_log("[!] Could not rebuild fonts after a DPI change");
					gui_smoke_failed = true;
					done = true;
					continue;
				}
			}
		}

		// Start the Dear ImGui frame
		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
		if (visual_focus_reset_pending) {
			io.AddMousePosEvent(
				-std::numeric_limits<float>::max(),
				-std::numeric_limits<float>::max());
			io.AddMouseButtonEvent(0, false);
		}
		// Feed Dear ImGui's normal input queue after the Win32 backend update, so
		// the test never moves the user's cursor. Pointer and keyboard press/release
		// events are split across frames and exercise normal widget navigation.
		if (!done && visual_case_configured && !visual_focus_reset_pending) {
			const VisualCaptureCase& capture_case =
				kVisualCaptureCases[visual_case_index];
			if (capture_case.attempt_locked_configuration) {
				if (visual_input_stage < 8U) {
					const unsigned int control_index = visual_input_stage / 2U;
					ImVec2 target{};
					bool available = false;
					switch (control_index) {
						case 0U:
							target = render_metrics.role_server_control_center;
							available = render_metrics.role_server_control_available;
							break;
						case 1U:
							target = render_metrics.transport_tcp_control_center;
							available = render_metrics.transport_tcp_control_available;
							break;
						case 2U:
							target = render_metrics.endpoint_input_center;
							available = render_metrics.endpoint_field.valid;
							break;
						case 3U:
							target = render_metrics.secret_action_center;
							available = render_metrics.secret_action_available;
							break;
						default:
							break;
					}
					if (available) {
						io.AddMouseSourceEvent(ImGuiMouseSource_Mouse);
						io.AddMousePosEvent(target.x, target.y);
						io.AddMouseButtonEvent(0, (visual_input_stage % 2U) == 0U);
						++visual_input_stage;
						visual_settle_frames = 0U;
					}
				} else if (visual_input_stage == 8U) {
					io.AddMousePosEvent(
						-std::numeric_limits<float>::max(),
						-std::numeric_limits<float>::max());
					visual_input_stage = 9U;
					visual_settle_frames = 0U;
				}
			} else if (capture_case.activate_recovery_with_keyboard) {
				if (visual_input_stage == 0U) {
					// Render the recovery switch with keyboard focus before sending
					// the standard Space press/release activation sequence.
					visual_input_stage = 1U;
					visual_settle_frames = 0U;
				} else if (visual_input_stage < 3U) {
					io.AddKeyEvent(
						ImGuiKey_Space, visual_input_stage == 1U);
					++visual_input_stage;
					visual_settle_frames = 0U;
				}
			} else if (capture_case.activate_primary_with_keyboard) {
				if (visual_input_stage == 0U) {
					// First render one frame with a keyboard-focus request on the
					// primary action, then deliver Enter through the input queue.
					visual_input_stage = 1U;
					visual_settle_frames = 0U;
				} else if (visual_input_stage < 3U) {
					io.AddKeyEvent(
						ImGuiKey_Enter, visual_input_stage == 1U);
					++visual_input_stage;
					visual_settle_frames = 0U;
				}
			} else {
				ImVec2 target{};
				bool available = false;
				if (capture_case.open_help) {
					target = render_metrics.help_button_center;
					available = render_metrics.help_button_available;
				} else if (capture_case.open_disconnect) {
					target = render_metrics.disconnect_button_center;
					available = render_metrics.disconnect_button_available;
				} else if (capture_case.focus_endpoint) {
					target = render_metrics.endpoint_input_center;
					available = render_metrics.endpoint_input_available;
				} else if (visual_input_stage < 2U) {
					visual_input_stage = 2U;
				}
				if (available && visual_input_stage < 2U) {
					io.AddMouseSourceEvent(ImGuiMouseSource_Mouse);
					io.AddMousePosEvent(target.x, target.y);
					io.AddMouseButtonEvent(0, visual_input_stage == 0U);
					++visual_input_stage;
					visual_settle_frames = 0U;
				}
				if (capture_case.tab_endpoint_to_port &&
					visual_input_stage >= 2U && visual_input_stage < 4U) {
					io.AddKeyEvent(ImGuiKey_Tab, visual_input_stage == 2U);
					++visual_input_stage;
					visual_settle_frames = 0U;
				}
				if (capture_case.dismiss_help_with_escape) {
					if (visual_input_stage == 2U && render_metrics.help_visible) {
						io.AddKeyEvent(ImGuiKey_Escape, true);
						visual_input_stage = 3U;
						visual_settle_frames = 0U;
					} else if (visual_input_stage == 3U) {
						io.AddKeyEvent(ImGuiKey_Escape, false);
						io.AddMousePosEvent(
							-std::numeric_limits<float>::max(),
							-std::numeric_limits<float>::max());
						visual_input_stage = 4U;
						visual_settle_frames = 0U;
					}
				}
			}
		}
#endif
		ImGui::NewFrame();
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
		if (visual_focus_reset_pending) {
			ImGui::ClearActiveID();
			visual_focus_reset_pending = false;
		}
#endif
		render_metrics.connect_action_visible = false;
		render_metrics.disconnect_action_visible = false;
		render_metrics.endpoint_focused = false;
		render_metrics.port_focused = false;
		render_metrics.primary_action_focused = false;
		render_metrics.validation_error_visible = false;
		render_metrics.activity_error_visible = false;
		render_metrics.help_visible = false;
		render_metrics.disconnect_confirmation_visible = false;
		render_metrics.partial_control_visible = false;
		render_metrics.partial_activity_row_visible = false;
		render_metrics.help_button_available = false;
		render_metrics.endpoint_input_available = false;
		render_metrics.disconnect_button_available = false;
		render_metrics.recovery_control_present = false;
		render_metrics.recovery_toggle_visible = false;
		render_metrics.recovery_toggle_enabled = false;
		render_metrics.recovery_toggle_focused = false;
		render_metrics.recovery_status_visible = false;
		render_metrics.configuration_controls_locked = false;
		render_metrics.secure_session_indicators_active = false;
		render_metrics.status_endpoint_port_visible = false;
		render_metrics.wide_layout = false;
		render_metrics.role_server_control_available = false;
		render_metrics.transport_tcp_control_available = false;
		render_metrics.secret_action_available = false;
		render_metrics.header_surface = {};
		render_metrics.help_button = {};
		render_metrics.status_card = {};
		render_metrics.status_context = {};
		render_metrics.status_endpoint = {};
		render_metrics.connection_card = {};
		render_metrics.recovery_card = {};
		render_metrics.endpoint_field = {};
		render_metrics.port_field = {};
		render_metrics.network_card = {};
		render_metrics.secret_card = {};
		render_metrics.activity_card = {};
		render_metrics.security_card = {};

		// The production executable and the unelevated visual test execute this
		// exact dashboard code. There is no screenshot-only replica.
		{
			const float scale = g_ui_scale;
			ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
			ImVec2 window_size = io.DisplaySize;
			RECT rect{};
			if (::GetClientRect(hwnd, &rect)) {
				window_size = ImVec2(static_cast<float>(rect.right), static_cast<float>(rect.bottom));
			}
			ImGui::SetNextWindowSize(window_size, ImGuiCond_Always);
			ImGui::PushStyleVar(
				ImGuiStyleVar_WindowPadding,
				ImVec2(24.0f * scale, 18.0f * scale));
			ImGui::PushStyleVar(
				ImGuiStyleVar_ItemSpacing,
				ImVec2(10.0f * scale, 9.0f * scale));

			const bool main_panel_visible = ImGui::Begin("##MainPanel", nullptr,
				ImGuiWindowFlags_NoTitleBar |
				ImGuiWindowFlags_NoResize |
				ImGuiWindowFlags_NoMove |
				ImGuiWindowFlags_NoCollapse |
				ImGuiWindowFlags_NoBringToFrontOnFocus |
				ImGuiWindowFlags_NoNavFocus |
				ImGuiWindowFlags_NoScrollbar |
				ImGuiWindowFlags_NoScrollWithMouse |
				ImGuiWindowFlags_NoSavedSettings |
				ImGuiWindowFlags_NoBackground);
			if (gui_smoke_test && main_panel_visible) smoke_main_panel_visible = true;
			if (main_panel_visible) {
				ImDrawList *canvas_draw = ImGui::GetWindowDrawList();
				const ImVec2 canvas_min = ImGui::GetWindowPos();
				const ImVec2 canvas_max = ImVec2(canvas_min.x + ImGui::GetWindowWidth(),
					canvas_min.y + ImGui::GetWindowHeight());
				// A low-contrast tonal field gives translucent surfaces depth without
				// competing with controls or reading as decorative product chrome.
				canvas_draw->AddRectFilledMultiColor(
					canvas_min, canvas_max,
					ImGui::GetColorU32(ImVec4(0.024f, 0.033f, 0.047f, 1.0f)),
					ImGui::GetColorU32(ImVec4(0.021f, 0.029f, 0.042f, 1.0f)),
					ImGui::GetColorU32(ImVec4(0.010f, 0.014f, 0.022f, 1.0f)),
					ImGui::GetColorU32(ImVec4(0.009f, 0.013f, 0.020f, 1.0f)));
			}

			const bool native_tcp = selected_transport == 0;
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
			const VpnDaemon::State daemon_state = visual_daemon_state;
#else
			const VpnDaemon::State daemon_state = g_vpn_daemon
				? g_vpn_daemon->state() : VpnDaemon::State::Idle;
#endif
			const bool is_idle = daemon_state == VpnDaemon::State::Idle;
			const bool is_running = daemon_state == VpnDaemon::State::Running;
			const bool is_starting = daemon_state == VpnDaemon::State::Starting;
			const bool is_stopping = daemon_state == VpnDaemon::State::Stopping;
			ConnectionStatus connection_status{};
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
			connection_status = visual_connection_status;
#else
			if (g_vpn_daemon) connection_status = g_vpn_daemon->connection_status();
#endif
			const bool is_connecting =
				connection_status.phase == ConnectionPhase::Connecting ||
				(is_starting && connection_status.phase == ConnectionPhase::Idle);
			const bool is_connected =
				connection_status.phase == ConnectionPhase::Connected;
			const bool is_reconnecting =
				connection_status.phase == ConnectionPhase::Reconnecting;
			const bool is_listening =
				connection_status.phase == ConnectionPhase::Listening;
			const bool configuration_locked = !is_idle;
			const bool secure_session_active = is_connected || is_listening;
			render_metrics.configuration_controls_locked = configuration_locked;
			render_metrics.secure_session_indicators_active = secure_session_active;
			ImVec4 state_color(0.58f, 0.66f, 0.77f, 1.0f);
			if (is_stopping) state_color = ImVec4(1.0f, 0.48f, 0.34f, 1.0f);
			else if (is_reconnecting) state_color = ImVec4(1.0f, 0.70f, 0.24f, 1.0f);
			else if (is_connected || is_listening) state_color = ImVec4(0.28f, 0.88f, 0.56f, 1.0f);
			else if (is_connecting || is_starting) state_color = ImVec4(1.0f, 0.78f, 0.26f, 1.0f);
			const bool has_general_error =
				!ui_error.empty() && ui_error_field == UiErrorField::General;
			if (has_general_error) {
				state_color = ImVec4(1.0f, 0.38f, 0.36f, 1.0f);
			}
			const bool is_server = selected_mode == 0;
			std::string status_detail_storage;
			const char* status_title = has_general_error
				? "Tunnel could not start"
				: is_stopping ? "Disconnecting"
				: is_reconnecting ? "Connection lost · retrying"
				: is_connected ? "Tunnel connected"
				: is_listening ? "Server listening"
				: is_connecting ? (is_server ? "Starting secure server" : "Connecting securely")
				: (is_server ? "Ready to listen" : "Ready to connect");
			if (has_general_error) {
				status_detail_storage = ui_error;
			} else if (is_stopping) {
				status_detail_storage = "Closing keys and network resources";
			} else if (is_reconnecting) {
				status_detail_storage = "Attempt " +
					std::to_string(connection_status.retry_attempt);
				if (connection_status.retry_delay.count() > 0) {
					const auto retry_seconds = (std::max)(1LL,
						(connection_status.retry_delay.count() + 999LL) / 1000LL);
					status_detail_storage += " · next retry in " +
						std::to_string(retry_seconds) + "s";
				} else {
					status_detail_storage += " · reconnecting now";
				}
			} else if (is_connected) {
				status_detail_storage = recovery_options.enabled
					? "Encrypted traffic is flowing · recovery is armed"
					: "Encrypted traffic is flowing";
			} else if (is_listening) {
				status_detail_storage = "Ready for an authenticated peer";
			} else if (is_connecting) {
				status_detail_storage = "Preparing the interface and secure session";
			} else {
				status_detail_storage = "No active tunnel";
			}
			const char* status_detail = status_detail_storage.c_str();
			const std::string endpoint_summary = is_server
				? std::string("All interfaces · port ") + port
				: server_address[0] == '\0'
					? std::string("Missing server address · port ") + port
					: std::string(server_address) + ":" + port;

			// A quiet application bar keeps identity and help available without
			// displacing the connection workflow with marketing copy.
			const float header_height = 54.0f * scale;
			const ImVec2 header_origin = ImGui::GetCursorScreenPos();
			draw_glass_surface(
				header_origin,
				ImVec2(ImGui::GetContentRegionAvail().x, header_height),
				ImVec4(0.30f, 0.66f, 1.0f, 1.0f), scale);
			ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
			ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 16.0f * scale);
			ImGui::PushStyleVar(
				ImGuiStyleVar_WindowPadding, ImVec2(10.0f * scale, 8.0f * scale));
			ImGui::BeginChild("##Header", ImVec2(0, header_height), false,
				ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
				ImGuiWindowFlags_NoBackground);
			draw_brand_mark(scale);
			ImGui::SameLine(0.0f, 12.0f * scale);
			ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 5.0f * scale);
			if (fonts.title != nullptr) ImGui::PushFont(fonts.title);
			ImGui::TextUnformatted("TrueTunnel");
			if (fonts.title != nullptr) ImGui::PopFont();
			const float title_right =
				ImGui::GetItemRectMax().x - ImGui::GetWindowPos().x;
			const float help_width = (std::max)(
				68.0f * scale,
				ImGui::CalcTextSize("Help").x + 28.0f * scale);
			const float help_x = (std::max)(
				title_right + 18.0f * scale,
				ImGui::GetWindowContentRegionMax().x - help_width);
			ImGui::SameLine(help_x);
			ImGui::SetCursorPosY(12.0f * scale);
			if (ImGui::Button("Help", ImVec2(help_width, 30.0f * scale))) {
				ImGui::OpenPopup("Connection help");
			}
			decorate_last_button_surface(
				scale, ImVec4(0.52f, 0.76f, 1.0f, 0.45f));
			render_metrics.help_button_available = ImGui::IsItemVisible();
			render_metrics.help_button_center = last_item_center();
			record_last_item_bounds(render_metrics.help_button);
			ImGui::EndChild();
			record_last_item_bounds(render_metrics.header_surface);
			ImGui::PopStyleVar(2);
			ImGui::PopStyleColor();

#ifdef TRUETUNNEL_GUI_VISUAL_TEST
			if (visual_help_open && visual_input_stage >= 2U &&
				!visual_help_popup_opened_once) {
				ImGui::OpenPopup("Connection help");
				visual_help_popup_opened_once = true;
			}
#endif
			ImGui::PushStyleColor(
				ImGuiCol_PopupBg, ImVec4(0.027f, 0.041f, 0.061f, 1.0f));
			ImGui::PushStyleColor(
				ImGuiCol_Border, ImVec4(0.35f, 0.52f, 0.72f, 0.88f));
			ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 1.0f * scale);
			ImGui::PushStyleVar(
				ImGuiStyleVar_WindowPadding, ImVec2(24.0f * scale, 20.0f * scale));
			ImGui::SetNextWindowPos(
				ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing,
				ImVec2(0.5f, 0.5f));
			if (ImGui::BeginPopupModal(
					"Connection help", nullptr,
					ImGuiWindowFlags_AlwaysAutoResize |
					ImGuiWindowFlags_NoSavedSettings)) {
			#ifdef TRUETUNNEL_GUI_VISUAL_TEST
				if (!visual_help_open) ImGui::CloseCurrentPopup();
			#endif
				render_metrics.help_visible = true;
				decorate_popup_surface(
					scale, ImVec4(0.30f, 0.66f, 1.0f, 1.0f));
				if (fonts.semibold != nullptr) ImGui::PushFont(fonts.semibold);
				ImGui::TextUnformatted("Before you connect");
				if (fonts.semibold != nullptr) ImGui::PopFont();
				ImGui::TextDisabled("A quick guide to the required settings.");
				ImGui::Separator();
				ImGui::Spacing();
				ImGui::BulletText("Server listens for an authenticated peer; Client connects to one.");
				ImGui::BulletText("Generate the shared key on Server, then paste it into Client.");
				ImGui::BulletText("Use TCP for reliable streams or UDP for latency-sensitive traffic.");
				ImGui::BulletText("Client recovery is optional: 5s heartbeat, 15s timeout, capped retry delay.");
				ImGui::BulletText("Minimize to keep TrueTunnel in the system tray.");
				if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
				if (ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
				ImGui::EndPopup();
			}
			ImGui::PopStyleVar(2);
			ImGui::PopStyleColor(2);

			// A compact command surface keeps status and the primary action visible.
			if (begin_card("##StatusCard", scale, true)) {
				if (ImGui::BeginTable(
						"##StatusLayout", 2,
						ImGuiTableFlags_SizingStretchProp |
						ImGuiTableFlags_NoSavedSettings)) {
					ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthStretch, 1.25f);
					ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthStretch, 1.0f);
					ImGui::TableNextRow();
					ImGui::TableSetColumnIndex(0);
					const ImVec2 status_pos = ImGui::GetCursorScreenPos();
					ImGui::GetWindowDrawList()->AddCircleFilled(
						ImVec2(status_pos.x + 6.0f * scale, status_pos.y + 12.0f * scale),
						5.0f * scale, ImGui::GetColorU32(state_color));
					ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 18.0f * scale);
					if (fonts.semibold != nullptr) ImGui::PushFont(fonts.semibold);
					ImGui::TextUnformatted(status_title);
					if (fonts.semibold != nullptr) ImGui::PopFont();
					if (has_general_error) {
						ImGui::PushStyleColor(
							ImGuiCol_Text, ImVec4(1.0f, 0.62f, 0.59f, 1.0f));
						ImGui::PushTextWrapPos(0.0f);
						ImGui::TextWrapped("%s", status_detail);
						ImGui::PopTextWrapPos();
						ImGui::PopStyleColor();
						render_metrics.validation_error_visible = ImGui::IsItemVisible();
					} else {
						ImGui::TextDisabled("%s", status_detail);
					}
					if (is_reconnecting && ImGui::IsItemVisible()) {
						render_metrics.recovery_status_visible = true;
					}

					ImGui::TableSetColumnIndex(1);
					const std::string status_context =
						std::string(mode_labels[selected_mode]) + " · " +
						transport_labels[selected_transport];
					const float summary_gap = 9.0f * scale;
					const float endpoint_width = (std::max)(
						1.0f,
						ImGui::GetContentRegionAvail().x -
							ImGui::CalcTextSize(status_context.c_str()).x - summary_gap);
					const std::string visible_endpoint =
						ellipsize_text_to_width(endpoint_summary, endpoint_width);
					const std::string expected_port_suffix = std::string(":") + port;
					render_metrics.status_endpoint_port_visible = is_server ||
						server_address[0] == '\0' ||
						(visible_endpoint.size() >= expected_port_suffix.size() &&
						 visible_endpoint.compare(
							visible_endpoint.size() - expected_port_suffix.size(),
							expected_port_suffix.size(), expected_port_suffix) == 0);
					ImGui::TextDisabled("%s", status_context.c_str());
					record_last_item_bounds(render_metrics.status_context);
					ImGui::SameLine(0.0f, summary_gap);
					ImGui::TextUnformatted(visible_endpoint.c_str());
					record_last_item_bounds(render_metrics.status_endpoint);
					if (visible_endpoint != endpoint_summary &&
						ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
						ImGui::SetTooltip("%s", endpoint_summary.c_str());
					}
					const float action_width = ImGui::GetContentRegionAvail().x;
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
					const bool connect_disabled = !is_idle;
#else
					const bool connect_disabled = !g_vpn_daemon || !is_idle;
#endif
					bool connect_clicked = false;
					bool disconnect_clicked = false;
					if (is_idle) {
						ImGui::BeginDisabled(connect_disabled);
						ImGui::PushStyleColor(
							ImGuiCol_Button, ImVec4(0.15f, 0.43f, 0.91f, 1.0f));
						ImGui::PushStyleColor(
							ImGuiCol_ButtonHovered, ImVec4(0.24f, 0.55f, 1.0f, 1.0f));
						ImGui::PushStyleColor(
							ImGuiCol_Border, ImVec4(0.34f, 0.58f, 0.82f, 0.70f));
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
						if (visual_activate_primary_with_keyboard &&
							visual_input_stage >= 1U &&
							!visual_keyboard_primary_activated) {
							ImGui::SetKeyboardFocusHere();
						}
#endif
						connect_clicked = ImGui::Button(
							is_server ? "Start server" : "Connect",
							ImVec2(action_width, 38.0f * scale));
						decorate_last_button_surface(
							scale, ImVec4(0.72f, 0.90f, 1.0f, 0.85f),
							!connect_disabled);
						render_metrics.connect_action_visible = ImGui::IsItemVisible();
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
						render_metrics.primary_action_focused = ImGui::IsItemFocused();
						if (visual_activate_primary_with_keyboard && connect_clicked) {
							visual_keyboard_primary_activated = true;
						}
#endif
						if (gui_smoke_test &&
							(!kGuiVisualTestBuild || ImGui::IsItemVisible())) {
							smoke_connect_rendered = true;
						}
						ImGui::PopStyleColor(3);
						ImGui::EndDisabled();
					} else {
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
						const bool can_disconnect = is_running || is_starting;
#else
						const bool can_disconnect =
							g_vpn_daemon && (is_running || is_starting);
#endif
						ImGui::BeginDisabled(!can_disconnect);
						ImGui::PushStyleColor(
							ImGuiCol_Button, ImVec4(0.090f, 0.145f, 0.230f, 0.96f));
						ImGui::PushStyleColor(
							ImGuiCol_ButtonHovered, ImVec4(0.58f, 0.20f, 0.24f, 0.96f));
						ImGui::PushStyleColor(
							ImGuiCol_ButtonActive, ImVec4(0.46f, 0.14f, 0.18f, 1.0f));
						disconnect_clicked = ImGui::Button(
							is_stopping ? "Disconnecting..."
							            : is_starting ? "Cancel connection"
							                          : "Disconnect",
							ImVec2(action_width, 38.0f * scale));
						decorate_last_button_surface(
							scale, ImVec4(0.50f, 0.69f, 0.92f, 0.62f),
							can_disconnect);
						render_metrics.disconnect_action_visible = ImGui::IsItemVisible();
						render_metrics.disconnect_button_available =
							ImGui::IsItemVisible() && can_disconnect;
						render_metrics.disconnect_button_center = last_item_center();
						if (gui_smoke_test &&
							(!kGuiVisualTestBuild || ImGui::IsItemVisible())) {
							smoke_disconnect_rendered = true;
						}
						ImGui::PopStyleColor(3);
						ImGui::EndDisabled();
					}
#ifndef TRUETUNNEL_GUI_VISUAL_TEST
					if (connect_clicked) {
						clear_ui_error();
						append_log(is_server
							? "[System] Start server requested"
							: "[System] Connect requested");
						int port_num = 0;
						try { port_num = std::stoi(port); } catch (...) { port_num = 0; }
						if (selected_mode == 1 && server_address[0] == '\0') {
							ui_error = "Enter the server address.";
							ui_error_field = UiErrorField::Endpoint;
							append_log("[!] Server address is required");
						} else if (port_num < 1 || port_num > 65535) {
							ui_error = "Enter a port from 1 to 65535.";
							ui_error_field = UiErrorField::Port;
							append_log("[!] Invalid port entered");
						} else if (is_server && !password_generated) {
							ui_error =
								"Server mode requires a key generated by Windows CNG. "
								"Choose Regenerate.";
							ui_error_field = UiErrorField::SharedSecret;
							append_log(
								"[!] Server start rejected: the shared key was imported");
						} else if (const auto secret_error =
								secure::validate_shared_secret(shared_secret_text(password));
							secret_error != secure::SharedSecretValidationError::None) {
							ui_error = std::string{
								secure::shared_secret_validation_message(secret_error)};
							ui_error_field = UiErrorField::SharedSecret;
							append_log("[!] Invalid shared key; use Regenerate for a canonical 256-bit value");
						} else if (real_adapters_.empty() || current_adapter_idx_ < 0 ||
							current_adapter_idx_ >= static_cast<int>(real_adapters_.size())) {
							ui_error = "Select an available physical network adapter.";
							ui_error_field = UiErrorField::Adapter;
							append_log("[!] No physical network adapter is selected");
						} else {
							VpnDaemon::SessionConfig config{};
							config.mode = mode;
							config.server_ip = server_address;
							config.port = port_num;
							config.local_ip = local_ip;
							config.gateway = gateway;
							config.password = password.data();
							config.adapter_name = adapter_name;
							config.subnet_mask = subnet_mask;
							config.real_adapter = (current_adapter_idx_ >= 0 &&
								current_adapter_idx_ < static_cast<int>(real_adapters_.size()))
								? real_adapters_[current_adapter_idx_].alias : "Unknown";
							config.real_adapter_luid = (current_adapter_idx_ >= 0 &&
								current_adapter_idx_ < static_cast<int>(real_adapters_.size()))
								? real_adapters_[current_adapter_idx_].luid_value : 0U;
							config.transport = native_tcp
								? TransportProtocol::Tcp : TransportProtocol::Udp;
							config.recovery = is_server
								? ConnectionRecoveryOptions{}
								: recovery_options;
							append_log(std::string("[*] Transport: ") +
								transport_labels[selected_transport]);
							config.cipher_suite = secure::CipherSuite::Aes256Gcm;
							append_log(native_tcp
								? "[*] TLS profile: TLS 1.3 / TLS_AES_256_GCM_SHA384"
								: "[*] DTLS profile: DTLS 1.3 / TLS_AES_256_GCM_SHA384 / P-256 ECDHE-PSK");
							const bool started = g_vpn_daemon->start(config);
							if (!config.password.empty()) {
								::SecureZeroMemory(config.password.data(), config.password.size());
								config.password.clear();
							}
							if (!started) {
								ui_error = "The tunnel could not start. Check Activity for details.";
								ui_error_field = UiErrorField::General;
								append_log(kSessionStartFailureLog);
							}
						}
					}
#else
					(void)connect_clicked;
#endif
					if (disconnect_clicked) {
						ImGui::OpenPopup("Disconnect tunnel");
					}
					ImGui::EndTable();
				}
			}
			end_card(scale, state_color, true);
			record_last_item_bounds(render_metrics.status_card);

#ifdef TRUETUNNEL_GUI_VISUAL_TEST
			if (visual_disconnect_open && visual_input_stage >= 2U) {
				ImGui::OpenPopup("Disconnect tunnel");
			}
#endif
			ImGui::PushStyleColor(
				ImGuiCol_PopupBg, ImVec4(0.030f, 0.039f, 0.055f, 1.0f));
			ImGui::PushStyleColor(
				ImGuiCol_Border, ImVec4(0.58f, 0.31f, 0.34f, 0.90f));
			ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 1.0f * scale);
			ImGui::PushStyleVar(
				ImGuiStyleVar_WindowPadding, ImVec2(24.0f * scale, 20.0f * scale));
			ImGui::SetNextWindowPos(
				ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing,
				ImVec2(0.5f, 0.5f));
			if (ImGui::BeginPopupModal(
					"Disconnect tunnel", nullptr,
					ImGuiWindowFlags_AlwaysAutoResize |
					ImGuiWindowFlags_NoSavedSettings)) {
			#ifdef TRUETUNNEL_GUI_VISUAL_TEST
				if (!visual_disconnect_open) ImGui::CloseCurrentPopup();
			#endif
				render_metrics.disconnect_confirmation_visible = true;
				decorate_popup_surface(
					scale, ImVec4(1.0f, 0.36f, 0.38f, 1.0f));
				if (fonts.semibold != nullptr) ImGui::PushFont(fonts.semibold);
				ImGui::TextUnformatted("End this secure session?");
				if (fonts.semibold != nullptr) ImGui::PopFont();
				ImGui::TextDisabled("Traffic through the tunnel will stop immediately.");
				ImGui::Spacing();
				ImGui::PushStyleColor(
					ImGuiCol_Button, ImVec4(0.53f, 0.13f, 0.17f, 1.0f));
				ImGui::PushStyleColor(
					ImGuiCol_ButtonHovered, ImVec4(0.72f, 0.18f, 0.22f, 1.0f));
				ImGui::PushStyleColor(
					ImGuiCol_ButtonActive, ImVec4(0.43f, 0.09f, 0.13f, 1.0f));
				ImGui::PushStyleColor(
					ImGuiCol_Border, ImVec4(1.0f, 0.43f, 0.46f, 0.78f));
				if (ImGui::Button(
						"Disconnect", ImVec2(132.0f * scale, 36.0f * scale))) {
					append_log("[System] Disconnect requested");
					if (g_vpn_daemon) g_vpn_daemon->stop();
					ImGui::CloseCurrentPopup();
				}
				ImGui::PopStyleColor(4);
				ImGui::SameLine();
				if (ImGui::Button(
						"Keep connected", ImVec2(132.0f * scale, 36.0f * scale))) {
					ImGui::CloseCurrentPopup();
				}
				if (ImGui::IsKeyPressed(ImGuiKey_Escape)) ImGui::CloseCurrentPopup();
				ImGui::EndPopup();
			}
			ImGui::PopStyleVar(2);
			ImGui::PopStyleColor(2);

			ImGui::Dummy(ImVec2(0.0f, 3.0f * scale));
			ImGui::BeginChild(
				"##DashboardScroll", ImVec2(0.0f, 0.0f), false,
				ImGuiWindowFlags_None);
			// Query Dear ImGui's active clip rectangle instead of estimating the
			// scrollbar reservation. It is exact for both scrollable compact layouts
			// and scrollbar-free desktop layouts, including parent clipping.
			const ImVec2 dashboard_clip_minimum =
				ImGui::GetWindowDrawList()->GetClipRectMin();
			const ImVec2 dashboard_clip_maximum =
				ImGui::GetWindowDrawList()->GetClipRectMax();
			render_metrics.dashboard_clip_minimum = dashboard_clip_minimum;
			render_metrics.dashboard_clip_maximum = dashboard_clip_maximum;
			if (requested_content_scroll_ratio >= 0.0f) {
				float requested_scroll_y =
					std::clamp(requested_content_scroll_ratio, 0.0f, 1.0f) *
					ImGui::GetScrollMaxY();
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
				switch (visual_content_target) {
					case VisualContentTarget::Top:
						requested_scroll_y = 0.0f;
						break;
					case VisualContentTarget::Network:
						requested_scroll_y = render_metrics.network_anchor_y;
						break;
					case VisualContentTarget::Secret:
						requested_scroll_y = render_metrics.secret_anchor_y;
						break;
					case VisualContentTarget::Activity:
						requested_scroll_y = render_metrics.activity_anchor_y;
						break;
					case VisualContentTarget::Recovery:
						requested_scroll_y = render_metrics.recovery_anchor_y;
						break;
					case VisualContentTarget::Bottom:
						requested_scroll_y = render_metrics.security_anchor_y;
						break;
				}
#endif
				requested_scroll_y = std::clamp(
					requested_scroll_y, 0.0f, ImGui::GetScrollMaxY());
				ImGui::SetScrollY(requested_scroll_y);
				render_metrics.requested_content_scroll_y = requested_scroll_y;
			}
			const float dashboard_window_top = ImGui::GetWindowPos().y;
			const float dashboard_scroll_y = ImGui::GetScrollY();
			const auto content_anchor = [dashboard_window_top, dashboard_scroll_y, scale](
					const float screen_y) noexcept {
				return (std::max)(
					0.0f, screen_y - dashboard_window_top + dashboard_scroll_y -
						12.0f * scale);
			};

			const bool wide_layout =
				ImGui::GetContentRegionAvail().x >= 1080.0f * scale;
			render_metrics.wide_layout = wide_layout;
			bool dashboard_table_open = false;
			if (wide_layout) {
				dashboard_table_open = ImGui::BeginTable(
					"##DashboardColumns", 3,
					ImGuiTableFlags_SizingStretchProp |
					ImGuiTableFlags_NoSavedSettings,
					ImVec2(0.0f, 0.0f));
				if (dashboard_table_open) {
					ImGui::TableSetupColumn(
						"Connection", ImGuiTableColumnFlags_WidthStretch, 1.08f);
					ImGui::TableSetupColumn(
						"Network and credentials",
						ImGuiTableColumnFlags_WidthStretch, 0.96f);
					ImGui::TableSetupColumn(
						"Activity and security",
						ImGuiTableColumnFlags_WidthStretch, 1.06f);
					ImGui::TableNextRow();
					ImGui::TableSetColumnIndex(0);
				}
			}

			if (begin_card("##ConnectionCard", scale)) {
				card_heading(
					fonts.semibold, "Connection",
					configuration_locked
						? "Settings are locked to the active tunnel."
						: "Choose how this device joins the tunnel.");

				ImGui::TextDisabled("Role");
				const float segment_gap = ImGui::GetStyle().ItemSpacing.x;
				const float segment_width =
					(ImGui::GetContentRegionAvail().x - segment_gap) * 0.5f;
				ImGui::BeginDisabled(configuration_locked);
				if (segment_button(
						"Server##role", selected_mode == 0,
						ImVec2(segment_width, 40.0f * scale), scale,
						configuration_locked)) {
					selected_mode = 0;
					strncpy_s(mode, mode_options[0], sizeof(mode) - 1U);
					clear_ui_error();
				}
				render_metrics.role_server_control_available = ImGui::IsItemVisible();
				render_metrics.role_server_control_center = last_item_center();
				observe_last_control(
					render_metrics, dashboard_clip_minimum, dashboard_clip_maximum);
				ImGui::SameLine(0.0f, segment_gap);
				if (segment_button(
						"Client##role", selected_mode == 1,
						ImVec2(segment_width, 40.0f * scale), scale,
						configuration_locked)) {
					selected_mode = 1;
					strncpy_s(mode, mode_options[1], sizeof(mode) - 1U);
					clear_ui_error();
				}
				observe_last_control(
					render_metrics, dashboard_clip_minimum, dashboard_clip_maximum);
				ImGui::EndDisabled();
				if (wide_layout) {
					ImGui::TextDisabled("%s", selected_mode == 0
						? "Listen for one authenticated peer"
						: "Connect to a server");
				}

				ImGui::Dummy(ImVec2(0.0f, 3.0f * scale));
				ImGui::TextDisabled("Transport");
				ImGui::BeginDisabled(configuration_locked);
				if (segment_button(
						"TCP  |  Reliable##transport", selected_transport == 0,
						ImVec2(segment_width, 40.0f * scale), scale,
						configuration_locked)) {
					selected_transport = 0;
					clear_ui_error();
				}
				render_metrics.transport_tcp_control_available = ImGui::IsItemVisible();
				render_metrics.transport_tcp_control_center = last_item_center();
				observe_last_control(
					render_metrics, dashboard_clip_minimum, dashboard_clip_maximum);
				ImGui::SameLine(0.0f, segment_gap);
				if (segment_button(
						"UDP  |  Low latency##transport", selected_transport == 1,
						ImVec2(segment_width, 40.0f * scale), scale,
						configuration_locked)) {
					selected_transport = 1;
					clear_ui_error();
				}
				observe_last_control(
					render_metrics, dashboard_clip_minimum, dashboard_clip_maximum);
				if (gui_smoke_test &&
					(!kGuiVisualTestBuild || ImGui::IsItemVisible())) {
					smoke_transport_rendered = true;
				}
				ImGui::EndDisabled();
				if (wide_layout) {
					ImGui::TextDisabled("%s", native_tcp
						? "Best compatibility for general network traffic"
						: "Preserves datagram boundaries for latency-sensitive traffic");
				}

				ImGui::Dummy(ImVec2(0.0f, 3.0f * scale));
				if (selected_mode == 1) {
					const bool endpoint_invalid =
						ui_error_field == UiErrorField::Endpoint;
					const bool port_invalid = ui_error_field == UiErrorField::Port;
					if (ImGui::BeginTable(
							"##ClientEndpoint", 2,
							ImGuiTableFlags_SizingFixedFit |
							ImGuiTableFlags_NoSavedSettings)) {
						ImGui::TableSetupColumn(
							"Address", ImGuiTableColumnFlags_WidthStretch, 1.0f);
						ImGui::TableSetupColumn(
							"Port", ImGuiTableColumnFlags_WidthFixed, 112.0f * scale);

						// Labels and fields get their own shared rows. This keeps both
						// baselines and both frame tops pixel-aligned at every DPI.
						ImGui::TableNextRow();
						ImGui::TableSetColumnIndex(0);
						ImGui::AlignTextToFramePadding();
						ImGui::TextDisabled("Server address");
						ImGui::TableSetColumnIndex(1);
						ImGui::AlignTextToFramePadding();
						ImGui::TextDisabled("Port");

						ImGui::TableNextRow();
						ImGui::TableSetColumnIndex(0);
						ImGui::SetNextItemWidth(-1.0f);
						push_validation_frame(endpoint_invalid);
						ImGui::BeginDisabled(configuration_locked);
						if (ImGui::InputTextWithHint(
							"##server_address", "vpn.example.net or 203.0.113.10",
							server_address, IM_ARRAYSIZE(server_address))) {
							clear_ui_error();
						}
						ImGui::EndDisabled();
						pop_validation_frame(endpoint_invalid);
						render_metrics.endpoint_input_available =
							ImGui::IsItemVisible() && !configuration_locked;
						render_metrics.endpoint_input_center = last_item_center();
						record_last_item_bounds(render_metrics.endpoint_field);
						observe_last_control(
							render_metrics, dashboard_clip_minimum,
							dashboard_clip_maximum);
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
						if (visual_attempt_locked_configuration && ImGui::IsItemActive()) {
							visual_locked_endpoint_activated = true;
						}
						if (visual_focus_endpoint) {
							render_metrics.endpoint_focused = ImGui::IsItemActive();
						}
#endif
						ImGui::TableSetColumnIndex(1);
						ImGui::SetNextItemWidth(-1.0f);
						push_validation_frame(port_invalid);
						ImGui::BeginDisabled(configuration_locked);
						if (ImGui::InputText("##port", port, IM_ARRAYSIZE(port))) {
							clear_ui_error();
						}
						ImGui::EndDisabled();
						pop_validation_frame(port_invalid);
						record_last_item_bounds(render_metrics.port_field);
						observe_last_control(
							render_metrics, dashboard_clip_minimum,
							dashboard_clip_maximum);
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
						if (visual_tab_endpoint_to_port) {
							render_metrics.port_focused = ImGui::IsItemFocused();
						}
#endif
						ImGui::EndTable();
					}
					if (endpoint_invalid || port_invalid) {
						inline_validation_error(render_metrics, ui_error);
					}
				} else {
					ImGui::TextDisabled("Listening port");
					ImGui::SetNextItemWidth(-1.0f);
					const bool port_invalid = ui_error_field == UiErrorField::Port;
					push_validation_frame(port_invalid);
					ImGui::BeginDisabled(configuration_locked);
					if (ImGui::InputText("##port", port, IM_ARRAYSIZE(port))) {
						clear_ui_error();
					}
					ImGui::EndDisabled();
					pop_validation_frame(port_invalid);
					observe_last_control(
						render_metrics, dashboard_clip_minimum,
						dashboard_clip_maximum);
					ImGui::PushTextWrapPos(0.0f);
					ImGui::TextDisabled("Accepts peers on all available addresses");
					ImGui::PopTextWrapPos();
					observe_last_control(
						render_metrics, dashboard_clip_minimum,
						dashboard_clip_maximum);
					if (port_invalid) {
						inline_validation_error(render_metrics, ui_error);
					}
				}

				if (!is_server) {
					render_metrics.recovery_control_present = true;
					ImGui::Dummy(ImVec2(0.0f, 6.0f * scale));
					render_metrics.recovery_anchor_y =
						content_anchor(ImGui::GetCursorScreenPos().y);
					ImGui::BeginGroup();
					ImGui::PushStyleColor(
						ImGuiCol_ChildBg, ImVec4(0.050f, 0.074f, 0.108f, 0.96f));
					ImGui::PushStyleColor(
						ImGuiCol_Border, ImVec4(0.29f, 0.45f, 0.65f, 0.82f));
					ImGui::PushStyleVar(
						ImGuiStyleVar_ChildRounding, 12.0f * scale);
					ImGui::PushStyleVar(
						ImGuiStyleVar_WindowPadding,
						ImVec2(14.0f * scale, 9.0f * scale));
					ImGui::BeginChild(
						"##RecoverySection", ImVec2(0.0f, 0.0f),
						ImGuiChildFlags_Borders |
						ImGuiChildFlags_AlwaysUseWindowPadding |
						ImGuiChildFlags_AutoResizeY |
						ImGuiChildFlags_AlwaysAutoResize,
						ImGuiWindowFlags_NoScrollbar |
						ImGuiWindowFlags_NoScrollWithMouse);
					const bool recovery_controls_disabled = !is_idle;
					ImGui::TextDisabled("Connection recovery");
					if (ImGui::BeginTable(
							"##RecoveryControl", 2,
							ImGuiTableFlags_SizingStretchProp |
							ImGuiTableFlags_NoSavedSettings)) {
						ImGui::TableSetupColumn(
							"Description", ImGuiTableColumnFlags_WidthStretch, 1.0f);
						ImGui::TableSetupColumn(
							"Control", ImGuiTableColumnFlags_WidthFixed, 86.0f * scale);
						ImGui::TableNextRow();
						ImGui::TableSetColumnIndex(0);
						ImGui::TextUnformatted("Automatic reconnect");
						ImGui::PushTextWrapPos(0.0f);
						ImGui::TextDisabled(
							recovery_controls_disabled
								? (recovery_options.enabled
									? "Monitoring active · retries continue until disconnect."
									: "Off for this session · disconnect to change.")
								: "5s heartbeat · 15s timeout · 1-30s retry delay until disconnect.");
						ImGui::PopTextWrapPos();
						ImGui::TableSetColumnIndex(1);
						ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 2.0f * scale);
						ImGui::AlignTextToFramePadding();
						ImGui::TextColored(
							recovery_options.enabled
								? ImVec4(0.55f, 0.82f, 1.0f, 1.0f)
								: ImVec4(0.61f, 0.68f, 0.77f, 1.0f),
							recovery_options.enabled ? "On" : "Off");
						ImGui::SameLine(0.0f, 7.0f * scale);
					#ifdef TRUETUNNEL_GUI_VISUAL_TEST
						if (visual_activate_recovery_with_keyboard &&
							visual_input_stage >= 1U &&
							visual_input_stage < 3U &&
							!recovery_controls_disabled &&
							!visual_keyboard_recovery_activated) {
							ImGui::SetKeyboardFocusHere();
						}
					#endif
						bool recovery_toggle_focused = false;
						if (toggle_switch(
								"Recovery", recovery_options.enabled,
								!recovery_controls_disabled, scale,
								&recovery_toggle_focused)) {
							clear_ui_error();
							append_log(recovery_options.enabled
								? "[System] Automatic recovery enabled"
								: "[System] Automatic recovery disabled");
						#ifdef TRUETUNNEL_GUI_VISUAL_TEST
							if (visual_activate_recovery_with_keyboard) {
								visual_keyboard_recovery_activated = true;
							}
						#endif
						}
						render_metrics.recovery_toggle_visible = ImGui::IsItemVisible();
						render_metrics.recovery_toggle_enabled =
							!recovery_controls_disabled;
						render_metrics.recovery_toggle_focused = recovery_toggle_focused;
						observe_last_control(
							render_metrics, dashboard_clip_minimum,
							dashboard_clip_maximum);
						if (gui_smoke_test && ImGui::IsItemVisible() &&
							!is_server && recovery_options.enabled) {
							smoke_recovery_rendered = true;
						}
						ImGui::EndTable();
					}
					ImGui::EndChild();
					ImGui::PopStyleVar(2);
					ImGui::PopStyleColor(2);
					ImGui::EndGroup();
					record_last_item_bounds(render_metrics.recovery_card);
					if (render_metrics.recovery_card.valid) {
						ImGui::GetWindowDrawList()->AddLine(
							ImVec2(
								render_metrics.recovery_card.minimum.x + 14.0f * scale,
								render_metrics.recovery_card.minimum.y + 1.0f * scale),
							ImVec2(
								render_metrics.recovery_card.maximum.x - 14.0f * scale,
								render_metrics.recovery_card.minimum.y + 1.0f * scale),
							ImGui::GetColorU32(ImVec4(0.78f, 0.90f, 1.0f, 0.18f)),
							1.0f * scale);
					}
				}

			}
			end_card(scale);
			record_last_item_bounds(render_metrics.connection_card);

			if (dashboard_table_open) {
				ImGui::TableSetColumnIndex(1);
			} else {
				ImGui::Dummy(ImVec2(0.0f, 16.0f * scale));
			}

				render_metrics.network_anchor_y =
					content_anchor(ImGui::GetCursorScreenPos().y);
			if (begin_card("##NetworkCard", scale)) {
				card_heading(
					fonts.semibold, "Windows network",
					configuration_locked
						? "The active tunnel keeps its physical path locked."
						: "Choose the physical path used by the tunnel.");
				ImGui::PushStyleColor(
					ImGuiCol_ChildBg, ImVec4(0.052f, 0.069f, 0.094f, 0.96f));
				ImGui::PushStyleColor(
					ImGuiCol_Border, ImVec4(0.27f, 0.32f, 0.39f, 0.66f));
				ImGui::PushStyleVar(
					ImGuiStyleVar_WindowPadding,
					ImVec2(13.0f * scale, 10.0f * scale));
				ImGui::BeginChild(
					"##InterfaceIdentity", ImVec2(0.0f, 57.0f * scale), true,
					ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
				ImGui::TextDisabled("Virtual adapter");
				ImGui::SameLine();
				ImGui::TextUnformatted(adapter_name);
				ImGui::TextColored(
					secure_session_active
						? ImVec4(0.43f, 0.80f, 0.65f, 1.0f)
						: is_reconnecting
							? ImVec4(1.0f, 0.70f, 0.32f, 1.0f)
							: ImVec4(0.49f, 0.72f, 0.96f, 1.0f),
					secure_session_active
						? "Stable identity active"
						: is_reconnecting
							? "Stable identity reserved for retry"
							: "Stable Windows identity reserved");
				ImGui::EndChild();
				ImGui::PopStyleVar();
				ImGui::PopStyleColor(2);
				ImGui::TextDisabled("Physical uplink");
				if (!adapter_labels_.empty()) {
					ImGui::SetNextItemWidth(-1.0f);
					const bool adapter_invalid =
						ui_error_field == UiErrorField::Adapter;
					push_validation_frame(adapter_invalid);
					ImGui::BeginDisabled(configuration_locked);
					const bool valid_adapter_selection = current_adapter_idx_ >= 0 &&
						current_adapter_idx_ < static_cast<int>(adapter_labels_.size());
					const char* adapter_preview = valid_adapter_selection
						? adapter_labels_[static_cast<std::size_t>(current_adapter_idx_)].c_str()
						: "Select a physical adapter...";
					if (ImGui::BeginCombo("##real_adapter", adapter_preview)) {
						for (std::size_t index = 0; index < adapter_labels_.size(); ++index) {
							const bool selected = current_adapter_idx_ ==
								static_cast<int>(index);
							if (ImGui::Selectable(
									adapter_labels_[index].c_str(), selected)) {
								current_adapter_idx_ = static_cast<int>(index);
								clear_ui_error();
							}
							if (selected) ImGui::SetItemDefaultFocus();
						}
						ImGui::EndCombo();
					}
					ImGui::EndDisabled();
					pop_validation_frame(adapter_invalid);
					observe_last_control(
						render_metrics, dashboard_clip_minimum,
						dashboard_clip_maximum);
					if (adapter_invalid) {
						inline_validation_error(render_metrics, ui_error);
					}
				} else {
					ImGui::TextColored(
						ImVec4(1.0f, 0.60f, 0.42f, 1.0f),
						"No usable physical network adapter was detected.");
				}

			}
			end_card(scale);
			record_last_item_bounds(render_metrics.network_card);

			ImGui::Dummy(ImVec2(0.0f, 16.0f * scale));
				render_metrics.secret_anchor_y =
					content_anchor(ImGui::GetCursorScreenPos().y);
			if (begin_card("##CredentialsCard", scale)) {
				const char* secret_subtitle = configuration_locked
					? "Locked for the active tunnel; copying remains available."
					: is_server
						? "Generate the server key here, then copy it to each client."
						: "Paste the server's generated 256-bit key exactly.";
				card_heading(
					fonts.semibold, "Shared key",
					secret_subtitle);
				const bool current_secret_valid =
					shared_secret_invariants_hold(password);
				const bool secret_invalid =
					ui_error_field == UiErrorField::SharedSecret;
				ImGui::SetNextItemWidth(-1.0f);
				push_validation_frame(secret_invalid);
				const ImGuiInputTextFlags secret_input_flags =
					ImGuiInputTextFlags_Password |
					(is_server ? ImGuiInputTextFlags_ReadOnly
					           : ImGuiInputTextFlags_None);
				ImGui::BeginDisabled(configuration_locked);
				if (ImGui::InputText(
						"##password", password.data(), password.size(),
						secret_input_flags)) {
					password_generated = false;
					clear_ui_error();
				}
				ImGui::EndDisabled();
				pop_validation_frame(secret_invalid);
				observe_last_control(
					render_metrics, dashboard_clip_minimum,
					dashboard_clip_maximum);
				if (gui_smoke_test &&
					(!kGuiVisualTestBuild || ImGui::IsItemVisible())) {
					smoke_password_rendered = true;
				}

				if (ImGui::BeginTable(
						"##SecretActions", 2,
						ImGuiTableFlags_SizingStretchProp |
						ImGuiTableFlags_NoSavedSettings)) {
					ImGui::TableSetupColumn(
						is_server ? "Regenerate" : "Clear",
						ImGuiTableColumnFlags_WidthStretch, 1.0f);
					ImGui::TableSetupColumn(
						"Copy", ImGuiTableColumnFlags_WidthStretch, 1.0f);
					ImGui::TableNextRow();
					ImGui::TableSetColumnIndex(0);
					ImGui::BeginDisabled(configuration_locked);
					if (ImGui::Button(
							is_server ? "Regenerate##password" : "Clear##password",
							ImVec2(-1.0f, 0.0f))) {
						secret_clipboard.clear_now_if_owned(hwnd);
						if (is_server) {
							password_generated = generate_shared_secret(password);
						} else {
							::SecureZeroMemory(password.data(), password.size());
							password.fill('\0');
							password_generated = false;
						}
						clear_ui_error();
						if (is_server && !password_generated) {
							append_log("[!] Windows CSPRNG failed; shared key was cleared");
						}
					}
					render_metrics.secret_action_available = ImGui::IsItemVisible();
					render_metrics.secret_action_center = last_item_center();
					observe_last_control(
						render_metrics, dashboard_clip_minimum,
						dashboard_clip_maximum);
					if (gui_smoke_test &&
						(!kGuiVisualTestBuild || ImGui::IsItemVisible())) {
						smoke_regenerate_rendered = true;
					}
					ImGui::EndDisabled();
					ImGui::TableSetColumnIndex(1);
					ImGui::BeginDisabled(
						!current_secret_valid || (is_server && !password_generated));
					if (ImGui::Button("Copy##password", ImVec2(-1.0f, 0.0f))) {
						if (!secret_clipboard.copy_secret(hwnd, password)) {
						append_log("[!] The shared key could not be copied securely");
						}
					}
					observe_last_control(
						render_metrics, dashboard_clip_minimum,
						dashboard_clip_maximum);
					ImGui::EndDisabled();
					ImGui::EndTable();
				}
				if (secret_invalid) {
					inline_validation_error(render_metrics, ui_error);
				} else {
					ImGui::PushStyleColor(
						ImGuiCol_Text,
						current_secret_valid
							? ImVec4(0.40f, 0.84f, 0.63f, 1.0f)
							: ImVec4(1.0f, 0.72f, 0.35f, 1.0f));
					ImGui::PushTextWrapPos(0.0f);
					ImGui::TextWrapped("%s",
						is_server
							? (password_generated && current_secret_valid
								? "Server-generated 256-bit key  |  Clipboard clears in 30 seconds"
								: "Server keys must be generated here. Choose Regenerate.")
							: (current_secret_valid
								? "Imported 256-bit server key  |  Clipboard clears in 30 seconds"
								: "Required: paste the server's canonical 43-character key"));
					ImGui::PopTextWrapPos();
					ImGui::PopStyleColor();
					observe_last_control(
						render_metrics, dashboard_clip_minimum,
						dashboard_clip_maximum);
				}
			}
			end_card(scale);
			record_last_item_bounds(render_metrics.secret_card);

			const auto render_security_card = [&]() {
				render_metrics.security_anchor_y =
					content_anchor(ImGui::GetCursorScreenPos().y);
				if (begin_card("##SecurityPosture", scale)) {
					if (fonts.semibold != nullptr) ImGui::PushFont(fonts.semibold);
					ImGui::TextUnformatted("Security profile");
					if (fonts.semibold != nullptr) ImGui::PopFont();
					ImGui::SameLine();
					ImGui::TextColored(
						is_reconnecting
							? ImVec4(1.0f, 0.70f, 0.32f, 1.0f)
							: secure_session_active
								? ImVec4(0.43f, 0.80f, 0.65f, 1.0f)
								: ImVec4(0.49f, 0.72f, 0.96f, 1.0f),
						is_reconnecting
							? "· Negotiating"
							: secure_session_active ? "· Active" : "· Configured");
					ImGui::Spacing();
					posture_row(
						"Protocol",
						native_tcp
							? (is_reconnecting
								? "TLS 1.3 · pending"
								: secure_session_active ? "TLS 1.3" : "TLS 1.3 · selected")
							: (is_reconnecting
								? "DTLS 1.3 · pending"
								: secure_session_active ? "DTLS 1.3" : "DTLS 1.3 · selected"),
						scale, secure_session_active);
					posture_row(
						"Provider",
						native_tcp ? "Windows Schannel" : "wolfSSL",
						scale, secure_session_active);
					posture_row(
						"Cipher",
						is_reconnecting
							? "AES-256-GCM · pending"
							: secure_session_active
								? "AES-256-GCM"
								: "AES-256-GCM · selected",
						scale, secure_session_active);
					posture_row(
						"Key lifecycle",
						is_reconnecting
							? "Fresh keys on reconnect"
							: secure_session_active
								? (native_tcp ? "Provider-managed" : "Automatic")
								: "Starts after authentication",
						scale, secure_session_active);
					if (gui_smoke_test &&
						(!kGuiVisualTestBuild || ImGui::IsItemVisible())) {
						smoke_cipher_rendered = true;
					}
				}
				end_card(scale);
				record_last_item_bounds(render_metrics.security_card);
			};

			if (dashboard_table_open) {
				ImGui::TableSetColumnIndex(2);
				render_security_card();
				if (render_metrics.secret_card.valid) {
					const ImVec2 cursor = ImGui::GetCursorScreenPos();
					ImGui::SetCursorScreenPos(ImVec2(
						cursor.x,
						(std::max)(cursor.y, render_metrics.secret_card.minimum.y)));
				}
			} else {
				ImGui::Dummy(ImVec2(0.0f, 16.0f * scale));
			}

			render_metrics.activity_anchor_y =
				content_anchor(ImGui::GetCursorScreenPos().y);
			if (begin_card("##ActivityCard", scale, false, 14.0f)) {
				const ImVec2 activity_item_spacing = ImGui::GetStyle().ItemSpacing;
				ImGui::PushStyleVar(
					ImGuiStyleVar_ItemSpacing,
					ImVec2(activity_item_spacing.x, 6.0f * scale));
				if (fonts.semibold != nullptr) ImGui::PushFont(fonts.semibold);
				ImGui::TextUnformatted("Activity");
				if (fonts.semibold != nullptr) ImGui::PopFont();
				const float clear_width = 66.0f * scale;
				ImGui::SameLine(
					ImGui::GetWindowContentRegionMax().x - clear_width);
				if (ImGui::Button("Clear", ImVec2(clear_width, 0.0f))) {
					clear_logs();
					last_log_length = 0;
				}
				observe_last_control(
					render_metrics, dashboard_clip_minimum, dashboard_clip_maximum);
				if (ImGui::BeginTable(
						"##ActivityScrollControl", 2,
						ImGuiTableFlags_SizingStretchProp |
						ImGuiTableFlags_NoSavedSettings)) {
					ImGui::TableSetupColumn(
						"Label", ImGuiTableColumnFlags_WidthStretch, 1.0f);
					ImGui::TableSetupColumn(
						"Control", ImGuiTableColumnFlags_WidthFixed, 48.0f * scale);
					ImGui::TableNextRow();
					ImGui::TableSetColumnIndex(0);
					ImGui::AlignTextToFramePadding();
					ImGui::TextUnformatted("Auto-scroll activity");
					ImGui::TableSetColumnIndex(1);
					(void)toggle_switch(
						"ActivityAutoScroll", auto_scroll, true, scale);
					observe_last_control(
						render_metrics, dashboard_clip_minimum,
						dashboard_clip_maximum);
					ImGui::EndTable();
				}

				const std::vector<std::string> log_snapshot = snapshot_logs();
				ImGui::PushStyleColor(
					ImGuiCol_ChildBg, ImVec4(0.012f, 0.018f, 0.027f, 0.68f));
				ImGui::PushStyleColor(
					ImGuiCol_Border, ImVec4(0.27f, 0.32f, 0.39f, 0.64f));
				ImGui::PushStyleVar(
					ImGuiStyleVar_WindowPadding,
					ImVec2(12.0f * scale, 10.0f * scale));
				ImGui::PushStyleVar(
					ImGuiStyleVar_ItemSpacing,
					ImVec2(8.0f * scale, 4.0f * scale));
				const float activity_log_height =
					(wide_layout ? 114.0f : 109.0f) * scale;
				ImGui::BeginChild(
					"##ActivityLog", ImVec2(0.0f, activity_log_height), true,
					ImGuiWindowFlags_AlwaysVerticalScrollbar);
				const ImVec2 activity_clip_minimum =
					ImGui::GetWindowDrawList()->GetClipRectMin();
				const ImVec2 activity_clip_maximum =
					ImGui::GetWindowDrawList()->GetClipRectMax();
				std::vector<float> activity_row_scroll_positions;
				activity_row_scroll_positions.reserve(log_snapshot.size());
				const float timestamp_width =
					ImGui::CalcTextSize("[00:00:00]").x;
				const float indicator_column_x =
					ImGui::GetWindowContentRegionMin().x + timestamp_width +
						10.0f * scale;
				for (const auto& line : log_snapshot) {
					activity_row_scroll_positions.push_back(
						ImGui::GetCursorPosY() -
							ImGui::GetStyle().WindowPadding.y);
					const std::string_view timestamp = activity_timestamp(line);
					const std::string_view message = activity_message(line);
					const ImVec4 indicator = activity_line_color(line);
					const ImVec2 row_origin = ImGui::GetCursorScreenPos();
					if (!timestamp.empty()) {
						ImGui::TextDisabled(
							"%.*s", static_cast<int>(timestamp.size()), timestamp.data());
					} else {
						ImGui::Dummy(ImVec2(timestamp_width, ImGui::GetTextLineHeight()));
					}
					ImGui::SameLine(indicator_column_x);
					ImGui::GetWindowDrawList()->AddCircleFilled(
						ImVec2(ImGui::GetCursorScreenPos().x + 4.0f * scale,
						       row_origin.y + ImGui::GetTextLineHeight() * 0.5f),
						3.0f * scale, ImGui::GetColorU32(indicator));
					ImGui::Dummy(ImVec2(9.0f * scale, ImGui::GetTextLineHeight()));
					ImGui::SameLine(0.0f, 4.0f * scale);
					ImGui::PushTextWrapPos(0.0f);
					const bool is_error = line.find("[!]") != std::string::npos ||
						line.find("FAIL") != std::string::npos;
					if (is_error) ImGui::PushStyleColor(ImGuiCol_Text, indicator);
					ImGui::TextWrapped(
						"%.*s", static_cast<int>(message.size()), message.data());
					const ImVec2 message_minimum = ImGui::GetItemRectMin();
					const ImVec2 message_maximum = ImGui::GetItemRectMax();
					const float row_clip_tolerance = 0.5f * scale;
					const float visible_row_threshold = 1.0f * scale;
					const bool message_intersects =
						message_maximum.y >
							activity_clip_minimum.y + visible_row_threshold &&
						message_minimum.y <
							activity_clip_maximum.y - visible_row_threshold;
					const bool message_contained =
						message_minimum.y >=
							activity_clip_minimum.y - row_clip_tolerance &&
						message_maximum.y <=
							activity_clip_maximum.y + row_clip_tolerance;
					if (message_intersects && !message_contained) {
						render_metrics.partial_activity_row_visible = true;
					}
					if (is_error && ImGui::IsItemVisible()) {
						render_metrics.activity_error_visible = true;
					}
					if (is_error) ImGui::PopStyleColor();
					ImGui::PopTextWrapPos();
				}
				// Keep enough trailing breathing room to align the first visible log
				// row exactly at the top even when viewing the newest entries.
				ImGui::Dummy(ImVec2(0.0f, ImGui::GetTextLineHeightWithSpacing()));
				if (requested_activity_scroll_ratio >= 0.0f) {
					const float desired_scroll =
						std::clamp(requested_activity_scroll_ratio, 0.0f, 1.0f) *
						ImGui::GetScrollMaxY();
					float snapped_scroll = 0.0f;
					float closest_distance = std::numeric_limits<float>::max();
					for (const float row_scroll : activity_row_scroll_positions) {
						const float aligned_row_scroll = (std::max)(
							0.0f,
							row_scroll - 2.0f * ImGui::GetStyle().WindowPadding.y);
						if (aligned_row_scroll > ImGui::GetScrollMaxY()) continue;
						const float candidate = (std::min)(
							ImGui::GetScrollMaxY(),
							aligned_row_scroll +
								(desired_scroll > 0.0f ? 5.0f * scale : 0.0f));
						const float distance = std::abs(candidate - desired_scroll);
						if (distance < closest_distance) {
							closest_distance = distance;
							snapped_scroll = candidate;
						}
					}
					ImGui::SetScrollY(snapped_scroll);
					render_metrics.requested_activity_scroll_y = snapped_scroll;
				} else if (auto_scroll &&
					log_snapshot.size() > static_cast<std::size_t>(last_log_length)) {
					ImGui::SetScrollHereY(1.0f);
				}
				render_metrics.activity_scroll_y = ImGui::GetScrollY();
				render_metrics.activity_scroll_max = ImGui::GetScrollMaxY();
				last_log_length = static_cast<int>(log_snapshot.size());
				ImGui::EndChild();
				ImGui::PopStyleVar(2);
				ImGui::PopStyleColor(2);

				ImGui::TextDisabled("Message to peer");
				if (ImGui::BeginTable(
						"##MessageControls", 2,
						ImGuiTableFlags_SizingStretchProp |
						ImGuiTableFlags_NoSavedSettings)) {
					ImGui::TableSetupColumn(
						"Message", ImGuiTableColumnFlags_WidthStretch, 1.0f);
					ImGui::TableSetupColumn(
						"Send", ImGuiTableColumnFlags_WidthFixed, 72.0f * scale);
					ImGui::TableNextRow();
					ImGui::TableSetColumnIndex(0);
					if (focus_message_input) {
						ImGui::SetKeyboardFocusHere();
						focus_message_input = false;
					}
					ImGui::SetNextItemWidth(-1.0f);
					const bool enter_pressed = ImGui::InputTextWithHint(
						"##message", "Type a short encrypted message",
						message_input, IM_ARRAYSIZE(message_input),
						ImGuiInputTextFlags_EnterReturnsTrue);
					observe_last_control(
						render_metrics, dashboard_clip_minimum,
						dashboard_clip_maximum);
					if (gui_smoke_test &&
						(!kGuiVisualTestBuild || ImGui::IsItemVisible())) {
						smoke_message_rendered = true;
					}
					ImGui::TableSetColumnIndex(1);
					const bool session_can_send = is_connected || is_listening;
					ImGui::BeginDisabled(!session_can_send || message_input[0] == '\0');
					const bool send_clicked = ImGui::Button("Send", ImVec2(-1.0f, 0.0f));
					observe_last_control(
						render_metrics, dashboard_clip_minimum,
						dashboard_clip_maximum);
					ImGui::EndDisabled();
					const bool send_requested = enter_pressed || send_clicked;
					if (send_requested && message_input[0] != '\0') {
						bool sent = false;
						if (g_vpn_daemon && session_can_send && g_vpn_daemon->is_running()) {
							sent = g_vpn_daemon->send_message(message_input);
						}
						append_log(std::string(sent ? "[You] " : "[!] Failed to send: ") +
							message_input);
						message_input[0] = '\0';
						focus_message_input = true;
					}
					ImGui::EndTable();
				}
				ImGui::PopStyleVar();
			}
			end_card(scale);
			record_last_item_bounds(render_metrics.activity_card);

			if (!dashboard_table_open) {
				ImGui::Dummy(ImVec2(0.0f, 16.0f * scale));
				render_security_card();
			}

			if (dashboard_table_open) ImGui::EndTable();
			render_metrics.content_scroll_y = ImGui::GetScrollY();
			render_metrics.content_scroll_max = ImGui::GetScrollMaxY();
			ImGui::EndChild();

			ImGui::End();
			ImGui::PopStyleVar(2);
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

#ifdef TRUETUNNEL_GUI_VISUAL_TEST
		if (visual_case_configured &&
			visual_case_index < kVisualCaptureCases.size()) {
			if (render_metrics.help_visible) visual_help_was_visible = true;
			const VisualCaptureCase& capture_case =
				kVisualCaptureCases[visual_case_index];
			RECT client{};
			const bool client_size_available = ::GetClientRect(hwnd, &client) != FALSE;
			const LONG expected_width = static_cast<LONG>(std::lround(
				static_cast<double>(capture_case.logical_width) * g_ui_scale));
			const LONG expected_height = static_cast<LONG>(std::lround(
				static_cast<double>(capture_case.logical_height) * g_ui_scale));
			const bool size_stable = client_size_available &&
				std::abs(client.right - expected_width) <= 2L &&
				std::abs(client.bottom - expected_height) <= 2L &&
				g_ResizeWidth == 0U && g_ResizeHeight == 0U;
			visual_settle_frames = size_stable
				? visual_settle_frames + 1U : 0U;

			if (visual_settle_frames >= 8U) {
				const GuiRenderMetrics::Bounds* target_card = nullptr;
				switch (capture_case.content_target) {
					case VisualContentTarget::Top:
						target_card = &render_metrics.connection_card;
						break;
					case VisualContentTarget::Network:
						target_card = &render_metrics.network_card;
						break;
					case VisualContentTarget::Secret:
						target_card = &render_metrics.secret_card;
						break;
					case VisualContentTarget::Activity:
						target_card = &render_metrics.activity_card;
						break;
					case VisualContentTarget::Recovery:
						target_card = &render_metrics.recovery_card;
						break;
					case VisualContentTarget::Bottom:
						target_card = &render_metrics.security_card;
						break;
				}
				const bool compact_layout = capture_case.logical_width < 1080;
				const bool compact_section_capture =
					compact_layout &&
					!capture_case.capture_full_viewport;
				const float containment_tolerance = 2.0f * g_ui_scale;
				const bool target_card_contained = target_card != nullptr &&
					target_card->valid &&
					target_card->minimum.x >=
						render_metrics.dashboard_clip_minimum.x - containment_tolerance &&
					target_card->minimum.y >=
						render_metrics.dashboard_clip_minimum.y - containment_tolerance &&
					target_card->maximum.x <=
						render_metrics.dashboard_clip_maximum.x + containment_tolerance &&
					target_card->maximum.y <=
						render_metrics.dashboard_clip_maximum.y + containment_tolerance;

				RECT capture_region{0L, 0L, expected_width, expected_height};
				if (compact_section_capture && target_card != nullptr &&
					target_card->valid) {
					const float margin = 12.0f * g_ui_scale;
					if (capture_case.content_target == VisualContentTarget::Top) {
						// Preserve the compact app bar and command surface, then stop
						// cleanly after Connection instead of clipping the next card.
						capture_region.bottom = static_cast<LONG>(std::ceil(
							(std::min)(
								static_cast<float>(expected_height),
								target_card->maximum.y + margin)));
					} else {
						// Scrolled captures are component proofs. Cropping to the complete
						// target card avoids ambiguous fragments from adjacent sections.
						capture_region.left = static_cast<LONG>(std::floor(
							(std::max)(0.0f, target_card->minimum.x - margin)));
						capture_region.top = static_cast<LONG>(std::floor(
							(std::max)(0.0f, target_card->minimum.y - margin)));
						capture_region.right = static_cast<LONG>(std::ceil(
							(std::min)(
								static_cast<float>(expected_width),
								target_card->maximum.x + margin)));
						capture_region.bottom = static_cast<LONG>(std::ceil(
							(std::min)(
								static_cast<float>(expected_height),
								target_card->maximum.y + margin)));
					}
				}
				const bool capture_region_valid =
					capture_region.left >= 0L && capture_region.top >= 0L &&
					capture_region.right <= expected_width &&
					capture_region.bottom <= expected_height &&
					capture_region.right > capture_region.left &&
					capture_region.bottom > capture_region.top;
				BackBufferCaptureStats capture_stats{};
				const std::filesystem::path capture_path =
					visual_output_directory / capture_case.filename;
				const bool encoded = capture_region_valid &&
					capture_back_buffer_png(
						capture_path, capture_stats, &capture_region);
				const UINT expected_capture_width = capture_region_valid
					? static_cast<UINT>(capture_region.right - capture_region.left) : 0U;
				const UINT expected_capture_height = capture_region_valid
					? static_cast<UINT>(capture_region.bottom - capture_region.top) : 0U;
				const bool dimensions_ok = encoded &&
					capture_stats.width == expected_capture_width &&
					capture_stats.height == expected_capture_height;
				const bool contrast_ok = encoded &&
					capture_stats.maximum_luma > capture_stats.minimum_luma &&
					static_cast<unsigned int>(capture_stats.maximum_luma -
						capture_stats.minimum_luma) >= 32U;
				const bool content_scroll_exists =
					render_metrics.content_scroll_max > 20.0f * g_ui_scale;
				const bool content_position_reached =
					!capture_case.require_content_scroll ||
					std::abs(render_metrics.content_scroll_y -
						render_metrics.requested_content_scroll_y) <=
						2.0f * g_ui_scale;
				const bool activity_scroll_exists =
					render_metrics.activity_scroll_max > 20.0f * g_ui_scale;
				const bool activity_position_reached =
					!capture_case.require_activity_scroll ||
					std::abs(render_metrics.activity_scroll_y -
						render_metrics.requested_activity_scroll_y) <=
						2.0f * g_ui_scale;
				const bool scroll_ok =
					(!capture_case.require_content_scroll || content_scroll_exists) &&
					(!capture_case.require_activity_scroll || activity_scroll_exists) &&
					content_position_reached && activity_position_reached;
				const bool action_state_ok =
					capture_case.open_help || capture_case.open_disconnect ||
					(capture_case.daemon_state == VpnDaemon::State::Idle
						? render_metrics.connect_action_visible
						: render_metrics.disconnect_action_visible);
				const bool validation_state_ok =
					(capture_case.validation_error == nullptr ||
						render_metrics.validation_error_visible) &&
					(!capture_case.focus_endpoint ||
						(capture_case.tab_endpoint_to_port
							? render_metrics.port_focused
							: render_metrics.endpoint_focused)) &&
					(capture_case.validation_field != UiErrorField::General ||
						render_metrics.activity_error_visible);
				const bool endpoint_alignment_ok = capture_case.role != 1 ||
					(render_metrics.endpoint_field.valid &&
					 render_metrics.port_field.valid &&
					 std::abs(render_metrics.endpoint_field.minimum.y -
						render_metrics.port_field.minimum.y) <= 1.0f * g_ui_scale &&
					 std::abs(render_metrics.endpoint_field.maximum.y -
						render_metrics.port_field.maximum.y) <= 1.0f * g_ui_scale &&
					 render_metrics.port_field.minimum.x -
						render_metrics.endpoint_field.maximum.x >= 4.0f * g_ui_scale &&
					 render_metrics.port_field.minimum.x -
						render_metrics.endpoint_field.maximum.x <= 20.0f * g_ui_scale);
				const float edge_tolerance = 1.5f * g_ui_scale;
				const auto horizontal_edges_match = [edge_tolerance](
						const GuiRenderMetrics::Bounds& left,
						const GuiRenderMetrics::Bounds& right) noexcept {
					return left.valid && right.valid &&
						std::abs(left.minimum.x - right.minimum.x) <= edge_tolerance &&
						std::abs(left.maximum.x - right.maximum.x) <= edge_tolerance;
				};
				const auto top_edges_match = [edge_tolerance](
						const GuiRenderMetrics::Bounds& left,
						const GuiRenderMetrics::Bounds& right) noexcept {
					return left.valid && right.valid &&
						std::abs(left.minimum.y - right.minimum.y) <= edge_tolerance;
				};
				const bool help_geometry_ok =
					render_metrics.header_surface.valid &&
					render_metrics.help_button.valid &&
					render_metrics.help_button.minimum.x >=
						render_metrics.header_surface.minimum.x - edge_tolerance &&
					render_metrics.help_button.minimum.y >=
						render_metrics.header_surface.minimum.y - edge_tolerance &&
					render_metrics.help_button.maximum.x <=
						render_metrics.header_surface.maximum.x + edge_tolerance &&
					render_metrics.help_button.maximum.y <=
						render_metrics.header_surface.maximum.y + edge_tolerance;
				const bool status_summary_geometry_ok =
					render_metrics.status_card.valid &&
					render_metrics.status_context.valid &&
					render_metrics.status_endpoint.valid &&
					render_metrics.status_endpoint_port_visible &&
					std::abs(render_metrics.status_context.minimum.y -
						render_metrics.status_endpoint.minimum.y) <= edge_tolerance &&
					render_metrics.status_endpoint.minimum.x -
						render_metrics.status_context.maximum.x >= 4.0f * g_ui_scale &&
					render_metrics.status_endpoint.maximum.x <=
						render_metrics.status_card.maximum.x - 16.0f * g_ui_scale;
				const bool chrome_alignment_ok = horizontal_edges_match(
					render_metrics.header_surface, render_metrics.status_card) &&
					help_geometry_ok && status_summary_geometry_ok;
				const bool card_grid_alignment_ok = render_metrics.wide_layout
					? (top_edges_match(
							render_metrics.connection_card,
							render_metrics.network_card) &&
					   top_edges_match(
							render_metrics.connection_card,
							render_metrics.security_card) &&
					   top_edges_match(
							render_metrics.secret_card,
							render_metrics.activity_card) &&
					   horizontal_edges_match(
							render_metrics.network_card,
							render_metrics.secret_card) &&
					   horizontal_edges_match(
							render_metrics.security_card,
							render_metrics.activity_card))
					: (horizontal_edges_match(
							render_metrics.connection_card,
							render_metrics.network_card) &&
					   horizontal_edges_match(
							render_metrics.connection_card,
							render_metrics.secret_card) &&
					   horizontal_edges_match(
							render_metrics.connection_card,
							render_metrics.activity_card) &&
					   horizontal_edges_match(
							render_metrics.connection_card,
							render_metrics.security_card));
				const bool geometry_alignment_ok =
					chrome_alignment_ok && card_grid_alignment_ok;
				const unsigned int required_input_stage =
					capture_case.attempt_locked_configuration ? 9U
					: (capture_case.activate_primary_with_keyboard ||
					 capture_case.activate_recovery_with_keyboard) ? 3U
					: (capture_case.tab_endpoint_to_port ||
						capture_case.dismiss_help_with_escape) ? 4U : 2U;
				const bool input_path_ok =
					visual_input_stage >= required_input_stage;
				const bool recovery_keyboard_path_ok =
					!capture_case.activate_recovery_with_keyboard ||
					(capture_case.daemon_state == VpnDaemon::State::Idle
						? visual_keyboard_recovery_activated &&
							render_metrics.recovery_toggle_focused
						: !visual_keyboard_recovery_activated &&
							!render_metrics.recovery_toggle_focused);
				const bool keyboard_path_ok =
					(!capture_case.activate_primary_with_keyboard ||
						(visual_keyboard_primary_activated &&
							render_metrics.primary_action_focused)) &&
					recovery_keyboard_path_ok &&
					(!capture_case.dismiss_help_with_escape ||
						(visual_help_was_visible && !render_metrics.help_visible));
				const bool help_state_ok = !capture_case.open_help ||
					(capture_case.dismiss_help_with_escape
						? visual_help_was_visible && !render_metrics.help_visible
						: render_metrics.help_visible);
				const bool recovery_expected = capture_case.role == 1;
				const bool recovery_visibility_required = recovery_expected &&
					(capture_case.content_target == VisualContentTarget::Top ||
					 capture_case.content_target == VisualContentTarget::Recovery);
				const bool recovery_value_expected =
					(capture_case.activate_recovery_with_keyboard &&
					 capture_case.daemon_state == VpnDaemon::State::Idle)
						? true : capture_case.recovery_enabled;
				const bool recovery_state_ok =
					render_metrics.recovery_control_present == recovery_expected &&
					(!recovery_visibility_required ||
					 render_metrics.recovery_toggle_visible) &&
					(!recovery_expected ||
						(recovery_options.enabled == recovery_value_expected &&
						 render_metrics.recovery_toggle_enabled ==
							(capture_case.daemon_state == VpnDaemon::State::Idle)));
				const bool configuration_state_ok =
					render_metrics.configuration_controls_locked ==
						(capture_case.daemon_state != VpnDaemon::State::Idle);
				const bool configuration_behavior_ok =
					!capture_case.attempt_locked_configuration ||
					(selected_mode == capture_case.role &&
					 selected_transport == capture_case.transport &&
					 std::string_view{server_address} == "vpn.example.net" &&
					 shared_secret_invariants_hold(password) &&
					 !visual_locked_endpoint_activated);
				const bool secure_session_expected =
					visual_connection_status.phase == ConnectionPhase::Connected ||
					visual_connection_status.phase == ConnectionPhase::Listening;
				const bool security_state_ok =
					render_metrics.secure_session_indicators_active ==
						secure_session_expected;
				const bool phase_state_ok =
					capture_case.connection_phase < 0 ||
					(static_cast<int>(visual_connection_status.phase) == capture_case.connection_phase &&
						(capture_case.connection_phase !=
							static_cast<int>(ConnectionPhase::Reconnecting) ||
						 render_metrics.recovery_status_visible));
				const bool interaction_ok = action_state_ok && validation_state_ok &&
					endpoint_alignment_ok &&
					input_path_ok && keyboard_path_ok && help_state_ok &&
					recovery_state_ok && configuration_state_ok &&
					configuration_behavior_ok && security_state_ok && phase_state_ok &&
					(!capture_case.open_disconnect ||
						render_metrics.disconnect_confirmation_visible);
				const bool activity_rows_required = !compact_section_capture ||
					capture_case.content_target == VisualContentTarget::Activity;
				const bool activity_rows_ok = !activity_rows_required ||
					!render_metrics.partial_activity_row_visible;
				const bool controls_ok = compact_section_capture ||
					!render_metrics.partial_control_visible;
				const bool containment_ok = controls_ok &&
					activity_rows_ok;
				const auto card_is_contained = [&](
						const GuiRenderMetrics::Bounds& bounds) noexcept {
					return bounds.valid &&
						bounds.minimum.x >= render_metrics.dashboard_clip_minimum.x -
							containment_tolerance &&
						bounds.minimum.y >= render_metrics.dashboard_clip_minimum.y -
							containment_tolerance &&
						bounds.maximum.x <= render_metrics.dashboard_clip_maximum.x +
							containment_tolerance &&
						bounds.maximum.y <= render_metrics.dashboard_clip_maximum.y +
							containment_tolerance;
				};
				const bool desktop_dashboard_contained = compact_layout ||
					(card_is_contained(render_metrics.connection_card) &&
					 card_is_contained(render_metrics.network_card) &&
					 card_is_contained(render_metrics.secret_card) &&
					 card_is_contained(render_metrics.activity_card) &&
					 card_is_contained(render_metrics.security_card) &&
					 (!recovery_expected ||
						card_is_contained(render_metrics.recovery_card)));
				const bool capture_ok =
					encoded && dimensions_ok && contrast_ok && scroll_ok &&
					interaction_ok && containment_ok && target_card_contained &&
					desktop_dashboard_contained && geometry_alignment_ok;

				std::ostringstream result;
				result << "[VISUAL] " << (capture_ok ? "PASS: " : "FAIL: ")
				       << capture_case.label << " -> "
				       << capture_path.filename().string()
				       << " | " << capture_stats.width << 'x' << capture_stats.height
				       << " | content " << render_metrics.content_scroll_y << '/'
				       << render_metrics.content_scroll_max
				       << " | activity " << render_metrics.activity_scroll_y << '/'
				       << render_metrics.activity_scroll_max
					   << " | interaction " << (interaction_ok ? "ok" : "failed")
					   << " | endpoint alignment "
					   << (endpoint_alignment_ok ? "ok" : "failed")
					   << " | chrome edges "
					   << (chrome_alignment_ok ? "aligned" : "failed")
					   << " | status summary "
					   << (status_summary_geometry_ok ? "contained" : "failed")
					   << " | card grid "
					   << (card_grid_alignment_ok ? "aligned" : "failed")
					   << " | recovery " << (recovery_state_ok ? "ok" : "failed")
					   << " | config lock " << (configuration_state_ok ? "ok" : "failed")
					   << " | locked input "
					   << (configuration_behavior_ok ? "rejected" : "changed")
					   << " | security state " << (security_state_ok ? "ok" : "failed")
					   << " | phase " << (phase_state_ok ? "ok" : "failed")
					   << " | keyboard " << (keyboard_path_ok ? "ok" : "failed")
					   << " | controls " << (containment_ok ? "contained" : "clipped")
					   << " | activity rows "
					   << (activity_rows_ok ? "complete" : "clipped")
					   << " | dashboard "
					   << (desktop_dashboard_contained ? "complete" : "clipped")
					   << " | target card "
					   << (target_card_contained ? "complete" : "clipped")
					   << " | capture "
					   << (compact_section_capture ? "section" : "viewport")
				       << " | luma "
				       << static_cast<unsigned int>(capture_stats.minimum_luma)
				       << ".."
				       << static_cast<unsigned int>(capture_stats.maximum_luma);
				append_visual_report(result.str());
				if (!capture_ok) gui_smoke_failed = true;

				++visual_case_index;
				visual_settle_frames = 0U;
				visual_case_configured = false;
				if (visual_case_index == kVisualCaptureCases.size()) {
					append_visual_report(std::string("[VISUAL] ") +
						(gui_smoke_failed ? "FAIL" : "PASS") +
						": all scripted views and scroll positions captured");
					done = true;
				}
			}
		}
#endif

		// Present
		HRESULT hr = g_pSwapChain->Present(1, 0); // Present with vsync
		//HRESULT hr = g_pSwapChain->Present(0, 0); // Present without vsync
		g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
		if (FAILED(hr)) {
			gui_smoke_failed = true;
			done = gui_smoke_test;
		} else if (gui_smoke_test && !g_SwapChainOccluded) {
			++rendered_smoke_frames;
#ifndef TRUETUNNEL_GUI_VISUAL_TEST
			if (rendered_smoke_frames >= 30U) {
				done = true;
			}
#endif
		}
	}

	if (gui_smoke_test) {
		const bool frames_ok = rendered_smoke_frames >= 30U;
		const bool action_states_ok = smoke_connect_rendered &&
			(!kGuiVisualTestBuild || smoke_disconnect_rendered);
		const bool controls_ok =
			action_states_ok &&
			smoke_password_rendered && smoke_regenerate_rendered &&
			smoke_transport_rendered && smoke_cipher_rendered &&
			smoke_message_rendered && smoke_recovery_rendered &&
			smoke_main_panel_visible;
		append_log(std::string("[SMOKE] rendered frames (30 required): ") +
		           (frames_ok ? "PASS" : "FAIL"));
		append_log(std::string("[SMOKE] core controls rendered: ") +
		           (controls_ok ? "PASS" : "FAIL"));
		append_log(std::string("[SMOKE] client recovery control visible and enabled: ") +
		           (smoke_recovery_rendered ? "PASS" : "FAIL"));
		if (!frames_ok || !controls_ok || g_gui_smoke_log_write_failed) {
			gui_smoke_failed = true;
		}
	}

	// Cleanup
	if (!secret_clipboard.clear_before_shutdown(hwnd)) {
		append_log("[!] Exiting without clearing the copied shared key at the user's request");
	}
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
	::SecureZeroMemory(password.data(), password.size());
	close_gui_smoke_log();

	return gui_smoke_failed ? 1 : 0;
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
	// Dear ImGui already anti-aliases its geometry. A single-sample swap chain
	// matches the official DX11 backend example and avoids needless resolve work.
	sd.SampleDesc.Count = 1;
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
	const UINT feature_level_count =
		static_cast<UINT>(IM_ARRAYSIZE(featureLevelArray));
	HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
	                                            featureLevelArray, feature_level_count, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
	                                            &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
	if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
		res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags,
		                                    featureLevelArray, feature_level_count, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice,
		                                    &featureLevel, &g_pd3dDeviceContext);
	if (res != S_OK)
		return false;

	return CreateRenderTarget();
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

bool CreateRenderTarget() {
	if (g_pSwapChain == nullptr || g_pd3dDevice == nullptr) return false;

	ID3D11Texture2D* back_buffer = nullptr;
	const HRESULT buffer_result =
		g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
	if (FAILED(buffer_result) || back_buffer == nullptr) return false;

	const HRESULT view_result = g_pd3dDevice->CreateRenderTargetView(
		back_buffer, nullptr, &g_mainRenderTargetView);
	back_buffer->Release();
	return SUCCEEDED(view_result) && g_mainRenderTargetView != nullptr;
}

void CleanupRenderTarget() {
	if (g_mainRenderTargetView) {
		g_mainRenderTargetView->Release();
		g_mainRenderTargetView = nullptr;
	}
}

namespace {
#ifdef TRUETUNNEL_GUI_VISUAL_TEST
bool capture_back_buffer_png(
		const std::filesystem::path& path,
		BackBufferCaptureStats& stats,
		const RECT* capture_region) noexcept {
	stats = {};
	if (g_pSwapChain == nullptr || g_pd3dDevice == nullptr ||
		g_pd3dDeviceContext == nullptr || path.empty()) {
		return false;
	}

	try {
		using Microsoft::WRL::ComPtr;
		ComPtr<ID3D11Texture2D> back_buffer;
		if (FAILED(g_pSwapChain->GetBuffer(
				0U, IID_PPV_ARGS(back_buffer.GetAddressOf()))) || !back_buffer) {
			return false;
		}

		D3D11_TEXTURE2D_DESC source_description{};
		back_buffer->GetDesc(&source_description);
		if (source_description.Width == 0U || source_description.Height == 0U ||
			source_description.Width >
				(std::numeric_limits<UINT>::max)() / 4U) {
			return false;
		}
		UINT output_left = 0U;
		UINT output_top = 0U;
		UINT output_width = source_description.Width;
		UINT output_height = source_description.Height;
		if (capture_region != nullptr) {
			if (capture_region->left < 0L || capture_region->top < 0L ||
				capture_region->right <= capture_region->left ||
				capture_region->bottom <= capture_region->top ||
				static_cast<UINT>(capture_region->right) > source_description.Width ||
				static_cast<UINT>(capture_region->bottom) > source_description.Height) {
				return false;
			}
			output_left = static_cast<UINT>(capture_region->left);
			output_top = static_cast<UINT>(capture_region->top);
			output_width = static_cast<UINT>(
				capture_region->right - capture_region->left);
			output_height = static_cast<UINT>(
				capture_region->bottom - capture_region->top);
		}

		ComPtr<ID3D11Texture2D> resolved;
		ID3D11Texture2D* copy_source = back_buffer.Get();
		if (source_description.SampleDesc.Count > 1U) {
			D3D11_TEXTURE2D_DESC resolved_description = source_description;
			resolved_description.SampleDesc.Count = 1U;
			resolved_description.SampleDesc.Quality = 0U;
			resolved_description.Usage = D3D11_USAGE_DEFAULT;
			resolved_description.BindFlags = 0U;
			resolved_description.CPUAccessFlags = 0U;
			resolved_description.MiscFlags = 0U;
			if (FAILED(g_pd3dDevice->CreateTexture2D(
					&resolved_description, nullptr, resolved.GetAddressOf())) ||
				!resolved) {
				return false;
			}
			g_pd3dDeviceContext->ResolveSubresource(
				resolved.Get(), 0U, back_buffer.Get(), 0U,
				source_description.Format);
			copy_source = resolved.Get();
			source_description = resolved_description;
		}

		D3D11_TEXTURE2D_DESC staging_description = source_description;
		staging_description.Usage = D3D11_USAGE_STAGING;
		staging_description.BindFlags = 0U;
		staging_description.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
		staging_description.MiscFlags = 0U;
		staging_description.SampleDesc.Count = 1U;
		staging_description.SampleDesc.Quality = 0U;
		ComPtr<ID3D11Texture2D> staging;
		if (FAILED(g_pd3dDevice->CreateTexture2D(
				&staging_description, nullptr, staging.GetAddressOf())) ||
			!staging) {
			return false;
		}
		g_pd3dDeviceContext->CopyResource(staging.Get(), copy_source);

		const UINT source_stride = source_description.Width * 4U;
		if (output_width > (std::numeric_limits<UINT>::max)() / 4U) {
			return false;
		}
		const UINT stride = output_width * 4U;
		const std::uint64_t byte_count_64 =
			static_cast<std::uint64_t>(stride) * output_height;
		if (byte_count_64 == 0U ||
			byte_count_64 > (std::numeric_limits<UINT>::max)() ||
			byte_count_64 > (std::numeric_limits<std::size_t>::max)()) {
			return false;
		}
		const UINT byte_count = static_cast<UINT>(byte_count_64);
		std::vector<std::uint8_t> pixels(static_cast<std::size_t>(byte_count));

		D3D11_MAPPED_SUBRESOURCE mapped{};
		if (FAILED(g_pd3dDeviceContext->Map(
				staging.Get(), 0U, D3D11_MAP_READ, 0U, &mapped))) {
			return false;
		}
		if (mapped.pData == nullptr || mapped.RowPitch < source_stride) {
			g_pd3dDeviceContext->Unmap(staging.Get(), 0U);
			return false;
		}
		for (UINT row = 0U; row < output_height; ++row) {
			const auto* source = static_cast<const std::uint8_t*>(mapped.pData) +
				static_cast<std::size_t>(output_top + row) * mapped.RowPitch +
				static_cast<std::size_t>(output_left) * 4U;
			auto* destination = pixels.data() +
				static_cast<std::size_t>(row) * stride;
			std::memcpy(destination, source, stride);
		}
		g_pd3dDeviceContext->Unmap(staging.Get(), 0U);

		for (std::size_t offset = 0U; offset < pixels.size(); offset += 4U) {
			const unsigned int luma =
				(static_cast<unsigned int>(pixels[offset]) * 54U +
				 static_cast<unsigned int>(pixels[offset + 1U]) * 183U +
				 static_cast<unsigned int>(pixels[offset + 2U]) * 19U) >> 8U;
			stats.minimum_luma = (std::min)(
				stats.minimum_luma, static_cast<std::uint8_t>(luma));
			stats.maximum_luma = (std::max)(
				stats.maximum_luma, static_cast<std::uint8_t>(luma));
			// WIC's PNG encoder accepts 32-bit BGRA. The DXGI swap chain is
			// R8G8B8A8, so perform the explicit channel conversion here.
			std::swap(pixels[offset], pixels[offset + 2U]);
		}

		if (!::DeleteFileW(path.c_str())) {
			const DWORD error = ::GetLastError();
			if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
				return false;
			}
		}

		ComPtr<IWICImagingFactory> factory;
		if (FAILED(::CoCreateInstance(
				CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
				IID_PPV_ARGS(factory.GetAddressOf()))) || !factory) {
			return false;
		}
		ComPtr<IWICStream> stream;
		if (FAILED(factory->CreateStream(stream.GetAddressOf())) || !stream ||
			FAILED(stream->InitializeFromFilename(path.c_str(), GENERIC_WRITE))) {
			return false;
		}
		ComPtr<IWICBitmapEncoder> encoder;
		if (FAILED(factory->CreateEncoder(
				GUID_ContainerFormatPng, nullptr, encoder.GetAddressOf())) ||
			!encoder ||
			FAILED(encoder->Initialize(stream.Get(), WICBitmapEncoderNoCache))) {
			return false;
		}
		ComPtr<IWICBitmapFrameEncode> frame;
		ComPtr<IPropertyBag2> properties;
		if (FAILED(encoder->CreateNewFrame(
				frame.GetAddressOf(), properties.GetAddressOf())) || !frame ||
			FAILED(frame->Initialize(properties.Get())) ||
			FAILED(frame->SetSize(
				output_width, output_height))) {
			return false;
		}
		WICPixelFormatGUID pixel_format = GUID_WICPixelFormat32bppBGRA;
		if (FAILED(frame->SetPixelFormat(&pixel_format)) ||
			!::IsEqualGUID(pixel_format, GUID_WICPixelFormat32bppBGRA) ||
			FAILED(frame->WritePixels(
				output_height, stride, byte_count, pixels.data())) ||
			FAILED(frame->Commit()) || FAILED(encoder->Commit()) ||
			FAILED(stream->Commit(STGC_DEFAULT))) {
			return false;
		}

		stats.width = output_width;
		stats.height = output_height;
		return true;
	} catch (...) {
		return false;
	}
}
#endif
} // namespace

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0 // From Windows SDK 8.1+ headers
#endif

// Win32 message handler
// You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
// - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
// - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
// Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
		return true;

	switch (msg) {
		case WM_GETMINMAXINFO: {
			auto* const limits = reinterpret_cast<MINMAXINFO*>(lParam);
			if (limits != nullptr) {
				const float window_scale = static_cast<float>(
					(std::max)(96U, ::GetDpiForWindow(hWnd))) / 96.0f;
				limits->ptMinTrackSize.x = static_cast<LONG>(760.0f * window_scale);
				limits->ptMinTrackSize.y = static_cast<LONG>(640.0f * window_scale);
			}
			return 0;
		}

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
			// Dear ImGui uses a uniform logical coordinate scale; use the X-axis
			// DPI from LOWORD as specified by WM_DPICHANGED.
			g_pending_dpi = LOWORD(wParam);
			if (const auto* suggested_rect =
					reinterpret_cast<const RECT*>(lParam)) {
				::SetWindowPos(
					hWnd, nullptr, suggested_rect->left, suggested_rect->top,
					suggested_rect->right - suggested_rect->left,
					suggested_rect->bottom - suggested_rect->top,
					SWP_NOZORDER | SWP_NOACTIVATE);
			}
			return 0;
	}

	return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
