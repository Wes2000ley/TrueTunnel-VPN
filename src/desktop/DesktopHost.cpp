#include "BridgeProtocol.h"
#include "DesktopAssets.h"
#include "NativeCommon.h"
#include "SecretStore.h"
// clang-format off
#include <objbase.h>
#include <WebView2.h>
#include <WebView2EnvironmentOptions.h>
// clang-format on
#include <atomic>
#include <chrono>
#include <deque>
#include <dwmapi.h>
#include <fstream>
#include <functional>
#include <iphlpapi.h>
#include <json.hpp>
#include <mutex>
#include <shlobj.h>
#include <shlwapi.h>
#include <thread>
#include <wrl.h>
#include <ws2tcpip.h>

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;
using Json = nlohmann::json;
namespace desktop {
namespace {
constexpr wchar_t kOrigin[] = L"https://app.truetunnel.invalid";
constexpr wchar_t kDocument[] = L"https://app.truetunnel.invalid/";
constexpr UINT kUpdated = WM_APP + 1;
constexpr UINT kTray = WM_APP + 2;
constexpr UINT kTimer = 1;
constexpr UINT kTrayIcon = 1;

void checked(HRESULT result) {
    if (FAILED(result))
        throw std::runtime_error(
            "Unable to configure the secure desktop view. Update WebView2 and restart TrueTunnel.");
}

// Own the child until its normal cleanup has completed, on every exit path.
// A second connection may not start while the old Wintun lease is being closed.
struct BrokerLifetime {
    HANDLE pipe;
    Handle process;
    std::function<void()> stopping;
    ~BrokerLifetime() {
        DisconnectNamedPipe(pipe);
        if (process) {
            try {
                stopping();
            } catch (...) {
            }
            WaitForSingleObject(process.get(), INFINITE);
        }
    }
};

std::string timestamp() {
    SYSTEMTIME time{};
    GetLocalTime(&time);
    char text[16]{};
    sprintf_s(text, "%02u:%02u:%02u", time.wHour, time.wMinute, time.wSecond);
    return text;
}
Json enumerate_adapters() {
    ULONG length = 16000;
    std::vector<BYTE> buffer(length);
    ULONG result = 0;
    for (int attempt = 0; attempt < 3; ++attempt) {
        result = GetAdaptersAddresses(
            AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()), &length);
        if (result != ERROR_BUFFER_OVERFLOW)
            break;
        if (length > 1024 * 1024)
            throw std::runtime_error("Adapter inventory exceeds safe limit");
        buffer.resize(length);
    }
    Json adapters = Json::array();
    if (result == ERROR_NO_DATA)
        return adapters;
    if (result != NO_ERROR)
        throw std::runtime_error("Windows could not enumerate network adapters");
    for (auto *row = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()); row;
         row = row->Next) {
        if (row->OperStatus != IfOperStatusUp ||
            (row->IfType != IF_TYPE_ETHERNET_CSMACD && row->IfType != IF_TYPE_IEEE80211) ||
            row->TunnelType != TUNNEL_TYPE_NONE)
            continue;
        for (auto *address = row->FirstUnicastAddress; address; address = address->Next) {
            if (!address->Address.lpSockaddr || address->Address.lpSockaddr->sa_family != AF_INET)
                continue;
            char ip[INET_ADDRSTRLEN]{};
            auto *ipv4 = reinterpret_cast<sockaddr_in *>(address->Address.lpSockaddr);
            if (!inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof(ip)))
                continue;
            adapters.push_back({{"id", std::to_string(row->Luid.Value)},
                                {"name", narrow(row->FriendlyName ? row->FriendlyName : L"")},
                                {"description", narrow(row->Description ? row->Description : L"")},
                                {"ip", ip}});
            break;
        }
    }
    return adapters;
}

class DesktopHost {
  public:
    HWND window{};
    bool smoke{};
    int exit_code{};
    DesktopHost() : stop_event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
        if (!stop_event_)
            throw std::runtime_error("Cannot create desktop shutdown event");
    }
    ~DesktopHost() {
        SetEvent(stop_event_.get());
        if (worker_.joinable())
            worker_.join();
        if (controller_)
            controller_->Close();
        clipboard_.clear_now_if_owned(window);
        remove_tray();
    }
    void initialize() {
        {
            std::lock_guard lock(mutex_);
            state_["adapters"] = enumerate_adapters();
        }
        if (smoke) {
            std::lock_guard lock(mutex_);
            state_["adapters"] = Json::array({{{"id", "1"},
                                               {"name", "Ethernet"},
                                               {"description", "Desktop preview adapter"},
                                               {"ip", "192.0.2.20"}}});
        }
        PWSTR app_data = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &app_data)))
            throw std::runtime_error("Cannot locate local application data");
        std::filesystem::path folder =
            std::filesystem::path(app_data) / L"TrueTunnel" / L"WebView2";
        CoTaskMemFree(app_data);
        auto options = Microsoft::WRL::Make<CoreWebView2EnvironmentOptions>();
        options->put_AllowSingleSignOnUsingOSPrimaryAccount(FALSE);
        const HRESULT created = CreateCoreWebView2EnvironmentWithOptions(
            nullptr, folder.c_str(), options.Get(),
            Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
                [this](HRESULT hr, ICoreWebView2Environment *environment) -> HRESULT {
                    if (FAILED(hr) || !environment) {
                        fail_start("Microsoft Edge WebView2 Runtime is required. Install or update "
                                   "the Evergreen Runtime, then reopen TrueTunnel.");
                        return S_OK;
                    }
                    environment_ = environment;
                    ComPtr<ICoreWebView2Environment10> environment10;
                    if (FAILED(environment_.As(&environment10))) {
                        fail_start(
                            "Update the Microsoft Edge WebView2 Runtime to open TrueTunnel.");
                        return S_OK;
                    }
                    ComPtr<ICoreWebView2ControllerOptions> controller_options;
                    if (FAILED(environment10->CreateCoreWebView2ControllerOptions(
                            &controller_options)) ||
                        FAILED(controller_options->put_IsInPrivateModeEnabled(TRUE))) {
                        fail_start("Unable to create a private desktop browser profile.");
                        return S_OK;
                    }
                    return environment10->CreateCoreWebView2ControllerWithOptions(
                        window, controller_options.Get(),
                        Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                            [this](HRESULT result, ICoreWebView2Controller *controller) -> HRESULT {
                                if (FAILED(result) || !controller) {
                                    fail_start("Unable to create the TrueTunnel desktop view.");
                                    return S_OK;
                                }
                                controller_ = controller;
                                controller_->get_CoreWebView2(&webview_);
                                try {
                                    configure_webview();
                                } catch (const std::exception &error) {
                                    fail_start(error.what());
                                }
                                return S_OK;
                            })
                            .Get());
                })
                .Get());
        if (FAILED(created))
            fail_start("Microsoft Edge WebView2 Runtime could not start. Install the Evergreen "
                       "Runtime and try again.");
        SetTimer(window, kTimer, 250, nullptr);
    }
    void resize() {
        if (controller_) {
            RECT rect{};
            GetClientRect(window, &rect);
            controller_->put_Bounds(rect);
        }
    }
    void timer() {
        clipboard_.clear_if_expired(window);
        if (clipboard_expires_ != std::chrono::steady_clock::time_point{} &&
            std::chrono::steady_clock::now() < clipboard_expires_)
            publish();
        else if (clipboard_expires_ != std::chrono::steady_clock::time_point{}) {
            clipboard_expires_ = {};
            publish();
        }
        if (smoke && GetTickCount64() - started_at_ > 25000)
            finish_smoke(false, "Timed out waiting for the React UI");
    }
    void publish() {
        if (!webview_ || !ready_)
            return;
        Json snapshot;
        {
            std::lock_guard lock(mutex_);
            snapshot = state_;
        }
        snapshot["keyReady"] = secret_.ready();
        snapshot["keyGenerated"] = secret_.generated;
        snapshot["clipboardSeconds"] =
            std::max<int64_t>(0, std::chrono::duration_cast<std::chrono::seconds>(
                                     clipboard_expires_ - std::chrono::steady_clock::now())
                                     .count());
        const auto payload = widen(snapshot.dump(-1, ' ', false, Json::error_handler_t::replace));
        webview_->PostWebMessageAsJson(payload.c_str());
    }
    void close() {
        if (busy()) {
            // Normal close owns a normal engine stop. Minimize keeps the
            // tunnel alive in the tray and does not sever IPC ownership.
            if (MessageBoxW(window,
                            L"Disconnect the active tunnel and close TrueTunnel? Use Minimize to "
                            L"keep it running in the tray.",
                            L"Close TrueTunnel", MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
                return;
        }
        (void)clipboard_.clear_before_shutdown(window);
        SetEvent(stop_event_.get());
        DestroyWindow(window);
    }
    void minimize() {
        NOTIFYICONDATAW icon{};
        icon.cbSize = sizeof(icon);
        icon.hWnd = window;
        icon.uID = kTrayIcon;
        icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        icon.uCallbackMessage = kTray;
        icon.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(101));
        wcscpy_s(icon.szTip, L"TrueTunnel");
        if (Shell_NotifyIconW(NIM_ADD, &icon)) {
            tray_ = true;
            ShowWindow(window, SW_HIDE);
        }
    }
    void restore() {
        remove_tray();
        ShowWindow(window, SW_RESTORE);
        SetForegroundWindow(window);
    }
    void tray_menu() {
        HMENU menu = CreatePopupMenu();
        if (!menu)
            return;
        AppendMenuW(menu, MF_STRING, 1, L"Open TrueTunnel");
        AppendMenuW(menu, MF_STRING, 2, L"Disconnect and exit");
        POINT point{};
        GetCursorPos(&point);
        SetForegroundWindow(window);
        const UINT choice = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY, point.x, point.y, 0,
                                           window, nullptr);
        DestroyMenu(menu);
        if (choice == 1)
            restore();
        else if (choice == 2)
            close();
    }

  private:
    std::mutex mutex_;
    Json state_{{"phase", "idle"},       {"adapters", Json::array()},
                {"logs", Json::array()}, {"error", ""},
                {"uptime", 0},           {"retryAttempt", 0},
                {"retryDelay", 0},       {"engineReady", true}};
    std::deque<std::string> messages_;
    bool stop_requested_{false};
    std::thread worker_;
    Handle stop_event_;
    SecretStore secret_;
    SecretClipboardLease clipboard_;
    std::chrono::steady_clock::time_point clipboard_expires_{};
    ComPtr<ICoreWebView2Environment> environment_;
    ComPtr<ICoreWebView2Controller> controller_;
    ComPtr<ICoreWebView2> webview_;
    bool ready_{false};
    bool tray_{false};
    bool smoke_finished_{false};
    uint64_t log_id_{};
    ULONGLONG started_at_{GetTickCount64()};
    std::chrono::steady_clock::time_point command_window_{};
    unsigned command_count_{};

    bool busy() {
        std::lock_guard lock(mutex_);
        return state_["phase"] != "idle";
    }
    void remove_tray() {
        if (tray_) {
            NOTIFYICONDATAW icon{};
            icon.cbSize = sizeof(icon);
            icon.hWnd = window;
            icon.uID = kTrayIcon;
            Shell_NotifyIconW(NIM_DELETE, &icon);
            tray_ = false;
        }
    }
    void signal() { PostMessageW(window, kUpdated, 0, 0); }
    void append_locked(std::string text) {
        text.resize(std::min<size_t>(text.size(), 2048));
        const char *level =
            text.find("[!]") != std::string::npos || text.find("failed") != std::string::npos
                ? "warning"
            : text.find("[PASS]") != std::string::npos ||
                    text.find("authenticated") != std::string::npos ||
                    text.find("connected") != std::string::npos
                ? "success"
                : "info";
        auto &logs = state_["logs"];
        size_t retained_bytes = text.size();
        for (const auto &entry : logs)
            retained_bytes += entry.at("message").get_ref<const std::string &>().size();
        while (!logs.empty() && (logs.size() >= 500 || retained_bytes > 128000)) {
            retained_bytes -= logs.front().at("message").get_ref<const std::string &>().size();
            logs.erase(logs.begin());
        }
        logs.push_back({{"id", ++log_id_},
                        {"time", timestamp()},
                        {"level", level},
                        {"message", std::move(text)}});
    }
    void error(std::string text) {
        {
            std::lock_guard lock(mutex_);
            state_["error"] = text;
            append_locked(text);
        }
        signal();
    }
    void fail_start(std::string_view text) {
        if (smoke) {
            finish_smoke(false, text);
            return;
        }
        MessageBoxW(window, widen(text).c_str(), L"TrueTunnel", MB_OK | MB_ICONERROR);
        exit_code = 1;
        DestroyWindow(window);
    }
    void configure_webview() {
        if (!webview_)
            throw std::runtime_error("The WebView2 controller returned no view");
        ComPtr<ICoreWebView2Settings> settings;
        checked(webview_->get_Settings(&settings));
        checked(settings->put_AreDefaultContextMenusEnabled(FALSE));
        checked(settings->put_AreDevToolsEnabled(FALSE));
        checked(settings->put_AreHostObjectsAllowed(FALSE));
        checked(settings->put_IsStatusBarEnabled(FALSE));
        checked(settings->put_IsZoomControlEnabled(FALSE));
        checked(settings->put_IsBuiltInErrorPageEnabled(FALSE));
        ComPtr<ICoreWebView2Settings3> settings3;
        checked(settings.As(&settings3));
        checked(settings3->put_AreBrowserAcceleratorKeysEnabled(FALSE));
        ComPtr<ICoreWebView2Settings4> settings4;
        checked(settings.As(&settings4));
        checked(settings4->put_IsPasswordAutosaveEnabled(FALSE));
        checked(settings4->put_IsGeneralAutofillEnabled(FALSE));
        ComPtr<ICoreWebView2Controller2> controller2;
        if (SUCCEEDED(controller_.As(&controller2)))
            controller2->put_DefaultBackgroundColor({255, 12, 16, 19});
        EventRegistrationToken token{};
        checked(webview_->add_NavigationStarting(
            Callback<ICoreWebView2NavigationStartingEventHandler>(
                [](ICoreWebView2 *, ICoreWebView2NavigationStartingEventArgs *args) -> HRESULT {
                    LPWSTR uri = nullptr;
                    args->get_Uri(&uri);
                    const bool allowed = uri && std::wstring_view(uri) == kDocument;
                    CoTaskMemFree(uri);
                    args->put_Cancel(!allowed);
                    return S_OK;
                })
                .Get(),
            &token));
        checked(webview_->add_NewWindowRequested(
            Callback<ICoreWebView2NewWindowRequestedEventHandler>(
                [](ICoreWebView2 *, ICoreWebView2NewWindowRequestedEventArgs *args) -> HRESULT {
                    args->put_Handled(TRUE);
                    return S_OK;
                })
                .Get(),
            &token));
        checked(webview_->add_PermissionRequested(
            Callback<ICoreWebView2PermissionRequestedEventHandler>(
                [](ICoreWebView2 *, ICoreWebView2PermissionRequestedEventArgs *args) -> HRESULT {
                    args->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);
                    return S_OK;
                })
                .Get(),
            &token));
        ComPtr<ICoreWebView2_4> view4;
        checked(webview_.As(&view4));
        checked(view4->add_DownloadStarting(
            Callback<ICoreWebView2DownloadStartingEventHandler>(
                [](ICoreWebView2 *, ICoreWebView2DownloadStartingEventArgs *args) -> HRESULT {
                    args->put_Cancel(TRUE);
                    return S_OK;
                })
                .Get(),
            &token));
        checked(webview_->add_ProcessFailed(
            Callback<ICoreWebView2ProcessFailedEventHandler>(
                [this](ICoreWebView2 *, ICoreWebView2ProcessFailedEventArgs *args) -> HRESULT {
                    COREWEBVIEW2_PROCESS_FAILED_KIND kind{};
                    args->get_ProcessFailedKind(&kind);
                    if (kind == COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED ||
                        kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED ||
                        kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_UNRESPONSIVE) {
                        SetEvent(stop_event_.get());
                        fail_start("The desktop renderer stopped responding. TrueTunnel is "
                                   "disconnecting safely. Reopen the app to reconnect.");
                    }
                    return S_OK;
                })
                .Get(),
            &token));
        checked(
            webview_->AddWebResourceRequestedFilter(L"*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL));
        checked(webview_->add_WebResourceRequested(
            Callback<ICoreWebView2WebResourceRequestedEventHandler>(
                [this](ICoreWebView2 *,
                       ICoreWebView2WebResourceRequestedEventArgs *args) -> HRESULT {
                    ComPtr<ICoreWebView2WebResourceRequest> request;
                    args->get_Request(&request);
                    LPWSTR uri = nullptr;
                    LPWSTR method = nullptr;
                    request->get_Uri(&uri);
                    request->get_Method(&method);
                    std::wstring path = uri ? uri : L"";
                    bool valid = method && std::wstring_view(method) == L"GET";
                    CoTaskMemFree(uri);
                    CoTaskMemFree(method);
                    const EmbeddedAsset *asset = nullptr;
                    std::wstring prefix = std::wstring(kOrigin) + L"/";
                    if (valid && path.starts_with(prefix)) {
                        path.erase(0, std::size(kOrigin) - 1);
                        if (path == L"/")
                            path = L"/index.html";
                        for (const auto &entry : kDesktopAssets)
                            if (path == entry.path) {
                                asset = &entry;
                                break;
                            }
                    }
                    ComPtr<IStream> stream;
                    if (asset) {
                        HRSRC resource =
                            FindResourceW(nullptr, MAKEINTRESOURCEW(asset->id), RT_RCDATA);
                        HGLOBAL memory = resource ? LoadResource(nullptr, resource) : nullptr;
                        if (memory)
                            stream.Attach(
                                SHCreateMemStream(static_cast<const BYTE *>(LockResource(memory)),
                                                  SizeofResource(nullptr, resource)));
                    }
                    std::wstring headers =
                        L"Cache-Control: no-store\r\nX-Content-Type-Options: "
                        L"nosniff\r\nContent-Security-Policy: default-src 'none'; script-src "
                        L"'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src "
                        L"'self'; connect-src 'none'; frame-src 'none'; object-src 'none'; "
                        L"base-uri 'none'; form-action 'none'\r\nContent-Type: ";
                    headers += asset ? asset->mime : L"text/plain";
                    ComPtr<ICoreWebView2WebResourceResponse> response;
                    const HRESULT result = environment_->CreateWebResourceResponse(
                        stream.Get(), stream ? 200 : 403, stream ? L"OK" : L"Forbidden",
                        headers.c_str(), &response);
                    if (FAILED(result)) {
                        fail_start("The embedded desktop resource could not be served.");
                        return result;
                    }
                    return args->put_Response(response.Get());
                })
                .Get(),
            &token));
        checked(webview_->add_WebMessageReceived(
            Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                [this](ICoreWebView2 *, ICoreWebView2WebMessageReceivedEventArgs *args) -> HRESULT {
                    LPWSTR source = nullptr;
                    args->get_Source(&source);
                    bool trusted = source && std::wstring_view(source) == kDocument;
                    CoTaskMemFree(source);
                    if (!trusted)
                        return S_OK;
                    LPWSTR raw = nullptr;
                    args->get_WebMessageAsJson(&raw);
                    try {
                        if (raw && wcsnlen_s(raw, 4097) <= 4096)
                            command(Json::parse(narrow(raw)));
                    } catch (...) {
                        error("The desktop request was invalid. No network changes were made.");
                    }
                    CoTaskMemFree(raw);
                    return S_OK;
                })
                .Get(),
            &token));
        checked(webview_->add_NavigationCompleted(
            Callback<ICoreWebView2NavigationCompletedEventHandler>(
                [this](ICoreWebView2 *,
                       ICoreWebView2NavigationCompletedEventArgs *args) -> HRESULT {
                    BOOL success = FALSE;
                    args->get_IsSuccess(&success);
                    if (!success)
                        fail_start("The embedded TrueTunnel interface could not load.");
                    return S_OK;
                })
                .Get(),
            &token));
        resize();
        checked(controller_->put_IsVisible(TRUE));
        checked(webview_->Navigate(kDocument));
    }
    void command(const Json &command) {
        if (!command.is_object() || !command.contains("type") || !command["type"].is_string())
            return;
        const auto now = std::chrono::steady_clock::now();
        if (now - command_window_ > std::chrono::seconds(1)) {
            command_window_ = now;
            command_count_ = 0;
        }
        if (++command_count_ > 30)
            return;
        const auto type = command["type"].get<std::string>();
        if (type == "ready") {
            ready_ = true;
            publish();
            if (smoke && !smoke_started_) {
                smoke_started_ = true;
                run_smoke();
            }
            return;
        }
        if (type == "smokeResult" && smoke) {
            finish_smoke(command.value("ok", false), "React DOM, layout and native bridge smoke");
            return;
        }
        if (type == "clearLogs") {
            std::lock_guard lock(mutex_);
            state_["logs"] = Json::array();
        } else if (type == "copyKey" && secret_.ready()) {
            if (clipboard_.copy_secret(window, secret_.value))
                clipboard_expires_ = now + kClipboardSecretLifetime;
            else
                error("The clipboard is busy. Try copying again.");
        } else if (type == "stop") {
            std::lock_guard lock(mutex_);
            stop_requested_ = true;
            if (state_["phase"] != "idle")
                state_["phase"] = "stopping";
        } else if (type == "sendMessage") {
            auto text = command.at("text").get<std::string>();
            if (text.empty() || text.size() > 512 || text.find('\0') != std::string::npos)
                throw std::runtime_error("Invalid chat message");
            std::lock_guard lock(mutex_);
            if (messages_.size() < 8 &&
                (state_["phase"] == "connected" || state_["phase"] == "listening"))
                messages_.push_back(std::move(text));
        } else if (!busy()) {
            if (type == "refreshAdapters") {
                auto adapters = enumerate_adapters();
                std::lock_guard lock(mutex_);
                state_["adapters"] = std::move(adapters);
                state_["error"] = "";
            } else if (type == "generateKey") {
                clipboard_.clear_now_if_owned(window);
                if (!secret_.generate())
                    error("Windows could not generate the access key.");
                else {
                    std::lock_guard lock(mutex_);
                    state_["error"] = "";
                }
            } else if (type == "pasteKey") {
                if (!secret_.paste(window))
                    error("Clipboard must contain exactly the server’s generated 43-character "
                          "access key.");
                else {
                    std::lock_guard lock(mutex_);
                    state_["error"] = "";
                }
            } else if (type == "clearKey") {
                clipboard_.clear_now_if_owned(window);
                clipboard_expires_ = {};
                secret_.clear();
            } else if (type == "start" && !smoke)
                start(command.at("config"));
        }
        publish();
    }
    void start(const Json &config) {
        const auto role = config.at("role").get<std::string>();
        const auto transport = config.at("transport").get<std::string>();
        const auto address = config.at("address").get<std::string>();
        const auto port_text = config.at("port").get<std::string>();
        const auto adapter = config.at("adapter").get<std::string>();
        const bool recovery = config.at("recovery").get<bool>();
        if ((role != "client" && role != "server") || (transport != "udp" && transport != "tcp") ||
            address.size() > 253 || address.find('\0') != std::string::npos || port_text.empty() ||
            port_text.size() > 5 ||
            port_text.find_first_not_of("0123456789") != std::string::npos || adapter.empty() ||
            adapter.size() > 20 || adapter.find_first_not_of("0123456789") != std::string::npos)
            throw std::runtime_error("Invalid connection settings");
        const unsigned port = std::stoul(port_text);
        if (!port || port > 65535 || !secret_.ready() || (role == "server" && !secret_.generated)) {
            error("Add a valid access key and port before connecting. Servers require a generated "
                  "key.");
            return;
        }
        if (role == "client" &&
            (address.empty() ||
             address.find_first_not_of(
                 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-") !=
                 std::string::npos)) {
            error("Enter an IPv4 address or hostname without a URL or port.");
            return;
        }
        bool adapter_valid = false;
        {
            std::lock_guard lock(mutex_);
            for (const auto &entry : state_["adapters"])
                if (entry["id"] == adapter)
                    adapter_valid = true;
        }
        if (!adapter_valid) {
            error("Select a currently available physical network adapter.");
            return;
        }
        if (worker_.joinable())
            worker_.join();
        SensitiveStartRequest request{new StartRequest{}};
        request->adapter_luid = std::stoull(adapter);
        request->port = port;
        request->server = role == "server";
        request->udp = transport == "udp";
        request->recovery = recovery;
        std::copy(address.begin(), address.end(), request->address.begin());
        request->secret = secret_.value;
        {
            std::lock_guard lock(mutex_);
            state_["phase"] = "authorizing";
            state_["error"] = "";
            stop_requested_ = false;
            messages_.clear();
            append_locked("Requesting permission to start the Windows network worker.");
        }
        ResetEvent(stop_event_.get());
        try {
            worker_ = std::thread([this, request = std::move(request)]() mutable {
                try {
                    run_session(*request);
                } catch (const std::exception &exception) {
                    error(exception.what());
                }
                SecureZeroMemory(request.get(), sizeof(StartRequest));
                request.reset();
                {
                    std::lock_guard lock(mutex_);
                    state_["phase"] = "idle";
                    state_["uptime"] = 0;
                    state_["retryAttempt"] = 0;
                    messages_.clear();
                }
                signal();
            });
        } catch (...) {
            std::lock_guard lock(mutex_);
            state_["phase"] = "idle";
            throw;
        }
    }
    void run_session(StartRequest &request) {
        const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (FAILED(com))
            throw std::runtime_error("Cannot initialize the Windows permission launcher");
        struct Apartment {
            ~Apartment() { CoUninitialize(); }
        } apartment;
        const std::wstring pipe_name = L"\\\\.\\pipe\\TrueTunnel.Desktop." + random_suffix();
        Handle pipe = create_private_pipe(pipe_name);
        Handle connected(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!connected)
            throw std::runtime_error("Cannot create the networking connection event");
        OVERLAPPED connection{};
        connection.hEvent = connected.get();
        BOOL immediate = ConnectNamedPipe(pipe.get(), &connection);
        DWORD pending_error = immediate ? ERROR_SUCCESS : GetLastError();
        struct PendingConnection {
            HANDLE pipe, event;
            OVERLAPPED *operation;
            bool pending;
            ~PendingConnection() {
                // Includes allocation/launch exceptions before the child exists.
                // The OVERLAPPED storage may not die while Windows still uses it.
                if (pending) {
                    CancelIoEx(pipe, operation);
                    WaitForSingleObject(event, INFINITE);
                }
            }
        } pending{pipe.get(), connected.get(), &connection, pending_error == ERROR_IO_PENDING};
        if (!immediate && pending_error != ERROR_IO_PENDING &&
            pending_error != ERROR_PIPE_CONNECTED)
            throw std::runtime_error("Cannot listen on the private networking channel");
        const std::wstring arguments =
            L"--broker " + pipe_name + L" " + std::to_wstring(GetCurrentProcessId());
        SHELLEXECUTEINFOW launch{};
        launch.cbSize = sizeof(launch);
        launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        launch.hwnd = window;
        launch.lpVerb = L"runas";
        const auto image = executable();
        launch.lpFile = image.c_str();
        launch.lpParameters = arguments.c_str();
        launch.nShow = SW_HIDE;
        const BOOL launched = ShellExecuteExW(&launch);
        const DWORD launch_error = launched ? 0 : GetLastError();
        BrokerLifetime lifetime{pipe.get(), Handle(launch.hProcess), [this] {
                                    {
                                        std::lock_guard lock(mutex_);
                                        state_["phase"] = "stopping";
                                    }
                                    signal();
                                }};
        const Handle &child = lifetime.process;
        bool accepted = immediate || pending_error == ERROR_PIPE_CONNECTED;
        if (launched && child && !accepted) {
            HANDLE waits[]{connected.get(), child.get(), stop_event_.get()};
            accepted = WaitForMultipleObjects(3, waits, FALSE, 15000) == WAIT_OBJECT_0;
        }
        if (!accepted && pending_error == ERROR_IO_PENDING) {
            CancelIoEx(pipe.get(), &connection);
            WaitForSingleObject(connected.get(), INFINITE);
            pending.pending = false;
        }
        if (!launched)
            throw std::runtime_error(
                launch_error == ERROR_CANCELLED
                    ? "Windows approval was cancelled. Your settings are ready when you want to "
                      "try again."
                    : "Windows could not launch the network worker. Check administrator access.");
        if (!accepted || !child)
            throw std::runtime_error("The network worker did not establish its private channel.");
        ULONG client_pid = 0;
        if (!GetNamedPipeClientProcessId(pipe.get(), &client_pid) ||
            client_pid != GetProcessId(child.get()) || !same_application(child.get()))
            throw std::runtime_error("The network worker identity could not be verified.");
        bool cancelled = WaitForSingleObject(stop_event_.get(), 0) != WAIT_TIMEOUT;
        {
            std::lock_guard lock(mutex_);
            cancelled = cancelled || stop_requested_;
            if (!cancelled)
                state_["phase"] = "connecting";
        }
        if (cancelled) {
            DisconnectNamedPipe(pipe.get());
            return;
        }
        signal();
        bool first = true;
        bool normal_end = false;
        while (WaitForSingleObject(stop_event_.get(), 0) == WAIT_TIMEOUT) {
            Operation operation = Operation::Poll;
            std::string chat;
            {
                std::lock_guard lock(mutex_);
                if (stop_requested_)
                    operation = Operation::Stop;
                else if (first)
                    operation = Operation::Start;
                else if (!messages_.empty()) {
                    operation = Operation::Chat;
                    chat = std::move(messages_.front());
                    messages_.pop_front();
                }
            }
            const void *data = operation == Operation::Start
                                   ? static_cast<const void *>(&request)
                                   : static_cast<const void *>(chat.data());
            uint32_t length = operation == Operation::Start  ? sizeof(request)
                              : operation == Operation::Chat ? static_cast<uint32_t>(chat.size())
                                                             : 0;
            if (!write_frame(pipe.get(), operation, data, length, stop_event_.get()))
                break;
            if (first) {
                SecureZeroMemory(&request, sizeof(request));
                first = false;
            }
            Header header;
            if (!read_header(pipe.get(), header, stop_event_.get()) ||
                header.operation != Operation::Snapshot)
                break;
            std::string bytes(header.length, '\0');
            if (!pipe_io(pipe.get(), false, bytes.data(), header.length, stop_event_.get()))
                break;
            auto update = Json::parse(bytes);
            {
                std::lock_guard lock(mutex_);
                for (const auto *key : {"phase", "uptime", "retryAttempt", "retryDelay", "error"})
                    state_[key] = update.at(key);
                if (stop_requested_ || state_["phase"] == "idle")
                    state_["phase"] = "stopping";
                for (const auto &entry : update.at("logs"))
                    append_locked(entry.get<std::string>());
            }
            signal();
            if (update["phase"] == "idle" || operation == Operation::Stop) {
                normal_end = true;
                break;
            }
            WaitForSingleObject(stop_event_.get(), 200);
        }
        {
            std::lock_guard lock(mutex_);
            normal_end = normal_end || stop_requested_;
        }
        if (!normal_end && WaitForSingleObject(stop_event_.get(), 0) == WAIT_TIMEOUT)
            error("The network worker stopped responding. Disconnecting safely; check Activity "
                  "before reconnecting.");
    }
    bool smoke_started_{false};
    void run_smoke() {
        if (!secret_.generate()) {
            finish_smoke(false, "Native CNG generation failed");
            return;
        }
        publish();
        webview_->ExecuteScript(LR"JS(
          (() => { const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
          (async () => { await wait(350);
            const headings = [...document.querySelectorAll('h1,h2')].map(x=>x.textContent);
            const address = document.getElementById('address'), port = document.getElementById('port');
            let ok = headings.includes('Connection') && headings.includes('Access key') && !!document.querySelector('[role="switch"]');
            ok = ok && address && port && Math.abs(address.getBoundingClientRect().top-port.getBoundingClientRect().top)<1;
            ok = ok && document.documentElement.scrollWidth<=innerWidth;
            ok = ok && !document.body.innerText.includes('undefined');
            window.chrome.webview.postMessage({type:'smokeResult',ok:!!ok});
          })(); })();
        )JS",
                                nullptr);
    }
    void finish_smoke(bool ok, std::string_view description) {
        if (smoke_finished_)
            return;
        smoke_finished_ = true;
        const auto directory = executable().parent_path();
        const auto log = directory / L"TrueTunnel-gui-smoke.log";
        ok = ok && !elevated() && secret_.ready();
        const std::string text =
            std::string(ok ? "[PASS] " : "[FAIL] ") + std::string(description) +
            "\nFrontend: React / TypeScript / WebView2\nSecrets: native CNG memory only\nNetwork "
            "worker: not started\nIntegrity: unelevated\n";
        ok = write_diagnostic_file(log,
                                   {reinterpret_cast<const BYTE *>(text.data()), text.size()}) &&
             ok;
        exit_code = ok ? 0 : 1;
        if (ok && webview_) {
            ComPtr<IStream> stream;
            if (SUCCEEDED(CreateStreamOnHGlobal(nullptr, TRUE, &stream))) {
                const HRESULT captured = webview_->CapturePreview(
                    COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG, stream.Get(),
                    Callback<ICoreWebView2CapturePreviewCompletedHandler>([this, stream](HRESULT hr)
                                                                              -> HRESULT {
                        HGLOBAL memory{};
                        STATSTG stats{};
                        bool saved = false;
                        if (SUCCEEDED(hr) && SUCCEEDED(stream->Stat(&stats, STATFLAG_NONAME)) &&
                            stats.cbSize.QuadPart <= 16 * 1024 * 1024 &&
                            SUCCEEDED(GetHGlobalFromStream(stream.Get(), &memory))) {
                            if (const auto *bytes = static_cast<const BYTE *>(GlobalLock(memory))) {
                                saved = write_diagnostic_file(
                                    executable().parent_path() / L"TrueTunnel-gui-smoke.png",
                                    {bytes, static_cast<size_t>(stats.cbSize.QuadPart)});
                                GlobalUnlock(memory);
                            }
                        }
                        if (!saved)
                            exit_code = 1;
                        DestroyWindow(window);
                        return S_OK;
                    }).Get());
                if (SUCCEEDED(captured))
                    return;
            }
            exit_code = 1;
        }
        DestroyWindow(window);
    }
};

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    auto *host = reinterpret_cast<DesktopHost *>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        host =
            static_cast<DesktopHost *>(reinterpret_cast<CREATESTRUCTW *>(lparam)->lpCreateParams);
        host->window = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(host));
    }
    if (host) {
        switch (message) {
        case WM_SIZE:
            if (wparam == SIZE_MINIMIZED && !host->smoke)
                host->minimize();
            else
                host->resize();
            return 0;
        case WM_GETMINMAXINFO: {
            auto *limits = reinterpret_cast<MINMAXINFO *>(lparam);
            const UINT dpi = GetDpiForWindow(window);
            limits->ptMinTrackSize = {MulDiv(780, static_cast<int>(dpi), 96),
                                      MulDiv(600, static_cast<int>(dpi), 96)};
            return 0;
        }
        case WM_DPICHANGED: {
            const auto *rect = reinterpret_cast<RECT *>(lparam);
            SetWindowPos(window, nullptr, rect->left, rect->top, rect->right - rect->left,
                         rect->bottom - rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
            return 0;
        }
        case WM_TIMER:
            host->timer();
            return 0;
        case kUpdated:
            host->publish();
            return 0;
        case kTray:
            if (lparam == WM_LBUTTONDBLCLK)
                host->restore();
            else if (lparam == WM_RBUTTONUP)
                host->tray_menu();
            return 0;
        case WM_CLOSE:
            host->close();
            return 0;
        case WM_DESTROY:
            KillTimer(window, kTimer);
            PostQuitMessage(host->exit_code);
            return 0;
        }
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

int launch_unelevated() {
    const auto failed = [] {
        MessageBoxW(nullptr,
                    L"TrueTunnel could not obtain an unelevated desktop token. Open the app "
                    L"normally from your Windows desktop, without Run as administrator.",
                    L"Open TrueTunnel normally", MB_OK | MB_ICONERROR);
        return 1;
    };
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
        return failed();
    Handle token(raw);
    TOKEN_LINKED_TOKEN linked{};
    DWORD size{};
    if (!GetTokenInformation(token.get(), TokenLinkedToken, &linked, sizeof(linked), &size))
        return failed();
    Handle linked_token(linked.LinkedToken);
    std::wstring command(GetCommandLineW());
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessWithTokenW(linked_token.get(), 0, executable().c_str(), command.data(), 0,
                                 nullptr, executable().parent_path().c_str(), &startup, &process))
        return failed();
    Handle child(process.hProcess);
    Handle thread(process.hThread);
    WaitForSingleObject(child.get(), INFINITE);
    DWORD code{};
    GetExitCodeProcess(child.get(), &code);
    return static_cast<int>(code);
}
} // namespace
} // namespace desktop

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    using namespace desktop;
    int count{};
    LPWSTR *args = CommandLineToArgvW(GetCommandLineW(), &count);
    if (!args)
        return 2;
    std::vector<std::wstring> arguments;
    for (int index = 1; index < count; ++index)
        arguments.emplace_back(args[index]);
    LocalFree(args);
    try {
        if (!arguments.empty() && arguments[0] == L"--broker") {
            if (arguments.size() != 3 || arguments[2].empty() || arguments[2].size() > 10 ||
                arguments[2].find_first_not_of(L"0123456789") != std::wstring::npos)
                return 2;
            return run_broker(arguments[1], std::stoul(arguments[2]));
        }
        const bool smoke = arguments.size() == 1 && arguments[0] == L"--gui-smoke-test";
        if (!arguments.empty() && !smoke)
            return 2;
        if (elevated())
            return launch_unelevated();
        const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (FAILED(com))
            return 1;
        WSADATA winsock{};
        WSAStartup(MAKEWORD(2, 2), &winsock);
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        int result = 0;
        {
            DesktopHost host;
            host.smoke = smoke;
            WNDCLASSEXW cls{};
            cls.cbSize = sizeof(cls);
            cls.hInstance = instance;
            cls.lpfnWndProc = window_proc;
            cls.lpszClassName = L"TrueTunnel.Desktop";
            cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
            cls.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(101));
            cls.hIconSm = cls.hIcon;
            if (!RegisterClassExW(&cls))
                throw std::runtime_error("Cannot register desktop window");
            const UINT dpi = GetDpiForSystem();
            HWND window = CreateWindowExW(
                0, cls.lpszClassName, L"TrueTunnel", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                CW_USEDEFAULT, MulDiv(1240, static_cast<int>(dpi), 96),
                MulDiv(900, static_cast<int>(dpi), 96), nullptr, nullptr, instance, &host);
            if (!window)
                throw std::runtime_error("Cannot create desktop window");
            BOOL dark = TRUE;
            DwmSetWindowAttribute(window, 20, &dark, sizeof(dark));
            const DWM_WINDOW_CORNER_PREFERENCE corners = DWMWCP_ROUND;
            DwmSetWindowAttribute(window, DWMWA_WINDOW_CORNER_PREFERENCE, &corners,
                                  sizeof(corners));
            ShowWindow(window, smoke ? SW_SHOWNOACTIVATE : SW_SHOW);
            UpdateWindow(window);
            host.initialize();
            MSG message{};
            while (GetMessageW(&message, nullptr, 0, 0) > 0) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            result = host.exit_code;
        }
        WSACleanup();
        CoUninitialize();
        return result;
    } catch (const std::exception &exception) {
        MessageBoxW(nullptr, widen(exception.what()).c_str(), L"TrueTunnel", MB_OK | MB_ICONERROR);
        return 1;
    }
}
