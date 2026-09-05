#include "BridgeProtocol.h"
#include "Networking.h"
#include "core/VpnDaemon.h"
#include "secure/SharedSecret.h"
#include <deque>
#include <json.hpp>
#include <mutex>

namespace desktop {
namespace {
using Json = nlohmann::json;
const char *phase_name(ConnectionPhase phase) {
    switch (phase) {
    case ConnectionPhase::Connecting:
        return "connecting";
    case ConnectionPhase::Connected:
        return "connected";
    case ConnectionPhase::Reconnecting:
        return "reconnecting";
    case ConnectionPhase::Listening:
        return "listening";
    default:
        return "idle";
    }
}
bool start_daemon(VpnDaemon &daemon, const StartRequest &request) {
    if (!valid_start_request(request))
        return false;
    std::string_view secret(request.secret.data(),
                            strnlen_s(request.secret.data(), request.secret.size()));
    std::string_view address(request.address.data(),
                             strnlen_s(request.address.data(), request.address.size()));
    // Resolve identity again in the privileged process; never accept adapter
    // names, routes, executable paths or networking commands from JavaScript.
    MIB_IF_ROW2 row{};
    row.InterfaceLuid.Value = request.adapter_luid;
    if (GetIfEntry2(&row) != NO_ERROR || row.OperStatus != IfOperStatusUp ||
        (row.Type != IF_TYPE_ETHERNET_CSMACD && row.Type != IF_TYPE_IEEE80211) ||
        row.TunnelType != TUNNEL_TYPE_NONE)
        return false;
    VpnDaemon::SessionConfig config;
    config.mode = request.server ? "server" : "client";
    config.server_ip = std::string(address);
    config.port = static_cast<int>(request.port);
    config.adapter_name = "TrueTunnel VPN Adapter";
    config.real_adapter = GetNetworkAdapterAlias(row.InterfaceLuid);
    config.real_adapter_luid = request.adapter_luid;
    config.transport = request.udp ? TransportProtocol::Udp : TransportProtocol::Tcp;
    config.recovery.enabled = !request.server && request.recovery;
    config.password.assign(secret);
    try {
        bool started = daemon.start(config);
        SecureZeroMemory(config.password.data(), config.password.size());
        return started;
    } catch (...) {
        SecureZeroMemory(config.password.data(), config.password.size());
        throw;
    }
}
} // namespace

int run_broker(std::wstring_view pipe_name, DWORD parent_pid) {
    // Only an explicitly launched, elevated copy of this image may own Wintun.
    constexpr std::wstring_view prefix = L"\\\\.\\pipe\\TrueTunnel.Desktop.";
    if (!elevated() || parent_pid == 0 || !pipe_name.starts_with(prefix) ||
        pipe_name.size() != prefix.size() + 48 ||
        pipe_name.substr(prefix.size()).find_first_not_of(L"0123456789abcdef") !=
            std::wstring_view::npos)
        return 2;
    Handle parent(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, parent_pid));
    if (!parent || !same_application(parent.get()))
        return 3;
    const std::wstring name(pipe_name);
    Handle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                            nullptr));
    if (!pipe)
        return 4;
    ULONG actual_parent = 0;
    if (!GetNamedPipeServerProcessId(pipe.get(), &actual_parent) || actual_parent != parent_pid)
        return 5;
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0)
        return 6;
    const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    int result = 0;
    {
        std::mutex logs_mutex;
        std::deque<std::string> logs;
        std::string error;
        VpnDaemon daemon;
        daemon.set_event_callback([&](const VpnDaemon::TelemetryEvent &event) {
            std::lock_guard lock(logs_mutex);
            std::string text = event.message.substr(0, 2048);
            if (event.type == VpnDaemon::EventType::Error)
                error = text;
            if (logs.size() >= 128)
                logs.pop_front();
            logs.push_back(std::move(text));
        });
        bool started = false;
        auto start_time = std::chrono::steady_clock::now();
        try {
            while (WaitForSingleObject(parent.get(), 0) == WAIT_TIMEOUT) {
                Header header;
                if (!read_header(pipe.get(), header, parent.get()) || !valid_request(header))
                    break;
                std::array<char, 512> chat{};
                bool stop = false;
                if (header.operation == Operation::Start) {
                    StartRequest request{};
                    if (!pipe_io(pipe.get(), false, &request, sizeof(request), parent.get())) {
                        SecureZeroMemory(&request, sizeof(request));
                        break;
                    }
                    bool accepted = false;
                    try {
                        if (!started)
                            accepted = start_daemon(daemon, request);
                    } catch (...) {
                        SecureZeroMemory(&request, sizeof(request));
                        throw;
                    }
                    SecureZeroMemory(&request, sizeof(request));
                    if (!accepted) {
                        std::lock_guard lock(logs_mutex);
                        error = "The network worker rejected the connection settings. Check the "
                                "endpoint, key and physical adapter.";
                        stop = true;
                    } else {
                        started = true;
                        start_time = std::chrono::steady_clock::now();
                    }
                } else if (header.operation == Operation::Chat) {
                    if (!started ||
                        !pipe_io(pipe.get(), false, chat.data(), header.length, parent.get()))
                        break;
                    std::string text(chat.data(), header.length);
                    if (text.find('\0') != std::string::npos || !daemon.send_message(text)) {
                        std::lock_guard lock(logs_mutex);
                        if (logs.size() >= 128)
                            logs.pop_front();
                        logs.push_back("[!] Message could not be delivered.");
                    }
                    SecureZeroMemory(chat.data(), chat.size());
                } else if (header.operation == Operation::Stop) {
                    daemon.stop();
                    stop = true;
                } else if (!started)
                    break;
                const auto status = daemon.connection_status();
                Json update{{"phase", phase_name(status.phase)},
                            {"retryAttempt", status.retry_attempt},
                            {"retryDelay", status.retry_delay.count()},
                            {"uptime", std::chrono::duration_cast<std::chrono::seconds>(
                                           std::chrono::steady_clock::now() - start_time)
                                           .count()},
                            {"logs", Json::array()}};
                {
                    std::lock_guard lock(logs_mutex);
                    update["error"] = error;
                    size_t bytes = 0;
                    while (!logs.empty()) {
                        const size_t encoded =
                            Json(logs.front())
                                .dump(-1, ' ', false, Json::error_handler_t::replace)
                                .size();
                        if (bytes + encoded > 14000)
                            break;
                        bytes += encoded;
                        update["logs"].push_back(std::move(logs.front()));
                        logs.pop_front();
                    }
                }
                const auto serialized = update.dump(-1, ' ', false, Json::error_handler_t::replace);
                if (!write_frame(pipe.get(), Operation::Snapshot, serialized.data(),
                                 static_cast<uint32_t>(serialized.size()), parent.get()))
                    break;
                if (stop || (started && status.phase == ConnectionPhase::Idle))
                    break;
            }
        } catch (...) {
            result = 7;
        }
        // A closed pipe, dead UI, protocol violation or timeout all tear down
        // the exact existing engine normally, including its Wintun lease.
        daemon.stop();
        daemon.set_event_callback({});
    }
    if (SUCCEEDED(com))
        CoUninitialize();
    WSACleanup();
    return result;
}
} // namespace desktop
