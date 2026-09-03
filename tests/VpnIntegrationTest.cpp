#include "VpnServer.h"
#include "VpnClient.h"
#include "VpnController.h"
#include "utils.hpp"
#include "vpn.hpp"
#include "Networking.h"
#include "raii.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_set>
#include <vector>

#include <devguid.h>
#include <devpropdef.h>
#include <shellapi.h>
#include <setupapi.h>
#include <tlhelp32.h>

namespace {

using namespace std::chrono_literals;

constexpr std::string_view kIntegrationSharedKey =
    "QbS8dV16wlVZZO8kchOpKO_HLQHLlNpzQZNi31KK1-U";

class ThreadSafeTeeBuffer final : public std::streambuf {
public:
    ThreadSafeTeeBuffer(std::streambuf* console,
                        std::streambuf* file,
                        std::mutex& mutex) noexcept
        : console_{console}, file_{file}, mutex_{mutex} {}

protected:
    std::streamsize xsputn(const char* data, std::streamsize count) override {
        std::lock_guard<std::mutex> lock{mutex_};
        const std::streamsize console_written = console_->sputn(data, count);
        const std::streamsize file_written = file_->sputn(data, count);
        file_->pubsync();
        return (console_written == count && file_written == count) ? count : 0;
    }

    int_type overflow(const int_type value) override {
        if (traits_type::eq_int_type(value, traits_type::eof())) {
            return sync() == 0 ? traits_type::not_eof(value) : traits_type::eof();
        }
        const char character = traits_type::to_char_type(value);
        return xsputn(&character, 1) == 1
                   ? value
                   : traits_type::eof();
    }

    int sync() override {
        std::lock_guard<std::mutex> lock{mutex_};
        const int console_result = console_->pubsync();
        const int file_result = file_->pubsync();
        return (console_result == 0 && file_result == 0) ? 0 : -1;
    }

private:
    std::streambuf* console_;
    std::streambuf* file_;
    std::mutex& mutex_;
};

class ScopedProcessLog final {
public:
    explicit ScopedProcessLog(const std::filesystem::path& path)
        : file_{path, std::ios::out | std::ios::trunc},
          original_out_{std::cout.rdbuf()},
          original_err_{std::cerr.rdbuf()},
          out_buffer_{original_out_, file_.rdbuf(), mutex_},
          err_buffer_{original_err_, file_.rdbuf(), mutex_} {
        if (!file_) {
            throw std::runtime_error("Unable to open integration log: " +
                                     path.string());
        }
        std::cout.rdbuf(&out_buffer_);
        std::cerr.rdbuf(&err_buffer_);
    }

    ~ScopedProcessLog() {
        std::cout.flush();
        std::cerr.flush();
        std::cout.rdbuf(original_out_);
        std::cerr.rdbuf(original_err_);
    }

    ScopedProcessLog(const ScopedProcessLog&) = delete;
    ScopedProcessLog& operator=(const ScopedProcessLog&) = delete;

private:
    std::ofstream file_;
    std::mutex mutex_;
    std::streambuf* original_out_;
    std::streambuf* original_err_;
    ThreadSafeTeeBuffer out_buffer_;
    ThreadSafeTeeBuffer err_buffer_;
};

[[nodiscard]] std::filesystem::path executable_path() {
    std::vector<wchar_t> buffer(32'768U, L'\0');
    const DWORD copied = ::GetModuleFileNameW(
        nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (copied == 0U ||
        static_cast<std::size_t>(copied) >= buffer.size()) {
        throw std::runtime_error("GetModuleFileNameW failed");
    }
    return std::filesystem::path{std::wstring_view{buffer.data(), copied}};
}

[[nodiscard]] std::filesystem::path requested_log_path(int argc, char** argv) {
    for (int index = 1; index < argc; ++index) {
        if (std::string_view{argv[index]} == "--log-file") {
            if (index + 1 >= argc || std::string_view{argv[index + 1]}.empty()) {
                throw std::invalid_argument("--log-file requires a path");
            }
            return std::filesystem::absolute(argv[index + 1]);
        }
    }
    return executable_path().parent_path() / L"vpn-integration.log";
}

[[nodiscard]] std::wstring quote_windows_argument(const std::wstring& value) {
    std::wstring quoted{L"\""};
    std::size_t backslashes = 0U;
    for (const wchar_t character : value) {
        if (character == L'\\') {
            ++backslashes;
            continue;
        }
        if (character == L'\"') {
            quoted.append(backslashes * 2U + 1U, L'\\');
            quoted.push_back(L'\"');
        } else {
            quoted.append(backslashes, L'\\');
            quoted.push_back(character);
        }
        backslashes = 0U;
    }
    quoted.append(backslashes * 2U, L'\\');
    quoted.push_back(L'\"');
    return quoted;
}

[[nodiscard]] int relaunch_elevated_and_wait(int argc, char** argv) {
    std::wstring parameters;
    for (int index = 1; index < argc; ++index) {
        if (!parameters.empty()) parameters.push_back(L' ');
        parameters.append(quote_windows_argument(
            std::filesystem::path{argv[index]}.wstring()));
    }
    if (!parameters.empty()) parameters.push_back(L' ');
    parameters.append(L"--elevated-child");

    const std::filesystem::path executable = executable_path();
    const std::filesystem::path executable_directory = executable.parent_path();
    SHELLEXECUTEINFOW launch{};
    launch.cbSize = sizeof(launch);
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    launch.lpVerb = L"runas";
    launch.lpFile = executable.c_str();
    launch.lpParameters = parameters.c_str();
    launch.lpDirectory = executable_directory.c_str();
    launch.nShow = SW_HIDE;
    if (!::ShellExecuteExW(&launch) || launch.hProcess == nullptr) {
        std::cerr << "[FAIL] Native UAC elevation failed: "
                  << ::GetLastError() << '\n';
        return 1;
    }

    constexpr DWORD kElevatedTestTimeoutMilliseconds = 5U * 60U * 1'000U;
    const DWORD wait_result = ::WaitForSingleObject(
        launch.hProcess, kElevatedTestTimeoutMilliseconds);
    DWORD exit_code = 1U;
    if (wait_result == WAIT_TIMEOUT) {
        std::cerr << "[FAIL] Elevated integration child exceeded five minutes\n";
        (void)::TerminateProcess(launch.hProcess, 1U);
        (void)::WaitForSingleObject(launch.hProcess, 5'000U);
    } else if (wait_result != WAIT_OBJECT_0 ||
        !::GetExitCodeProcess(launch.hProcess, &exit_code)) {
        std::cerr << "[FAIL] Unable to obtain elevated test result: "
                  << ::GetLastError() << '\n';
        exit_code = 1U;
    }
    ::CloseHandle(launch.hProcess);
    return static_cast<int>(exit_code);
}

[[nodiscard]] std::string local_timestamp() {
    const std::time_t now = std::time(nullptr);
    std::tm local{};
    if (::localtime_s(&local, &now) != 0) return "unknown";
    std::ostringstream output;
    output << std::put_time(&local, "%Y-%m-%d %H:%M:%S");
    return output.str();
}

void ensure_local_host_route(const std::string& adapter_name,
                             const std::string& address) {
    if (!IsIpv4AddressAssignedLocally(address)) {
        throw std::runtime_error(
            "Selected adapter address is not present in the local address table");
    }
    if (HasIpv4HostRoute(adapter_name, address)) {
        std::cout << "[PRECHECK] Local /32 route is present for " << address << '\n';
        return;
    }

    std::cerr << "[REPAIR] Windows' system-owned local /32 route is missing for "
              << address << "; refreshing the address through IP Helper\n";
    RestoreIpv4LocalHostRoute(adapter_name, address);
    if (!HasIpv4HostRoute(adapter_name, address)) {
        throw std::runtime_error("Failed to restore the local IPv4 host route");
    }
    std::cout << "[REPAIR] Restored local /32 route for " << address << '\n';
}

void start_client_with_timeout(VpnClient& client,
                               const std::string_view label,
                               const std::chrono::seconds timeout) {
    std::atomic<bool> completed{false};
    std::exception_ptr error;
    std::thread starter{[&client, &completed, &error]() {
        try {
            client.start();
        } catch (...) {
            error = std::current_exception();
        }
        completed.store(true, std::memory_order_release);
    }};

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!completed.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(100ms);
    }
    if (!completed.load(std::memory_order_acquire)) {
        std::cerr << "[!] " << label << " startup exceeded " << timeout.count()
                  << " seconds; cancelling\n";
        client.stop();
    }
    starter.join();
    if (error) std::rethrow_exception(error);
    if (!client.is_active()) {
        throw std::runtime_error(std::string{label} + " did not become active");
    }
}

bool run_source_binding_test() {
    std::array<BYTE, 20> packet{};
    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = 20;
    packet[12] = 10;
    packet[13] = 10;
    packet[14] = 100;
    packet[15] = 10;

    if (!ipv4_source_matches(packet.data(), packet.size(), "10.10.100.10")) {
        std::cerr << "[FAIL] Assigned IPv4 source was rejected\n";
        return false;
    }

    if (is_well_formed_ipv4_packet(nullptr, packet.size()) ||
        ipv4_source_matches(nullptr, packet.size(), "10.10.100.10")) {
        std::cerr << "[FAIL] Null packet pointer was accepted\n";
        return false;
    }

    packet[15] = 11;
    if (ipv4_source_matches(packet.data(), packet.size(), "10.10.100.10")) {
        std::cerr << "[FAIL] Spoofed IPv4 source was accepted\n";
        return false;
    }

    if (ipv4_source_matches(packet.data(), 19U, "10.10.100.10")) {
        std::cerr << "[FAIL] Truncated IPv4 packet was accepted\n";
        return false;
    }

    packet[0] = 0x60;
    if (is_well_formed_ipv4_packet(packet.data(), packet.size()) ||
        ipv4_source_matches(packet.data(), packet.size(), "10.10.100.10")) {
        std::cerr << "[FAIL] IPv6 traffic was accepted by the IPv4 tunnel\n";
        return false;
    }

    packet[0] = 0x45;
    packet[3] = 21;
    if (is_well_formed_ipv4_packet(packet.data(), packet.size())) {
        std::cerr << "[FAIL] IPv4 packet with inconsistent total length was accepted\n";
        return false;
    }

    packet[3] = 20;
    packet[0] = 0x44;
    if (is_well_formed_ipv4_packet(packet.data(), packet.size())) {
        std::cerr << "[FAIL] IPv4 header shorter than 20 bytes was accepted\n";
        return false;
    }
    packet[0] = 0x4FU;
    if (is_well_formed_ipv4_packet(packet.data(), packet.size())) {
        std::cerr << "[FAIL] IPv4 header longer than the packet was accepted\n";
        return false;
    }
    packet[0] = 0x45U;
    packet[2] = 0U;
    packet[3] = 0U;
    if (is_well_formed_ipv4_packet(packet.data(), packet.size())) {
        std::cerr << "[FAIL] Zero-length IPv4 packet was accepted\n";
        return false;
    }

    std::vector<BYTE> oversized(secure::kMaximumDatagramPayloadSize + 1U, 0U);
    oversized[0] = 0x45U;
    oversized[2] = static_cast<BYTE>(oversized.size() >> 8U);
    oversized[3] = static_cast<BYTE>(oversized.size());
    if (is_well_formed_ipv4_packet(oversized.data(), oversized.size())) {
        std::cerr << "[FAIL] Packet above the tunnel MTU was accepted\n";
        return false;
    }

    bool client_port_rejected = false;
    try {
        VpnClient invalid_client{
            "127.0.0.1", 0, std::string{kIntegrationSharedKey}, "invalid-client",
            "invalid-uplink", "127.0.0.1",
            secure::CipherSuite::Aes256Gcm, TransportProtocol::Tcp};
        (void)invalid_client;
    } catch (const std::invalid_argument&) {
        client_port_rejected = true;
    }
    if (!client_port_rejected) {
        std::cerr << "[FAIL] Invalid client port was accepted\n";
        return false;
    }

    bool server_port_rejected = false;
    try {
        VpnServer invalid_server{
            65'536, "invalid-uplink", std::string{kIntegrationSharedKey},
            "invalid-server", secure::CipherSuite::Aes256Gcm,
            TransportProtocol::Udp};
        (void)invalid_server;
    } catch (const std::invalid_argument&) {
        server_port_rejected = true;
    }
    if (!server_port_rejected) {
        std::cerr << "[FAIL] Invalid server port was accepted\n";
        return false;
    }

    VpnController controller;
    if (controller.start(
            "client", "127.0.0.1", -1, {}, {},
            std::string{kIntegrationSharedKey}, "invalid-controller", {},
            "127.0.0.1", "invalid-uplink",
            0U,
            secure::CipherSuite::Aes256Gcm, TransportProtocol::Tcp)) {
        std::cerr << "[FAIL] Controller started with an invalid port\n";
        controller.stop();
        return false;
    }

    std::cout << "[PASS] IPv4 bounds/source binding and public port validation\n";
    return true;
}

bool run_wintun_identity_derivation_test() {
    try {
        const GUID canonical =
            derive_wintun_adapter_guid("TrueTunnel VPN Adapter");
        const GUID same_name_different_case =
            derive_wintun_adapter_guid("TRUETUNNEL VPN ADAPTER");
        const GUID different_name =
            derive_wintun_adapter_guid("TrueTunnel VPN Adapter Test");

        if (!::IsEqualGUID(canonical, same_name_different_case)) {
            std::cerr << "[FAIL] Adapter identity changed with Windows-insensitive casing\n";
            return false;
        }
        if (::IsEqualGUID(canonical, different_name)) {
            std::cerr << "[FAIL] Distinct adapter names received the same identity\n";
            return false;
        }
        constexpr std::string_view kExpectedIdentity =
            "{7D292814-55D5-865C-A33A-0CA83668DFC0}";
        if (format_guid(canonical) != kExpectedIdentity) {
            std::cerr << "[FAIL] Stable adapter GUID drifted: "
                      << format_guid(canonical) << '\n';
            return false;
        }

        bool trailing_space_rejected = false;
        try {
            (void)derive_wintun_adapter_guid("TrueTunnel VPN Adapter ");
        } catch (const std::invalid_argument&) {
            trailing_space_rejected = true;
        }
        if (!trailing_space_rejected) {
            std::cerr << "[FAIL] Ambiguous trailing-space adapter name was accepted\n";
            return false;
        }

        bool oversized_name_rejected = false;
        try {
            (void)derive_wintun_adapter_guid(std::string(
                kMaximumWintunAdapterNameLength + 1U, 'A'));
        } catch (const std::invalid_argument&) {
            oversized_name_rejected = true;
        }
        if (!oversized_name_rejected) {
            std::cerr << "[FAIL] Wintun adapter name above the ABI limit was accepted\n";
            return false;
        }

        std::cout << "[PASS] Stable case-insensitive Wintun identity "
                  << format_guid(canonical) << " and name bounds\n";
        return true;
    } catch (const std::exception& ex) {
        std::cerr << "[FAIL] Wintun identity derivation threw: " << ex.what()
                  << '\n';
        return false;
    }
}

[[nodiscard]] bool run_controller_cancel_child() {
    ComInit com;
    WsaInit wsa;
    populate_real_adapters();
    if (real_adapters_.empty() || real_adapters_.front().ip.empty()) {
        std::cerr << "[FAIL] Controller cancellation test found no physical IPv4 adapter\n";
        return false;
    }

    const std::string adapter_name = real_adapters_.front().alias;
    const std::string adapter_ip = real_adapters_.front().ip;
    SocketGuard reservation{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    if (reservation.get() == INVALID_SOCKET) {
        std::cerr << "[FAIL] Controller cancellation test could not create its port reservation\n";
        return false;
    }
    const BOOL exclusive = TRUE;
    if (::setsockopt(reservation.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char*>(&exclusive),
                     sizeof(exclusive)) == SOCKET_ERROR) {
        std::cerr << "[FAIL] Controller cancellation test could not reserve an exclusive port\n";
        return false;
    }

    sockaddr_in reserved_address{};
    reserved_address.sin_family = AF_INET;
    reserved_address.sin_port = 0;
    if (::inet_pton(AF_INET, adapter_ip.c_str(),
                    &reserved_address.sin_addr) != 1 ||
        ::bind(reservation.get(),
               reinterpret_cast<const sockaddr*>(&reserved_address),
               sizeof(reserved_address)) == SOCKET_ERROR) {
        std::cerr << "[FAIL] Controller cancellation test could not bind its port reservation\n";
        return false;
    }
    int address_size = sizeof(reserved_address);
    if (::getsockname(reservation.get(),
                      reinterpret_cast<sockaddr*>(&reserved_address),
                      &address_size) == SOCKET_ERROR) {
        std::cerr << "[FAIL] Controller cancellation test could not read its reserved port\n";
        return false;
    }
    const int port = static_cast<int>(::ntohs(reserved_address.sin_port));

    std::atomic<bool> saw_connect_attempt{false};
    VpnController controller;
    controller.set_log_callback([&saw_connect_attempt](const std::string& line) {
        if (line.find("Connecting (TCP)") != std::string::npos) {
            saw_connect_attempt.store(true, std::memory_order_release);
        }
    });
    if (!controller.start(
            "client", adapter_ip, port, {}, {},
            std::string{kIntegrationSharedKey}, "TrueTunnel Cancel Client", {},
            adapter_ip, adapter_name, 0U, secure::CipherSuite::Aes256Gcm,
            TransportProtocol::Tcp)) {
        std::cerr << "[FAIL] Controller cancellation test could not start its worker\n";
        return false;
    }

    const auto connect_deadline = std::chrono::steady_clock::now() + 5s;
    while (!saw_connect_attempt.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < connect_deadline) {
        std::this_thread::sleep_for(20ms);
    }

    const auto stop_start = std::chrono::steady_clock::now();
    controller.stop();
    const auto stop_elapsed = std::chrono::steady_clock::now() - stop_start;
    if (!saw_connect_attempt.load(std::memory_order_acquire)) {
        std::cerr << "[FAIL] Controller cancellation test never reached the connection retry path\n";
        return false;
    }
    if (stop_elapsed > 2s || controller.is_running()) {
        std::cerr << "[FAIL] Controller cancellation exceeded two seconds or remained active\n";
        return false;
    }

    const double elapsed_ms =
        std::chrono::duration<double, std::milli>{stop_elapsed}.count();
    std::cout << "[PASS] Controller cancelled an in-flight client startup in "
              << std::fixed << std::setprecision(2) << elapsed_ms << " ms\n";

    std::atomic<bool> saw_server_start{false};
    VpnController server_controller;
    server_controller.set_log_callback(
        [&saw_server_start](const std::string& line) {
            if (line.find("Starting VPN server") != std::string::npos) {
                saw_server_start.store(true, std::memory_order_release);
            }
        });
    if (!server_controller.start(
            "server", adapter_ip, port, {}, {},
            std::string{kIntegrationSharedKey}, "TrueTunnel Cancel Server", {},
            adapter_ip, adapter_name, 0U, secure::CipherSuite::Aes256Gcm,
            TransportProtocol::Tcp)) {
        std::cerr << "[FAIL] Server setup cancellation test could not start its worker\n";
        return false;
    }
    const auto server_deadline = std::chrono::steady_clock::now() + 5s;
    while (!saw_server_start.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < server_deadline) {
        std::this_thread::sleep_for(20ms);
    }
    const auto server_stop_start = std::chrono::steady_clock::now();
    server_controller.stop();
    const auto server_stop_elapsed =
        std::chrono::steady_clock::now() - server_stop_start;
    if (!saw_server_start.load(std::memory_order_acquire)) {
        std::cerr << "[FAIL] Server setup cancellation never entered VpnServer::start\n";
        return false;
    }
    if (server_stop_elapsed > 5s || server_controller.is_running()) {
        std::cerr << "[FAIL] Server setup cancellation exceeded five seconds or remained active\n";
        return false;
    }
    const double server_elapsed_ms =
        std::chrono::duration<double, std::milli>{server_stop_elapsed}.count();
    std::cout << "[PASS] Controller cancelled in-flight server setup in "
              << std::fixed << std::setprecision(2) << server_elapsed_ms
              << " ms\n";
    return true;
}

[[nodiscard]] bool run_controller_cancel_process() {
    const std::filesystem::path directory = executable_path().parent_path();
    const std::filesystem::path executable = executable_path();
    const std::filesystem::path child_log =
        directory / L"vpn-controller-cancel.log";

    std::wstring command_line = quote_windows_argument(executable.wstring());
    command_line.append(L" --controller-cancel-child --log-file ");
    command_line.append(quote_windows_argument(child_log.wstring()));
    std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!::CreateProcessW(executable.c_str(), mutable_command.data(), nullptr,
                          nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                          directory.c_str(), &startup, &process)) {
        std::cerr << "[FAIL] CreateProcessW(controller cancellation child) failed: "
                  << ::GetLastError() << '\n';
        return false;
    }
    ::CloseHandle(process.hThread);

    const DWORD wait_result = ::WaitForSingleObject(process.hProcess, 20'000U);
    DWORD exit_code = 1U;
    if (wait_result == WAIT_TIMEOUT) {
        std::cerr << "[FAIL] Controller cancellation child hung for 20 seconds\n";
        (void)::TerminateProcess(process.hProcess, 1U);
        (void)::WaitForSingleObject(process.hProcess, 5'000U);
    } else if (wait_result != WAIT_OBJECT_0 ||
               !::GetExitCodeProcess(process.hProcess, &exit_code)) {
        std::cerr << "[FAIL] Unable to read controller cancellation child result: "
                  << ::GetLastError() << '\n';
    }
    ::CloseHandle(process.hProcess);

    std::ifstream log_input{child_log};
    const std::string log_contents{
        std::istreambuf_iterator<char>{log_input},
        std::istreambuf_iterator<char>{}};
    constexpr std::array<std::string_view, 2> required_results{
        "[PASS] Controller cancelled an in-flight client startup",
        "[PASS] Controller cancelled in-flight server setup",
    };
    const bool has_required_results = std::all_of(
        required_results.begin(), required_results.end(),
        [&log_contents](const std::string_view result) {
            return log_contents.find(result) != std::string::npos;
        });
    if (wait_result != WAIT_OBJECT_0 || exit_code != 0U ||
        !has_required_results) {
        std::cerr << "[FAIL] Controller cancellation regression failed; log="
                  << child_log.string() << '\n';
        return false;
    }
    std::cout << "[PASS] Bounded controller startup cancellation subprocess | log="
              << child_log.string() << '\n';
    return true;
}

struct Scenario {
    secure::CipherSuite cipher;
    TransportProtocol transport;
    std::string name;
};

bool wait_for_ip(const VpnClient& client,
                 std::chrono::milliseconds timeout,
                 std::chrono::milliseconds poll_interval = 200ms) {
    const auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < timeout) {
        if (!client.local_ip().empty()) return true;
        std::this_thread::sleep_for(poll_interval);
    }
    return false;
}

bool wait_for_message(VpnClient& client,
                      const std::string& sender_ip,
                      const std::string& text,
                      std::chrono::milliseconds timeout) {
    const auto start = std::chrono::steady_clock::now();
    const std::string needle = sender_ip + "|" + text;
    while (std::chrono::steady_clock::now() - start < timeout) {
        auto messages = client.drain_messages();
        for (const auto& msg : messages) {
            if (msg == needle) {
                return true;
            }
        }
        std::this_thread::sleep_for(100ms);
    }
    return false;
}

constexpr std::uint8_t kIntegrationIpProtocol = 253U;
constexpr std::size_t kIpv4HeaderSize = 20U;
constexpr std::size_t kProbeHeaderSize = 9U;
constexpr std::size_t kProbeEnvelopeSize =
    kIpv4HeaderSize + kProbeHeaderSize;
constexpr std::array<std::uint8_t, 4> kProbeMagic{'T', 'T', 'E', '2'};

enum class ProbeKind : std::uint8_t {
    Data = 1U,
    Ping = 2U,
    Ack = 3U,
};

struct ParsedProbe {
    ProbeKind kind{};
    std::uint32_t sequence{};
    std::size_t payload_size{};
};

void require_test(const bool condition, const std::string_view message) {
    if (!condition) throw std::runtime_error(std::string{message});
}

constexpr DEVPROPKEY kWintunNameProperty{
    {0x3361c968, 0x2f2e, 0x4660,
     {0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9}},
    DEVPROPID_FIRST_USABLE + 1U};

struct WintunDeviceRecord {
    std::wstring instance_id;
    std::wstring name;
    std::wstring service;
};

class DeviceInfoSet final {
public:
    explicit DeviceInfoSet(const HDEVINFO handle) noexcept : handle_{handle} {}
    ~DeviceInfoSet() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            (void)::SetupDiDestroyDeviceInfoList(handle_);
        }
    }

    DeviceInfoSet(const DeviceInfoSet&) = delete;
    DeviceInfoSet& operator=(const DeviceInfoSet&) = delete;

    [[nodiscard]] HDEVINFO get() const noexcept { return handle_; }

private:
    HDEVINFO handle_ = INVALID_HANDLE_VALUE;
};

[[nodiscard]] std::wstring get_device_instance_id(
    const HDEVINFO set,
    SP_DEVINFO_DATA& device) {
    DWORD required = 0U;
    (void)::SetupDiGetDeviceInstanceIdW(set, &device, nullptr, 0U, &required);
    const DWORD error = ::GetLastError();
    if (required == 0U || error != ERROR_INSUFFICIENT_BUFFER) {
        throw std::system_error(
            static_cast<int>(error), std::system_category(),
            "SetupDiGetDeviceInstanceIdW(size)");
    }
    std::vector<wchar_t> buffer(required, L'\0');
    if (!::SetupDiGetDeviceInstanceIdW(
            set, &device, buffer.data(),
            static_cast<DWORD>(buffer.size()), nullptr)) {
        throw std::system_error(
            static_cast<int>(::GetLastError()), std::system_category(),
            "SetupDiGetDeviceInstanceIdW");
    }
    return buffer.data();
}

[[nodiscard]] std::wstring get_device_property_string(
    const HDEVINFO set,
    SP_DEVINFO_DATA& device,
    const DEVPROPKEY& key) {
    DEVPROPTYPE property_type = 0U;
    DWORD required = 0U;
    (void)::SetupDiGetDevicePropertyW(
        set, &device, &key, &property_type, nullptr, 0U, &required, 0U);
    const DWORD error = ::GetLastError();
    if (error == ERROR_NOT_FOUND || error == ERROR_INVALID_DATA) return {};
    if (required == 0U || error != ERROR_INSUFFICIENT_BUFFER) {
        throw std::system_error(
            static_cast<int>(error), std::system_category(),
            "SetupDiGetDevicePropertyW(size)");
    }
    std::vector<wchar_t> buffer(
        (static_cast<std::size_t>(required) + sizeof(wchar_t) - 1U) /
            sizeof(wchar_t),
        L'\0');
    if (!::SetupDiGetDevicePropertyW(
            set, &device, &key, &property_type,
            reinterpret_cast<PBYTE>(buffer.data()),
            static_cast<DWORD>(buffer.size() * sizeof(wchar_t)),
            nullptr, 0U)) {
        throw std::system_error(
            static_cast<int>(::GetLastError()), std::system_category(),
            "SetupDiGetDevicePropertyW");
    }
    if (property_type != DEVPROP_TYPE_STRING) {
        throw std::runtime_error("Wintun name property is not a string");
    }
    return buffer.data();
}

[[nodiscard]] std::wstring get_device_service(
    const HDEVINFO set,
    SP_DEVINFO_DATA& device) {
    DWORD property_type = 0U;
    DWORD required = 0U;
    (void)::SetupDiGetDeviceRegistryPropertyW(
        set, &device, SPDRP_SERVICE, &property_type, nullptr, 0U, &required);
    const DWORD error = ::GetLastError();
    if (error == ERROR_NOT_FOUND || error == ERROR_INVALID_DATA) return {};
    if (required == 0U || error != ERROR_INSUFFICIENT_BUFFER) {
        throw std::system_error(
            static_cast<int>(error), std::system_category(),
            "SetupDiGetDeviceRegistryPropertyW(size)");
    }
    std::vector<wchar_t> buffer(
        (static_cast<std::size_t>(required) + sizeof(wchar_t) - 1U) /
            sizeof(wchar_t),
        L'\0');
    if (!::SetupDiGetDeviceRegistryPropertyW(
            set, &device, SPDRP_SERVICE, &property_type,
            reinterpret_cast<PBYTE>(buffer.data()),
            static_cast<DWORD>(buffer.size() * sizeof(wchar_t)), nullptr)) {
        throw std::system_error(
            static_cast<int>(::GetLastError()), std::system_category(),
            "SetupDiGetDeviceRegistryPropertyW");
    }
    if (property_type != REG_SZ) {
        throw std::runtime_error("Wintun service property is not REG_SZ");
    }
    return buffer.data();
}

void append_wintun_enumerator(
    const wchar_t* const enumerator,
    const bool present_only,
    std::vector<WintunDeviceRecord>& output) {
    const DWORD flags = present_only ? DIGCF_PRESENT : 0U;
    DeviceInfoSet set{::SetupDiGetClassDevsExW(
        &GUID_DEVCLASS_NET, enumerator, nullptr, flags,
        nullptr, nullptr, nullptr)};
    if (set.get() == INVALID_HANDLE_VALUE) {
        const DWORD error = ::GetLastError();
        if (error == ERROR_NOT_FOUND || error == ERROR_INVALID_DATA) return;
        throw std::system_error(
            static_cast<int>(error), std::system_category(),
            "SetupDiGetClassDevsExW(Wintun)");
    }

    for (DWORD index = 0U;; ++index) {
        SP_DEVINFO_DATA device{sizeof(device)};
        if (!::SetupDiEnumDeviceInfo(set.get(), index, &device)) {
            const DWORD error = ::GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) break;
            throw std::system_error(
                static_cast<int>(error), std::system_category(),
                "SetupDiEnumDeviceInfo(Wintun)");
        }
        WintunDeviceRecord record{
            get_device_instance_id(set.get(), device),
            get_device_property_string(
                set.get(), device, kWintunNameProperty),
            get_device_service(set.get(), device)};
        require_test(
            record.service.empty() ||
                _wcsicmp(record.service.c_str(), L"Wintun") == 0,
            "A device on the Wintun enumerator reported a foreign service");
        output.push_back(std::move(record));
    }
}

[[nodiscard]] std::vector<WintunDeviceRecord> query_wintun_devices(
    const bool present_only) {
    std::vector<WintunDeviceRecord> devices;
    append_wintun_enumerator(L"SWD\\Wintun", present_only, devices);
    append_wintun_enumerator(L"ROOT\\Wintun", present_only, devices);
    std::sort(devices.begin(), devices.end(),
              [](const WintunDeviceRecord& left,
                 const WintunDeviceRecord& right) {
                  return left.instance_id < right.instance_id;
              });
    return devices;
}

[[nodiscard]] std::vector<std::wstring> wintun_instance_ids(
    const std::vector<WintunDeviceRecord>& devices) {
    std::vector<std::wstring> ids;
    ids.reserve(devices.size());
    for (const auto& device : devices) ids.push_back(device.instance_id);
    return ids;
}

[[nodiscard]] std::size_t count_wintun_name(
    const std::vector<WintunDeviceRecord>& devices,
    const std::wstring_view name) noexcept {
    return static_cast<std::size_t>(std::count_if(
        devices.begin(), devices.end(),
        [name](const WintunDeviceRecord& device) {
            return device.name.size() == name.size() &&
                   _wcsnicmp(device.name.c_str(), name.data(), name.size()) == 0;
        }));
}

[[nodiscard]] bool wait_for_wintun_baseline(
    const std::vector<std::wstring>& expected_ids,
    const std::chrono::seconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    do {
        if (wintun_instance_ids(query_wintun_devices(false)) == expected_ids) {
            return true;
        }
        std::this_thread::sleep_for(50ms);
    } while (std::chrono::steady_clock::now() < deadline);
    return wintun_instance_ids(query_wintun_devices(false)) == expected_ids;
}

[[nodiscard]] std::optional<DWORD> registry_subkey_count(
    const wchar_t* const path) noexcept {
    HKEY key = nullptr;
    const LSTATUS open_status = ::RegOpenKeyExW(
        HKEY_LOCAL_MACHINE, path, 0U,
        KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &key);
    if (open_status == ERROR_FILE_NOT_FOUND) return 0U;
    if (open_status != ERROR_SUCCESS) return std::nullopt;

    DWORD subkeys = 0U;
    const LSTATUS query_status = ::RegQueryInfoKeyW(
        key, nullptr, nullptr, nullptr, &subkeys, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr);
    (void)::RegCloseKey(key);
    if (query_status != ERROR_SUCCESS) return std::nullopt;
    return subkeys;
}

bool run_wintun_lifecycle_test() {
    constexpr std::string_view kAdapterName = "TrueTunnel Lifecycle Test";
    constexpr std::wstring_view kWideAdapterName = L"TrueTunnel Lifecycle Test";
    constexpr std::string_view kCollisionName =
        "TrueTunnel Lifecycle Collision Test";
    constexpr std::wstring_view kWideCollisionName =
        L"TrueTunnel Lifecycle Collision Test";
    constexpr std::size_t kIterations = 12U;
    constexpr wchar_t kNetworkProfilesPath[] =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles";

    try {
        const auto baseline_all = query_wintun_devices(false);
        const auto baseline_present = query_wintun_devices(true);
        const auto baseline_ids = wintun_instance_ids(baseline_all);
        const auto profiles_before = registry_subkey_count(kNetworkProfilesPath);
        std::cout << "[WINTUN AUDIT] baseline all=" << baseline_all.size()
                  << " present=" << baseline_present.size()
                  << " NLA-profiles=";
        if (profiles_before) std::cout << *profiles_before;
        else std::cout << "access-unavailable";
        std::cout << '\n';

        require_test(count_wintun_name(baseline_all, kWideAdapterName) == 0U,
                     "Lifecycle test adapter already exists before the test");
        require_test(count_wintun_name(baseline_all, kWideCollisionName) == 0U,
                     "Collision test adapter already exists before the test");

        const GUID expected_guid = derive_wintun_adapter_guid(kAdapterName);
        for (std::size_t iteration = 0U; iteration < kIterations; ++iteration) {
            {
                WintunAdapterLease lease{kAdapterName};
                require_test(::IsEqualGUID(lease.guid(), expected_guid),
                             "Adapter GUID changed between lifecycle iterations");

                GUID actual_guid{};
                const NETIO_STATUS status =
                    ::ConvertInterfaceLuidToGuid(&lease.luid(), &actual_guid);
                require_test(status == NO_ERROR &&
                                 ::IsEqualGUID(actual_guid, expected_guid),
                             "Active adapter GUID did not match requested identity");

                const auto present = query_wintun_devices(true);
                require_test(count_wintun_name(present, kWideAdapterName) == 1U,
                             "Expected exactly one present lifecycle-test device");

                if (iteration == 0U) {
                    std::atomic<bool> duplicate_rejected{false};
                    std::thread contender{[&duplicate_rejected]() {
                        try {
                            WintunAdapterLease duplicate{kAdapterName};
                            (void)duplicate;
                        } catch (const std::exception&) {
                            duplicate_rejected.store(true, std::memory_order_release);
                        }
                    }};
                    contender.join();
                    require_test(
                        duplicate_rejected.load(std::memory_order_acquire),
                        "Concurrent same-identity adapter creation was accepted");
                }
            }
            NET_LUID retired_alias_luid{};
            NET_LUID retired_guid_luid{};
            require_test(
                ::ConvertInterfaceAliasToLuid(
                    std::wstring{kWideAdapterName}.c_str(),
                    &retired_alias_luid) != NO_ERROR &&
                    ::ConvertInterfaceGuidToLuid(
                        &expected_guid, &retired_guid_luid) != NO_ERROR,
                "Production adapter lease returned before Windows released "
                "its alias/GUID identity");
            require_test(wait_for_wintun_baseline(baseline_ids, 10s),
                         "Wintun device inventory did not return to baseline");
        }

        const std::wstring collision_name_wide{
            kWideCollisionName.begin(), kWideCollisionName.end()};
        const GUID legacy_guid =
            derive_wintun_adapter_guid("TrueTunnel Stable Legacy Test Identity");
        WINTUN_ADAPTER_HANDLE legacy = WintunCreateAdapter(
            collision_name_wide.c_str(), L"TrueTunnel", &legacy_guid);
        if (legacy == nullptr) {
            throw std::system_error(
                static_cast<int>(::GetLastError()), std::system_category(),
                "WintunCreateAdapter(collision fixture)");
        }
        WintunAdapterGuard legacy_guard{legacy};

        NET_LUID legacy_luid{};
        WintunGetAdapterLUID(legacy, &legacy_luid);
        std::array<wchar_t, IF_MAX_STRING_SIZE + 1U> alias_before{};
        require_test(
            ::ConvertInterfaceLuidToAlias(
                &legacy_luid, alias_before.data(), alias_before.size()) == NO_ERROR &&
                _wcsicmp(alias_before.data(), collision_name_wide.c_str()) == 0,
            "Collision fixture did not receive its requested alias");

        bool collision_rejected = false;
        try {
            WintunAdapterLease duplicate{kCollisionName};
            (void)duplicate;
        } catch (const std::exception&) {
            collision_rejected = true;
        }
        require_test(collision_rejected,
                     "Existing-name collision was not rejected before creation");

        std::array<wchar_t, IF_MAX_STRING_SIZE + 1U> alias_after{};
        require_test(
            ::ConvertInterfaceLuidToAlias(
                &legacy_luid, alias_after.data(), alias_after.size()) == NO_ERROR &&
                _wcsicmp(alias_after.data(), collision_name_wide.c_str()) == 0,
            "Collision preflight renamed the existing adapter");
        legacy_guard.Reset();
        require_test(wait_for_wintun_baseline(baseline_ids, 10s),
                     "Collision fixture did not fully tear down");

        const auto profiles_after = registry_subkey_count(kNetworkProfilesPath);
        if (profiles_before && profiles_after) {
            require_test(
                *profiles_after <= *profiles_before + 2U,
                "Repeated stable adapter creation produced excessive NLA profiles");
        }
        const auto final_all = query_wintun_devices(false);
        const auto final_present = query_wintun_devices(true);
        require_test(wintun_instance_ids(final_all) == baseline_ids,
                     "Final Wintun device inventory differs from baseline");

        std::cout << "[PASS] Wintun stable identity churn x" << kIterations
                  << ", concurrent-owner rejection, collision safety, and cleanup"
                  << " | final all=" << final_all.size()
                  << " present=" << final_present.size()
                  << " NLA-profiles=";
        if (profiles_after) std::cout << *profiles_after;
        else std::cout << "access-unavailable";
        std::cout << '\n';
        return true;
    } catch (const std::exception& ex) {
        std::cerr << "[FAIL] Wintun lifecycle regression: " << ex.what() << '\n';
        return false;
    }
}

void write_u32_be(std::uint8_t* const output,
                  const std::uint32_t value) noexcept {
    output[0] = static_cast<std::uint8_t>(value >> 24U);
    output[1] = static_cast<std::uint8_t>(value >> 16U);
    output[2] = static_cast<std::uint8_t>(value >> 8U);
    output[3] = static_cast<std::uint8_t>(value);
}

[[nodiscard]] std::uint32_t read_u32_be(
    const std::uint8_t* const input) noexcept {
    return (static_cast<std::uint32_t>(input[0]) << 24U) |
           (static_cast<std::uint32_t>(input[1]) << 16U) |
           (static_cast<std::uint32_t>(input[2]) << 8U) |
           static_cast<std::uint32_t>(input[3]);
}

[[nodiscard]] std::uint16_t ipv4_header_checksum(
    const std::span<const std::uint8_t> header) noexcept {
    std::uint32_t sum = 0U;
    for (std::size_t offset = 0; offset + 1U < header.size(); offset += 2U) {
        sum += (static_cast<std::uint32_t>(header[offset]) << 8U) |
               static_cast<std::uint32_t>(header[offset + 1U]);
    }
    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum);
}

[[nodiscard]] std::vector<std::uint8_t> make_probe_packet(
    const std::string& source_ip,
    const std::string& destination_ip,
    const ProbeKind kind,
    const std::uint32_t sequence,
    const std::size_t payload_size) {
    const std::size_t packet_size = kProbeEnvelopeSize + payload_size;
    require_test(packet_size <= secure::kMaximumDatagramPayloadSize,
                 "integration probe exceeds tunnel MTU");

    std::vector<std::uint8_t> packet(packet_size, 0U);
    packet[0] = 0x45U;
    packet[2] = static_cast<std::uint8_t>(packet_size >> 8U);
    packet[3] = static_cast<std::uint8_t>(packet_size);
    packet[4] = static_cast<std::uint8_t>(sequence >> 8U);
    packet[5] = static_cast<std::uint8_t>(sequence);
    packet[6] = 0x40U;
    packet[8] = 64U;
    packet[9] = kIntegrationIpProtocol;

    IN_ADDR source{};
    IN_ADDR destination{};
    require_test(::inet_pton(AF_INET, source_ip.c_str(), &source) == 1,
                 "invalid probe source IPv4 address");
    require_test(::inet_pton(AF_INET, destination_ip.c_str(), &destination) == 1,
                 "invalid probe destination IPv4 address");
    std::memcpy(packet.data() + 12U, &source, sizeof(source));
    std::memcpy(packet.data() + 16U, &destination, sizeof(destination));

    std::copy(kProbeMagic.begin(), kProbeMagic.end(),
              packet.begin() + static_cast<std::ptrdiff_t>(kIpv4HeaderSize));
    packet[24] = static_cast<std::uint8_t>(kind);
    write_u32_be(packet.data() + 25U, sequence);
    for (std::size_t index = 0; index < payload_size; ++index) {
        packet[kProbeEnvelopeSize + index] = static_cast<std::uint8_t>(
            (static_cast<std::size_t>(sequence) * 31U + index * 17U) & 0xFFU);
    }

    const std::uint16_t checksum = ipv4_header_checksum(
        std::span<const std::uint8_t>{packet.data(), kIpv4HeaderSize});
    packet[10] = static_cast<std::uint8_t>(checksum >> 8U);
    packet[11] = static_cast<std::uint8_t>(checksum);
    return packet;
}

[[nodiscard]] std::optional<ParsedProbe> parse_probe_packet(
    const std::span<const std::uint8_t> packet) noexcept {
    if (packet.size() < kProbeEnvelopeSize ||
        !is_well_formed_ipv4_packet(packet.data(), packet.size()) ||
        packet[9] != kIntegrationIpProtocol ||
        !std::equal(kProbeMagic.begin(), kProbeMagic.end(),
                    packet.begin() + static_cast<std::ptrdiff_t>(kIpv4HeaderSize))) {
        return std::nullopt;
    }
    const auto kind = static_cast<ProbeKind>(packet[24]);
    if (kind != ProbeKind::Data && kind != ProbeKind::Ping &&
        kind != ProbeKind::Ack) {
        return std::nullopt;
    }
    return ParsedProbe{kind,
                       read_u32_be(packet.data() + 25U),
                       packet.size() - kProbeEnvelopeSize};
}

[[nodiscard]] bool probe_addresses_match(
    const std::span<const std::uint8_t> packet,
    const std::string& expected_source,
    const std::string& expected_destination) noexcept {
    IN_ADDR source{};
    IN_ADDR destination{};
    if (::inet_pton(AF_INET, expected_source.c_str(), &source) != 1 ||
        ::inet_pton(AF_INET, expected_destination.c_str(), &destination) != 1) {
        return false;
    }
    return packet.size() >= kIpv4HeaderSize &&
           std::memcmp(packet.data() + 12U, &source, sizeof(source)) == 0 &&
           std::memcmp(packet.data() + 16U, &destination,
                       sizeof(destination)) == 0;
}

class ProbeTracker final {
public:
    void begin_data_run(const std::size_t expected_frames) {
        std::lock_guard<std::mutex> lock(mutex_);
        data_seen_.assign(expected_frames, false);
        data_frames_ = 0U;
        data_bytes_ = 0U;
        failure_.clear();
    }

    void begin_latency_run() {
        std::lock_guard<std::mutex> lock(mutex_);
        acknowledgements_.clear();
        failure_.clear();
    }

    void note_data(const std::uint32_t sequence,
                   const std::size_t payload_size) {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::size_t index = static_cast<std::size_t>(sequence);
        if (index >= data_seen_.size()) {
            set_failure_locked("probe sequence exceeded the expected window");
        } else if (!data_seen_[index]) {
            data_seen_[index] = true;
            ++data_frames_;
            data_bytes_ += payload_size;
        }
        ready_.notify_all();
    }

    void note_ack(const std::uint32_t sequence) {
        std::lock_guard<std::mutex> lock(mutex_);
        acknowledgements_.insert(sequence);
        ready_.notify_all();
    }

    void fail(std::string message) {
        std::lock_guard<std::mutex> lock(mutex_);
        set_failure_locked(std::move(message));
        ready_.notify_all();
    }

    [[nodiscard]] bool wait_for_data(const std::size_t frames,
                                     const std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        return ready_.wait_for(lock, timeout, [&]() {
            return data_frames_ >= frames || !failure_.empty();
        }) && failure_.empty() && data_frames_ >= frames;
    }

    [[nodiscard]] bool wait_for_ack(const std::uint32_t sequence,
                                    const std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        const bool signaled = ready_.wait_for(lock, timeout, [&]() {
            return acknowledgements_.contains(sequence) || !failure_.empty();
        });
        if (!signaled || !failure_.empty()) return false;
        acknowledgements_.erase(sequence);
        return true;
    }

    [[nodiscard]] std::size_t data_bytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return data_bytes_;
    }

    [[nodiscard]] std::string failure() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return failure_;
    }

private:
    void set_failure_locked(std::string message) {
        if (failure_.empty()) failure_ = std::move(message);
    }

    mutable std::mutex mutex_;
    std::condition_variable ready_;
    std::vector<bool> data_seen_;
    std::unordered_set<std::uint32_t> acknowledgements_;
    std::size_t data_frames_{0U};
    std::size_t data_bytes_{0U};
    std::string failure_;
};

void configure_probe_observer(VpnClient& client,
                              const std::string& local_ip,
                              const std::string& peer_ip,
                              ProbeTracker& tracker) {
    client.set_integration_packet_observer(
        [&client, local_ip, peer_ip, &tracker](
            const std::span<const std::uint8_t> packet) {
            const auto parsed = parse_probe_packet(packet);
            if (!parsed) return false;
            if (!probe_addresses_match(packet, peer_ip, local_ip)) {
                tracker.fail("probe arrived with unexpected source/destination");
                return true;
            }
            switch (parsed->kind) {
                case ProbeKind::Data:
                    tracker.note_data(parsed->sequence, parsed->payload_size);
                    break;
                case ProbeKind::Ping: {
                    const auto acknowledgement = make_probe_packet(
                        local_ip, peer_ip, ProbeKind::Ack,
                        parsed->sequence, 0U);
                    if (!client.send_integration_ipv4_packet(acknowledgement)) {
                        tracker.fail("failed to send probe acknowledgement");
                    }
                    break;
                }
                case ProbeKind::Ack:
                    tracker.note_ack(parsed->sequence);
                    break;
            }
            return true;
        });
}

struct ThroughputResult {
    double megabits_per_second{};
    std::size_t payload_bytes{};
    std::size_t frames{};
};

[[nodiscard]] ThroughputResult measure_throughput(
    VpnClient& sender,
    ProbeTracker& receiver,
    const std::string& source_ip,
    const std::string& destination_ip,
    const std::string_view label) {
    constexpr std::size_t kPayloadBytes = 2U * 1024U * 1024U;
    constexpr std::size_t kPacketBytes = 1'300U;
    constexpr std::size_t kPayloadPerFrame = kPacketBytes - kProbeEnvelopeSize;
    constexpr std::size_t kWindowFrames = 24U;
    const std::size_t frame_count =
        (kPayloadBytes + kPayloadPerFrame - 1U) / kPayloadPerFrame;
    receiver.begin_data_run(frame_count);

    std::size_t remaining = kPayloadBytes;
    const auto started = std::chrono::steady_clock::now();
    for (std::size_t index = 0; index < frame_count; ++index) {
        const std::size_t payload = (std::min)(remaining, kPayloadPerFrame);
        const auto packet = make_probe_packet(
            source_ip, destination_ip, ProbeKind::Data,
            static_cast<std::uint32_t>(index), payload);
        require_test(sender.send_integration_ipv4_packet(packet),
                     "encrypted throughput send failed");
        remaining -= payload;

        const std::size_t sent_frames = index + 1U;
        if (sent_frames % kWindowFrames == 0U ||
            sent_frames == frame_count) {
            require_test(receiver.wait_for_data(sent_frames, 10s),
                         "encrypted throughput receive window timed out");
        }
    }
    const auto finished = std::chrono::steady_clock::now();
    require_test(receiver.failure().empty(), receiver.failure());
    require_test(receiver.data_bytes() == kPayloadBytes,
                 "throughput payload byte count changed in transit");

    const double seconds =
        std::chrono::duration<double>(finished - started).count();
    const double megabits_per_second =
        (static_cast<double>(kPayloadBytes) * 8.0) / seconds / 1'000'000.0;
    require_test(megabits_per_second >= 0.5,
                 "encrypted packet-path throughput fell below 0.5 Mbit/s");
    std::cout << "[THROUGHPUT] " << label << ": " << std::fixed
              << std::setprecision(2) << megabits_per_second
              << " Mbit/s, payload=" << kPayloadBytes
              << " bytes, frames=" << frame_count << '\n';
    return {megabits_per_second, kPayloadBytes, frame_count};
}

struct LatencyResult {
    double median_milliseconds{};
    double p95_milliseconds{};
};

[[nodiscard]] LatencyResult measure_latency(
    VpnClient& sender,
    ProbeTracker& sender_tracker,
    const std::string& source_ip,
    const std::string& destination_ip,
    const std::string_view label,
    const std::size_t sample_count,
    const std::uint32_t sequence_base) {
    sender_tracker.begin_latency_run();
    std::vector<double> samples;
    samples.reserve(sample_count);
    for (std::size_t index = 0; index < sample_count; ++index) {
        const std::uint32_t sequence =
            sequence_base + static_cast<std::uint32_t>(index);
        const auto packet = make_probe_packet(
            source_ip, destination_ip, ProbeKind::Ping, sequence, 35U);
        const auto started = std::chrono::steady_clock::now();
        require_test(sender.send_integration_ipv4_packet(packet),
                     "latency probe send failed");
        require_test(sender_tracker.wait_for_ack(sequence, 2s),
                     "latency probe acknowledgement timed out");
        samples.push_back(std::chrono::duration<double, std::milli>(
                              std::chrono::steady_clock::now() - started)
                              .count());
    }
    require_test(sender_tracker.failure().empty(), sender_tracker.failure());
    std::sort(samples.begin(), samples.end());
    const std::size_t p95_index =
        ((sample_count * 95U + 99U) / 100U) - 1U;
    const double median = samples[sample_count / 2U];
    const double p95 = samples[p95_index];
    require_test(p95 < 1'000.0,
                 "encrypted packet-path p95 latency exceeded 1000 ms");
    std::cout << "[LATENCY] " << label << ": median=" << std::fixed
              << std::setprecision(2) << median << " ms, p95=" << p95
              << " ms, samples=" << sample_count << '\n';
    return {median, p95};
}

void verify_backpressured_server_shutdown(
    VpnServer& server,
    VpnClient& sending_client,
    VpnClient& stalled_client,
    const std::string& sending_ip,
    const std::string& stalled_ip) {
    std::atomic<bool> release_stalled_observer{false};
    std::atomic<bool> stalled_observer_entered{false};
    std::atomic<bool> stalled_observer_exited{false};
    stalled_client.set_integration_packet_observer(
        [&](const std::span<const std::uint8_t>) {
            stalled_observer_entered.store(true, std::memory_order_release);
            while (!release_stalled_observer.load(std::memory_order_acquire)) {
                std::this_thread::sleep_for(1ms);
            }
            stalled_observer_exited.store(true, std::memory_order_release);
            return true;
        });

    const auto packet = make_probe_packet(
        sending_ip, stalled_ip, ProbeKind::Data, 0x5000U,
        secure::kMaximumDatagramPayloadSize - kProbeEnvelopeSize);
    const bool trigger_sent =
        sending_client.send_integration_ipv4_packet(packet);
    const auto observer_deadline = std::chrono::steady_clock::now() + 5s;
    while (!stalled_observer_entered.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < observer_deadline) {
        std::this_thread::sleep_for(10ms);
    }
    const bool observer_entered =
        stalled_observer_entered.load(std::memory_order_acquire);

    std::atomic<bool> keep_flooding{observer_entered};
    std::atomic<bool> flood_finished{!observer_entered};
    std::atomic<std::uint64_t> completed_sends{0U};
    std::thread flood_thread;
    if (observer_entered) {
        flood_thread = std::thread([&]() {
            while (keep_flooding.load(std::memory_order_acquire) &&
                   sending_client.send_integration_ipv4_packet(packet)) {
                completed_sends.fetch_add(1U, std::memory_order_relaxed);
            }
            flood_finished.store(true, std::memory_order_release);
        });
    }

    bool backpressure_observed = false;
    std::uint64_t previous_count = completed_sends.load(std::memory_order_relaxed);
    auto unchanged_since = std::chrono::steady_clock::now();
    const auto backpressure_deadline = std::chrono::steady_clock::now() + 10s;
    while (observer_entered &&
           !flood_finished.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < backpressure_deadline) {
        std::this_thread::sleep_for(25ms);
        const std::uint64_t current_count =
            completed_sends.load(std::memory_order_relaxed);
        if (current_count != previous_count) {
            previous_count = current_count;
            unchanged_since = std::chrono::steady_clock::now();
        } else if (current_count > 0U &&
                   std::chrono::steady_clock::now() - unchanged_since >= 300ms) {
            backpressure_observed = true;
            break;
        }
    }

    std::atomic<bool> stop_completed{false};
    std::chrono::steady_clock::duration stop_elapsed{};
    std::thread stop_thread([&]() {
        const auto started = std::chrono::steady_clock::now();
        server.stop();
        stop_elapsed = std::chrono::steady_clock::now() - started;
        stop_completed.store(true, std::memory_order_release);
    });

    const auto stop_deadline = std::chrono::steady_clock::now() + 5s;
    while (!stop_completed.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < stop_deadline) {
        std::this_thread::sleep_for(10ms);
    }
    const bool stop_completed_in_time =
        stop_completed.load(std::memory_order_acquire);

    // Releasing the deliberately stalled callback makes the test recover even
    // if the historical map-lock/TLS-write deadlock regresses. Client close()
    // also interrupts a flood sender that is waiting on the other direction.
    release_stalled_observer.store(true, std::memory_order_release);
    keep_flooding.store(false, std::memory_order_release);
    sending_client.stop();
    stalled_client.stop();
    stop_thread.join();
    if (flood_thread.joinable()) flood_thread.join();
    stalled_client.set_integration_packet_observer({});

    require_test(trigger_sent,
                 "backpressure trigger packet could not be sent");
    require_test(observer_entered,
                 "stalled client did not enter its receive callback");
    require_test(backpressure_observed,
                 "encrypted TCP flood did not reach receiver backpressure");
    require_test(stalled_observer_exited.load(std::memory_order_acquire),
                 "stalled client observer did not exit during teardown");
    require_test(stop_completed_in_time && stop_elapsed <= 5s,
                 "server stop did not interrupt a backpressured TLS send within 5 seconds");

    std::cout << "[SHUTDOWN] Backpressured TLS send interrupted in "
              << std::fixed << std::setprecision(2)
              << std::chrono::duration<double, std::milli>(stop_elapsed).count()
              << " ms after " << completed_sends.load(std::memory_order_relaxed)
              << " completed flood frames\n"
              << "[PASS] Server send/stop lock ordering under real TCP backpressure\n";
}

void verify_chat_roundtrip(VpnClient& client_a,
                           VpnClient& client_b,
                           const std::string& ip_a,
                           const std::string& ip_b,
                           const std::string& token_prefix) {
    client_a.drain_messages();
    client_b.drain_messages();
    const std::string token_ab = token_prefix + "_A_TO_B";
    const std::string token_ba = token_prefix + "_B_TO_A";
    require_test(client_a.send_chat_message(token_ab) &&
                     wait_for_message(client_b, ip_a, token_ab, 5s),
                 "chat A-to-B failed");
    require_test(client_b.send_chat_message(token_ba) &&
                     wait_for_message(client_a, ip_b, token_ba, 5s),
                 "chat B-to-A failed");
}

void verify_server_chat_fanout_budget(VpnServer& server,
                                      VpnClient& client_a,
                                      VpnClient& client_b) {
    constexpr std::size_t kAllowedPerWindow = 16U;
    client_a.drain_messages();
    client_b.drain_messages();

    const auto started = std::chrono::steady_clock::now();
    for (std::size_t index = 0U; index < kAllowedPerWindow; ++index) {
        require_test(
            server.send_chat("FANOUT_" + std::to_string(index)),
            "server chat fanout was rejected below its configured budget");
    }
    require_test(!server.send_chat("FANOUT_REJECT"),
                 "server chat fanout exceeded its per-source event budget");
    const auto elapsed = std::chrono::steady_clock::now() - started;
    require_test(elapsed < 1s,
                 "chat fanout budget test crossed its one-second window");
    require_test(wait_for_message(client_a, "server", "FANOUT_15", 5s) &&
                     wait_for_message(client_b, "server", "FANOUT_15", 5s),
                 "allowed server chat did not reach every authenticated peer");

    std::this_thread::sleep_for(1'100ms);
    const std::string recovery = "FANOUT_RECOVERY";
    require_test(server.send_chat(recovery) &&
                     wait_for_message(client_a, "server", recovery, 5s) &&
                     wait_for_message(client_b, "server", recovery, 5s),
                 "chat fanout did not recover after its bounded window");
    std::cout << "[DOS] Authenticated chat fanout capped at "
              << kAllowedPerWindow
              << " messages per source/window and recovered\n";
}

void verify_authenticated_chat_rate_limit(VpnServer& server,
                                          VpnClient& abusive_client,
                                          VpnClient& healthy_client) {
    constexpr std::size_t kBurstMessages = 32U;
    std::size_t locally_accepted = 0U;
    for (std::size_t index = 0U; index < kBurstMessages; ++index) {
        if (!abusive_client.send_chat_message(
                "CHAT_BURST_" + std::to_string(index))) {
            break;
        }
        ++locally_accepted;
    }

    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (abusive_client.is_active() &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }
    require_test(!abusive_client.is_active(),
                 "authenticated chat flood did not disconnect its sender");
    require_test(healthy_client.is_active(),
                 "authenticated chat flood disconnected an unrelated peer");

    const std::string recovery = "CHAT_ABUSE_ISOLATED";
    require_test(server.send_chat(recovery) &&
                     wait_for_message(
                         healthy_client, "server", recovery, 5s),
                 "healthy peer did not recover after chat sender isolation");
    std::cout << "[DOS] Authenticated chat burst isolated its sender after "
              << locally_accepted << " local writes; healthy peer remained active\n";
}

[[nodiscard]] bool run_gui_smoke_process() {
    const std::filesystem::path directory = executable_path().parent_path();
    const std::filesystem::path gui_executable = directory / L"vpn.exe";
    const std::filesystem::path gui_log = directory / L"vpn-gui-smoke.log";
    if (!std::filesystem::exists(gui_executable)) {
        std::cerr << "[FAIL] GUI executable is missing: "
                  << gui_executable.string() << '\n';
        return false;
    }

    enum class ChildRunResult {
        completed,
        create_failed,
        timed_out,
        wait_failed,
        exit_code_failed,
    };
    const auto child_result_text = [](const ChildRunResult result) {
        switch (result) {
        case ChildRunResult::completed: return "completed";
        case ChildRunResult::create_failed: return "could not be created";
        case ChildRunResult::timed_out: return "timed out";
        case ChildRunResult::wait_failed: return "could not be waited on";
        case ChildRunResult::exit_code_failed: return "did not report an exit code";
        }
        return "returned an unknown status";
    };
    const auto run_child = [&](std::wstring command_line,
                               const DWORD timeout_milliseconds,
                               DWORD& exit_code,
                               DWORD& diagnostic_code) -> ChildRunResult {
        diagnostic_code = ERROR_SUCCESS;
        std::vector<wchar_t> mutable_command(command_line.begin(),
                                             command_line.end());
        mutable_command.push_back(L'\0');
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        if (!::CreateProcessW(gui_executable.c_str(),
                              mutable_command.data(),
                              nullptr,
                              nullptr,
                              FALSE,
                               CREATE_NO_WINDOW,
                               nullptr,
                               directory.c_str(),
                               &startup,
                               &process)) {
            diagnostic_code = ::GetLastError();
            return ChildRunResult::create_failed;
        }
        ::CloseHandle(process.hThread);
        const DWORD wait_result =
            ::WaitForSingleObject(process.hProcess, timeout_milliseconds);
        if (wait_result == WAIT_TIMEOUT) {
            (void)::TerminateProcess(process.hProcess, 1U);
            (void)::WaitForSingleObject(process.hProcess, 5'000U);
            diagnostic_code = WAIT_TIMEOUT;
            ::CloseHandle(process.hProcess);
            return ChildRunResult::timed_out;
        }
        if (wait_result != WAIT_OBJECT_0) {
            diagnostic_code = wait_result == WAIT_FAILED
                                  ? ::GetLastError()
                                  : wait_result;
            ::CloseHandle(process.hProcess);
            return ChildRunResult::wait_failed;
        }
        if (!::GetExitCodeProcess(process.hProcess, &exit_code)) {
            diagnostic_code = ::GetLastError();
            ::CloseHandle(process.hProcess);
            return ChildRunResult::exit_code_failed;
        }
        ::CloseHandle(process.hProcess);
        return ChildRunResult::completed;
    };

    const std::filesystem::path sentinel =
        directory /
        (L"vpn-gui-smoke-sentinel-" + std::to_wstring(::GetCurrentProcessId()) +
         L".txt");
    constexpr std::string_view sentinel_contents =
        "TrueTunnel smoke path sentinel - must remain unchanged";
    HANDLE sentinel_handle = ::CreateFileW(
        sentinel.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (sentinel_handle == INVALID_HANDLE_VALUE) {
        std::cerr << "[FAIL] Could not create GUI smoke path sentinel: "
                  << ::GetLastError() << '\n';
        return false;
    }
    DWORD sentinel_written = 0U;
    const bool sentinel_initialized =
        ::WriteFile(sentinel_handle,
                    sentinel_contents.data(),
                    static_cast<DWORD>(sentinel_contents.size()),
                    &sentinel_written,
                    nullptr) &&
        sentinel_written == sentinel_contents.size();
    ::CloseHandle(sentinel_handle);
    if (!sentinel_initialized) {
        (void)::DeleteFileW(sentinel.c_str());
        std::cerr << "[FAIL] Could not initialize GUI smoke path sentinel\n";
        return false;
    }

    std::wstring rejected_command =
        quote_windows_argument(gui_executable.wstring());
    rejected_command.append(L" --gui-smoke-log ");
    rejected_command.append(quote_windows_argument(sentinel.wstring()));
    DWORD rejected_exit = 0U;
    DWORD rejected_diagnostic = ERROR_SUCCESS;
    const ChildRunResult rejected_result = run_child(
        std::move(rejected_command), 10'000U, rejected_exit,
        rejected_diagnostic);
    std::ifstream sentinel_input{sentinel, std::ios::binary};
    const std::string sentinel_after{
        std::istreambuf_iterator<char>{sentinel_input},
        std::istreambuf_iterator<char>{}};
    sentinel_input.close();
    (void)::DeleteFileW(sentinel.c_str());
    if (rejected_result != ChildRunResult::completed || rejected_exit == 0U ||
        sentinel_after != sentinel_contents) {
        std::cerr << "[FAIL] Elevated GUI accepted or modified a caller-selected "
                     "smoke-log path (child "
                  << child_result_text(rejected_result) << ", diagnostic "
                  << rejected_diagnostic << ")\n";
        return false;
    }

    std::wstring command_line = quote_windows_argument(gui_executable.wstring());
    command_line.append(L" --gui-smoke-test");
    DWORD exit_code = 1U;
    DWORD smoke_diagnostic = ERROR_SUCCESS;
    const ChildRunResult smoke_result = run_child(
        std::move(command_line), 30'000U, exit_code, smoke_diagnostic);
    if (smoke_result != ChildRunResult::completed) {
        std::cerr << "[FAIL] vpn.exe GUI smoke "
                  << child_result_text(smoke_result) << " (diagnostic "
                  << smoke_diagnostic << ")\n";
        return false;
    }
    if (exit_code != 0U) {
        std::cerr << "[FAIL] Actual GUI smoke exited with code "
                  << exit_code << '\n';
        return false;
    }

    std::ifstream log_input{gui_log};
    const std::string log_contents{
        std::istreambuf_iterator<char>{log_input},
        std::istreambuf_iterator<char>{}};
    const std::array<std::string_view, 7> required_results{
        "[SMOKE] D3D initialization: PASS",
        "[SMOKE] ImGui context: PASS",
        "[SMOKE] ImGui Win32 backend: PASS",
        "[SMOKE] ImGui DX11 backend: PASS",
        "[SMOKE] generated secret invariant: PASS",
        "[SMOKE] rendered frames (30 required): PASS",
        "[SMOKE] core controls rendered: PASS",
    };
    for (const std::string_view result : required_results) {
        if (log_contents.find(result) == std::string::npos) {
            std::cerr << "[FAIL] GUI smoke log is missing: " << result << '\n';
            return false;
        }
    }
    std::cout << "[PASS] Actual vpn.exe D3D/ImGui/secret/control smoke | log="
              << gui_log.string() << '\n';
    return true;
}

[[nodiscard]] std::size_t current_process_thread_count() {
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0U);
    if (snapshot == INVALID_HANDLE_VALUE) {
        throw std::system_error(
            static_cast<int>(::GetLastError()), std::system_category(),
            "CreateToolhelp32Snapshot(threads)");
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    const DWORD process_id = ::GetCurrentProcessId();
    std::size_t count = 0U;
    if (::Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID == process_id) ++count;
            entry.dwSize = sizeof(entry);
        } while (::Thread32Next(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    return count;
}

void verify_tcp_pre_authentication_flood(const std::string& server_ip,
                                         const std::uint16_t port) {
    constexpr std::size_t kConnectionAttempts = 96U;
    constexpr std::size_t kMaximumAdmissionThreads = 20U;
    const std::size_t threads_before = current_process_thread_count();
    std::vector<SOCKET> sockets;
    sockets.reserve(kConnectionAttempts);
    const auto close_sockets = [&]() noexcept {
        for (const SOCKET socket : sockets) {
            if (socket != INVALID_SOCKET) {
                (void)::shutdown(socket, SD_BOTH);
                (void)::closesocket(socket);
            }
        }
        sockets.clear();
    };

    try {
        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_port = htons(port);
        require_test(::inet_pton(AF_INET, server_ip.c_str(),
                                 &destination.sin_addr) == 1,
                     "TCP flood server address is invalid");

        DWORD timeout_ms = 1'000U;
        std::size_t connected = 0U;
        for (std::size_t index = 0U; index < kConnectionAttempts; ++index) {
            const SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            require_test(socket != INVALID_SOCKET,
                         "TCP flood socket creation failed");
            sockets.push_back(socket);
            (void)::setsockopt(
                socket, SOL_SOCKET, SO_RCVTIMEO,
                reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
            (void)::setsockopt(
                socket, SOL_SOCKET, SO_SNDTIMEO,
                reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
            if (::connect(socket,
                          reinterpret_cast<const sockaddr*>(&destination),
                          sizeof(destination)) == 0) {
                ++connected;
            }
        }

        require_test(connected >= 32U,
                     "too few TCP flood connections reached the listener");
        std::this_thread::sleep_for(500ms);
        const std::size_t threads_after = current_process_thread_count();
        require_test(threads_after <=
                         threads_before + kMaximumAdmissionThreads,
                     "TCP pre-authentication flood exceeded the worker budget");
        std::cout << "[DOS] " << connected
                  << " raw TCP connections: threads " << threads_before
                  << " -> " << threads_after
                  << " (per-source admission bounded before TLS)\n";
    } catch (...) {
        close_sockets();
        throw;
    }
    close_sockets();

    // Let admitted handshake workers unwind and the fixed admission window
    // expire before connecting real authenticated clients.
    std::this_thread::sleep_for(1'100ms);
}

void verify_udp_pre_authentication_flood(const std::string& server_ip,
                                         const std::uint16_t port) {
    constexpr std::size_t kFloodSources = 320U;
    const std::size_t threads_before = current_process_thread_count();
    std::vector<SOCKET> sockets;
    sockets.reserve(kFloodSources);
    const auto close_sockets = [&]() noexcept {
        for (const SOCKET socket : sockets) {
            if (socket != INVALID_SOCKET) (void)::closesocket(socket);
        }
        sockets.clear();
    };

    try {
        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_port = htons(port);
        require_test(::inet_pton(AF_INET, server_ip.c_str(),
                                 &destination.sin_addr) == 1,
                     "UDP flood server address is invalid");
        sockaddr_in source{};
        source.sin_family = AF_INET;
        source.sin_port = 0U;
        require_test(::inet_pton(AF_INET, server_ip.c_str(),
                                 &source.sin_addr) == 1,
                     "UDP flood source address is invalid");

        std::array<std::uint8_t, 48> malformed{};
        for (std::size_t index = 0; index != kFloodSources; ++index) {
            const SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            require_test(socket != INVALID_SOCKET,
                         "UDP flood socket creation failed");
            sockets.push_back(socket);
            require_test(::bind(socket,
                                reinterpret_cast<const sockaddr*>(&source),
                                sizeof(source)) != SOCKET_ERROR,
                         "UDP flood source bind failed");
            malformed[0] = static_cast<std::uint8_t>(index);
            const int sent = ::sendto(
                socket,
                reinterpret_cast<const char*>(malformed.data()),
                static_cast<int>(malformed.size()),
                0,
                reinterpret_cast<const sockaddr*>(&destination),
                sizeof(destination));
            require_test(sent == static_cast<int>(malformed.size()),
                         "UDP flood datagram send failed");
        }

        std::this_thread::sleep_for(750ms);
        const std::size_t threads_after = current_process_thread_count();
        require_test(threads_after <= threads_before + 4U,
                     "malformed UDP tuples created pre-authentication workers");
        std::cout << "[DOS] " << kFloodSources
                  << " malformed UDP tuples: threads " << threads_before
                  << " -> " << threads_after
                  << " (no per-tuple worker allocation)\n";
    } catch (...) {
        close_sockets();
        throw;
    }
    close_sockets();

    // The flood intentionally consumes the per-source one-second budget.
    // Verify recovery by letting that bounded window expire before the real
    // authenticated clients connect.
    std::this_thread::sleep_for(1'100ms);
}

bool run_scenario(int index,
                  const Scenario& scenario,
                  const std::string& real_adapter_name,
                  const std::string& real_adapter_ip,
                  const std::uint64_t real_adapter_luid,
                  const std::string& password) {
    const int port = 6500 + index;
    const std::string server_adapter =
        "TrueTunnel Test Server " + std::to_string(index);
    const std::string clientA_adapter =
        "TrueTunnel Test Client A " + std::to_string(index);
    const std::string clientB_adapter =
        "TrueTunnel Test Client B " + std::to_string(index);

    std::cout << "\n[ SCENARIO ] " << scenario.name
              << " | Port " << port << '\n';

    bool success = false;
    VpnServer server(port, real_adapter_name, password, server_adapter,
                     scenario.cipher, scenario.transport, {},
                     real_adapter_luid);
    std::unique_ptr<VpnClient> clientA;
    std::unique_ptr<VpnClient> clientB;
    ProbeTracker trackerA;
    ProbeTracker trackerB;

    try {
        server.start();
        std::this_thread::sleep_for(500ms);
        if (scenario.transport == TransportProtocol::Udp) {
            verify_udp_pre_authentication_flood(
                real_adapter_ip, static_cast<std::uint16_t>(port));
        } else {
            verify_tcp_pre_authentication_flood(
                real_adapter_ip, static_cast<std::uint16_t>(port));
        }

        clientA = std::make_unique<VpnClient>(
            real_adapter_ip, port, password,
            clientA_adapter, real_adapter_name, real_adapter_ip,
            scenario.cipher, scenario.transport,
            secure::TrafficKeyRotationPolicy{}, real_adapter_luid);

        clientB = std::make_unique<VpnClient>(
            real_adapter_ip, port, password,
            clientB_adapter, real_adapter_name, real_adapter_ip,
            scenario.cipher, scenario.transport,
            secure::TrafficKeyRotationPolicy{}, real_adapter_luid);

        start_client_with_timeout(*clientA, "Client A", 30s);
        start_client_with_timeout(*clientB, "Client B", 30s);

        if (!wait_for_ip(*clientA, 10s) || !wait_for_ip(*clientB, 10s)) {
            std::cerr << "[!] Timed out waiting for client IP assignment\n";
            throw std::runtime_error("ip timeout");
        }

        const std::string ipA = clientA->local_ip();
        const std::string ipB = clientB->local_ip();

        std::cout << "    Client A IP: " << ipA << '\n'
                  << "    Client B IP: " << ipB << '\n';

        std::cout << "[PATH] Probes use production TLS/DTLS framing, server "
                     "source binding and peer routing, and client IPv4 "
                     "validation; same-host probes are consumed immediately "
                     "before Wintun injection.\n";
        configure_probe_observer(*clientA, ipA, ipB, trackerA);
        configure_probe_observer(*clientB, ipB, ipA, trackerB);

        verify_chat_roundtrip(*clientA, *clientB, ipA, ipB,
                              "BASE_" + std::to_string(index));
        std::cout << "[PASS] Bidirectional authenticated chat\n";
        verify_server_chat_fanout_budget(server, *clientA, *clientB);

        (void)measure_latency(*clientA, trackerA, ipA, ipB,
                              "A -> B -> A", 30U, 0x1000U);
        (void)measure_latency(*clientB, trackerB, ipB, ipA,
                              "B -> A -> B", 30U, 0x2000U);
        (void)measure_throughput(*clientA, trackerB, ipA, ipB, "A -> B");
        (void)measure_throughput(*clientB, trackerA, ipB, ipA, "B -> A");

        trackerB.begin_data_run(1U);
        const auto maximum_packet = make_probe_packet(
            ipA, ipB, ProbeKind::Data, 0U,
            secure::kMaximumDatagramPayloadSize - kProbeEnvelopeSize);
        require_test(clientA->send_integration_ipv4_packet(maximum_packet) &&
                         trackerB.wait_for_data(1U, 5s),
                     "maximum-size tunnel packet did not survive the secure path");
        auto oversized_packet = maximum_packet;
        oversized_packet.push_back(0U);
        require_test(!clientA->send_integration_ipv4_packet(oversized_packet),
                     "packet above the tunnel MTU was accepted");

        const std::string oversized_message(kMaximumChatMessageSize + 1U, 'X');
        require_test(!clientA->send_chat_message(oversized_message),
                     "oversized chat message was accepted");
        const std::string post_boundary_message =
            "POST_BOUNDARY_" + std::to_string(index);
        require_test(clientA->send_chat_message(post_boundary_message) &&
                         wait_for_message(*clientB, ipA,
                                          post_boundary_message, 5s),
                     "connection failed after rejected boundary inputs");
        std::cout << "[PASS] MTU/chat overflow boundaries preserve the session\n";

        verify_authenticated_chat_rate_limit(server, *clientA, *clientB);

        // Reclaim the rate-limited client and reuse the same stable adapter
        // identity while the server and the other authenticated peer stay up.
        clientA->set_integration_packet_observer({});
        clientB->set_integration_packet_observer({});
        clientA->stop();
        clientA.reset();
        std::this_thread::sleep_for(1'100ms);

        secure::TrafficKeyRotationPolicy reconnect_policy{};
        if (scenario.transport == TransportProtocol::Udp) {
            reconnect_policy.max_records = 8U;
            reconnect_policy.max_bytes = 1ULL << 30U;
            reconnect_policy.max_age = std::chrono::hours{24};
        }
        clientA = std::make_unique<VpnClient>(
            real_adapter_ip, port, password,
            clientA_adapter, real_adapter_name, real_adapter_ip,
            scenario.cipher, scenario.transport, reconnect_policy,
            real_adapter_luid);
        start_client_with_timeout(*clientA, "Reconnected client A", 30s);
        require_test(wait_for_ip(*clientA, 10s),
                     "reconnected client did not receive an IP address");
        const std::string reconnected_ipA = clientA->local_ip();
        configure_probe_observer(
            *clientA, reconnected_ipA, ipB, trackerA);
        configure_probe_observer(
            *clientB, ipB, reconnected_ipA, trackerB);
        verify_chat_roundtrip(
            *clientA, *clientB, reconnected_ipA, ipB,
            "RECONNECT_" + std::to_string(index));
        (void)measure_latency(
            *clientA, trackerA, reconnected_ipA, ipB,
            "reconnected A -> B -> A", 10U, 0x3000U);
        std::cout << "[PASS] Rate-limit disconnect/reconnect with adapter and port reuse\n";

        const auto rotation_before = clientA->integration_rotation_stats();
        if (scenario.transport == TransportProtocol::Udp) {
            (void)measure_latency(
                *clientA, trackerA, reconnected_ipA, ipB,
                "forced DTLS rotation", 24U, 0x4000U);
            const auto rotation_after = clientA->integration_rotation_stats();
            require_test(rotation_after.application_initiation_supported,
                         "DTLS did not report application key-update support");
            require_test(rotation_after.key_update_requests >
                             rotation_before.key_update_requests,
                         "low-threshold DTLS traffic did not rotate keys");
            require_test(rotation_after.rotation_failures == 0U,
                         "DTLS key rotation reported a failure");
            const std::string post_rotation_message =
                "POST_ROTATION_" + std::to_string(index);
            require_test(clientA->send_chat_message(post_rotation_message) &&
                             wait_for_message(*clientB, reconnected_ipA,
                                              post_rotation_message, 5s),
                         "application traffic failed after DTLS key rotation");
            std::cout << "[ROTATION] DTLS requests="
                      << rotation_after.key_update_requests
                      << ", failures=" << rotation_after.rotation_failures
                      << ", post-update traffic=ok\n";
        } else {
            require_test(!rotation_before.application_initiation_supported,
                         "Schannel unexpectedly advertised app-initiated rotation");
            std::cout << "[ROTATION] TCP uses Schannel provider-managed TLS 1.3 "
                         "key epochs; app-initiated KeyUpdate is unavailable.\n";
            verify_backpressured_server_shutdown(
                server, *clientA, *clientB, reconnected_ipA, ipB);
        }

        success = true;
    } catch (const std::exception& ex) {
        std::cerr << "[!] Scenario error: " << ex.what() << '\n';
    }

    if (clientA) {
        clientA->set_integration_packet_observer({});
        clientA->stop();
    }
    if (clientB) {
        clientB->set_integration_packet_observer({});
        clientB->stop();
    }
    server.stop();
    std::this_thread::sleep_for(1s); // allow adapters to tear down

    return success;
}

} // namespace

int main(int argc, char** argv) {
    bool lightweight_mode = false;
    bool elevated_child = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--wintun-load-only" ||
            argument == "--wintun-identity-test" ||
            argument == "--source-binding-test") {
            lightweight_mode = true;
        } else if (argument == "--elevated-child") {
            elevated_child = true;
        }
    }
    if (!lightweight_mode && !is_running_as_admin()) {
        if (elevated_child) {
            std::cerr << "[FAIL] Elevated child does not have administrator rights\n";
            return 1;
        }
        return relaunch_elevated_and_wait(argc, argv);
    }

    std::filesystem::path log_path;
    std::unique_ptr<ScopedProcessLog> process_log;
    try {
        log_path = requested_log_path(argc, argv);
        process_log = std::make_unique<ScopedProcessLog>(log_path);
    } catch (const std::exception& ex) {
        std::cerr << "[FAIL] Unable to initialize integration logging: "
                  << ex.what() << '\n';
        return 2;
    }
    std::cout << "[LOG] " << log_path.string() << '\n'
              << "[START] " << local_timestamp() << " | pid="
              << ::GetCurrentProcessId() << '\n';
    if (elevated_child) {
        std::cout << "[PRIVILEGE] Elevated through native ShellExecuteExW\n";
    }

    bool wintun_load_only = false;
    bool wintun_identity_test = false;
    bool wintun_lifecycle_test = false;
    bool source_binding_test = false;
    bool controller_cancel_child = false;
    bool repair_network = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--wintun-load-only") {
            wintun_load_only = true;
        }
        if (std::string_view(argv[i]) == "--wintun-identity-test") {
            wintun_identity_test = true;
        }
        if (std::string_view(argv[i]) == "--wintun-lifecycle-test") {
            wintun_lifecycle_test = true;
        }
        if (std::string_view(argv[i]) == "--source-binding-test") {
            source_binding_test = true;
        }
        if (std::string_view(argv[i]) == "--controller-cancel-child") {
            controller_cancel_child = true;
        }
        if (std::string_view(argv[i]) == "--repair-network") {
            repair_network = true;
        }
    }

    if (source_binding_test) {
        return run_source_binding_test() ? 0 : 1;
    }

    if (wintun_identity_test) {
        return run_wintun_identity_derivation_test() ? 0 : 1;
    }

    if (wintun_load_only) {
        try {
            LoadWintun();
            std::cout << "[PASS] Loaded the adjacent pinned Wintun runtime\n";
            return 0;
        } catch (const std::exception& ex) {
            std::cerr << "[FAIL] Wintun loader rejected the runtime: "
                      << ex.what() << '\n';
            return 1;
        }
    }

    if (controller_cancel_child) {
        return run_controller_cancel_child() ? 0 : 1;
    }

    if (!is_running_as_admin()) {
        std::cerr << "[!] Integration test must run as Administrator\n";
        return 1;
    }

    ComInit com;
    WsaInit wsa;

    try {
        LoadWintun();
    } catch (const std::exception& ex) {
        std::cerr << "[!] Failed to load Wintun: " << ex.what() << '\n';
        return 1;
    }

    if (wintun_lifecycle_test) {
        return run_wintun_lifecycle_test() ? 0 : 1;
    }

    if (!run_wintun_lifecycle_test()) {
        return 1;
    }

    populate_real_adapters();
    if (real_adapters_.empty() || real_adapters_.front().ip.empty()) {
        std::cerr << "[!] No suitable physical adapter found for binding\n";
        return 1;
    }

    std::string real_adapter_name = real_adapters_.front().alias;
    std::string real_adapter_ip   = real_adapters_.front().ip;
    const std::uint64_t real_adapter_luid =
        real_adapters_.front().luid_value;

    std::cout << "[PRECHECK] Selected uplink '" << real_adapter_name
              << "' with IPv4 " << real_adapter_ip << '\n';
    try {
        require_test(real_adapter_luid != 0U,
                     "selected uplink did not expose a stable LUID");
        const NET_LUID pinned = ResolveNetworkAdapterLuid(
            real_adapter_name, real_adapter_luid);
        require_test(pinned.Value == real_adapter_luid &&
                         NetworkAdapterAliasMatchesLuid(
                             real_adapter_name, pinned),
                     "selected uplink LUID/alias verification failed");

        std::uint64_t wrong_luid = real_adapter_luid + 1U;
        if (wrong_luid == 0U) wrong_luid = 1U;
        bool mismatch_rejected = false;
        try {
            (void)ResolveNetworkAdapterLuid(real_adapter_name, wrong_luid);
        } catch (const std::exception&) {
            mismatch_rejected = true;
        }
        require_test(mismatch_rejected,
                     "stale physical-adapter identity was accepted");
        std::cout << "[PASS] Physical uplink alias is pinned to LUID "
                  << real_adapter_luid << '\n';
    } catch (const std::exception& ex) {
        std::cerr << "[!] Uplink identity precheck failed: " << ex.what()
                  << '\n';
        return 1;
    }
    try {
        ensure_local_host_route(real_adapter_name, real_adapter_ip);
    } catch (const std::exception& ex) {
        if (!repair_network) {
            std::cerr << "[!] Network precheck failed: " << ex.what() << '\n'
                      << "    Re-run once with --repair-network to reacquire the "
                         "selected adapter's DHCP address through IP Helper.\n";
            return 1;
        }

        std::cerr << "[REPAIR] Address refresh was insufficient: " << ex.what()
                  << '\n'
                  << "[REPAIR] Reacquiring DHCP on '" << real_adapter_name
                  << "' through IpReleaseAddress/IpRenewAddress; connectivity "
                     "will briefly pause\n";
        try {
            ReacquireDhcpIpv4Address(real_adapter_name);
            const auto deadline = std::chrono::steady_clock::now() + 30s;
            bool repaired = false;
            while (std::chrono::steady_clock::now() < deadline) {
                try {
                    populate_real_adapters();
                    const auto found = std::find_if(
                        real_adapters_.begin(), real_adapters_.end(),
                        [&real_adapter_name](const network_adapter_info& adapter) {
                            return adapter.alias == real_adapter_name &&
                                   !adapter.ip.empty();
                        });
                    if (found != real_adapters_.end() &&
                        HasIpv4HostRoute(found->alias, found->ip)) {
                        real_adapter_ip = found->ip;
                        repaired = true;
                        break;
                    }
                } catch (...) {
                    // The interface and DHCP address reappear asynchronously.
                }
                std::this_thread::sleep_for(250ms);
            }
            if (!repaired) {
                throw std::runtime_error(
                    "The local route did not return after reacquiring DHCP");
            }
            std::cout << "[REPAIR] Windows rebuilt the local route for "
                      << real_adapter_ip << '\n';
        } catch (const std::exception& repair_error) {
            std::cerr << "[!] Network repair failed: " << repair_error.what()
                      << '\n';
            return 1;
        }
    }

    if (!run_controller_cancel_process()) {
        return 1;
    }

    const std::vector<Scenario> scenarios = {
        { secure::CipherSuite::Aes256Gcm,        TransportProtocol::Tcp, "TLS 1.3 AES256-GCM / TCP"},
        { secure::CipherSuite::Aes256Gcm,        TransportProtocol::Udp, "wolfSSL DTLS 1.3 / UDP"  },
    };

    const std::string password{kIntegrationSharedKey};
    bool pause_at_end = true;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (arg == "--no-pause" || arg == "-y") {
            pause_at_end = false;
        }
    }

    int passed = 0;

    for (std::size_t i = 0; i < scenarios.size(); ++i) {
        if (run_scenario(static_cast<int>(i), scenarios[i],
                         real_adapter_name, real_adapter_ip,
                         real_adapter_luid, password)) {
            ++passed;
        } else {
            std::cerr << "[!] Scenario failed: " << scenarios[i].name << '\n';
        }
    }

    const bool gui_passed = run_gui_smoke_process();
    std::cout << "\nSummary: " << passed << " / " << scenarios.size()
              << " transport scenarios passed; GUI smoke: "
              << (gui_passed ? "passed" : "failed") << '\n';
    if (pause_at_end) {
        std::cout << "Press Enter to exit...";
        std::cin.get();
    }
    return passed == static_cast<int>(scenarios.size()) && gui_passed ? 0 : 1;
}
