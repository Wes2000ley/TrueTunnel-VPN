#pragma once
#include "NativeCommon.h"
#include "secure/SharedSecret.h"
#include <span>
#include <type_traits>
#include <memory>

namespace desktop {
// Versioned, bounded local IPC. Secrets never pass through JSON or JavaScript.
inline constexpr std::uint32_t kBridgeMagic = 0x31555454;
inline constexpr std::uint32_t kMaximumPayload = 32768;

inline Handle create_private_pipe(const std::wstring &name) {
    const auto descriptor =
        L"D:P(A;;GA;;;" + user_sid(GetCurrentProcess()) + L")(A;;GA;;;BA)S:(ML;;NW;;;ME)";
    PSECURITY_DESCRIPTOR security = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.c_str(), SDDL_REVISION_1,
                                                              &security, nullptr))
        throw std::runtime_error("Cannot secure the local networking channel");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), security, FALSE};
    Handle pipe(CreateNamedPipeW(
        name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
        kMaximumPayload, kMaximumPayload, 5000, &attributes));
    LocalFree(security);
    if (!pipe)
        throw std::runtime_error("Cannot create the private networking channel");
    return pipe;
}
enum class Operation : std::uint32_t { Start = 1, Poll = 2, Stop = 3, Chat = 4, Snapshot = 5 };
struct Header {
    std::uint32_t magic{kBridgeMagic};
    std::uint32_t version{1};
    Operation operation{};
    std::uint32_t length{};
};
struct StartRequest {
    std::uint64_t adapter_luid{};
    std::uint32_t port{};
    std::uint32_t server{};
    std::uint32_t udp{};
    std::uint32_t recovery{};
    std::array<char, 256> address{};
    std::array<char, 64> secret{};
};
static_assert(std::is_trivially_copyable_v<StartRequest> && sizeof(StartRequest) == 344);
struct StartRequestDeleter {
    void operator()(StartRequest *request) const noexcept {
        if (request) {
            SecureZeroMemory(request, sizeof(*request));
            delete request;
        }
    }
};
using SensitiveStartRequest = std::unique_ptr<StartRequest, StartRequestDeleter>;
inline bool valid_start_request(const StartRequest &request) noexcept {
    if (!request.adapter_luid || !request.port || request.port > 65535 || request.server > 1 ||
        request.udp > 1 || request.recovery > 1 || request.address.back() || request.secret.back())
        return false;
    const std::string_view secret(request.secret.data(),
                                  strnlen_s(request.secret.data(), request.secret.size()));
    const std::string_view address(request.address.data(),
                                   strnlen_s(request.address.data(), request.address.size()));
    if (!secure::is_valid_shared_secret(secret))
        return false;
    if (request.server)
        return true;
    if (address.empty() || address.size() > 253 || address.front() == '.' || address.back() == '.')
        return false;
    return std::all_of(address.begin(), address.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
               ch == '.' || ch == '-';
    });
}
inline bool valid_header(const Header &header) noexcept {
    return header.magic == kBridgeMagic && header.version == 1 &&
           header.length <= kMaximumPayload && header.operation >= Operation::Start &&
           header.operation <= Operation::Snapshot;
}
inline bool valid_request(const Header &header) noexcept {
    if (!valid_header(header))
        return false;
    switch (header.operation) {
    case Operation::Start:
        return header.length == sizeof(StartRequest);
    case Operation::Poll:
    case Operation::Stop:
        return header.length == 0;
    case Operation::Chat:
        return header.length > 0 && header.length <= 512;
    default:
        return false;
    }
}
inline bool pipe_io(HANDLE pipe, bool writing, void *data, DWORD length, HANDLE stop,
                    DWORD timeout = 5000) {
    auto *bytes = static_cast<BYTE *>(data);
    while (length) {
        Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!event)
            return false;
        OVERLAPPED overlapped{};
        overlapped.hEvent = event.get();
        DWORD transferred = 0;
        BOOL done = writing ? WriteFile(pipe, bytes, length, &transferred, &overlapped)
                            : ReadFile(pipe, bytes, length, &transferred, &overlapped);
        if (!done) {
            if (GetLastError() != ERROR_IO_PENDING)
                return false;
            HANDLE waits[]{event.get(), stop};
            DWORD result = WaitForMultipleObjects(stop ? 2U : 1U, waits, FALSE, timeout);
            if (result != WAIT_OBJECT_0) {
                CancelIoEx(pipe, &overlapped);
                WaitForSingleObject(event.get(), INFINITE);
                return false;
            }
            if (!GetOverlappedResult(pipe, &overlapped, &transferred, FALSE))
                return false;
        }
        if (transferred == 0 || transferred > length)
            return false;
        bytes += transferred;
        length -= transferred;
    }
    return true;
}
inline bool write_frame(HANDLE pipe, Operation operation, const void *data, std::uint32_t length,
                        HANDLE stop) {
    if (length > kMaximumPayload)
        return false;
    Header header{kBridgeMagic, 1, operation, length};
    return pipe_io(pipe, true, &header, sizeof(header), stop) &&
           (!length || pipe_io(pipe, true, const_cast<void *>(data), length, stop));
}
inline bool read_header(HANDLE pipe, Header &header, HANDLE stop) {
    return pipe_io(pipe, false, &header, sizeof(header), stop) && valid_header(header);
}
int run_broker(std::wstring_view pipe_name, DWORD parent_pid);
} // namespace desktop
