#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// Windows headers have an order dependency; keep Winsock before Windows/BCrypt.
// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
// clang-format on
#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <sddl.h>
#include <shellapi.h>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace desktop {
class Handle {
  public:
    explicit Handle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    Handle(Handle &&other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    Handle &operator=(Handle &&other) noexcept {
        if (this != &other)
            reset(std::exchange(other.value_, nullptr));
        return *this;
    }
    HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }
    void reset(HANDLE value = nullptr) noexcept {
        if (*this)
            CloseHandle(value_);
        value_ = value;
    }

  private:
    HANDLE value_;
};
inline std::wstring widen(std::string_view text) {
    if (text.empty())
        return {};
    if (text.size() > 1'000'000)
        throw std::runtime_error("Text exceeds desktop bridge limit");
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                     static_cast<int>(text.size()), nullptr, 0);
    if (!length)
        throw std::runtime_error("Invalid UTF-8");
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                        result.data(), length);
    return result;
}
inline std::string narrow(std::wstring_view text) {
    if (text.empty())
        return {};
    if (text.size() > 1'000'000)
        throw std::runtime_error("Text exceeds desktop bridge limit");
    int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                                     static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!length)
        throw std::runtime_error("Invalid UTF-16");
    std::string result(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                        result.data(), length, nullptr, nullptr);
    return result;
}
inline std::wstring process_path(HANDLE process) {
    std::wstring result(32768, L'\0');
    DWORD length = static_cast<DWORD>(result.size());
    if (!QueryFullProcessImageNameW(process, 0, result.data(), &length))
        throw std::runtime_error("Cannot verify desktop process image");
    result.resize(length);
    return result;
}
inline std::filesystem::path executable() { return process_path(GetCurrentProcess()); }
inline std::wstring user_sid(HANDLE process) {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &raw))
        throw std::runtime_error("Cannot verify process owner");
    Handle token(raw);
    DWORD size = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    std::vector<BYTE> data(size);
    if (!GetTokenInformation(token.get(), TokenUser, data.data(), size, &size))
        throw std::runtime_error("Cannot read process owner");
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid, &sid))
        throw std::runtime_error("Cannot encode process owner");
    std::wstring result(sid);
    LocalFree(sid);
    return result;
}
inline bool elevated() {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
        return false;
    Handle token(raw);
    TOKEN_ELEVATION value{};
    DWORD size = 0;
    return GetTokenInformation(token.get(), TokenElevation, &value, sizeof(value), &size) &&
           value.TokenIsElevated;
}
inline bool same_application(HANDLE process) {
    return _wcsicmp(process_path(process).c_str(), executable().c_str()) == 0 &&
           user_sid(process) == user_sid(GetCurrentProcess());
}
inline std::wstring random_suffix() {
    std::array<BYTE, 24> bytes{};
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("Windows random generator failed");
    constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring text;
    for (BYTE byte : bytes) {
        text += hex[byte >> 4];
        text += hex[byte & 15];
    }
    SecureZeroMemory(bytes.data(), bytes.size());
    return text;
}
// Validate the opened object before truncating it. Diagnostic output must never
// follow a reparse point or overwrite a file through an existing hard link.
inline bool write_diagnostic_file(const std::filesystem::path &path, std::span<const BYTE> data) {
    if (data.size() > 16 * 1024 * 1024)
        return false;
    Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    if (!file || GetFileType(file.get()) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(file.get(), &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
        info.nNumberOfLinks != 1)
        return false;
    LARGE_INTEGER beginning{};
    if (!SetFilePointerEx(file.get(), beginning, nullptr, FILE_BEGIN) || !SetEndOfFile(file.get()))
        return false;
    DWORD written{};
    return WriteFile(file.get(), data.data(), static_cast<DWORD>(data.size()), &written, nullptr) &&
           written == data.size() && FlushFileBuffers(file.get());
}
} // namespace desktop
