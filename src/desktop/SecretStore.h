#pragma once
#include "NativeCommon.h"
#include "secure/SharedSecret.h"
#include <chrono>
#include <cstring>

namespace desktop {
using SharedSecretBuffer = std::array<char, 64>;
inline constexpr auto kClipboardSecretLifetime = std::chrono::seconds{30};
inline std::string_view shared_secret_text(const SharedSecretBuffer &value) noexcept {
    const auto end = std::find(value.begin(), value.end(), '\0');
    return {value.data(), static_cast<size_t>(end - value.begin())};
}
// Preserve the existing CNG generation and ownership-checked clipboard lease.
inline bool shared_secret_invariants_hold(const SharedSecretBuffer &value) noexcept {
    return secure::is_valid_shared_secret(shared_secret_text(value));
}

inline bool generate_shared_secret(SharedSecretBuffer &destination) noexcept {
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (unsigned int attempt = 0U; attempt < 8U; ++attempt) {
        std::array<std::uint8_t, secure::kSharedSecretBytes> random_bytes{};
        const NTSTATUS status =
            ::BCryptGenRandom(nullptr, random_bytes.data(), static_cast<ULONG>(random_bytes.size()),
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
    [[nodiscard]] bool copy_secret(HWND owner, const SharedSecretBuffer &secret) noexcept {
        const int wide_characters =
            ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, secret.data(), -1, nullptr, 0);
        if (owner == nullptr || wide_characters <= 1)
            return false;

        const SIZE_T secret_bytes = static_cast<SIZE_T>(wide_characters) * sizeof(wchar_t);
        HGLOBAL secret_memory = ::GlobalAlloc(GMEM_MOVEABLE, secret_bytes);
        if (secret_memory == nullptr)
            return false;

        auto *const secret_text = static_cast<wchar_t *>(::GlobalLock(secret_memory));
        if (secret_text == nullptr) {
            ::GlobalFree(secret_memory);
            return false;
        }
        const int converted = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, secret.data(),
                                                    -1, secret_text, wide_characters);
        if (converted != wide_characters) {
            ::SecureZeroMemory(secret_text, secret_bytes);
            ::GlobalUnlock(secret_memory);
            ::GlobalFree(secret_memory);
            return false;
        }
        ::GlobalUnlock(secret_memory);

        const UINT exclusion_format =
            ::RegisterClipboardFormatW(L"ExcludeClipboardContentFromMonitorProcessing");
        HGLOBAL exclusion_memory = ::GlobalAlloc(GMEM_MOVEABLE, sizeof(DWORD));
        if (exclusion_format == 0U || exclusion_memory == nullptr) {
            wipe_and_free(secret_memory, secret_bytes);
            if (exclusion_memory != nullptr) {
                ::GlobalFree(exclusion_memory);
            }
            return false;
        }
        auto *const exclusion_value = static_cast<DWORD *>(::GlobalLock(exclusion_memory));
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
        if (::SetClipboardData(exclusion_format, exclusion_memory) == nullptr) {
            ::EmptyClipboard();
            ::CloseClipboard();
            wipe_and_free(secret_memory, secret_bytes);
            ::GlobalFree(exclusion_memory);
            return false;
        }
        exclusion_memory = nullptr; // The system owns it now.

        if (::SetClipboardData(CF_UNICODETEXT, secret_memory) == nullptr) {
            ::EmptyClipboard();
            ::CloseClipboard();
            wipe_and_free(secret_memory, secret_bytes);
            return false;
        }
        secret_memory = nullptr; // The system owns and will free it.

        // No other process can mutate the clipboard while it is open,
        // so this sequence number belongs to the successful write.
        const DWORD sequence = ::GetClipboardSequenceNumber();
        const bool ownership_confirmed = sequence != 0U && ::GetClipboardOwner() == owner;
        if (!ownership_confirmed) {
            ::EmptyClipboard();
            ::CloseClipboard();
            return false;
        }

        sequence_ = sequence;
        owner_ = owner;
        expires_ = std::chrono::steady_clock::now() + kClipboardSecretLifetime;
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
        if (active_)
            clear_if_owned(owner);
    }

    [[nodiscard]] bool clear_before_shutdown(HWND owner) noexcept {
        while (active_) {
            const auto retry_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
            do {
                clear_if_owned(owner);
                if (!active_)
                    return true;
                ::Sleep(10U);
            } while (std::chrono::steady_clock::now() < retry_deadline);

            const int choice =
                ::MessageBoxW(owner,
                              L"The clipboard is busy, so TrueTunnel could "
                              L"not clear the copied shared key. Close the "
                              L"application using the clipboard, then choose "
                              L"Retry. Cancel exits without clearing it.",
                              L"TrueTunnel clipboard protection",
                              MB_RETRYCANCEL | MB_ICONWARNING | MB_DEFBUTTON1 | MB_TASKMODAL);
            if (choice != IDRETRY)
                return false;
        }
        return true;
    }

  private:
    void clear_if_owned(HWND owner) noexcept {
        const DWORD before_open = ::GetClipboardSequenceNumber();
        if (owner != owner_ || before_open == 0U || before_open != sequence_ ||
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
        if (after_open == sequence_ && ::GetClipboardOwner() == owner_ && ::EmptyClipboard()) {
            active_ = false;
        } else if (after_open != sequence_ || ::GetClipboardOwner() != owner_) {
            active_ = false;
        }
        ::CloseClipboard();
    }

    static void wipe_and_free(HGLOBAL memory, const SIZE_T bytes) noexcept {
        if (memory == nullptr)
            return;
        void *const data = ::GlobalLock(memory);
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

class SecretStore {
  public:
    SecretStore() { locked_ = VirtualLock(value.data(), value.size()) != FALSE; }
    ~SecretStore() {
        clear();
        if (locked_)
            VirtualUnlock(value.data(), value.size());
    }
    SecretStore(const SecretStore &) = delete;
    SecretStore &operator=(const SecretStore &) = delete;
    bool ready() const { return shared_secret_invariants_hold(value); }
    bool generate() {
        clear();
        generated = generate_shared_secret(value);
        return generated;
    }
    void clear() {
        SecureZeroMemory(value.data(), value.size());
        generated = false;
    }
    bool paste(HWND owner) {
        if (!OpenClipboard(owner))
            return false;
        HANDLE memory = GetClipboardData(CF_UNICODETEXT);
        SharedSecretBuffer candidate{};
        bool valid = false;
        if (memory && GlobalSize(memory) >= 44 * sizeof(wchar_t)) {
            const auto *text = static_cast<const wchar_t *>(GlobalLock(memory));
            if (text) {
                bool ascii = true;
                for (size_t index = 0; index < 43; ++index) {
                    if (text[index] < 1 || text[index] > 127)
                        ascii = false;
                    candidate[index] = static_cast<char>(text[index] & 0x7f);
                }
                valid = ascii && text[43] == L'\0' && shared_secret_invariants_hold(candidate);
                GlobalUnlock(memory);
            }
        }
        CloseClipboard();
        if (valid) {
            clear();
            value = candidate;
        }
        SecureZeroMemory(candidate.data(), candidate.size());
        return valid;
    }
    SharedSecretBuffer value{};
    bool generated{false};

  private:
    bool locked_{false};
};
} // namespace desktop
