/*
* TrueTunnel VPN - Secure Windows VPN tunnel
 * Copyright (c) 2025 Wesley Atwell
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License OR GNU GPL v2.0 (at your option).
 *
 * You should have received a copy of both licenses in the LICENSE file.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include "vpn.hpp"
#include "utils.hpp"
#include "VpnController.h"
#include "Networking.h"

#include <iostream>
#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <span>
#include <thread>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <functional>		  //  ← ask() validator
#include <mutex>
#include <vector>


#include <mmsystem.h>     // timeBeginPeriod/timeEndPeriod
#pragma comment(lib, "winmm.lib")


#include "secure/SecureSocket.h"

#include <ppltasks.h>

#include <regex>



#include "raii.hpp"

namespace {

constexpr std::array<unsigned char, 32> kExpectedWintunSha256 = {
    0xE5, 0xDA, 0x84, 0x47, 0xDC, 0x2C, 0x32, 0x0E,
    0xDC, 0x0F, 0xC5, 0x2F, 0xA0, 0x18, 0x85, 0xC1,
    0x03, 0xDE, 0x8C, 0x11, 0x84, 0x81, 0xF6, 0x83,
    0x64, 0x3C, 0xAC, 0xC3, 0x22, 0x0D, 0xAF, 0xCE,
};

class FileHandle final {
public:
    explicit FileHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~FileHandle() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(handle_);
        }
    }

    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

class BCryptAlgorithm final {
public:
    BCryptAlgorithm() {
        const NTSTATUS status = ::BCryptOpenAlgorithmProvider(
            &handle_, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (status < 0) {
            throw std::runtime_error(
                "BCryptOpenAlgorithmProvider(SHA-256) failed: " +
                std::to_string(status));
        }
    }

    ~BCryptAlgorithm() {
        if (handle_ != nullptr) {
            ::BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }

    BCryptAlgorithm(const BCryptAlgorithm&) = delete;
    BCryptAlgorithm& operator=(const BCryptAlgorithm&) = delete;

    [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class BCryptHash final {
public:
    BCryptHash(BCRYPT_ALG_HANDLE algorithm, std::vector<unsigned char>& object) {
        const NTSTATUS status = ::BCryptCreateHash(
            algorithm,
            &handle_,
            object.data(),
            static_cast<ULONG>(object.size()),
            nullptr,
            0,
            0);
        if (status < 0) {
            throw std::runtime_error(
                "BCryptCreateHash(SHA-256) failed: " +
                std::to_string(status));
        }
    }

    ~BCryptHash() {
        if (handle_ != nullptr) {
            ::BCryptDestroyHash(handle_);
        }
    }

    BCryptHash(const BCryptHash&) = delete;
    BCryptHash& operator=(const BCryptHash&) = delete;

    [[nodiscard]] BCRYPT_HASH_HANDLE get() const noexcept { return handle_; }

private:
    BCRYPT_HASH_HANDLE handle_ = nullptr;
};

[[nodiscard]] std::filesystem::path executable_directory() {
    std::vector<wchar_t> path(512U);
    for (;;) {
        ::SetLastError(ERROR_SUCCESS);
        const DWORD copied = ::GetModuleFileNameW(
            nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (copied == 0U) {
            throw std::runtime_error(
                "GetModuleFileNameW failed: " + std::to_string(::GetLastError()));
        }
        if (static_cast<std::size_t>(copied) < path.size() - 1U) {
            return std::filesystem::path(
                       std::wstring(path.data(), static_cast<std::size_t>(copied)))
                .parent_path();
        }
        if (path.size() >= 32768U) {
            throw std::runtime_error("Executable path exceeds the Windows path limit");
        }
        path.resize(path.size() * 2U);
    }
}

[[nodiscard]] std::array<unsigned char, 32> sha256_file(HANDLE file) {
    LARGE_INTEGER beginning{};
    if (!::SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN)) {
        throw std::runtime_error(
            "SetFilePointerEx(wintun.dll) failed: " +
            std::to_string(::GetLastError()));
    }
    BCryptAlgorithm algorithm;

    DWORD object_size = 0U;
    DWORD copied = 0U;
    NTSTATUS status = ::BCryptGetProperty(
        algorithm.get(),
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size),
        sizeof(object_size),
        &copied,
        0);
    if (status < 0 || copied != sizeof(object_size) || object_size == 0U) {
        throw std::runtime_error("Unable to query the SHA-256 hash object size");
    }

    std::vector<unsigned char> hash_object(object_size);
    BCryptHash hash(algorithm.get(), hash_object);
    std::vector<unsigned char> buffer(64U * 1024U);

    for (;;) {
        DWORD bytes_read = 0U;
        if (!::ReadFile(file,
                        buffer.data(),
                        static_cast<DWORD>(buffer.size()),
                        &bytes_read,
                        nullptr)) {
            throw std::runtime_error(
                "ReadFile(wintun.dll) failed: " + std::to_string(::GetLastError()));
        }
        if (bytes_read == 0U) {
            break;
        }
        status = ::BCryptHashData(hash.get(), buffer.data(), bytes_read, 0);
        if (status < 0) {
            throw std::runtime_error(
                "BCryptHashData(wintun.dll) failed: " + std::to_string(status));
        }
    }

    std::array<unsigned char, 32> digest{};
    status = ::BCryptFinishHash(
        hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (status < 0) {
        throw std::runtime_error(
            "BCryptFinishHash(wintun.dll) failed: " + std::to_string(status));
    }
    return digest;
}

[[nodiscard]] std::wstring final_path_from_handle(
    HANDLE handle,
    const char* description) {
    constexpr DWORD kPathFlags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    const DWORD required = ::GetFinalPathNameByHandleW(
        handle, nullptr, 0U, kPathFlags);
    if (required == 0U) {
        throw std::runtime_error(
            std::string{"GetFinalPathNameByHandleW("} + description +
            ") failed: " + std::to_string(::GetLastError()));
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(required) + 1U, L'\0');
    const DWORD copied = ::GetFinalPathNameByHandleW(
        handle, buffer.data(), static_cast<DWORD>(buffer.size()), kPathFlags);
    if (copied == 0U || copied >= buffer.size()) {
        throw std::runtime_error(
            std::string{"GetFinalPathNameByHandleW("} + description +
            ") returned an unstable path");
    }
    return std::wstring{buffer.data(), copied};
}

[[nodiscard]] std::array<unsigned char, 32> sha256_bytes(
    const std::span<const unsigned char> input) {
    BCryptAlgorithm algorithm;

    DWORD object_size = 0U;
    DWORD copied = 0U;
    const NTSTATUS property_status = ::BCryptGetProperty(
        algorithm.get(),
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size),
        sizeof(object_size),
        &copied,
        0);
    if (property_status < 0 || copied != sizeof(object_size) || object_size == 0U) {
        throw std::runtime_error("Unable to query the SHA-256 hash object size");
    }

    std::vector<unsigned char> hash_object(object_size);
    BCryptHash hash(algorithm.get(), hash_object);
    if (!input.empty()) {
        const NTSTATUS hash_status = ::BCryptHashData(
            hash.get(),
            const_cast<PUCHAR>(input.data()),
            static_cast<ULONG>(input.size()),
            0);
        if (hash_status < 0) {
            throw std::runtime_error(
                "BCryptHashData(adapter identity) failed: " +
                std::to_string(hash_status));
        }
    }

    std::array<unsigned char, 32> digest{};
    const NTSTATUS finish_status = ::BCryptFinishHash(
        hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (finish_status < 0) {
        throw std::runtime_error(
            "BCryptFinishHash(adapter identity) failed: " +
            std::to_string(finish_status));
    }
    return digest;
}

[[nodiscard]] std::wstring widen_ascii(const std::string_view value) {
    return std::wstring(value.begin(), value.end());
}

[[nodiscard]] std::wstring format_guid_wide(const GUID& guid) {
    std::array<wchar_t, 40> text{};
    const int copied = ::StringFromGUID2(
        guid, text.data(), static_cast<int>(text.size()));
    if (copied <= 1) {
        throw std::runtime_error("StringFromGUID2 failed");
    }
    return std::wstring(text.data(), static_cast<std::size_t>(copied - 1));
}

[[nodiscard]] bool equal_guid(const GUID& left, const GUID& right) noexcept {
    return !!::IsEqualGUID(left, right);
}

[[nodiscard]] std::wstring identity_mutex_name(const GUID& guid) {
    std::wstring value = format_guid_wide(guid);
    value.erase(std::remove(value.begin(), value.end(), L'{'), value.end());
    value.erase(std::remove(value.begin(), value.end(), L'}'), value.end());
    return L"Global\\TrueTunnel.Wintun.Adapter." + value;
}

[[nodiscard]] std::string interface_alias_utf8(const NET_LUID& luid) {
    std::array<wchar_t, IF_MAX_STRING_SIZE + 1U> alias{};
    const NETIO_STATUS status = ::ConvertInterfaceLuidToAlias(
        &luid, alias.data(), alias.size());
    if (status != NO_ERROR) {
        throw std::system_error(
            static_cast<int>(status), std::system_category(),
            "ConvertInterfaceLuidToAlias");
    }
    return wide_to_utf8(alias.data());
}

[[nodiscard]] bool interface_alias_exists(const std::wstring& alias) noexcept {
    NET_LUID luid{};
    return ::ConvertInterfaceAliasToLuid(alias.c_str(), &luid) == NO_ERROR;
}

// WintunCloseAdapter removes a created software device, but Windows can retire
// the SetupAPI node before IP Helper stops resolving its alias/GUID. Keep the
// product-wide identity mutex until both views have released our exact
// interface, otherwise an immediate real-app reconnect observes its own stale
// alias and either fails or lets Wintun suffix a duplicate.
[[nodiscard]] bool wait_for_interface_identity_release(
    const wchar_t* const alias,
    const GUID& expected_guid,
    const std::chrono::milliseconds timeout) noexcept {
    const auto identity_released = [&]() noexcept {
        NET_LUID guid_luid{};
        const bool guid_present =
            ::ConvertInterfaceGuidToLuid(&expected_guid, &guid_luid) == NO_ERROR;

        NET_LUID alias_luid{};
        if (::ConvertInterfaceAliasToLuid(alias, &alias_luid) != NO_ERROR) {
            return !guid_present;
        }

        GUID alias_guid{};
        if (::ConvertInterfaceLuidToGuid(&alias_luid, &alias_guid) != NO_ERROR) {
            return false;
        }

        // A foreign interface can claim the display alias without observing
        // TrueTunnel's mutex. It is not ours to wait on or alter; the next
        // create preflight will reject that collision safely.
        if (!equal_guid(alias_guid, expected_guid)) {
            return !guid_present;
        }
        return false;
    };

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    do {
        if (identity_released()) return true;
        ::Sleep(25U);
    } while (std::chrono::steady_clock::now() < deadline);
    return identity_released();
}

[[nodiscard]] HMODULE load_pinned_wintun() {
    const std::filesystem::path module_directory = executable_directory();
    const std::wstring module_directory_string = module_directory.native();
    FileHandle directory(::CreateFileW(
        module_directory_string.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (directory.get() == INVALID_HANDLE_VALUE) {
        throw std::runtime_error(
            "Unable to pin the executable directory for Wintun loading: " +
            std::to_string(::GetLastError()));
    }

    BY_HANDLE_FILE_INFORMATION directory_info{};
    if (!::GetFileInformationByHandle(directory.get(), &directory_info)) {
        throw std::runtime_error(
            "Unable to inspect the executable directory: " +
            std::to_string(::GetLastError()));
    }
    if ((directory_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
        (directory_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
        throw std::runtime_error(
            "The executable directory must be a real directory, not a reparse point");
    }

    const std::filesystem::path pinned_directory{
        final_path_from_handle(directory.get(), "executable directory")};

    const std::filesystem::path dll_path =
        (pinned_directory / L"wintun.dll").lexically_normal();
    const std::wstring dll_path_string = dll_path.native();

    FileHandle file(::CreateFileW(
        dll_path_string.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (file.get() == INVALID_HANDLE_VALUE) {
        throw std::runtime_error(
            "Unable to open the adjacent wintun.dll: " +
            std::to_string(::GetLastError()));
    }

    BY_HANDLE_FILE_INFORMATION file_info{};
    if (!::GetFileInformationByHandle(file.get(), &file_info)) {
        throw std::runtime_error(
            "Unable to inspect the adjacent wintun.dll: " +
            std::to_string(::GetLastError()));
    }
    if ((file_info.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U ||
        file_info.nNumberOfLinks != 1U) {
        throw std::runtime_error(
            "The adjacent wintun.dll must be a regular, single-link file");
    }

    const auto digest = sha256_file(file.get());
    if (digest != kExpectedWintunSha256) {
        throw std::runtime_error(
            "The adjacent wintun.dll failed its pinned SHA-256 integrity check");
    }

    const std::wstring pinned_dll_path =
        final_path_from_handle(file.get(), "wintun.dll");

    // Keep the file and its real containing directory open without delete
    // sharing through loading. Resolve the loader path from those handles,
    // then hash the locked file again after image mapping. This pins the
    // pathname container and detects a pre-existing writer racing the map.
    HMODULE module = ::LoadLibraryExW(
        pinned_dll_path.c_str(),
        nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module == nullptr) {
        throw std::runtime_error(
            "LoadLibraryExW(adjacent wintun.dll) failed: " +
            std::to_string(::GetLastError()));
    }

    try {
        if (sha256_file(file.get()) != kExpectedWintunSha256) {
            throw std::runtime_error(
                "The mapped wintun.dll changed during its integrity check");
        }
    } catch (...) {
        ::FreeLibrary(module);
        throw;
    }
    return module;
}

} // namespace

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"iphlpapi.lib")


#define CHECK(cond,msg)  do{ if(!(cond)) throw std::runtime_error(msg);}while(0)



void LoadWintun() {
	static std::once_flag once;
	std::call_once(once, []() {
		HMODULE module = load_pinned_wintun();

		auto load_fn = [module](auto &fn, const char *name) {
			fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(
				::GetProcAddress(module, name));
			if (fn == nullptr) {
				::FreeLibrary(module);
				throw std::runtime_error(
					std::string("GetProcAddress failed: ") + name);
			}
		};

		WINTUN_CREATE_ADAPTER_FUNC create_adapter = nullptr;
		WINTUN_OPEN_ADAPTER_FUNC open_adapter = nullptr;
		WINTUN_START_SESSION_FUNC start_session = nullptr;
		WINTUN_END_SESSION_FUNC end_session = nullptr;
		WINTUN_CLOSE_ADAPTER_FUNC close_adapter = nullptr;
		WINTUN_GET_ADAPTER_LUID_FUNC get_adapter_luid = nullptr;
		WINTUN_ALLOCATE_SEND_PACKET_FUNC allocate_send_packet = nullptr;
		WINTUN_SEND_PACKET_FUNC send_packet = nullptr;
		WINTUN_RECEIVE_PACKET_FUNC receive_packet = nullptr;
		WINTUN_RELEASE_RECEIVE_PACKET_FUNC release_receive_packet = nullptr;
		WINTUN_GET_READ_WAIT_EVENT_FUNC get_read_wait_event = nullptr;

		load_fn(create_adapter, "WintunCreateAdapter");
		load_fn(open_adapter, "WintunOpenAdapter");
		load_fn(start_session, "WintunStartSession");
		load_fn(end_session, "WintunEndSession");
		load_fn(close_adapter, "WintunCloseAdapter");
		load_fn(get_adapter_luid, "WintunGetAdapterLUID");
		load_fn(allocate_send_packet, "WintunAllocateSendPacket");
		load_fn(send_packet, "WintunSendPacket");
		load_fn(receive_packet, "WintunReceivePacket");
		load_fn(release_receive_packet, "WintunReleaseReceivePacket");
		load_fn(get_read_wait_event, "WintunGetReadWaitEvent");

		WintunCreateAdapter = create_adapter;
		WintunOpenAdapter = open_adapter;
		WintunStartSession = start_session;
		WintunEndSession = end_session;
		WintunCloseAdapter = close_adapter;
		WintunGetAdapterLUID = get_adapter_luid;
		WintunAllocateSendPacket = allocate_send_packet;
		WintunSendPacket = send_packet;
		WintunReceivePacket = receive_packet;
		WintunReleaseReceivePacket = release_receive_packet;
		WintunGetReadWaitEvent = get_read_wait_event;
		hWintun = module;
	});
}

std::string validate_wintun_adapter_name(const std::string_view name) {
	if (name.empty() || name.size() > kMaximumWintunAdapterNameLength) {
		throw std::invalid_argument(
			"Wintun adapter name must contain 1 to 127 characters");
	}
	if (name.front() == ' ' || name.back() == ' ') {
		throw std::invalid_argument(
			"Wintun adapter name cannot begin or end with a space");
	}
	return sanitize_shell_string(std::string{name});
}

GUID derive_wintun_adapter_guid(const std::string_view adapter_name) {
	const std::string validated = validate_wintun_adapter_name(adapter_name);
	constexpr std::string_view kIdentityNamespace =
		"TrueTunnel/Wintun/AdapterIdentity/v1:";
	std::vector<unsigned char> identity;
	identity.reserve(kIdentityNamespace.size() + validated.size());
	identity.insert(identity.end(),
	                kIdentityNamespace.begin(), kIdentityNamespace.end());
	for (const unsigned char character : validated) {
		identity.push_back(static_cast<unsigned char>(std::tolower(character)));
	}

	const auto digest = sha256_bytes(identity);
	GUID guid{};
	guid.Data1 = (static_cast<unsigned long>(digest[0]) << 24U) |
	             (static_cast<unsigned long>(digest[1]) << 16U) |
	             (static_cast<unsigned long>(digest[2]) << 8U) |
	             static_cast<unsigned long>(digest[3]);
	guid.Data2 = static_cast<unsigned short>(
		(static_cast<unsigned short>(digest[4]) << 8U) |
		static_cast<unsigned short>(digest[5]));
	guid.Data3 = static_cast<unsigned short>(
		(static_cast<unsigned short>(digest[6]) << 8U) |
		static_cast<unsigned short>(digest[7]));
	guid.Data3 = static_cast<unsigned short>((guid.Data3 & 0x0FFFU) | 0x8000U);
	std::copy_n(digest.begin() + 8, 8, guid.Data4);
	guid.Data4[0] = static_cast<unsigned char>((guid.Data4[0] & 0x3FU) | 0x80U);
	return guid;
}

std::string format_guid(const GUID& guid) {
	return wide_to_utf8(format_guid_wide(guid));
}

WintunAdapterLease::WintunAdapterLease(const std::string_view adapter_name)
	: guid_{derive_wintun_adapter_guid(adapter_name)},
	  name_{validate_wintun_adapter_name(adapter_name)} {
	const std::wstring wide_name = widen_ascii(name_);
	const std::wstring mutex_name = identity_mutex_name(guid_);
	identity_mutex_ = ::CreateMutexW(nullptr, FALSE, mutex_name.c_str());
	if (identity_mutex_ == nullptr) {
		throw std::system_error(
			static_cast<int>(::GetLastError()), std::system_category(),
			"CreateMutexW(Wintun adapter identity)");
	}

	const DWORD wait_result = ::WaitForSingleObject(identity_mutex_, 0U);
	if (wait_result != WAIT_OBJECT_0 && wait_result != WAIT_ABANDONED) {
		const DWORD error = wait_result == WAIT_TIMEOUT
			                    ? ERROR_BUSY
			                    : ::GetLastError();
		::CloseHandle(identity_mutex_);
		identity_mutex_ = nullptr;
		throw std::system_error(
			static_cast<int>(error), std::system_category(),
			"The requested TrueTunnel adapter identity is already in use");
	}
	owns_identity_mutex_ = true;

	try {
		LoadWintun();

		// Wintun renames the current owner to "Name 1", "Name 2", etc. when
		// an alias collides. Refuse the collision before calling CreateAdapter.
		if (interface_alias_exists(wide_name)) {
			throw std::runtime_error(
				"A Windows network interface already uses adapter name '" + name_ +
				"'; close the owning TrueTunnel instance or rename the conflicting interface");
		}

		::SetLastError(ERROR_SUCCESS);
		WINTUN_ADAPTER_HANDLE existing = WintunOpenAdapter(wide_name.c_str());
		if (existing != nullptr) {
			WintunCloseAdapter(existing);
			throw std::runtime_error(
				"A Wintun device already owns adapter name '" + name_ +
				"'; refusing to create a suffixed duplicate");
		}
		const DWORD open_error = ::GetLastError();
		if (open_error != ERROR_FILE_NOT_FOUND && open_error != ERROR_NOT_FOUND) {
			throw std::system_error(
				static_cast<int>(open_error), std::system_category(),
				"WintunOpenAdapter preflight");
		}

		::SetLastError(ERROR_SUCCESS);
		adapter_ = WintunCreateAdapter(wide_name.c_str(), L"TrueTunnel", &guid_);
		if (adapter_ == nullptr) {
			throw std::system_error(
				static_cast<int>(::GetLastError()), std::system_category(),
				"WintunCreateAdapter");
		}

		WintunGetAdapterLUID(adapter_, &luid_);
		GUID actual_guid{};
		const NETIO_STATUS guid_status =
			::ConvertInterfaceLuidToGuid(&luid_, &actual_guid);
		if (guid_status != NO_ERROR) {
			throw std::system_error(
				static_cast<int>(guid_status), std::system_category(),
				"ConvertInterfaceLuidToGuid");
		}
		if (!equal_guid(actual_guid, guid_)) {
			throw std::runtime_error(
				"Wintun created an unexpected interface GUID; requested " +
				format_guid(guid_) + ", received " + format_guid(actual_guid));
		}

		const std::string actual_alias = interface_alias_utf8(luid_);
		if (_stricmp(actual_alias.c_str(), name_.c_str()) != 0) {
			throw std::runtime_error(
				"Wintun could not reserve the requested adapter name '" + name_ +
				"' (Windows assigned '" + actual_alias + "'); refusing a suffixed duplicate");
		}
		NET_LUID alias_luid{};
		const NETIO_STATUS alias_status =
			::ConvertInterfaceAliasToLuid(wide_name.c_str(), &alias_luid);
		if (alias_status != NO_ERROR) {
			throw std::system_error(
				static_cast<int>(alias_status), std::system_category(),
				"ConvertInterfaceAliasToLuid(post-create identity check)");
		}
		GUID alias_guid{};
		const NETIO_STATUS alias_guid_status =
			::ConvertInterfaceLuidToGuid(&alias_luid, &alias_guid);
		if (alias_guid_status != NO_ERROR) {
			throw std::system_error(
				static_cast<int>(alias_guid_status), std::system_category(),
				"ConvertInterfaceLuidToGuid(post-create alias check)");
		}
		if (alias_luid.Value != luid_.Value || !equal_guid(alias_guid, guid_)) {
			throw std::runtime_error(
				"Windows alias '" + name_ +
				"' resolves to a different interface identity; refusing configuration");
		}

		std::cout << "[Wintun] Adapter '" << name_ << "' identity "
		          << format_guid(guid_) << " verified\n";
	} catch (...) {
		Reset();
		throw;
	}
}

WintunAdapterLease::~WintunAdapterLease() {
	Reset();
}

WintunAdapterLease::WintunAdapterLease(WintunAdapterLease&& other) noexcept {
	move_from(std::move(other));
}

WintunAdapterLease& WintunAdapterLease::operator=(
	WintunAdapterLease&& other) noexcept {
	if (this != &other) {
		Reset();
		move_from(std::move(other));
	}
	return *this;
}

void WintunAdapterLease::move_from(WintunAdapterLease&& other) noexcept {
	identity_mutex_ = std::exchange(other.identity_mutex_, nullptr);
	owns_identity_mutex_ = std::exchange(other.owns_identity_mutex_, false);
	adapter_ = std::exchange(other.adapter_, nullptr);
	guid_ = other.guid_;
	luid_ = other.luid_;
	name_ = std::move(other.name_);
}

void WintunAdapterLease::Reset() noexcept {
	if (adapter_ != nullptr) {
		std::array<wchar_t, kMaximumWintunAdapterNameLength + 1U> wide_name{};
		const bool name_available = !name_.empty() &&
			name_.size() <= kMaximumWintunAdapterNameLength;
		if (name_available) {
			std::transform(name_.begin(), name_.end(), wide_name.begin(),
			               [](const unsigned char character) {
				               return static_cast<wchar_t>(character);
			               });
		}

		WintunCloseAdapter(adapter_);
		adapter_ = nullptr;
		if (name_available &&
		    !wait_for_interface_identity_release(
			    wide_name.data(), guid_, std::chrono::seconds{10})) {
			try {
				std::cerr << "[Wintun] Timed out waiting for adapter '" << name_
				          << "' identity " << format_guid(guid_)
				          << " to leave the Windows interface table; future starts "
				             "will fail safely while it remains\n";
			} catch (...) {
				// Reset is a destructor path and must remain noexcept.
			}
		}
	}
	if (owns_identity_mutex_ && identity_mutex_ != nullptr) {
		(void)::ReleaseMutex(identity_mutex_);
		owns_identity_mutex_ = false;
	}
	if (identity_mutex_ != nullptr) {
		(void)::CloseHandle(identity_mutex_);
		identity_mutex_ = nullptr;
	}
}


void tun_to_tls(WINTUN_SESSION_HANDLE session,
                const std::function<std::shared_ptr<secure::SecureSocket>()>&
                    tls_snapshot,
                std::mutex& tls_write_mutex,
                std::atomic<bool>& running,
                const std::atomic<bool>* old_writes_blocked,
                const std::atomic<bool>* control_write_pending,
                HANDLE cancellation_event) {
	std::cout << "[tun_to_tls] Started packet forwarding thread\n";

	// Raise priority for lower wake latency
	::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

	// Use Wintun read-wait event correctly (wait only when ring is empty)
	const HANDLE ev = WintunGetReadWaitEvent ? WintunGetReadWaitEvent(session) : nullptr;

	while (running) {
		// Drain all available packets
		for (;;) {
			UINT32 size = 0;
			BYTE *pkt = static_cast<BYTE*>(WintunReceivePacket(session, &size));
			if (!pkt) break;
			// Windows gives every Wintun adapter an IPv6 link-local address even
			// though TrueTunnel is intentionally IPv4-only. Drop that expected
			// background traffic before it reaches the authenticated channel.
			if (!is_well_formed_ipv4_packet(pkt, size)) {
				WintunReleaseReceivePacket(session, pkt);
				continue;
			}
			try {
				// Renewal swaps the SecureSocket while retaining this Wintun
				// session. Snapshot and serialize each packet so an old TLS
				// generation cannot be closed underneath an in-flight write.
				std::unique_lock write_guard{tls_write_mutex};
				while (((old_writes_blocked != nullptr &&
				         old_writes_blocked->load(std::memory_order_acquire)) ||
				        (control_write_pending != nullptr &&
				         control_write_pending->load(std::memory_order_acquire))) &&
				       running.load(std::memory_order_acquire)) {
					write_guard.unlock();
					if (cancellation_event != nullptr &&
					    ::WaitForSingleObject(cancellation_event, 10U) ==
							WAIT_OBJECT_0) {
						running.store(false, std::memory_order_release);
						break;
					}
					::Sleep(1U);
					write_guard.lock();
				}
				if (!running.load(std::memory_order_acquire)) {
					WintunReleaseReceivePacket(session, pkt);
					break;
				}
				auto tls = tls_snapshot();
				if (!tls) {
					throw std::runtime_error("secure transport unavailable");
				}
				const int sent = tls->send_record(
					PACKET_TYPE_IP, pkt, static_cast<uint16_t>(size));
				if (sent != static_cast<int>(size)) {
					throw std::runtime_error("short secure-record write");
				}
			} catch (...) {
				std::cerr << "[tun_to_tls] send_record failed; stopping tunnel\n";
				running = false;
				WintunReleaseReceivePacket(session, pkt);
				throw;
			}
			WintunReleaseReceivePacket(session, pkt);
		}
		if (!running) break;
		const DWORD err = ::GetLastError();
		if (err == ERROR_NO_MORE_ITEMS) {
			if (ev) {
				DWORD wait_rc = WAIT_FAILED;
				if (cancellation_event != nullptr) {
					const HANDLE events[] = {cancellation_event, ev};
					wait_rc = ::WaitForMultipleObjects(
						2U,
						events,
						FALSE,
						INFINITE);
					if (wait_rc == WAIT_OBJECT_0) {
						break;
					}
				} else {
					wait_rc = ::WaitForSingleObject(ev, INFINITE);
				}
				if (wait_rc == WAIT_FAILED) {
					::Sleep(1);
				}
			} else {
				::Sleep(1);
			}
		} else if (err == ERROR_HANDLE_EOF) {
			break; // session ending
		} else {
			::Sleep(1); // transient/unknown
		}
	}
}


/*void tls_to_tun(WINTUN_SESSION_HANDLE session, SSL *ssl, std::atomic<bool> &running, std::mutex &session_mutex) {
	std::cout << "[tls_to_tun] Started packet receiving thread\n";
	char buf[1600] {};
	while (running) {
		uint8_t pkt_type = 0;
		{
			std::lock_guard<std::mutex> lock(ssl_read_mutex);
			if (SSL_read(ssl, &pkt_type, 1) <= 0) break;
		}

if (pkt_type == PACKET_TYPE_IP) {
	int n = 0; {
		std::lock_guard<std::mutex> lock(ssl_read_mutex);
		n = SSL_read(ssl, buf, sizeof(buf));
		if (n <= 0) {
			int err = SSL_get_error(ssl, n);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
				continue;
			break;
		}
	}

	std::lock_guard<std::mutex> lock(session_mutex);  // ✅ protect Wintun write
			void *pkt = WintunAllocateSendPacket(session, (UINT32) n);
			if (!pkt) break;
			memcpy(pkt, buf, n);
		//	std::cout << "[tls_to_tun] Writing packet of size " << n << "\n";
			WintunSendPacket(session, pkt, (UINT32) n);

		} else if (pkt_type == PACKET_TYPE_MSG) {
			char msg_buf[1024] = {};
			int n = 0;
			{
				std::lock_guard<std::mutex> lock(ssl_read_mutex);
				n = SSL_read(ssl, msg_buf, sizeof(msg_buf) - 1);
			}
			if (n > 0) {
				msg_buf[n] = '\0';

				std::cout << "[📨] Message from peer: " << msg_buf << std::endl;

				if (std::string(msg_buf) == "/quit") {
					std::cout << "[!] Peer requested disconnect. Closing session.\n";
					break;
				}
			}
		}
	}
}*/




// void send_message(SSL *ssl, const std::string &msg) {
// std::lock_guard<std::mutex> lock(ssl_write_mutex);
// 	uint8_t packet_type = PACKET_TYPE_MSG;
// 	SSL_write(ssl, &packet_type, 1);
// 	SSL_write(ssl, msg.c_str(), static_cast<int>(msg.size()));
// }
