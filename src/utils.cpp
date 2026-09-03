#define WIN32_LEAN_AND_MEAN
#include "utils.hpp"

#include <codecvt>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include "vpn.hpp"
#include <shellapi.h>
#pragma comment(lib, "Shell32.lib")


#include <iostream>
#include <array>
#include <filesystem>
#include <thread>
#include <stdexcept>
#include <string>
#include <string_view>
#include <functional>		  //  ← ask() validator
#include <regex>
#include <atomic>
#include <chrono>

#include <stdint.h>
#include <netfw.h>
#include <comdef.h>
#include <stdexcept>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"iphlpapi.lib")



// ─── pretty logging helpers ───────────────────────────────────
namespace util {
	void logInfo(const std::string &s) {
	std::cout << "[INFO] " << s << std::endl;
	}

	void logWarn(const std::string &s) {
		std::cout  << "[WARN] "  << s << std::endl;
	}

	void logErr(const std::string &s) {
		std::cerr  << "[ERR ] "  << s << std::endl;
	}

	bool looksLikeIp(const std::string &v) {
		in_addr a{};
		return inet_pton(AF_INET, v.c_str(), &a) == 1;
	}

	void ask(const char *prompt, std::string &val,
	         std::function<bool(const std::string &)> ok) {
		if (!val.empty()) return;
		for (;;) {
			std::cout << prompt << ": ";
			std::getline(std::cin, val);
			if (!ok || ok(val)) break;
			logWarn("Invalid value, try again");
			val.clear();
		}
	}
} // namespace

bool is_running_as_admin() {
	BOOL is_admin = FALSE;
	PSID admin_group = nullptr;
	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

	if (AllocateAndInitializeSid(&nt_authority, 2,
	                             SECURITY_BUILTIN_DOMAIN_RID,
	                             DOMAIN_ALIAS_RID_ADMINS,
	                             0, 0, 0, 0, 0, 0, &admin_group)) {
		CheckTokenMembership(nullptr, admin_group, &is_admin);
		FreeSid(admin_group);
	}

	return is_admin;
}

bool is_valid_input(const std::string &s) {
	if (s.empty()) {
		return false;
	}
	return std::all_of(s.begin(), s.end(), [](char c) {
		return (c >= 'a' && c <= 'z')
		       || (c >= 'A' && c <= 'Z')
		       || (c >= '0' && c <= '9')
		       || c == '.';
	});
}

class HandleGuard {
public:
	explicit HandleGuard(HANDLE h = nullptr) noexcept : handle_(h) {}

	~HandleGuard() {
		if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
			CloseHandle(handle_);
		}
	}

	HandleGuard(HandleGuard&& other) noexcept : handle_(other.handle_) {
		other.handle_ = nullptr;
	}

	HandleGuard& operator=(HandleGuard&& other) noexcept {
		if (this != &other) {
			if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
				CloseHandle(handle_);
			}
			handle_ = other.handle_;
			other.handle_ = nullptr;
		}
		return *this;
	}

	[[nodiscard]] HANDLE get() const noexcept { return handle_; }
	[[nodiscard]] explicit operator bool() const noexcept { return handle_ && handle_ != INVALID_HANDLE_VALUE; }

	HandleGuard(const HandleGuard&) = delete;
	HandleGuard& operator=(const HandleGuard&) = delete;

private:
	HANDLE handle_;
};



bool run_command_hidden(const std::string& command,
	                    const std::atomic<bool>* keep_running,
	                    const std::chrono::milliseconds timeout) {
	if (timeout <= std::chrono::milliseconds::zero()) return false;
	constexpr std::string_view kDiscardOutputSuffix = " >nul 2>&1";
	std::string direct_command = command;
	if (direct_command.size() >= kDiscardOutputSuffix.size() &&
	    direct_command.compare(direct_command.size() - kDiscardOutputSuffix.size(),
	                           kDiscardOutputSuffix.size(),
	                           kDiscardOutputSuffix) == 0) {
		direct_command.erase(direct_command.size() - kDiscardOutputSuffix.size());
	}

	std::wstring executable_name;
	std::string arguments;
	if (direct_command.starts_with("netsh ")) {
		executable_name = L"netsh.exe";
		arguments = direct_command.substr(6U);
	} else if (direct_command.starts_with("route ")) {
		executable_name = L"route.exe";
		arguments = direct_command.substr(6U);
	} else {
		return false;
	}

	std::array<wchar_t, MAX_PATH + 1U> system_directory{};
	const UINT system_length = ::GetSystemDirectoryW(
		system_directory.data(), static_cast<UINT>(system_directory.size()));
	if (system_length == 0U || system_length >= system_directory.size()) {
		return false;
	}
	const std::filesystem::path executable_path =
		std::filesystem::path(system_directory.data()) / executable_name;
	const std::wstring wide_arguments(arguments.begin(), arguments.end());
	const std::wstring wide_command =
		L"\"" + executable_path.native() + L"\" " + wide_arguments;

	STARTUPINFOW startup_info = { sizeof(startup_info) };
	startup_info.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	startup_info.wShowWindow = SW_HIDE;
	SECURITY_ATTRIBUTES handle_attributes{sizeof(handle_attributes), nullptr, TRUE};
	HandleGuard null_device(::CreateFileW(
		L"NUL",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		&handle_attributes,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr));
	if (!null_device) return false;
	startup_info.hStdInput = null_device.get();
	startup_info.hStdOutput = null_device.get();
	startup_info.hStdError = null_device.get();

	PROCESS_INFORMATION process_info{};

	std::vector<wchar_t> command_buffer(wide_command.begin(), wide_command.end());
	command_buffer.push_back(L'\0');

	BOOL success = CreateProcessW(
		executable_path.c_str(),
		command_buffer.data(),
		nullptr,
		nullptr,
		TRUE,
		CREATE_NO_WINDOW,
		nullptr,
		nullptr,
		&startup_info,
		&process_info
	);

	if (!success) {
		return false;
	}

	HandleGuard process_handle(process_info.hProcess);
	HandleGuard thread_handle(process_info.hThread);

	const auto deadline = std::chrono::steady_clock::now() + timeout;
	for (;;) {
		const DWORD wait_result = ::WaitForSingleObject(process_handle.get(), 100U);
		if (wait_result == WAIT_OBJECT_0) break;
		if (wait_result != WAIT_TIMEOUT ||
		    (keep_running != nullptr &&
		     !keep_running->load(std::memory_order_acquire)) ||
		    std::chrono::steady_clock::now() >= deadline) {
			// This is always the exact netsh.exe/route.exe child created above.
			// Bound setup and teardown if a Windows networking utility stalls.
			(void)::TerminateProcess(process_handle.get(), ERROR_CANCELLED);
			(void)::WaitForSingleObject(process_handle.get(), 5'000U);
			return false;
		}
	}

	DWORD exit_code = 0;
	if (!::GetExitCodeProcess(process_handle.get(), &exit_code)) return false;

	return (exit_code == 0);
}





std::string sanitize_shell_string(const std::string &input) {
	static const std::regex allowed(R"(^[a-zA-Z0-9 _\.\-#\(\)]{1,128}$)");
	if (!std::regex_match(input, allowed)) {
		throw std::runtime_error("Unsafe characters in input string for shell command");
	}
	return input;
}

std::string sanitize_ip(const std::string &ip) {
	IN_ADDR parsed{};
	if (::InetPtonA(AF_INET, ip.c_str(), &parsed) != 1) {
		throw std::runtime_error("Invalid IP address");
	}
	std::array<char, INET_ADDRSTRLEN> canonical{};
	if (::InetNtopA(AF_INET,
	                &parsed,
	                canonical.data(),
	                static_cast<DWORD>(canonical.size())) == nullptr) {
		throw std::runtime_error("Unable to canonicalize IPv4 address");
	}
	return canonical.data();
}

std::string wide_to_utf8(const std::wstring& wide) {
	if (wide.empty()) return {};

	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (size_needed <= 0) return {};

	std::string result(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &result[0], size_needed, nullptr, nullptr);

	// Remove null terminator if present
	if (!result.empty() && result.back() == '\0')
		result.pop_back();

	return result;
}

ULONG convert_mask_to_prefix(const std::string& subnet_mask) {
	IN_ADDR addr {};
	if (InetPtonA(AF_INET, subnet_mask.c_str(), &addr) != 1) {
		throw std::invalid_argument("Invalid subnet mask: " + subnet_mask);
	}

	ULONG mask = ntohl(addr.S_un.S_addr);
	ULONG prefix_length = 0;

	const int max_bits = 32;
	for (; mask & 0x80000000 && prefix_length < max_bits; ++prefix_length) {
		mask <<= 1;
	}


	return prefix_length;
}
