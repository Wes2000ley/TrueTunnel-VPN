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
#include <filesystem>
#include <thread>
#include <stdexcept>
#include <string>
#include <functional>		  //  ← ask() validator
#include <regex>
#include "termcolor.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/provider.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <netfw.h>
#include <comdef.h>
#include <stdexcept>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"iphlpapi.lib")

using termcolor::bold;
using termcolor::green;
using termcolor::yellow;
using termcolor::red;
using termcolor::reset;

// ─── pretty logging helpers ───────────────────────────────────
namespace util {
	void logInfo(const std::string &s) {
		std::cout << bold << green << "[INFO] " << reset << s << std::endl;
	}

	void logWarn(const std::string &s) {
		std::cout << bold << yellow << "[WARN] " << reset << s << std::endl;
	}

	void logErr(const std::string &s) {
		std::cerr << bold << red << "[ERR ] " << reset << s << std::endl;
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



bool run_command_hidden(const std::string& command) {
	STARTUPINFOW startup_info = { sizeof(startup_info) };
	startup_info.dwFlags = STARTF_USESHOWWINDOW;
	startup_info.wShowWindow = SW_HIDE;

	PROCESS_INFORMATION process_info{};

	std::wstring wide_command(command.begin(), command.end());
	std::vector<wchar_t> command_buffer(wide_command.begin(), wide_command.end());
	command_buffer.push_back(L'\0');

	BOOL success = CreateProcessW(
		nullptr,
		command_buffer.data(),
		nullptr,
		nullptr,
		FALSE,
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

	WaitForSingleObject(process_handle.get(), INFINITE);

	DWORD exit_code = 0;
	GetExitCodeProcess(process_handle.get(), &exit_code);

	return (exit_code == 0);
}


bool run_command_admin(const std::string& command) {
	std::wstring wcmd = L"-Command \"" + std::wstring(command.begin(), command.end()) + L"\"";

	SHELLEXECUTEINFOW sei = { sizeof(sei) };
	sei.lpVerb = L"runas";
	sei.lpFile = L"powershell.exe";
	sei.lpParameters = wcmd.c_str();
	sei.nShow = SW_HIDE;
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;

	if (!ShellExecuteExW(&sei)) {
		DWORD err = GetLastError();
		std::cerr << "[!] ShellExecuteEx failed: " << err << "\n";
		return false;
	}

	HandleGuard process_handle(sei.hProcess);
	WaitForSingleObject(process_handle.get(), INFINITE);

	DWORD exit_code = 0;
	GetExitCodeProcess(process_handle.get(), &exit_code);

	return (exit_code == 0);
}




std::string sanitize_shell_string(const std::string &input) {
	static const std::regex allowed(R"(^[a-zA-Z0-9 _\.\-]{1,64}$)");
	if (!std::regex_match(input, allowed)) {
		throw std::runtime_error("Unsafe characters in input string for shell command");
	}
	return input;
}

std::string sanitize_ip(const std::string &ip) {
	static const std::regex ip_regex(R"(^\d{1,3}(\.\d{1,3}){3}$)");
	if (!std::regex_match(ip, ip_regex)) {
		throw std::runtime_error("Invalid IP address");
	}
	return ip;
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
