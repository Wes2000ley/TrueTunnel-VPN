#define WIN32_LEAN_AND_MEAN
#include "utils.hpp"

#include <codecvt>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <EASTL/vector.h>
#include "vpn.hpp"

#include <iostream>
#include <filesystem>
#include <thread>
#include <stdexcept>
#include <string>
#include <functional>		  //  ← ask() validator
#include "include/cxxopts.hpp"
#include "termcolor.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/provider.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

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
	void logInfo(const std::string& s) {
		std::cout << bold << green << "[INFO] " << reset << s << std::endl;
	}
	void logWarn(const std::string& s) {
		std::cout << bold << yellow << "[WARN] " << reset << s << std::endl;
	}
	void logErr(const std::string& s) {
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

bool is_running_as_admin()
{
	BOOL is_admin = FALSE;
	PSID admin_group = nullptr;
	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

	if (AllocateAndInitializeSid(&nt_authority, 2,
								 SECURITY_BUILTIN_DOMAIN_RID,
								 DOMAIN_ALIAS_RID_ADMINS,
								 0, 0, 0, 0, 0, 0, &admin_group))
	{
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

bool run_command_hidden(const std::string& command) {
	STARTUPINFOW si = { sizeof(si) };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE; // Hide the window

	PROCESS_INFORMATION pi;

	// Convert command to wide string
	std::wstring wcmd(command.begin(), command.end());

	// Create a writable buffer (CreateProcess needs non-const buffer)
	std::vector<wchar_t> buffer(wcmd.begin(), wcmd.end());
	buffer.push_back(L'\0');

	BOOL success = CreateProcessW(
		nullptr,        // No module name (use command line)
		buffer.data(),  // Command line
		nullptr,        // Process handle not inheritable
		nullptr,        // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		nullptr,        // Use parent's environment block
		nullptr,        // Use parent's starting directory
		&si,            // Pointer to STARTUPINFO structure
		&pi             // Pointer to PROCESS_INFORMATION structure
	);

	if (success) {
		// Wait for the process to finish
		WaitForSingleObject(pi.hProcess, INFINITE);

		DWORD exit_code = 0;
		GetExitCodeProcess(pi.hProcess, &exit_code);

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		return (exit_code == 0);
	} else {
		return false;
	}
}

std::vector<network_adapter_info> list_real_network_adapters() {
	std::vector<network_adapter_info> adapters;

	ULONG out_buf_len = 0;
	GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, nullptr, &out_buf_len);

	std::vector<BYTE> buffer(out_buf_len);
	IP_ADAPTER_ADDRESSES* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

	if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, addresses, &out_buf_len) != NO_ERROR) {
		std::cerr << "[!] Failed to enumerate adapters\n";
		return adapters;
	}

	for (IP_ADAPTER_ADDRESSES* adapter = addresses; adapter; adapter = adapter->Next) {
		if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
			continue; // Skip loopback or down interfaces

		network_adapter_info info;
		info.name = adapter->FriendlyName ? std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(adapter->FriendlyName) : "Unknown";

		for (IP_ADAPTER_UNICAST_ADDRESS* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
			if (ua->Address.lpSockaddr->sa_family == AF_INET) {
				char ip_buf[INET_ADDRSTRLEN] = {};
				sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
				inet_ntop(AF_INET, &ipv4->sin_addr, ip_buf, sizeof(ip_buf));
				info.ip = ip_buf;
				break;
			}
		}

		if (!info.ip.empty()) {
			adapters.push_back(info);
		}
	}

	return adapters;
}
