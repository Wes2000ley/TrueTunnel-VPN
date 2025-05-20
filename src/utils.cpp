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

bool run_command_hidden(const std::string &command) {
	STARTUPINFOW startup_info = {sizeof(startup_info)};
	startup_info.dwFlags = STARTF_USESHOWWINDOW;
	startup_info.wShowWindow = SW_HIDE;

	PROCESS_INFORMATION process_info;

	// Convert command to wide string
	std::wstring wide_command(command.begin(), command.end());

	// Create writable buffer for CreateProcessW
	std::vector<wchar_t> command_buffer(wide_command.begin(), wide_command.end());
	command_buffer.push_back(L'\0');

	BOOL success = CreateProcessW(
		nullptr, // No module name (use command line)
		command_buffer.data(), // Command line
		nullptr, // Process handle not inheritable
		nullptr, // Thread handle not inheritable
		FALSE, // Do not inherit handles
		CREATE_NO_WINDOW, // Do not create a window
		nullptr, // Use parent's environment block
		nullptr, // Use parent's starting directory
		&startup_info, // Pointer to STARTUPINFO
		&process_info // Pointer to PROCESS_INFORMATION
	);

	if (success) {
		WaitForSingleObject(process_info.hProcess, INFINITE);

		DWORD exit_code = 0;
		GetExitCodeProcess(process_info.hProcess, &exit_code);

		CloseHandle(process_info.hProcess);
		CloseHandle(process_info.hThread);

		return (exit_code == 0);
	}

	return false;
}

bool run_command_admin(const std::string &command) {
	std::wstring wcmd = L"-Command \"" + std::wstring(command.begin(), command.end()) + L"\"";

	SHELLEXECUTEINFOW sei = {sizeof(sei)};
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

	WaitForSingleObject(sei.hProcess, INFINITE);
	DWORD exit_code = 0;
	GetExitCodeProcess(sei.hProcess, &exit_code);
	CloseHandle(sei.hProcess);

	return (exit_code == 0);
}


std::vector<network_adapter_info> list_real_network_adapters() {
	std::vector<network_adapter_info> adapters;

	ULONG out_buf_len = 0;
	GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, nullptr, &out_buf_len);

	std::vector<BYTE> buffer(out_buf_len);
	IP_ADAPTER_ADDRESSES *addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());

	if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, addresses, &out_buf_len)
	    != NO_ERROR) {
		std::cerr << "[!] Failed to enumerate adapters\n";
		return adapters;
	}

	for (IP_ADAPTER_ADDRESSES *adapter = addresses; adapter; adapter = adapter->Next) {
		if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
			continue; // Skip loopback or down interfaces

		network_adapter_info info;
		info.name = adapter->FriendlyName
			            ? std::wstring_convert<std::codecvt_utf8<wchar_t> >().to_bytes(adapter->FriendlyName)
			            : "Unknown";

		for (IP_ADAPTER_UNICAST_ADDRESS *ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
			if (ua->Address.lpSockaddr->sa_family == AF_INET) {
				char ip_buf[INET_ADDRSTRLEN] = {};
				sockaddr_in *ipv4 = reinterpret_cast<sockaddr_in *>(ua->Address.lpSockaddr);
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

void SafeRelease(IUnknown *ptr) {
	if (ptr) ptr->Release();
}

void AddICMPv4Rule() {
	INetFwPolicy2 *firewall_policy = nullptr;
	INetFwRule *rule = nullptr;
	INetFwRules *rules = nullptr;

	try {
		HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
		                              IID_PPV_ARGS(&firewall_policy));
		if (FAILED(hr)) throw std::runtime_error("Failed to create INetFwPolicy2");

		hr = firewall_policy->get_Rules(&rules);
		if (FAILED(hr)) throw std::runtime_error("Failed to get rules interface");

		BSTR rule_name = SysAllocString(L"Allow ICMPv4-In");
		hr = rules->Item(rule_name, &rule);
		if (SUCCEEDED(hr)) {
			SysFreeString(rule_name);
			SafeRelease(rule);
			SafeRelease(rules);
			SafeRelease(firewall_policy);
			return;
		}
		SysFreeString(rule_name);

		hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
		                      IID_PPV_ARGS(&rule));
		if (FAILED(hr)) throw std::runtime_error("Failed to create INetFwRule");

		rule->put_Name(SysAllocString(L"Allow ICMPv4-In-True_tunnel_VPN"));
		rule->put_Protocol(1); // ICMP
		rule->put_IcmpTypesAndCodes(SysAllocString(L"8:*"));
		rule->put_Direction(NET_FW_RULE_DIR_IN);
		rule->put_Action(NET_FW_ACTION_ALLOW);
		rule->put_Enabled(VARIANT_TRUE);

		hr = rules->Add(rule);
		if (FAILED(hr)) throw std::runtime_error("Failed to add firewall rule");
	} catch (...) {
		SafeRelease(rules);
		SafeRelease(rule);
		SafeRelease(firewall_policy);
		throw;
	}

	SafeRelease(rules);
	SafeRelease(rule);
	SafeRelease(firewall_policy);
}

void SetStaticIPv4Address(const std::string &adapter_name,
                          const std::string &ip_address,
                          const std::string &subnet_mask) {
	// Convert strings to wide strings
	std::wstring w_adapter_name(adapter_name.begin(), adapter_name.end());

	// Retrieve the list of interfaces
	ULONG buffer_size = 0;
	GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &buffer_size);
	std::vector<BYTE> buffer(buffer_size);
	IP_ADAPTER_ADDRESSES *addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());

	if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &buffer_size) != NO_ERROR) {
		throw std::runtime_error("GetAdaptersAddresses failed");
	}

	// Find the adapter by name
	NET_LUID luid{};
	bool found = false;
	for (auto *adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
		if (adapter->FriendlyName && w_adapter_name == adapter->FriendlyName) {
			luid = adapter->Luid;
			found = true;
			break;
		}
	}

	if (!found) {
		throw std::runtime_error("Adapter not found: " + adapter_name);
	}

	// Prepare IP address
	MIB_UNICASTIPADDRESS_ROW row{};
	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid = luid;
	row.Address.si_family = AF_INET;
	inet_pton(AF_INET, ip_address.c_str(), &row.Address.Ipv4.sin_addr);

	// Convert subnet mask to prefix length
	ULONG mask = ntohl(inet_addr(subnet_mask.c_str()));
	ULONG prefix_length = 0;
	while (mask & 0x80000000) {
		prefix_length++;
		mask <<= 1;
	}
	row.OnLinkPrefixLength = static_cast<UINT8>(prefix_length);

	// Set static address
	row.DadState = IpDadStatePreferred;
	row.ValidLifetime = 0xFFFFFFFF;
	row.PreferredLifetime = 0xFFFFFFFF;

	DWORD result = CreateUnicastIpAddressEntry(&row);
	if (result != NO_ERROR) {
		throw std::runtime_error("CreateUnicastIpAddressEntry failed with code: " + std::to_string(result));
	}
}

void populate_real_adapters() {
	real_adapters_.clear();
	adapter_choices_.clear();
	adapter_labels_.clear();

	ULONG out_buf_len = 0;
	GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, nullptr, &out_buf_len);

	std::vector<BYTE> buffer(out_buf_len);
	IP_ADAPTER_ADDRESSES *addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());

	if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, addresses,
	                         &out_buf_len) != NO_ERROR)
		return;

	for (IP_ADAPTER_ADDRESSES *adapter = addresses; adapter; adapter = adapter->Next) {
		if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
			continue;

		std::string name = adapter->FriendlyName
			                   ? std::wstring_convert<std::codecvt_utf8<wchar_t> >().to_bytes(adapter->FriendlyName)
			                   : "Unknown";

		std::string ip;
		for (IP_ADAPTER_UNICAST_ADDRESS *ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
			if (ua->Address.lpSockaddr->sa_family == AF_INET) {
				char ip_buf[INET_ADDRSTRLEN] = {};
				sockaddr_in *ipv4 = reinterpret_cast<sockaddr_in *>(ua->Address.lpSockaddr);
				inet_ntop(AF_INET, &ipv4->sin_addr, ip_buf, sizeof(ip_buf));
				ip = ip_buf;
				break;
			}
		}

		if (!ip.empty()) {
			real_adapters_.push_back({name, ip});
			adapter_choices_.push_back(name);
		}
	}

	for (const std::string &choice: adapter_choices_) {
		adapter_labels_.push_back(choice.c_str());
	}

	if (!adapter_choices_.empty()) {
		current_adapter_idx_ = 0;
	}
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

std::string get_ipv4_for_adapter(const std::string &adapter_name) {
	ULONG size = 0;
	GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, nullptr, &size);

	std::vector<BYTE> buffer(size);
	IP_ADAPTER_ADDRESSES *adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());

	if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, adapters, &size) !=
	    NO_ERROR)
		return "";

	for (IP_ADAPTER_ADDRESSES *adapter = adapters; adapter; adapter = adapter->Next) {
		std::wstring wname(adapter->FriendlyName);
		std::string friendly = std::wstring_convert<std::codecvt_utf8<wchar_t> >().to_bytes(wname);
		if (friendly != adapter_name) continue;

		for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
			SOCKADDR_IN *sa_in = reinterpret_cast<SOCKADDR_IN *>(unicast->Address.lpSockaddr);
			char ip_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(sa_in->sin_addr), ip_str, INET_ADDRSTRLEN);
			return std::string(ip_str);
		}
	}
	return "";
}
