#define WIN32_LEAN_AND_MEAN
#include "Networking.h"


#include <codecvt>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include "vpn.hpp"
#include <shellapi.h>
#include "utils.hpp"
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
		std::string friendly = wide_to_utf8(wname);
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

void populate_real_adapters() {
	real_adapters_.clear();
	adapter_labels_.clear();
	adapter_cstrs_.clear();

	ULONG out_buf_len = 0;
	GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, nullptr, &out_buf_len);

	std::vector<BYTE> buffer(out_buf_len);
	IP_ADAPTER_ADDRESSES* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

	if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, addresses,
							 &out_buf_len) != NO_ERROR) {
		return;
							 }

	for (IP_ADAPTER_ADDRESSES* adapter = addresses; adapter; adapter = adapter->Next) {
		if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
			continue;

		std::string name = wide_to_utf8(adapter->FriendlyName);
		std::string ip;

		for (IP_ADAPTER_UNICAST_ADDRESS* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
			if (ua->Address.lpSockaddr->sa_family == AF_INET) {
				char ip_buf[INET_ADDRSTRLEN] = {};
				sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
				inet_ntop(AF_INET, &ipv4->sin_addr, ip_buf, sizeof(ip_buf));
				ip = ip_buf;
				break;
			}
		}

		real_adapters_.push_back({ name, ip });

		std::string label = name;
		if (!ip.empty()) {
			label += " (" + ip + ")";
		}

		adapter_labels_.push_back(label);
		adapter_cstrs_.push_back(adapter_labels_.back().c_str());

	}

	current_adapter_idx_ = adapter_cstrs_.empty() ? -1 : 0;
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
	if (inet_pton(AF_INET, ip_address.c_str(), &row.Address.Ipv4.sin_addr) != 1) {
		throw std::runtime_error("Invalid IP address: " + ip_address);
	}


	// Convert subnet mask to prefix length
	IN_ADDR addr {};
	InetPtonA(AF_INET, subnet_mask.c_str(), &addr);
	ULONG mask = ntohl(addr.S_un.S_addr);
	ULONG prefix_length = 0;
	while (mask & 0x80000000) {
		prefix_length++;
		mask <<= 1;
	}
	if ((mask & (mask + 1)) != 0) {
		throw std::runtime_error("Invalid subnet mask: not contiguous");
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

template<typename T>
struct ComReleaser {
	void operator()(T* ptr) const {
		if (ptr) ptr->Release();
	}
};

using ComPtrFwRule   = std::unique_ptr<INetFwRule,   ComReleaser<INetFwRule>>;
using ComPtrFwPolicy = std::unique_ptr<INetFwPolicy2, ComReleaser<INetFwPolicy2>>;
using ComPtrFwRules  = std::unique_ptr<INetFwRules,  ComReleaser<INetFwRules>>;

void AddICMPv4Rule() {
	// Create firewall policy
	INetFwPolicy2* raw_policy = nullptr;
	HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
								  IID_PPV_ARGS(&raw_policy));
	if (FAILED(hr)) throw std::runtime_error("Failed to create INetFwPolicy2");

	ComPtrFwPolicy firewall_policy(raw_policy);  // RAII takes over

	// Get rules interface
	INetFwRules* raw_rules = nullptr;
	hr = firewall_policy->get_Rules(&raw_rules);
	if (FAILED(hr)) throw std::runtime_error("Failed to get INetFwRules");

	ComPtrFwRules rules(raw_rules);

	// Check if the rule exists
	BSTR existing_name = SysAllocString(L"Allow ICMPv4-In");
	INetFwRule* existing = nullptr;
	hr = rules->Item(existing_name, &existing);
	SysFreeString(existing_name);

	if (SUCCEEDED(hr)) {
		existing->Release();  // We don't need it
		return;
	}

	// Create new rule
	INetFwRule* raw_rule = nullptr;
	hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&raw_rule));
	if (FAILED(hr)) throw std::runtime_error("Failed to create INetFwRule");

	ComPtrFwRule rule(raw_rule);

	BSTR rule_name = SysAllocString(L"Allow ICMPv4-In-True_tunnel_VPN");
	BSTR icmp_types = SysAllocString(L"8:*");
	if (!rule_name || !icmp_types) {
		SysFreeString(rule_name);
		SysFreeString(icmp_types);
		throw std::bad_alloc();
	}

	rule->put_Name(rule_name);
	rule->put_Protocol(1); // ICMP
	rule->put_IcmpTypesAndCodes(icmp_types);
	rule->put_Direction(NET_FW_RULE_DIR_IN);
	rule->put_Action(NET_FW_ACTION_ALLOW);
	rule->put_Enabled(VARIANT_TRUE);

	SysFreeString(rule_name);
	SysFreeString(icmp_types);

	hr = rules->Add(rule.get());
	if (FAILED(hr)) throw std::runtime_error("Failed to add firewall rule");
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
			? wide_to_utf8(adapter->FriendlyName)
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
