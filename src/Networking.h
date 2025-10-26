#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <shellapi.h>
#include <netlistmgr.h>
#include <comdef.h>


#include <iostream>
#include <filesystem>
#include <thread>
#include <stdexcept>
#include <string>
#include <functional>		  //  ← ask() validator
#include <optional>



#pragma comment(lib, "oleaut32.lib")



#include "utils.hpp"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib, "Shell32.lib")


struct network_adapter_info;

void AddICMPv4Rule(); // ✅ Declaration at global scope

void SetStaticIPv4Address(const std::string &adapter_name,
						  const std::string &ip_address,
						  const std::string &subnet_mask);

void populate_real_adapters();

inline std::vector<network_adapter_info> real_adapters_;     // alias/description/ip
inline std::vector<std::string> adapter_labels_;             // owns the memory
inline std::vector<const char*> adapter_cstrs_;              // points into adapter_labels_
inline int current_adapter_idx_ = -1;

std::string get_ipv4_for_adapter(const std::string &adapter_name);
std::optional<std::string> get_gateway_for_adapter(const std::string& adapter_name);

struct network_adapter_info {
	std::string alias;       // Friendly name (used by netsh)
	std::string description; // Adapter description
	std::string ip;
	ULONG if_index{0};
};


inline void SafeRelease(IUnknown *ptr) {
	if (ptr) ptr->Release();
}

std::string extract_ipv4_string(const BYTE* bytes);
