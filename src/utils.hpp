#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <EASTL/vector.h>
#include <shellapi.h>
#include <netlistmgr.h>
#include <comdef.h>


#include <iostream>
#include <filesystem>
#include <thread>
#include <stdexcept>
#include <string>
#include <functional>		  //  ← ask() validator
#include "include/cxxopts.hpp"
#include "termcolor.hpp"


#pragma comment(lib, "oleaut32.lib")

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
#pragma comment(lib, "Shell32.lib")


using termcolor::bold;
using termcolor::green;
using termcolor::yellow;
using termcolor::red;
using termcolor::reset;

// ─── pretty logging helpers ───────────────────────────────────
namespace util {
	void logInfo(const std::string &s);
	void logWarn(const std::string &s);
	void logErr(const std::string &s);

	bool looksLikeIp(const std::string &v);

	void ask(const char *prompt, std::string &val,
			 std::function<bool(const std::string &)> ok = nullptr);
} // namespace

bool is_running_as_admin();

bool is_valid_input(const std::string &s);

bool run_command_hidden(const std::string& command);

struct network_adapter_info {
	std::string name;
	std::string ip;
};
bool run_command_admin(const std::string& command);

void AddICMPv4Rule(); // ✅ Declaration at global scope

void SetStaticIPv4Address(const std::string& adapter_name,
						  const std::string& ip_address,
						  const std::string& subnet_mask);

void populate_real_adapters();

inline std::vector<network_adapter_info> real_adapters_;
inline std::vector<std::string> adapter_choices_;
inline std::vector<const char*> adapter_labels_;
inline int current_adapter_idx_ = 0;
