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
#include <atomic>
#include <chrono>


#pragma comment(lib, "oleaut32.lib")

#include <stdint.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib, "Shell32.lib")

#define LOG(msg) if (log_callback) log_callback(msg); else std::cout << msg << "\n";

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

bool run_command_hidden(
	const std::string& command,
	const std::atomic<bool>* keep_running = nullptr,
	std::chrono::milliseconds timeout = std::chrono::milliseconds{10'000});


std::string sanitize_shell_string(const std::string &input);


std::string sanitize_ip(const std::string &ip);


std::string wide_to_utf8(const std::wstring& wide);

ULONG convert_mask_to_prefix(const std::string& subnet_mask);
