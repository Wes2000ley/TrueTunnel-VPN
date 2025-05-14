#define WIN32_LEAN_AND_MEAN
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
