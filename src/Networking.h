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
#include <cstdint>
#include <string_view>



#pragma comment(lib, "oleaut32.lib")



#include "utils.hpp"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib, "Shell32.lib")


struct network_adapter_info;

class Ipv4RouteGuard {
public:
	Ipv4RouteGuard() noexcept = default;
	~Ipv4RouteGuard();

	Ipv4RouteGuard(const Ipv4RouteGuard&) = delete;
	Ipv4RouteGuard& operator=(const Ipv4RouteGuard&) = delete;
	Ipv4RouteGuard(Ipv4RouteGuard&& other) noexcept;
	Ipv4RouteGuard& operator=(Ipv4RouteGuard&& other) noexcept;

	[[nodiscard]] bool active() const noexcept { return active_; }
	void reset() noexcept;
	void release() noexcept { active_ = false; }

private:
	explicit Ipv4RouteGuard(const MIB_IPFORWARD_ROW2& row) noexcept;

	MIB_IPFORWARD_ROW2 row_{};
	bool active_{false};

	friend std::optional<Ipv4RouteGuard> AddIpv4Route(
		const std::string&,
		std::string_view,
		std::uint8_t,
		std::string_view,
		ULONG);
	friend std::optional<Ipv4RouteGuard> AddIpv4Route(
		const NET_LUID&,
		std::string_view,
		std::uint8_t,
		std::string_view,
		ULONG);
};

class FirewallRuleGuard {
public:
	FirewallRuleGuard() noexcept = default;
	~FirewallRuleGuard();

	FirewallRuleGuard(const FirewallRuleGuard&) = delete;
	FirewallRuleGuard& operator=(const FirewallRuleGuard&) = delete;
	FirewallRuleGuard(FirewallRuleGuard&& other) noexcept;
	FirewallRuleGuard& operator=(FirewallRuleGuard&& other) noexcept;

	[[nodiscard]] bool active() const noexcept { return active_; }
	void reset() noexcept;

private:
	explicit FirewallRuleGuard(std::wstring name) noexcept;

	std::wstring name_;
	bool active_{false};

	friend FirewallRuleGuard AddVpnInboundFirewallRule(
		std::uint16_t, bool, std::string_view);
	friend FirewallRuleGuard AddIcmpV4FirewallRule(std::string_view);
};

// Adds one active IPv4 route through the Windows IP Helper API. An empty
// optional means an identical destination route already exists on the target
// interface and therefore is not owned by this process.
std::optional<Ipv4RouteGuard> AddIpv4Route(
	const std::string& adapter_name,
	std::string_view destination,
	std::uint8_t prefix_length,
	std::string_view next_hop,
	ULONG metric);
std::optional<Ipv4RouteGuard> AddIpv4Route(
	const NET_LUID& adapter_luid,
	std::string_view destination,
	std::uint8_t prefix_length,
	std::string_view next_hop,
	ULONG metric);

// Resolve a user-facing alias once, optionally matching the stable identity
// captured when the GUI enumerated it. Privileged network operations should
// retain and use the returned LUID rather than resolving the alias repeatedly.
[[nodiscard]] NET_LUID ResolveNetworkAdapterLuid(
	const std::string& adapter_name,
	std::uint64_t expected_luid_value = 0U);
[[nodiscard]] std::string GetNetworkAdapterAlias(const NET_LUID& adapter_luid);
[[nodiscard]] bool NetworkAdapterAliasMatchesLuid(
	std::string_view adapter_name,
	const NET_LUID& adapter_luid) noexcept;

[[nodiscard]] bool IsIpv4AddressAssignedLocally(std::string_view address);
[[nodiscard]] bool HasIpv4HostRoute(const std::string& adapter_name,
										std::string_view address);
void RestoreIpv4LocalHostRoute(const std::string& adapter_name,
								   std::string_view address);
void ReacquireDhcpIpv4Address(const std::string& adapter_name);
void SetInterfaceMtu(const std::string& adapter_name, ULONG mtu);
void SetInterfaceMtu(const NET_LUID& adapter_luid, ULONG mtu);
[[nodiscard]] bool SetNetworkCategoryPrivate(const std::string& adapter_name);
[[nodiscard]] bool SetNetworkCategoryPrivate(const NET_LUID& adapter_luid);
FirewallRuleGuard AddVpnInboundFirewallRule(
	std::uint16_t port,
	bool udp,
	std::string_view local_address);
FirewallRuleGuard AddIcmpV4FirewallRule(std::string_view adapter_name);

void SetStaticIPv4Address(const std::string &adapter_name,
						  const std::string &ip_address,
						  const std::string &subnet_mask);
void SetStaticIPv4Address(const NET_LUID& adapter_luid,
						  const std::string& ip_address,
						  const std::string& subnet_mask);

void populate_real_adapters();

inline std::vector<network_adapter_info> real_adapters_;     // alias/description/ip
inline std::vector<std::string> adapter_labels_;             // owns the memory
inline std::vector<const char*> adapter_cstrs_;              // points into adapter_labels_
inline int current_adapter_idx_ = -1;

std::string get_ipv4_for_adapter(const std::string &adapter_name);
std::string get_ipv4_for_adapter(const NET_LUID& adapter_luid);
std::optional<std::string> get_gateway_for_adapter(const std::string& adapter_name);
std::optional<std::string> get_gateway_for_adapter(const NET_LUID& adapter_luid);

struct network_adapter_info {
	std::string alias;       // Friendly name (used by netsh)
	std::string description; // Adapter description
	std::string ip;
	ULONG if_index{0};
	std::uint64_t luid_value{0U};
};


inline void SafeRelease(IUnknown *ptr) {
	if (ptr) ptr->Release();
}

std::string extract_ipv4_string(const BYTE* bytes);
