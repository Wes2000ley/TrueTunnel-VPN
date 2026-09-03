#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
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
#include <array>
#include <filesystem>
#include <thread>
#include <stdexcept>
#include <string>
#include <functional>		  //  ← ask() validator
#include <regex>
#include <limits>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>


#include <netfw.h>
#include <comdef.h>
#include <stdexcept>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"iphlpapi.lib")

namespace {

[[nodiscard]] std::wstring utf8_to_wide_or_throw(const std::string_view value) {
	if (value.empty()) return {};
	const int required = ::MultiByteToWideChar(
		CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
		nullptr, 0);
	if (required <= 0) {
		throw std::runtime_error("Invalid UTF-8 adapter name");
	}
	std::wstring result(static_cast<std::size_t>(required), L'\0');
	if (::MultiByteToWideChar(
			CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
			result.data(), required) != required) {
		throw std::runtime_error("Failed to convert adapter name to UTF-16");
	}
	return result;
}

[[nodiscard]] NET_LUID adapter_luid_or_throw(const std::string& adapter_name) {
	const std::wstring wide_name = utf8_to_wide_or_throw(adapter_name);
	NET_LUID luid{};
	const NETIO_STATUS status = ::ConvertInterfaceAliasToLuid(wide_name.c_str(), &luid);
	if (status != NO_ERROR) {
		throw std::system_error(
			static_cast<int>(status), std::system_category(),
			"ConvertInterfaceAliasToLuid(" + adapter_name + ")");
	}
	return luid;
}

[[nodiscard]] IN_ADDR parse_ipv4_or_throw(const std::string_view address,
										 const char* field_name) {
	IN_ADDR parsed{};
	const std::string owned_address{address};
	if (::InetPtonA(AF_INET, owned_address.c_str(), &parsed) != 1) {
		throw std::invalid_argument(
			std::string{"Invalid IPv4 "} + field_name + ": " + owned_address);
	}
	return parsed;
}

[[nodiscard]] bool ipv4_equals(const IN_ADDR& left, const IN_ADDR& right) noexcept {
	return left.S_un.S_addr == right.S_un.S_addr;
}

[[nodiscard]] bool is_system_local_host_route(
	const MIB_IPFORWARD_ROW2& row,
	const NET_LUID& luid,
	const IN_ADDR& address) noexcept {
	return row.InterfaceLuid.Value == luid.Value &&
		row.DestinationPrefix.Prefix.si_family == AF_INET &&
		row.DestinationPrefix.PrefixLength == 32U &&
		ipv4_equals(row.DestinationPrefix.Prefix.Ipv4.sin_addr, address) &&
		row.NextHop.si_family == AF_INET &&
		row.NextHop.Ipv4.sin_addr.S_un.S_addr == INADDR_ANY &&
		row.Protocol == MIB_IPPROTO_LOCAL &&
		row.Loopback != FALSE &&
		row.Publish == FALSE &&
		row.SitePrefixLength == 0U &&
		row.Metric == 256U;
}

[[nodiscard]] MIB_UNICASTIPADDRESS_ROW get_unicast_address_or_throw(
	const NET_LUID& luid,
	const IN_ADDR& address) {
	MIB_UNICASTIPADDRESS_ROW row{};
	::InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid = luid;
	row.Address.Ipv4.sin_family = AF_INET;
	row.Address.Ipv4.sin_addr = address;
	const NETIO_STATUS status = ::GetUnicastIpAddressEntry(&row);
	if (status != NO_ERROR) {
		throw std::system_error(
			static_cast<int>(status), std::system_category(),
			"GetUnicastIpAddressEntry");
	}
	return row;
}

[[nodiscard]] IP_ADAPTER_INDEX_MAP get_adapter_index_map_or_throw(
	const NET_LUID& luid) {
	NET_IFINDEX interface_index = 0U;
	NETIO_STATUS status = ::ConvertInterfaceLuidToIndex(&luid, &interface_index);
	if (status != NO_ERROR) {
		throw std::system_error(
			static_cast<int>(status), std::system_category(),
			"ConvertInterfaceLuidToIndex");
	}

	ULONG buffer_size = 0U;
	DWORD result = ::GetInterfaceInfo(nullptr, &buffer_size);
	if (result != ERROR_INSUFFICIENT_BUFFER || buffer_size == 0U) {
		throw std::system_error(
			static_cast<int>(result), std::system_category(),
			"GetInterfaceInfo(size)");
	}
	std::vector<std::byte> storage(buffer_size);
	auto* information = reinterpret_cast<IP_INTERFACE_INFO*>(storage.data());
	result = ::GetInterfaceInfo(information, &buffer_size);
	if (result != NO_ERROR) {
		throw std::system_error(
			static_cast<int>(result), std::system_category(),
			"GetInterfaceInfo");
	}

	for (LONG index = 0; index < information->NumAdapters; ++index) {
		if (information->Adapter[index].Index != interface_index) continue;
		return information->Adapter[index];
	}
	throw std::runtime_error(
		"GetInterfaceInfo did not return the selected IPv4 adapter");
}

void renew_dhcp_address_or_throw(const NET_LUID& luid) {
	IP_ADAPTER_INDEX_MAP adapter = get_adapter_index_map_or_throw(luid);
	const DWORD result = ::IpRenewAddress(&adapter);
	if (result != NO_ERROR) {
		throw std::system_error(
			static_cast<int>(result), std::system_category(),
			"IpRenewAddress");
	}
}

} // namespace

NET_LUID ResolveNetworkAdapterLuid(
	const std::string& adapter_name,
	const std::uint64_t expected_luid_value) {
	const NET_LUID luid = adapter_luid_or_throw(adapter_name);
	if (expected_luid_value != 0U && luid.Value != expected_luid_value) {
		throw std::runtime_error(
			"The selected physical adapter identity changed before startup");
	}
	return luid;
}

std::string GetNetworkAdapterAlias(const NET_LUID& adapter_luid) {
	std::array<wchar_t, IF_MAX_STRING_SIZE + 1U> alias{};
	const NETIO_STATUS status = ::ConvertInterfaceLuidToAlias(
		&adapter_luid, alias.data(), alias.size());
	if (status != NO_ERROR) {
		throw std::system_error(
			static_cast<int>(status), std::system_category(),
			"ConvertInterfaceLuidToAlias");
	}
	return wide_to_utf8(alias.data());
}

bool NetworkAdapterAliasMatchesLuid(
	const std::string_view adapter_name,
	const NET_LUID& adapter_luid) noexcept {
	try {
		return adapter_luid_or_throw(std::string{adapter_name}).Value ==
			adapter_luid.Value;
	} catch (...) {
		return false;
	}
}

Ipv4RouteGuard::Ipv4RouteGuard(const MIB_IPFORWARD_ROW2& row) noexcept
	: row_{row}, active_{true} {}

Ipv4RouteGuard::~Ipv4RouteGuard() {
	reset();
}

Ipv4RouteGuard::Ipv4RouteGuard(Ipv4RouteGuard&& other) noexcept
	: row_{other.row_}, active_{std::exchange(other.active_, false)} {}

Ipv4RouteGuard& Ipv4RouteGuard::operator=(Ipv4RouteGuard&& other) noexcept {
	if (this != &other) {
		reset();
		row_ = other.row_;
		active_ = std::exchange(other.active_, false);
	}
	return *this;
}

void Ipv4RouteGuard::reset() noexcept {
	if (!active_) return;
	const NETIO_STATUS status = ::DeleteIpForwardEntry2(&row_);
	if (status != NO_ERROR && status != ERROR_NOT_FOUND &&
		status != ERROR_FILE_NOT_FOUND) {
		std::cerr << "[!] DeleteIpForwardEntry2 failed with code " << status << '\n';
	}
	active_ = false;
}

std::optional<Ipv4RouteGuard> AddIpv4Route(
	const std::string& adapter_name,
	const std::string_view destination,
	const std::uint8_t prefix_length,
	const std::string_view next_hop,
	const ULONG metric) {
	return AddIpv4Route(adapter_luid_or_throw(adapter_name), destination,
		prefix_length, next_hop, metric);
}

std::optional<Ipv4RouteGuard> AddIpv4Route(
	const NET_LUID& adapter_luid,
	const std::string_view destination,
	const std::uint8_t prefix_length,
	const std::string_view next_hop,
	const ULONG metric) {
	if (prefix_length > 32U) {
		throw std::invalid_argument("IPv4 route prefix length exceeds 32");
	}

	const IN_ADDR destination_address =
		parse_ipv4_or_throw(destination, "route destination");
	const IN_ADDR next_hop_address = parse_ipv4_or_throw(next_hop, "next hop");

	MIB_IPFORWARD_ROW2 row{};
	::InitializeIpForwardEntry(&row);
	row.InterfaceLuid = adapter_luid;
	row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
	row.DestinationPrefix.Prefix.Ipv4.sin_addr = destination_address;
	row.DestinationPrefix.PrefixLength = prefix_length;
	row.NextHop.Ipv4.sin_family = AF_INET;
	row.NextHop.Ipv4.sin_addr = next_hop_address;
	row.SitePrefixLength = prefix_length;
	row.Metric = metric;
	row.Protocol = MIB_IPPROTO_NETMGMT;
	row.Loopback = FALSE;
	row.AutoconfigureAddress = FALSE;
	row.Publish = FALSE;
	row.Immortal = FALSE;

	const NETIO_STATUS status = ::CreateIpForwardEntry2(&row);
	if (status == ERROR_OBJECT_ALREADY_EXISTS || status == ERROR_ALREADY_EXISTS) {
		return std::nullopt;
	}
	if (status != NO_ERROR) {
		throw std::system_error(
			static_cast<int>(status), std::system_category(),
			"CreateIpForwardEntry2");
	}
	return Ipv4RouteGuard{row};
}

bool IsIpv4AddressAssignedLocally(const std::string_view address) {
	const IN_ADDR target = parse_ipv4_or_throw(address, "address");
	PMIB_UNICASTIPADDRESS_TABLE raw_table = nullptr;
	const NETIO_STATUS status = ::GetUnicastIpAddressTable(AF_INET, &raw_table);
	if (status != NO_ERROR || raw_table == nullptr) {
		if (raw_table != nullptr) ::FreeMibTable(raw_table);
		throw std::system_error(
			static_cast<int>(status), std::system_category(),
			"GetUnicastIpAddressTable");
	}
	std::unique_ptr<MIB_UNICASTIPADDRESS_TABLE, decltype(&::FreeMibTable)>
		table{raw_table, &::FreeMibTable};
	for (ULONG index = 0; index < table->NumEntries; ++index) {
		const auto& row = table->Table[index];
		if (row.Address.si_family == AF_INET &&
			ipv4_equals(row.Address.Ipv4.sin_addr, target)) {
			return true;
		}
	}
	return false;
}

bool HasIpv4HostRoute(const std::string& adapter_name,
					  const std::string_view address) {
	const NET_LUID luid = adapter_luid_or_throw(adapter_name);
	const IN_ADDR target = parse_ipv4_or_throw(address, "host-route address");
	PMIB_IPFORWARD_TABLE2 raw_table = nullptr;
	const NETIO_STATUS status = ::GetIpForwardTable2(AF_INET, &raw_table);
	if (status != NO_ERROR || raw_table == nullptr) {
		if (raw_table != nullptr) ::FreeMibTable(raw_table);
		throw std::system_error(
			static_cast<int>(status), std::system_category(),
			"GetIpForwardTable2");
	}
	std::unique_ptr<MIB_IPFORWARD_TABLE2, decltype(&::FreeMibTable)>
		table{raw_table, &::FreeMibTable};
	for (ULONG index = 0; index < table->NumEntries; ++index) {
		const auto& row = table->Table[index];
		if (is_system_local_host_route(row, luid, target)) {
			return true;
		}
	}
	return false;
}

void RestoreIpv4LocalHostRoute(const std::string& adapter_name,
							   const std::string_view address) {
	const NET_LUID luid = adapter_luid_or_throw(adapter_name);
	const IN_ADDR target = parse_ipv4_or_throw(address, "local host-route address");
	MIB_UNICASTIPADDRESS_ROW address_row =
		get_unicast_address_or_throw(luid, target);
	if (address_row.DadState != IpDadStatePreferred) {
		throw std::runtime_error(
			"The selected local IPv4 address is not in the Preferred state");
	}

	PMIB_IPFORWARD_TABLE2 raw_table = nullptr;
	NETIO_STATUS status = ::GetIpForwardTable2(AF_INET, &raw_table);
	if (status != NO_ERROR || raw_table == nullptr) {
		if (raw_table != nullptr) ::FreeMibTable(raw_table);
		throw std::system_error(
			static_cast<int>(status), std::system_category(),
			"GetIpForwardTable2");
	}
	std::unique_ptr<MIB_IPFORWARD_TABLE2, decltype(&::FreeMibTable)>
		table{raw_table, &::FreeMibTable};
	for (ULONG index = 0; index < table->NumEntries; ++index) {
		const auto& existing = table->Table[index];
		if (existing.InterfaceLuid.Value != luid.Value ||
			existing.DestinationPrefix.Prefix.si_family != AF_INET ||
			existing.DestinationPrefix.PrefixLength != 32U ||
			!ipv4_equals(existing.DestinationPrefix.Prefix.Ipv4.sin_addr, target)) {
			continue;
		}
		if (is_system_local_host_route(existing, luid, target)) return;
		if ((existing.Protocol != MIB_IPPROTO_LOCAL &&
			 existing.Protocol != MIB_IPPROTO_NETMGMT) ||
			existing.NextHop.si_family != AF_INET ||
			existing.NextHop.Ipv4.sin_addr.S_un.S_addr != INADDR_ANY) {
			throw std::runtime_error(
				"Refusing to replace an unrelated host route for " +
				std::string{address});
		}
		status = ::DeleteIpForwardEntry2(&existing);
		if (status != NO_ERROR) {
			throw std::system_error(
				static_cast<int>(status), std::system_category(),
				"DeleteIpForwardEntry2(stale local route)");
		}
		break;
	}
	// Release the stale table snapshot before asking the address subsystem to
	// rebuild the route it owns.
	table.reset();

	status = ::SetUnicastIpAddressEntry(&address_row);
	if (status != NO_ERROR &&
		address_row.PrefixOrigin != IpPrefixOriginDhcp) {
		throw std::system_error(
			static_cast<int>(status), std::system_category(),
			"SetUnicastIpAddressEntry");
	}
	for (unsigned int attempt = 0U; attempt < 20U; ++attempt) {
		if (HasIpv4HostRoute(adapter_name, address)) return;
		::Sleep(50U);
	}

	if (address_row.PrefixOrigin == IpPrefixOriginDhcp &&
		address_row.SuffixOrigin == IpSuffixOriginDhcp) {
		renew_dhcp_address_or_throw(luid);
		for (unsigned int attempt = 0U; attempt < 100U; ++attempt) {
			if (HasIpv4HostRoute(adapter_name, address)) return;
			::Sleep(50U);
		}
	}

	throw std::runtime_error(
		"Windows did not regenerate the system-owned local IPv4 route");
}

void ReacquireDhcpIpv4Address(const std::string& adapter_name) {
	const NET_LUID luid = adapter_luid_or_throw(adapter_name);
	IP_ADAPTER_INDEX_MAP adapter = get_adapter_index_map_or_throw(luid);
	const DWORD release_result = ::IpReleaseAddress(&adapter);
	if (release_result != NO_ERROR) {
		throw std::system_error(
			static_cast<int>(release_result), std::system_category(),
			"IpReleaseAddress");
	}

	DWORD renew_result = ERROR_RETRY;
	for (unsigned int attempt = 0U; attempt < 3U; ++attempt) {
		renew_result = ::IpRenewAddress(&adapter);
		if (renew_result == NO_ERROR) return;
		::Sleep(500U);
	}
	throw std::system_error(
		static_cast<int>(renew_result), std::system_category(),
		"IpRenewAddress(after release)");
}

void SetInterfaceMtu(const std::string& adapter_name, const ULONG mtu) {
	SetInterfaceMtu(adapter_luid_or_throw(adapter_name), mtu);
}

void SetInterfaceMtu(const NET_LUID& adapter_luid, const ULONG mtu) {
	if (mtu < 576U || mtu > 65'535U) {
		throw std::invalid_argument("IPv4 MTU is outside the valid range");
	}
	MIB_IPINTERFACE_ROW row{};
	::InitializeIpInterfaceEntry(&row);
	row.Family = AF_INET;
	row.InterfaceLuid = adapter_luid;
	NETIO_STATUS status = ::GetIpInterfaceEntry(&row);
	if (status != NO_ERROR) {
		throw std::system_error(
			static_cast<int>(status), std::system_category(),
			"GetIpInterfaceEntry");
	}
	// Microsoft requires SitePrefixLength to be zero on IPv4 Set calls even
	// though GetIpInterfaceEntry can return a nonzero/unspecified sentinel.
	row.SitePrefixLength = 0U;
	row.NlMtu = mtu;
	status = ::SetIpInterfaceEntry(&row);
	if (status != NO_ERROR) {
		throw std::system_error(
			static_cast<int>(status), std::system_category(),
			"SetIpInterfaceEntry");
	}
}


std::string get_ipv4_for_adapter(const std::string &adapter_name) {
	try {
		return get_ipv4_for_adapter(adapter_luid_or_throw(adapter_name));
	} catch (...) {
		return "";
	}
}

std::string get_ipv4_for_adapter(const NET_LUID& adapter_luid) {
	ULONG size = 0;
	GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, nullptr, &size);

	std::vector<BYTE> buffer(size);
	IP_ADAPTER_ADDRESSES *adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());

	if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, nullptr, adapters, &size) !=
		NO_ERROR)
		return "";

	for (IP_ADAPTER_ADDRESSES *adapter = adapters; adapter; adapter = adapter->Next) {
		if (adapter->Luid.Value != adapter_luid.Value) continue;


		auto* unicast = adapter->FirstUnicastAddress;
		if (unicast == nullptr || unicast->Address.lpSockaddr == nullptr ||
		    unicast->Address.lpSockaddr->sa_family != AF_INET) continue;

		const auto* sa_in = reinterpret_cast<const SOCKADDR_IN*>(
			unicast->Address.lpSockaddr);
		char ip_str[INET_ADDRSTRLEN]{};
		if (inet_ntop(AF_INET, &sa_in->sin_addr, ip_str, sizeof(ip_str)) != nullptr) {
			return std::string(ip_str);
		}
	}
	return "";
}

std::optional<std::string> get_gateway_for_adapter(const std::string& adapter_name) {
	try {
		return get_gateway_for_adapter(adapter_luid_or_throw(adapter_name));
	} catch (...) {
		return std::nullopt;
	}
}

std::optional<std::string> get_gateway_for_adapter(
	const NET_LUID& adapter_luid) {
	ULONG size = 0;
	GetAdaptersAddresses(AF_INET,
	                    GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST,
	                    nullptr,
	                    nullptr,
	                    &size);

	if (size == 0) {
		return std::nullopt;
	}

	std::vector<BYTE> buffer(size);
	IP_ADAPTER_ADDRESSES* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

	if (GetAdaptersAddresses(AF_INET,
	                        GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST,
	                        nullptr,
	                        adapters,
	                        &size) != NO_ERROR) {
		return std::nullopt;
	}

	IP_ADAPTER_ADDRESSES* match = nullptr;

	for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
		if (adapter->Luid.Value == adapter_luid.Value) {
			match = adapter;
			break;
		}
	}

	if (!match) {
		return std::nullopt;
	}

	for (auto* gw = match->FirstGatewayAddress; gw; gw = gw->Next) {
		if (!gw->Address.lpSockaddr || gw->Address.lpSockaddr->sa_family != AF_INET) {
			continue;
		}
		auto* sa = reinterpret_cast<sockaddr_in*>(gw->Address.lpSockaddr);
		char buf[INET_ADDRSTRLEN] = {};
		if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf))) {
			return std::string(buf);
		}
	}

	PMIB_IPFORWARD_TABLE2 table = nullptr;
	if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR || !table) {
		return std::nullopt;
	}

	std::optional<std::string> fallback_gateway;
	ULONG best_metric = std::numeric_limits<ULONG>::max();

	for (ULONG i = 0; i < table->NumEntries; ++i) {
		const MIB_IPFORWARD_ROW2& row = table->Table[i];
		if (row.InterfaceIndex != match->IfIndex)
			continue;

		if (row.DestinationPrefix.Prefix.si_family != AF_INET ||
		    row.DestinationPrefix.PrefixLength != 0) {
			continue;
		}

		if (row.NextHop.si_family != AF_INET)
			continue;

		char buf[INET_ADDRSTRLEN] = {};
		if (!inet_ntop(AF_INET, &row.NextHop.Ipv4.sin_addr, buf, sizeof(buf)))
			continue;

		if (row.Metric < best_metric) {
			best_metric = row.Metric;
			fallback_gateway = std::string(buf);
		}
	}

	if (table) {
		FreeMibTable(table);
	}

	return fallback_gateway;
}

void populate_real_adapters() {
	real_adapters_.clear();
	adapter_labels_.clear();
	adapter_cstrs_.clear();

	ULONG out_buf_len = 0;
	GetAdaptersAddresses(AF_INET,
	                     GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST,
	                     nullptr,
	                     nullptr,
	                     &out_buf_len);

	if (out_buf_len == 0) {
		current_adapter_idx_ = -1;
		return;
	}

	std::vector<BYTE> buffer(out_buf_len);
	IP_ADAPTER_ADDRESSES* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

	if (GetAdaptersAddresses(AF_INET,
	                         GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST,
	                         nullptr,
	                         addresses,
	                         &out_buf_len) != NO_ERROR) {
		current_adapter_idx_ = -1;
		return;
	}

	for (IP_ADAPTER_ADDRESSES* adapter = addresses; adapter; adapter = adapter->Next) {
		if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
			continue;

		network_adapter_info info{};
		info.alias = wide_to_utf8(adapter->FriendlyName ? adapter->FriendlyName : L"");
		info.description = wide_to_utf8(adapter->Description ? adapter->Description : L"");
		info.if_index = adapter->IfIndex;
		info.luid_value = adapter->Luid.Value;

		for (IP_ADAPTER_UNICAST_ADDRESS* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
			if (ua->Address.lpSockaddr && ua->Address.lpSockaddr->sa_family == AF_INET) {
				char ip_buf[INET_ADDRSTRLEN] = {};
				const sockaddr_in* ipv4 = reinterpret_cast<const sockaddr_in*>(ua->Address.lpSockaddr);
				if (inet_ntop(AF_INET, &ipv4->sin_addr, ip_buf, sizeof(ip_buf))) {
					info.ip = ip_buf;
					break;
				}
			}
		}

		if (info.alias.empty())
			continue;

		std::string label = info.alias;
        if (!info.description.empty()) {
            label += " - " + info.description;
        }
		if (!info.ip.empty()) {
			label += " (" + info.ip + ")";
		}
		label += " [ifIndex:" + std::to_string(info.if_index) + "]";

		real_adapters_.push_back(info);
		adapter_labels_.push_back(label);
		adapter_cstrs_.push_back(adapter_labels_.back().c_str());
	}

	current_adapter_idx_ = adapter_cstrs_.empty() ? -1 : 0;
}

void SetStaticIPv4Address(const std::string &adapter_name,
						  const std::string &ip_address,
						  const std::string &subnet_mask) {
	SetStaticIPv4Address(
		adapter_luid_or_throw(adapter_name), ip_address, subnet_mask);
}

void SetStaticIPv4Address(const NET_LUID& adapter_luid,
						  const std::string& ip_address,
						  const std::string& subnet_mask) {

	// Prepare IP address
	MIB_UNICASTIPADDRESS_ROW row{};
	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid = adapter_luid;
	row.Address.si_family = AF_INET;
	if (inet_pton(AF_INET, ip_address.c_str(), &row.Address.Ipv4.sin_addr) != 1) {
		throw std::runtime_error("Invalid IP address: " + ip_address);
	}


	// Convert subnet mask to prefix length
	IN_ADDR addr {};
	if (InetPtonA(AF_INET, subnet_mask.c_str(), &addr) != 1) {
		throw std::runtime_error("Invalid subnet mask: " + subnet_mask);
	}
	ULONG mask = ntohl(addr.S_un.S_addr);
	ULONG prefix_length = 0;
	while (mask & 0x80000000) {
		prefix_length++;
		mask <<= 1;
	}
	if (mask != 0U) {
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
using ComPtrNetworkListManager =
	std::unique_ptr<INetworkListManager, ComReleaser<INetworkListManager>>;
using ComPtrNetworkConnectionEnumerator =
	std::unique_ptr<IEnumNetworkConnections, ComReleaser<IEnumNetworkConnections>>;
using ComPtrNetworkConnection =
	std::unique_ptr<INetworkConnection, ComReleaser<INetworkConnection>>;
using ComPtrNetwork = std::unique_ptr<INetwork, ComReleaser<INetwork>>;

FirewallRuleGuard::FirewallRuleGuard(std::wstring name) noexcept
	: name_{std::move(name)}, active_{true} {}

FirewallRuleGuard::~FirewallRuleGuard() {
	reset();
}

FirewallRuleGuard::FirewallRuleGuard(FirewallRuleGuard&& other) noexcept
	: name_{std::move(other.name_)},
	  active_{std::exchange(other.active_, false)} {}

FirewallRuleGuard& FirewallRuleGuard::operator=(FirewallRuleGuard&& other) noexcept {
	if (this != &other) {
		reset();
		name_ = std::move(other.name_);
		active_ = std::exchange(other.active_, false);
	}
	return *this;
}

void FirewallRuleGuard::reset() noexcept {
	if (!active_) return;
	active_ = false;

	INetFwPolicy2* raw_policy = nullptr;
	if (FAILED(::CoCreateInstance(
			__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
			IID_PPV_ARGS(&raw_policy))) || raw_policy == nullptr) {
		std::cerr << "[!] Unable to remove the TrueTunnel firewall rule\n";
		return;
	}
	ComPtrFwPolicy policy{raw_policy};
	INetFwRules* raw_rules = nullptr;
	if (FAILED(policy->get_Rules(&raw_rules)) || raw_rules == nullptr) {
		std::cerr << "[!] Unable to open Windows Firewall rules for cleanup\n";
		return;
	}
	ComPtrFwRules rules{raw_rules};
	BSTR rule_name = ::SysAllocString(name_.c_str());
	if (rule_name == nullptr) {
		std::cerr << "[!] Unable to allocate the firewall rule name for cleanup\n";
		return;
	}
	const HRESULT remove_result = rules->Remove(rule_name);
	::SysFreeString(rule_name);
	if (FAILED(remove_result) && remove_result != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
		std::cerr << "[!] Windows Firewall rule cleanup failed with HRESULT 0x"
				  << std::hex << static_cast<unsigned long>(remove_result)
				  << std::dec << '\n';
	}
}

FirewallRuleGuard AddVpnInboundFirewallRule(
	const std::uint16_t port,
	const bool udp,
	const std::string_view local_address) {
	(void)parse_ipv4_or_throw(local_address, "firewall local address");
	if (port == 0U) {
		throw std::invalid_argument("VPN firewall port cannot be zero");
	}

	std::vector<wchar_t> executable_buffer(32'768U, L'\0');
	const DWORD copied = ::GetModuleFileNameW(
		nullptr,
		executable_buffer.data(),
		static_cast<DWORD>(executable_buffer.size()));
	if (copied == 0U || static_cast<std::size_t>(copied) >= executable_buffer.size()) {
		throw std::system_error(
			static_cast<int>(::GetLastError()), std::system_category(),
			"GetModuleFileNameW");
	}
	const std::wstring executable_path{executable_buffer.data(), copied};
	const std::wstring protocol_name = udp ? L"UDP" : L"TCP";
	GUID ownership_id{};
	if (FAILED(::CoCreateGuid(&ownership_id))) {
		throw std::runtime_error("Failed to create firewall ownership identity");
	}
	std::array<wchar_t, 40> ownership_text{};
	if (::StringFromGUID2(ownership_id,
					  ownership_text.data(),
					  static_cast<int>(ownership_text.size())) <= 0) {
		throw std::runtime_error("Failed to format firewall ownership identity");
	}
	const std::wstring rule_name =
		L"TrueTunnel VPN " + protocol_name + L" " +
		utf8_to_wide_or_throw(local_address) + L":" + std::to_wstring(port) +
		L" " + ownership_text.data();
	const std::wstring port_text = std::to_wstring(port);
	const std::wstring local_address_text =
		utf8_to_wide_or_throw(local_address);
	const std::wstring description =
		L"Temporary inbound rule for the active TrueTunnel server";
	const std::wstring grouping = L"TrueTunnel VPN";

	INetFwPolicy2* raw_policy = nullptr;
	HRESULT result = ::CoCreateInstance(
		__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&raw_policy));
	if (FAILED(result) || raw_policy == nullptr) {
		throw std::runtime_error("Failed to create INetFwPolicy2");
	}
	ComPtrFwPolicy policy{raw_policy};
	INetFwRules* raw_rules = nullptr;
	result = policy->get_Rules(&raw_rules);
	if (FAILED(result) || raw_rules == nullptr) {
		throw std::runtime_error("Failed to get Windows Firewall rules");
	}
	ComPtrFwRules rules{raw_rules};
	BSTR legacy_name = ::SysAllocString(L"TrueTunnel VPN");
	if (legacy_name == nullptr) {
		throw std::bad_alloc();
	}
	// Older builds asked Windows to create broad TCP/UDP Public-profile rules
	// under this exact display name. Remove every legacy duplicate during the
	// upgrade path before installing the scoped temporary listener rule.
	for (unsigned int attempt = 0U; attempt < 16U; ++attempt) {
		INetFwRule* legacy_rule = nullptr;
		if (FAILED(rules->Item(legacy_name, &legacy_rule)) ||
			legacy_rule == nullptr) {
			break;
		}
		legacy_rule->Release();
		if (FAILED(rules->Remove(legacy_name))) break;
	}
	::SysFreeString(legacy_name);

	BSTR name_bstr = ::SysAllocString(rule_name.c_str());
	BSTR application_bstr = ::SysAllocString(executable_path.c_str());
	BSTR ports_bstr = ::SysAllocString(port_text.c_str());
	BSTR local_address_bstr = ::SysAllocString(local_address_text.c_str());
	BSTR description_bstr = ::SysAllocString(description.c_str());
	BSTR grouping_bstr = ::SysAllocString(grouping.c_str());
	if (name_bstr == nullptr || application_bstr == nullptr ||
		ports_bstr == nullptr || local_address_bstr == nullptr ||
		description_bstr == nullptr || grouping_bstr == nullptr) {
		::SysFreeString(name_bstr);
		::SysFreeString(application_bstr);
		::SysFreeString(ports_bstr);
		::SysFreeString(local_address_bstr);
		::SysFreeString(description_bstr);
		::SysFreeString(grouping_bstr);
		throw std::bad_alloc();
	}

	INetFwRule* raw_rule = nullptr;
	result = ::CoCreateInstance(
		__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&raw_rule));
	if (FAILED(result) || raw_rule == nullptr) {
		::SysFreeString(name_bstr);
		::SysFreeString(application_bstr);
		::SysFreeString(ports_bstr);
		::SysFreeString(local_address_bstr);
		::SysFreeString(description_bstr);
		::SysFreeString(grouping_bstr);
		throw std::runtime_error("Failed to create the VPN firewall rule");
	}
	ComPtrFwRule rule{raw_rule};
	const long protocol = udp ? NET_FW_IP_PROTOCOL_UDP : NET_FW_IP_PROTOCOL_TCP;
	const bool configured =
		SUCCEEDED(rule->put_Name(name_bstr)) &&
		SUCCEEDED(rule->put_Description(description_bstr)) &&
		SUCCEEDED(rule->put_Grouping(grouping_bstr)) &&
		SUCCEEDED(rule->put_ApplicationName(application_bstr)) &&
		SUCCEEDED(rule->put_Protocol(protocol)) &&
		SUCCEEDED(rule->put_LocalPorts(ports_bstr)) &&
		SUCCEEDED(rule->put_LocalAddresses(local_address_bstr)) &&
		SUCCEEDED(rule->put_Profiles(NET_FW_PROFILE2_PRIVATE)) &&
		SUCCEEDED(rule->put_Direction(NET_FW_RULE_DIR_IN)) &&
		SUCCEEDED(rule->put_Action(NET_FW_ACTION_ALLOW)) &&
		SUCCEEDED(rule->put_EdgeTraversal(VARIANT_FALSE)) &&
		SUCCEEDED(rule->put_Enabled(VARIANT_TRUE));

	::SysFreeString(name_bstr);
	::SysFreeString(application_bstr);
	::SysFreeString(ports_bstr);
	::SysFreeString(local_address_bstr);
	::SysFreeString(description_bstr);
	::SysFreeString(grouping_bstr);
	if (!configured) {
		throw std::runtime_error("Failed to configure the VPN firewall rule");
	}
	result = rules->Add(rule.get());
	if (FAILED(result)) {
		throw std::runtime_error("Failed to add the VPN firewall rule");
	}
	return FirewallRuleGuard{rule_name};
}

bool SetNetworkCategoryPrivate(const std::string& adapter_name) {
	try {
		return SetNetworkCategoryPrivate(adapter_luid_or_throw(adapter_name));
	} catch (const std::exception& ex) {
		std::cerr << "[!] Cannot resolve adapter for network category: "
				  << ex.what() << '\n';
		return false;
	}
}

bool SetNetworkCategoryPrivate(const NET_LUID& adapter_luid) {
	GUID adapter_id{};
	if (::ConvertInterfaceLuidToGuid(&adapter_luid, &adapter_id) != NO_ERROR) {
		return false;
	}

	INetworkListManager* raw_manager = nullptr;
	const HRESULT create_result = ::CoCreateInstance(
		CLSID_NetworkListManager,
		nullptr,
		CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&raw_manager));
	if (FAILED(create_result) || raw_manager == nullptr) {
		return false;
	}
	ComPtrNetworkListManager manager{raw_manager};

	// Network List Manager learns about a newly created Wintun interface
	// asynchronously. Retry briefly instead of spawning PowerShell and racing
	// its Get-NetConnectionProfile projection of the same COM state.
	for (unsigned int attempt = 0; attempt < 20U; ++attempt) {
		IEnumNetworkConnections* raw_enumerator = nullptr;
		if (FAILED(manager->GetNetworkConnections(&raw_enumerator)) ||
			raw_enumerator == nullptr) {
			return false;
		}
		ComPtrNetworkConnectionEnumerator enumerator{raw_enumerator};

		INetworkConnection* raw_connection = nullptr;
		ULONG fetched = 0U;
		while (enumerator->Next(1U, &raw_connection, &fetched) == S_OK &&
			   fetched == 1U) {
			ComPtrNetworkConnection connection{raw_connection};
			raw_connection = nullptr;
			GUID candidate_id{};
			if (SUCCEEDED(connection->GetAdapterId(&candidate_id)) &&
				::IsEqualGUID(candidate_id, adapter_id)) {
				INetwork* raw_network = nullptr;
				if (FAILED(connection->GetNetwork(&raw_network)) || raw_network == nullptr) {
					return false;
				}
				ComPtrNetwork network{raw_network};
				return SUCCEEDED(network->SetCategory(NLM_NETWORK_CATEGORY_PRIVATE));
			}
		}
		::Sleep(100U);
	}
	return false;
}

FirewallRuleGuard AddIcmpV4FirewallRule(const std::string_view adapter_name) {
	if (adapter_name.empty() || adapter_name.size() > 128U) {
		throw std::invalid_argument("Invalid adapter name for ICMP firewall rule");
	}

	std::vector<wchar_t> executable_buffer(32'768U, L'\0');
	const DWORD copied = ::GetModuleFileNameW(
		nullptr, executable_buffer.data(),
		static_cast<DWORD>(executable_buffer.size()));
	if (copied == 0U || static_cast<std::size_t>(copied) >= executable_buffer.size()) {
		throw std::system_error(
			static_cast<int>(::GetLastError()), std::system_category(),
			"GetModuleFileNameW");
	}
	const std::wstring executable_path{executable_buffer.data(), copied};
	const std::wstring rule_name =
		L"TrueTunnel ICMPv4 " + utf8_to_wide_or_throw(adapter_name);
	constexpr wchar_t kLegacyRuleName[] = L"Allow ICMPv4-In-TrueTunnel-VPN";
	constexpr wchar_t kIcmpTypes[] = L"8:*";
	constexpr wchar_t kVpnSubnet[] = L"10.10.100.0/255.255.255.0";
	constexpr long kIcmpV4Protocol = 1L;
	constexpr wchar_t kDescription[] =
		L"Temporary ICMPv4 echo rule for an active TrueTunnel adapter";
	constexpr wchar_t kGrouping[] = L"TrueTunnel VPN";

	INetFwPolicy2* raw_policy = nullptr;
	HRESULT result = ::CoCreateInstance(
		__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&raw_policy));
	if (FAILED(result) || raw_policy == nullptr) {
		throw std::runtime_error("Failed to create INetFwPolicy2");
	}
	ComPtrFwPolicy policy{raw_policy};
	INetFwRules* raw_rules = nullptr;
	result = policy->get_Rules(&raw_rules);
	if (FAILED(result) || raw_rules == nullptr) {
		throw std::runtime_error("Failed to get Windows Firewall rules");
	}
	ComPtrFwRules rules{raw_rules};

	BSTR legacy_name = ::SysAllocString(kLegacyRuleName);
	if (legacy_name == nullptr) throw std::bad_alloc();
	(void)rules->Remove(legacy_name);
	::SysFreeString(legacy_name);

	BSTR name_bstr = ::SysAllocString(rule_name.c_str());
	BSTR application_bstr = ::SysAllocString(executable_path.c_str());
	BSTR icmp_types_bstr = ::SysAllocString(kIcmpTypes);
	BSTR local_addresses_bstr = ::SysAllocString(kVpnSubnet);
	BSTR remote_addresses_bstr = ::SysAllocString(kVpnSubnet);
	BSTR description_bstr = ::SysAllocString(kDescription);
	BSTR grouping_bstr = ::SysAllocString(kGrouping);
	if (name_bstr == nullptr || application_bstr == nullptr ||
		icmp_types_bstr == nullptr || local_addresses_bstr == nullptr ||
		remote_addresses_bstr == nullptr || description_bstr == nullptr ||
		grouping_bstr == nullptr) {
		::SysFreeString(name_bstr);
		::SysFreeString(application_bstr);
		::SysFreeString(icmp_types_bstr);
		::SysFreeString(local_addresses_bstr);
		::SysFreeString(remote_addresses_bstr);
		::SysFreeString(description_bstr);
		::SysFreeString(grouping_bstr);
		throw std::bad_alloc();
	}

	// Replace only the stable rule owned by this exact adapter. This cleans up
	// an abnormal prior exit without sharing ownership between active adapters.
	(void)rules->Remove(name_bstr);

	INetFwRule* raw_rule = nullptr;
	result = ::CoCreateInstance(
		__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&raw_rule));
	if (FAILED(result) || raw_rule == nullptr) {
		::SysFreeString(name_bstr);
		::SysFreeString(application_bstr);
		::SysFreeString(icmp_types_bstr);
		::SysFreeString(local_addresses_bstr);
		::SysFreeString(remote_addresses_bstr);
		::SysFreeString(description_bstr);
		::SysFreeString(grouping_bstr);
		throw std::runtime_error("Failed to create the ICMPv4 firewall rule");
	}
	ComPtrFwRule rule{raw_rule};
	const bool configured =
		SUCCEEDED(rule->put_Name(name_bstr)) &&
		SUCCEEDED(rule->put_Description(description_bstr)) &&
		SUCCEEDED(rule->put_Grouping(grouping_bstr)) &&
		SUCCEEDED(rule->put_ApplicationName(application_bstr)) &&
		SUCCEEDED(rule->put_Protocol(kIcmpV4Protocol)) &&
		SUCCEEDED(rule->put_IcmpTypesAndCodes(icmp_types_bstr)) &&
		SUCCEEDED(rule->put_LocalAddresses(local_addresses_bstr)) &&
		SUCCEEDED(rule->put_RemoteAddresses(remote_addresses_bstr)) &&
		SUCCEEDED(rule->put_Profiles(NET_FW_PROFILE2_PRIVATE)) &&
		SUCCEEDED(rule->put_Direction(NET_FW_RULE_DIR_IN)) &&
		SUCCEEDED(rule->put_Action(NET_FW_ACTION_ALLOW)) &&
		SUCCEEDED(rule->put_EdgeTraversal(VARIANT_FALSE)) &&
		SUCCEEDED(rule->put_Enabled(VARIANT_TRUE));

	::SysFreeString(name_bstr);
	::SysFreeString(application_bstr);
	::SysFreeString(icmp_types_bstr);
	::SysFreeString(local_addresses_bstr);
	::SysFreeString(remote_addresses_bstr);
	::SysFreeString(description_bstr);
	::SysFreeString(grouping_bstr);
	if (!configured) {
		throw std::runtime_error("Failed to configure the ICMPv4 firewall rule");
	}
	result = rules->Add(rule.get());
	if (FAILED(result)) {
		throw std::runtime_error("Failed to add the ICMPv4 firewall rule");
	}
	return FirewallRuleGuard{rule_name};
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

	network_adapter_info info{};
	info.alias = adapter->FriendlyName ? wide_to_utf8(adapter->FriendlyName) : "Unknown";
	info.description = adapter->Description ? wide_to_utf8(adapter->Description) : std::string{};
	info.if_index = adapter->IfIndex;
	info.luid_value = adapter->Luid.Value;

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
std::string extract_ipv4_string(const BYTE* bytes) {
	char buf[16];
	snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
			 bytes[0], bytes[1], bytes[2], bytes[3]);
	return std::string(buf);
}
