// IpPoolManager.cpp
#include "IpPoolManager.h"

IpPoolManager::IpPoolManager() {
	for (int i = 10; i < 220; ++i)
		ip_pool_["10.10.100." + std::to_string(i)] = IpStatus::Available;
}

std::optional<std::string> IpPoolManager::assignTentative(const std::string& client_id) {
	std::lock_guard lock(mutex_);
	for (auto& [ip, status] : ip_pool_) {
		if (status == IpStatus::Available) {
			status = IpStatus::Tentative;
			assigned_ips_[client_id] = ip;
			return ip;
		}
	}
	return std::nullopt;
}

bool IpPoolManager::confirm(const std::string& client_id) {
	std::lock_guard lock(mutex_);
	auto it = assigned_ips_.find(client_id);
	if (it != assigned_ips_.end()) {
		ip_pool_[it->second] = IpStatus::Confirmed;
		return true;
	}
	return false;
}

void IpPoolManager::release(const std::string& client_id) {
	std::lock_guard lock(mutex_);
	auto it = assigned_ips_.find(client_id);
	if (it != assigned_ips_.end()) {
		ip_pool_[it->second] = IpStatus::Available;
		assigned_ips_.erase(it);
	}
}
