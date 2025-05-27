// IpPoolManager.h
#pragma once
#include <map>
#include <string>
#include <mutex>
#include <optional>

enum class IpStatus { Available, Tentative, Confirmed };

class IpPoolManager {
public:
	IpPoolManager();
	std::optional<std::string> assignTentative(const std::string& client_id);
	bool confirm(const std::string& client_id);
	void release(const std::string& client_id);
private:
	std::map<std::string, IpStatus> ip_pool_;
	std::map<std::string, std::string> assigned_ips_;
	std::mutex mutex_;
};
