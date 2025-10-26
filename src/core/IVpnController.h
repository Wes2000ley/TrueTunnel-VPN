#pragma once

#include <functional>
#include <string>

#include "TransportProtocol.h"
#include "secure/CipherSuite.h"

class IVpnController {
public:
        virtual ~IVpnController() = default;

        virtual bool start(std::string mode,
                           std::string server_ip,
                           int port,
                           std::string local_ip,
                           std::string gateway,
                           std::string password,
                           std::string adapter_name,
                           std::string subnet_mask,
                           std::string public_ip,
                           std::string real_adapter,
                           secure::CipherSuite cipher_suite,
                           TransportProtocol transport) = 0;

        virtual bool send_message(const std::string& text) = 0;

        virtual void stop() = 0;
        [[nodiscard]] virtual bool is_running() const = 0;
        virtual void set_log_callback(std::function<void(const std::string &)> cb) = 0;
};
