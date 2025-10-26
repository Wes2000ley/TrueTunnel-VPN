#pragma once

enum class TransportProtocol {
    Tcp,
    Udp
};

inline const char* to_string(TransportProtocol protocol) noexcept {
    switch (protocol) {
        case TransportProtocol::Tcp: return "TCP";
        case TransportProtocol::Udp: return "UDP";
        default: return "Unknown";
    }
}
