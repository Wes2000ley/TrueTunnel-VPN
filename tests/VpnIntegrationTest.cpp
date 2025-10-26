#include "VpnServer.h"
#include "VpnClient.h"
#include "utils.hpp"
#include "vpn.hpp"
#include "Networking.h"
#include "raii.hpp"

#include <chrono>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;

struct Scenario {
    secure::CipherSuite cipher;
    TransportProtocol transport;
    std::string name;
};

std::string cipher_name(secure::CipherSuite cipher) {
    switch (cipher) {
        case secure::CipherSuite::Aes256Gcm:        return "AES256-GCM";
        case secure::CipherSuite::Aes128Gcm:        return "AES128-GCM";
        case secure::CipherSuite::ChaCha20Poly1305: return "ChaCha20-Poly1305";
        default:                                    return "Unknown";
    }
}

std::string transport_name(TransportProtocol transport) {
    switch (transport) {
        case TransportProtocol::Tcp: return "TCP";
        case TransportProtocol::Udp: return "UDP";
        default:                     return "Unknown";
    }
}

bool wait_for_ip(const VpnClient& client,
                 std::chrono::milliseconds timeout,
                 std::chrono::milliseconds poll_interval = 200ms) {
    const auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < timeout) {
        if (!client.local_ip().empty()) return true;
        std::this_thread::sleep_for(poll_interval);
    }
    return false;
}

bool wait_for_message(VpnClient& client,
                      const std::string& sender_ip,
                      const std::string& text,
                      std::chrono::milliseconds timeout) {
    const auto start = std::chrono::steady_clock::now();
    const std::string needle = sender_ip + "|" + text;
    while (std::chrono::steady_clock::now() - start < timeout) {
        auto messages = client.drain_messages();
        for (const auto& msg : messages) {
            if (msg == needle) {
                return true;
            }
        }
        std::this_thread::sleep_for(100ms);
    }
    return false;
}

bool run_scenario(int index,
                  const Scenario& scenario,
                  const std::string& real_adapter_name,
                  const std::string& real_adapter_ip,
                  const std::string& password) {
    const int port = 6500 + index;
    const std::string server_adapter  = "TT_Srv_"  + std::to_string(index);
    const std::string clientA_adapter = "TT_CliA_" + std::to_string(index);
    const std::string clientB_adapter = "TT_CliB_" + std::to_string(index);

    std::cout << "\n[ SCENARIO ] " << scenario.name
              << " | Port " << port << '\n';

    bool success = false;
    VpnServer server(port, real_adapter_name, password, server_adapter,
                     scenario.cipher, scenario.transport);
    std::unique_ptr<VpnClient> clientA;
    std::unique_ptr<VpnClient> clientB;

    try {
        server.start();
        std::this_thread::sleep_for(500ms);

        clientA = std::make_unique<VpnClient>(
            real_adapter_ip, port, password,
            clientA_adapter, real_adapter_name, real_adapter_ip,
            scenario.cipher, scenario.transport);

        clientB = std::make_unique<VpnClient>(
            real_adapter_ip, port, password,
            clientB_adapter, real_adapter_name, real_adapter_ip,
            scenario.cipher, scenario.transport);

        clientA->start();
        clientB->start();

        if (!wait_for_ip(*clientA, 10s) || !wait_for_ip(*clientB, 10s)) {
            std::cerr << "[!] Timed out waiting for client IP assignment\n";
            throw std::runtime_error("ip timeout");
        }

        const std::string ipA = clientA->local_ip();
        const std::string ipB = clientB->local_ip();

        std::cout << "    Client A IP: " << ipA << '\n'
                  << "    Client B IP: " << ipB << '\n';

        std::this_thread::sleep_for(2s); // allow routing tables to settle

        clientA->drain_messages();
        clientB->drain_messages();

        std::string base = scenario.name + "_" + std::to_string(index);
        std::string tokenAB = "MSG_" + base + "_A";
        std::string tokenBA = "MSG_" + base + "_B";

        bool sendA = clientA->send_chat_message(tokenAB);
        bool recvB = wait_for_message(*clientB, ipA, tokenAB, 5s);

        bool sendB = clientB->send_chat_message(tokenBA);
        bool recvA = wait_for_message(*clientA, ipB, tokenBA, 5s);

        std::cout << "    Message A->B: " << ((sendA && recvB) ? "ok" : "failed") << '\n'
                  << "    Message B->A: " << ((sendB && recvA) ? "ok" : "failed") << '\n';

        success = sendA && recvB && sendB && recvA;
    } catch (const std::exception& ex) {
        std::cerr << "[!] Scenario error: " << ex.what() << '\n';
    }

    if (clientA) clientA->stop();
    if (clientB) clientB->stop();
    server.stop();
    std::this_thread::sleep_for(1s); // allow adapters to tear down

    return success;
}

} // namespace

int main(int argc, char** argv) {
    if (!is_running_as_admin()) {
        std::cerr << "[!] Integration test must run as Administrator\n";
        return 1;
    }

    ComInit com;
    WsaInit wsa;

    try {
        LoadWintun();
    } catch (const std::exception& ex) {
        std::cerr << "[!] Failed to load Wintun: " << ex.what() << '\n';
        return 1;
    }

    populate_real_adapters();
    if (real_adapters_.empty() || real_adapters_.front().ip.empty()) {
        std::cerr << "[!] No suitable physical adapter found for binding\n";
        return 1;
    }

    const std::string real_adapter_name = real_adapters_.front().name;
    const std::string real_adapter_ip   = real_adapters_.front().ip;

    const std::vector<Scenario> scenarios = {
        { secure::CipherSuite::Aes256Gcm,        TransportProtocol::Tcp, "AES256-GCM / TCP"        },
        { secure::CipherSuite::Aes128Gcm,        TransportProtocol::Tcp, "AES128-GCM / TCP"        },
        { secure::CipherSuite::ChaCha20Poly1305, TransportProtocol::Tcp, "ChaCha20 / TCP"          },
        { secure::CipherSuite::Aes256Gcm,        TransportProtocol::Udp, "AES256-GCM / UDP"        },
        { secure::CipherSuite::Aes128Gcm,        TransportProtocol::Udp, "AES128-GCM / UDP"        },
        { secure::CipherSuite::ChaCha20Poly1305, TransportProtocol::Udp, "ChaCha20 / UDP"          },
    };

    const std::string password = "AutoTestPassword123!";
    bool pause_at_end = true;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (arg == "--no-pause" || arg == "-y") {
            pause_at_end = false;
        }
    }

    int passed = 0;

    for (std::size_t i = 0; i < scenarios.size(); ++i) {
        if (run_scenario(static_cast<int>(i), scenarios[i],
                         real_adapter_name, real_adapter_ip, password)) {
            ++passed;
        } else {
            std::cerr << "[!] Scenario failed: " << scenarios[i].name << '\n';
        }
    }

    std::cout << "\nSummary: " << passed << " / " << scenarios.size() << " scenarios passed\n";
    if (pause_at_end) {
        std::cout << "Press Enter to exit...";
        std::cin.get();
    }
    return passed == static_cast<int>(scenarios.size()) ? 0 : 1;
}
