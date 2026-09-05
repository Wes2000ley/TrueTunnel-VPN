#include "desktop/BridgeProtocol.h"
#include "desktop/SecretStore.h"
#include <iostream>
#include <set>
#include <thread>
#include <fstream>

int main() {
    using namespace desktop;
    auto require = [](bool condition, const char *message) {
        if (!condition)
            throw std::runtime_error(message);
    };
    try {
        require(valid_request({kBridgeMagic, 1, Operation::Start, sizeof(StartRequest)}),
                "Start frame rejected");
        require(!valid_request({kBridgeMagic, 1, Operation::Start, sizeof(StartRequest) - 1}),
                "Truncated credential frame accepted");
        require(!valid_request({kBridgeMagic, 1, Operation::Start, kMaximumPayload}),
                "Oversized start accepted");
        require(!valid_request({kBridgeMagic, 1, Operation::Chat, 513}), "Oversized chat accepted");
        require(!valid_request({kBridgeMagic, 1, Operation::Stop, 1}), "Stop accepted a payload");
        require(!valid_request({kBridgeMagic, 2, Operation::Poll, 0}),
                "Unknown protocol version accepted");
        require(!valid_header({0, 1, Operation::Poll, 0}), "Bad magic accepted");
        require(!valid_header({kBridgeMagic, 1, static_cast<Operation>(99), 0}),
                "Unknown opcode accepted");
        require(same_application(GetCurrentProcess()), "Current process identity rejected");
        {
            SecretStore key;
            require(key.generate(), "Cannot generate validation fixture");
            StartRequest valid{};
            valid.adapter_luid = 1;
            valid.port = 5555;
            valid.secret = key.value;
            strcpy_s(valid.address.data(), valid.address.size(), "vpn.example.net");
            require(valid_start_request(valid), "Valid start settings rejected");
            auto invalid = valid;
            invalid.port = 65536;
            require(!valid_start_request(invalid), "Port overflow accepted");
            invalid = valid;
            invalid.udp = 2;
            require(!valid_start_request(invalid), "Unknown transport accepted");
            invalid = valid;
            invalid.recovery = 2;
            require(!valid_start_request(invalid), "Unknown recovery policy accepted");
            invalid = valid;
            invalid.adapter_luid = 0;
            require(!valid_start_request(invalid), "Missing adapter identity accepted");
            invalid = valid;
            invalid.secret.fill('x');
            require(!valid_start_request(invalid), "Unterminated secret accepted");
            invalid = valid;
            invalid.address.fill('x');
            require(!valid_start_request(invalid), "Unterminated endpoint accepted");
            invalid = valid;
            invalid.secret.fill(0);
            strcpy_s(invalid.secret.data(), invalid.secret.size(), "password");
            require(!valid_start_request(invalid), "Human password accepted");
            invalid = valid;
            strcpy_s(invalid.address.data(), invalid.address.size(), "https://example.net:443/");
            require(!valid_start_request(invalid), "URL accepted as endpoint");
            SecureZeroMemory(&valid, sizeof(valid));
            SecureZeroMemory(&invalid, sizeof(invalid));
        }
        {
            const auto directory = std::filesystem::temp_directory_path() /
                                   (L"TrueTunnel.BridgeTest." + random_suffix());
            require(std::filesystem::create_directory(directory),
                    "Cannot create diagnostic test directory");
            const auto original = directory / L"sentinel.txt";
            const auto link = directory / L"linked.txt";
            struct Cleanup {
                std::filesystem::path original, link, directory;
                ~Cleanup() {
                    DeleteFileW(link.c_str());
                    DeleteFileW(original.c_str());
                    RemoveDirectoryW(directory.c_str());
                }
            } cleanup{original, link, directory};
            const std::array<BYTE, 4> sentinel{'k', 'e', 'e', 'p'};
            const std::array<BYTE, 1> replacement{'x'};
            require(write_diagnostic_file(original, sentinel), "Cannot write diagnostic fixture");
            require(CreateHardLinkW(link.c_str(), original.c_str(), nullptr) != FALSE,
                    "Cannot create hard-link fixture");
            require(!write_diagnostic_file(link, replacement),
                    "Diagnostic write followed a hard link");
            std::ifstream input(original, std::ios::binary);
            const std::string contents{std::istreambuf_iterator<char>{input}, {}};
            require(contents == "keep", "Diagnostic rejection truncated the original file");
            input.close();
            require(DeleteFileW(link.c_str()) != FALSE, "Cannot retire hard-link fixture");
            require(write_diagnostic_file(original, replacement),
                    "Normal diagnostic overwrite failed");
        }
        std::set<std::string> keys;
        for (int index = 0; index < 100; ++index) {
            SecretStore secret;
            require(secret.generate(), "CNG generation failed");
            require(secret.ready(), "Generated key invalid");
            require(keys.emplace(shared_secret_text(secret.value)).second,
                    "Duplicate generated key");
            secret.clear();
            require(!secret.ready() && !secret.generated, "Cleared key remained ready");
            require(std::all_of(secret.value.begin(), secret.value.end(),
                                [](char ch) { return ch == 0; }),
                    "Key was not wiped");
        }
        // Exercise actual Windows pipe framing and cancellation without elevation.
        const auto name = L"\\\\.\\pipe\\TrueTunnel.BridgeTest." + random_suffix();
        Handle server = create_private_pipe(name);
        require(static_cast<bool>(server), "Cannot create test pipe");
        Handle client(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                  OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
        require(static_cast<bool>(client), "Cannot connect test pipe");
        ULONG server_pid{}, client_pid{};
        require(GetNamedPipeServerProcessId(client.get(), &server_pid) &&
                    server_pid == GetCurrentProcessId(),
                "Pipe server PID verification failed");
        require(GetNamedPipeClientProcessId(server.get(), &client_pid) &&
                    client_pid == GetCurrentProcessId(),
                "Pipe client PID verification failed");
        bool duplicate_rejected = false;
        try {
            auto duplicate = create_private_pipe(name);
        } catch (const std::runtime_error &) {
            duplicate_rejected = true;
        }
        require(duplicate_rejected, "A second first-instance listener was accepted");
        require(write_frame(client.get(), Operation::Chat, "hello", 5, nullptr),
                "Cannot write frame");
        Header header{};
        require(read_header(server.get(), header, nullptr) && valid_request(header),
                "Cannot read frame");
        std::array<char, 5> data{};
        require(pipe_io(server.get(), false, data.data(), 5, nullptr), "Cannot read payload");
        require(std::string_view(data.data(), data.size()) == "hello", "Payload corrupted");
        Handle cancelled(CreateEventW(nullptr, TRUE, TRUE, nullptr));
        auto before = GetTickCount64();
        require(!read_header(server.get(), header, cancelled.get()), "Cancelled read succeeded");
        require(GetTickCount64() - before < 1000, "Cancellation exceeded one second");
        std::cout << "[PASS] Desktop IPC bounds, CNG key generation/wiping, real pipe framing and "
                     "cancellation\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "[FAIL] " << error.what() << '\n';
        return 1;
    }
}
