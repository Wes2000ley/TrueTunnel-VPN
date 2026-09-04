#include "redirect_stream.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

[[nodiscard]] bool expect(const bool condition, const char* message) {
    if (condition) return true;
    std::cerr << "[FAIL] " << message << '\n';
    return false;
}

[[nodiscard]] std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::istringstream input{text};
    for (std::string line; std::getline(input, line);) {
        lines.push_back(std::move(line));
    }
    return lines;
}

class SyncOverlapProbeBuffer final : public std::streambuf {
public:
    std::atomic<bool> sync_entered{false};
    std::atomic<bool> release_sync{false};
    std::atomic<bool> overlap_observed{false};

protected:
    std::streamsize xsputn(const char*, const std::streamsize count) override {
        if (sync_active_.load(std::memory_order_acquire)) {
            overlap_observed.store(true, std::memory_order_release);
        }
        return count;
    }

    int sync() override {
        sync_active_.store(true, std::memory_order_release);
        sync_entered.store(true, std::memory_order_release);
        while (!release_sync.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        sync_active_.store(false, std::memory_order_release);
        return 0;
    }

private:
    std::atomic<bool> sync_active_{false};
};

} // namespace

int main() {
    bool passed = true;

    std::ostringstream unit_buffered_sink;
    unit_buffered_sink.setf(std::ios::unitbuf);
    std::vector<std::string> unit_buffered_messages;
    {
        redirect_stream redirect{
            unit_buffered_sink,
            [&unit_buffered_messages](const std::string& message) {
                unit_buffered_messages.push_back(message);
            }};

        unit_buffered_sink << "[!] udp-client: ";
        unit_buffered_sink << "integration-injected rejection";
        passed &= expect(unit_buffered_messages.empty(),
                         "unitbuf exposed a partial logical line");
        unit_buffered_sink << '\n';
        passed &= expect(
            unit_buffered_messages ==
                std::vector<std::string>{
                    "[!] udp-client: integration-injected rejection"},
            "unitbuf insertions were not delivered as one complete line");

        unit_buffered_sink << "unterminated tail";
        unit_buffered_sink.flush();
        passed &= expect(unit_buffered_messages.size() == 1U,
                         "explicit sync exposed an unterminated line");
    }
    passed &= expect(
        unit_buffered_messages ==
            std::vector<std::string>{
                "[!] udp-client: integration-injected rejection",
                "unterminated tail"},
        "destruction did not deliver the final unterminated line");
    passed &= expect(
        unit_buffered_sink.str() ==
            "[!] udp-client: integration-injected rejection\nunterminated tail",
        "forwarded stream contents changed");

    constexpr int kThreadCount = 8;
    std::ostringstream concurrent_sink;
    std::vector<std::string> concurrent_messages;
    std::mutex messages_mutex;
    std::atomic<int> prefixes_ready{0};
    {
        redirect_stream redirect{
            concurrent_sink,
            [&concurrent_messages, &messages_mutex](const std::string& message) {
                std::lock_guard<std::mutex> lock{messages_mutex};
                concurrent_messages.push_back(message);
            }};
        std::vector<std::thread> writers;
        writers.reserve(kThreadCount);
        for (int index = 0; index < kThreadCount; ++index) {
            writers.emplace_back([index, &redirect, &prefixes_ready] {
                const std::string prefix = "worker-" + std::to_string(index) + ':';
                const std::string suffix = "complete\n";
                (void)redirect.sputn(prefix.data(),
                                     static_cast<std::streamsize>(prefix.size()));
                prefixes_ready.fetch_add(1, std::memory_order_release);
                while (prefixes_ready.load(std::memory_order_acquire) <
                       kThreadCount) {
                    std::this_thread::yield();
                }
                (void)redirect.pubsync();
                (void)redirect.sputn(suffix.data(),
                                     static_cast<std::streamsize>(suffix.size()));
            });
        }
        for (auto& writer : writers) writer.join();
    }

    std::vector<std::string> expected;
    expected.reserve(kThreadCount);
    for (int index = 0; index < kThreadCount; ++index) {
        expected.push_back("worker-" + std::to_string(index) + ":complete");
    }
    auto forwarded_lines = split_lines(concurrent_sink.str());
    std::sort(expected.begin(), expected.end());
    std::sort(forwarded_lines.begin(), forwarded_lines.end());
    std::sort(concurrent_messages.begin(), concurrent_messages.end());
    passed &= expect(forwarded_lines == expected,
                     "concurrent forwarding spliced logical lines");
    passed &= expect(concurrent_messages == expected,
                     "concurrent callbacks spliced logical lines");

    SyncOverlapProbeBuffer overlap_probe;
    std::ostream overlap_sink{&overlap_probe};
    {
        redirect_stream redirect{overlap_sink, [](const std::string&) {}};
        std::thread flusher{[&redirect] { (void)redirect.pubsync(); }};
        while (!overlap_probe.sync_entered.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }

        std::thread sync_releaser{[&overlap_probe] {
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds{1};
            while (!overlap_probe.overlap_observed.load(
                       std::memory_order_acquire) &&
                   std::chrono::steady_clock::now() < deadline) {
                std::this_thread::yield();
            }
            overlap_probe.release_sync.store(true, std::memory_order_release);
        }};

        constexpr char kSerializedLine[] = "serialized\n";
        const auto written = redirect.sputn(
            kSerializedLine,
            static_cast<std::streamsize>(sizeof(kSerializedLine) - 1U));
        sync_releaser.join();
        flusher.join();

        passed &= expect(
            written == static_cast<std::streamsize>(
                           sizeof(kSerializedLine) - 1U),
            "serialized probe write was truncated");
        passed &= expect(
            !overlap_probe.overlap_observed.load(std::memory_order_acquire),
            "underlying stream sync overlapped a forwarded write");
    }

    if (passed) {
        std::cout << "[PASS] Log redirection preserves logical lines under "
                     "unitbuf and concurrent writes\n";
    }
    return passed ? 0 : 1;
}
