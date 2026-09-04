// redirect_stream.hpp - Enhanced version
#pragma once
#include <streambuf>
#include <ostream>
#include <functional>
#include <mutex>
#include <iostream>
#include <thread>
#include <unordered_map>
#include <vector>

class redirect_stream final : public std::streambuf {
public:
	using log_cb_t = std::function<void(const std::string &)>;

	// constructor → pass the ostream you want to tap and a callback
	explicit redirect_stream(std::ostream &stream, log_cb_t cb)
		: original_buf_(stream.rdbuf()), stream_(stream), cb_(std::move(cb)) {
		stream_.rdbuf(this); // hijack!
	}

	// not copyable / movable
	redirect_stream(const redirect_stream &) = delete;

	redirect_stream &operator=(const redirect_stream &) = delete;

	// destructor → restore original rdbuf
	~redirect_stream() override {
		flush_buffer();  // flush remaining buffered text
		stream_.rdbuf(original_buf_);
	}


private:
	//------------------------------------------------------------------
	// streambuf overrides
	//------------------------------------------------------------------
	int overflow(int ch) override {
		if (traits_type::eq_int_type(ch, traits_type::eof())) {
			return sync() == 0
				? traits_type::not_eof(ch)
				: traits_type::eof();
		}
		const char character = traits_type::to_char_type(ch);
		return xsputn(&character, 1) == 1 ? ch : traits_type::eof();
	}

	std::streamsize xsputn(const char *s, std::streamsize n) override {
		if (s == nullptr || n <= 0) return 0;
		std::vector<std::string> completed_lines;
		bool forwarded = true;
		{
			std::lock_guard<std::mutex> lock(buffer_mutex_);
			auto& buffer = buffers_[std::this_thread::get_id()];
			buffer.append(s, static_cast<size_t>(n));

			std::size_t pos;
			while ((pos = buffer.find('\n')) != std::string::npos) {
				std::string line = buffer.substr(0, pos + 1U);
				buffer.erase(0, pos + 1U);
				if (original_buf_->sputn(
						line.data(), static_cast<std::streamsize>(line.size())) !=
					static_cast<std::streamsize>(line.size())) {
					forwarded = false;
				}
				line.pop_back();
				if (!line.empty() && line.back() == '\r') line.pop_back();
				completed_lines.push_back(std::move(line));
			}
			if (buffer.empty()) buffers_.erase(std::this_thread::get_id());
		}
		for (const auto& line : completed_lines) {
			cb_thread_safe(line);
		}
		return forwarded ? n : 0;
	}

	int sync() override {
		// std::cerr has unitbuf enabled and therefore calls pubsync() after
		// every insertion.  Flushing the partial per-thread buffer here would
		// split one logical line (and let another thread splice text into it).
		// Complete lines are delivered by xsputn(); a final unterminated line is
		// delivered by the destructor.
		std::lock_guard<std::mutex> lock(buffer_mutex_);
		return original_buf_->pubsync();
	}

	//------------------------------------------------------------------
	// helpers
	//------------------------------------------------------------------
	void flush_buffer() {
		std::vector<std::string> pending_lines;
		{
			std::lock_guard<std::mutex> lock(buffer_mutex_);
			pending_lines.reserve(buffers_.size());
			for (auto& [_, pending] : buffers_) {
				if (pending.empty()) continue;
				(void)original_buf_->sputn(
					pending.data(), static_cast<std::streamsize>(pending.size()));
				if (!pending.empty() && pending.back() == '\r') pending.pop_back();
				pending_lines.push_back(std::move(pending));
			}
			buffers_.clear();
		}
		for (const auto& pending : pending_lines) {
			cb_thread_safe(pending);
		}
	}

	void cb_thread_safe(const std::string &line) {
		if (!cb_) return;
		std::lock_guard<std::mutex> lk(cb_mutex_);
		cb_(line);
	}

	std::unordered_map<std::thread::id, std::string> buffers_;
	std::streambuf *original_buf_;
	std::ostream &stream_;
	log_cb_t cb_;
	std::mutex buffer_mutex_;
	std::mutex cb_mutex_;
};

// ----------------------------
// Convenience helpers
// ----------------------------

// Redirect both cout and cerr easily
class dual_redirect_stream {
public:
	dual_redirect_stream(redirect_stream::log_cb_t callback)
		: cout_redirect_(std::cout, callback),
		  cerr_redirect_(std::cerr, callback) {
	}

private:
	redirect_stream cout_redirect_;
	redirect_stream cerr_redirect_;
};
