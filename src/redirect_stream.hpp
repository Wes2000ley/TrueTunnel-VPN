// redirect_stream.hpp - Enhanced version
#pragma once
#include <streambuf>
#include <ostream>
#include <functional>
#include <mutex>
#include <iostream>
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
		std::string completed_line;
		if (!traits_type::eq_int_type(ch, traits_type::eof())) {
			char c = static_cast<char>(ch);
			{
				std::lock_guard<std::mutex> lock(buffer_mutex_);
				buffer_.push_back(c);
				original_buf_->sputc(c); // still write to console
				if (c == '\n') {
					completed_line.assign(buffer_.data(), buffer_.size() - 1U);
					buffer_.clear();
				}
			}
			if (!completed_line.empty() || c == '\n') {
				cb_thread_safe(completed_line);
			}
			return ch;
		}
		return traits_type::not_eof(ch);
	}

	std::streamsize xsputn(const char *s, std::streamsize n) override {
		std::vector<std::string> completed_lines;
		{
			std::lock_guard<std::mutex> lock(buffer_mutex_);
			buffer_.append(s, static_cast<size_t>(n));
			original_buf_->sputn(s, n); // forward to console

			std::size_t pos;
			while ((pos = buffer_.find('\n')) != std::string::npos) {
				completed_lines.emplace_back(buffer_.substr(0, pos));
				buffer_.erase(0, pos + 1);
			}
		}
		for (const auto& line : completed_lines) {
			cb_thread_safe(line);
		}
		return n;
	}

	int sync() override {
		flush_buffer();
		return original_buf_->pubsync();
	}

	//------------------------------------------------------------------
	// helpers
	//------------------------------------------------------------------
	void flush_buffer() {
		std::string pending;
		{
			std::lock_guard<std::mutex> lock(buffer_mutex_);
			pending.swap(buffer_);
		}
		if (!pending.empty()) {
			cb_thread_safe(pending);
		}
	}

	void cb_thread_safe(const std::string &line) {
		if (!cb_) return;
		std::lock_guard<std::mutex> lk(cb_mutex_);
		cb_(line);
	}

	std::string buffer_;
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
