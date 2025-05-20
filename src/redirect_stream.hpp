// redirect_stream.hpp - Enhanced version
#pragma once
#include <streambuf>
#include <ostream>
#include <functional>
#include <mutex>
#include <iostream>

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
		stream_.rdbuf(original_buf_);
	}

private:
	//------------------------------------------------------------------
	// streambuf overrides
	//------------------------------------------------------------------
	int overflow(int ch) override {
		if (ch != EOF) {
			char c = static_cast<char>(ch);
			buffer_.push_back(c);
			original_buf_->sputc(c); // still write to console

			if (c == '\n') flush_buffer();
		}
		return ch;
	}

	std::streamsize xsputn(const char *s, std::streamsize n) override {
		buffer_.append(s, static_cast<size_t>(n));
		original_buf_->sputn(s, n); // forward to console

		std::size_t pos;
		while ((pos = buffer_.find('\n')) != std::string::npos) {
			std::string line = buffer_.substr(0, pos); // exclude '\n'
			cb_thread_safe(line);
			buffer_.erase(0, pos + 1);
		}
		return n;
	}

	//------------------------------------------------------------------
	// helpers
	//------------------------------------------------------------------
	void flush_buffer() {
		if (!buffer_.empty()) {
			cb_thread_safe(buffer_);
			buffer_.clear();
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
