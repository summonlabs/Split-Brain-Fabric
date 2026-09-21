#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include "sbf/status.hpp"

namespace sbf::net {

struct Endpoint {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;

  std::string to_string() const;
  static Status parse(std::string_view text, Endpoint& out) noexcept;
};

// RAII owning socket handle. Move-only: copying is deleted so that a handle can
// never be closed twice.
class Socket {
 public:
  Socket() = default;
  explicit Socket(std::intptr_t handle) noexcept : handle_(handle) {}
  ~Socket();

  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;

  bool valid() const noexcept;
  std::intptr_t handle() const noexcept { return handle_; }
  std::intptr_t release() noexcept;

  void close() noexcept;
  // Unblocks any thread blocked in recv/send on this socket.
  void shutdown() noexcept;

  bool set_nodelay(bool enabled) noexcept;
  bool set_reuse_address(bool enabled) noexcept;

  // Bounded wait for readability. Used only by service worker threads so that a
  // shutdown request is observed promptly on platforms where shutting a socket
  // down does not interrupt a blocked recv. No correctness property depends on
  // the wait duration; only shutdown latency does, and it is bounded by it.
  Status wait_readable(std::uint32_t milliseconds, bool& readable) noexcept;

  Status write_all(std::string_view bytes) noexcept;
  // Returns Ok with bytes_read == 0 on an orderly peer close; the caller
  // distinguishes orderly close from failure by inspecting the status.
  Status read_some(std::string& out, std::size_t max_bytes, std::size_t& bytes_read) noexcept;

 private:
  std::intptr_t handle_ = -1;
};

// Blocking listener with prompt, natural shutdown: stop() shuts the listener
// down and self-connects so that a thread parked in accept() returns
// immediately. No polling, no timeouts.
class Listener {
 public:
  Listener() = default;
  ~Listener();
  Listener(const Listener&) = delete;
  Listener& operator=(const Listener&) = delete;
  Listener(Listener&&) noexcept;
  Listener& operator=(Listener&&) noexcept;

  static Status listen(const Endpoint& endpoint, Listener& out, std::uint32_t backlog);
  // Blocks until a connection arrives or stop() is called.
  Status accept(Socket& out) noexcept;
  void stop() noexcept;
  std::uint16_t port() const noexcept { return port_; }
  const Endpoint& endpoint() const noexcept { return endpoint_; }

 private:
  Socket socket_;
  Endpoint endpoint_;
  std::uint16_t port_ = 0;
  std::atomic<bool> stopping_{false};
};

Status connect(const Endpoint& endpoint, Socket& out) noexcept;

// One-time process-wide network initialisation (Winsock startup on Windows).
Status initialize() noexcept;
void shutdown() noexcept;

std::string last_error_text() noexcept;

}  // namespace sbf::net
