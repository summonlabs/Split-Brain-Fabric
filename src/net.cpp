#include "sbf/net.hpp"

#include <cstring>
#include <mutex>
#include <string>

#include "sbf/text.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace sbf::net {
namespace {

#ifdef _WIN32
using raw_socket = SOCKET;
constexpr raw_socket kInvalidSocket = INVALID_SOCKET;
#else
using raw_socket = int;
constexpr raw_socket kInvalidSocket = -1;
#endif

std::once_flag g_init_once;
std::atomic<bool> g_initialised{false};

raw_socket to_raw(std::intptr_t handle) noexcept { return static_cast<raw_socket>(handle); }

std::intptr_t from_raw(raw_socket handle) noexcept { return static_cast<std::intptr_t>(handle); }

void close_raw(raw_socket handle) noexcept {
  if (handle == kInvalidSocket) return;
#ifdef _WIN32
  ::closesocket(handle);
#else
  ::close(handle);
#endif
}

void shutdown_raw(raw_socket handle) noexcept {
  if (handle == kInvalidSocket) return;
#ifdef _WIN32
  ::shutdown(handle, SD_BOTH);
#else
  ::shutdown(handle, SHUT_RDWR);
#endif
}

int last_socket_error() noexcept {
#ifdef _WIN32
  return ::WSAGetLastError();
#else
  return errno;
#endif
}

bool would_block(int error) noexcept {
#ifdef _WIN32
  return error == WSAEWOULDBLOCK;
#else
  return error == EAGAIN || error == EWOULDBLOCK;
#endif
}

}  // namespace

Status initialize() noexcept {
  std::call_once(g_init_once, []() {
#ifdef _WIN32
    WSADATA data{};
    if (::WSAStartup(MAKEWORD(2, 2), &data) == 0) {
      g_initialised.store(true);
    }
#else
    g_initialised.store(true);
#endif
  });
  if (!g_initialised.load()) {
    return Status::make(Outcome::Unsupported, Reason::ResourceExhausted);
  }
  return Status::ok();
}

void shutdown() noexcept {
#ifdef _WIN32
  if (g_initialised.load()) ::WSACleanup();
#endif
  g_initialised.store(false);
}

std::string last_error_text() noexcept {
  const int error = last_socket_error();
  std::string out = "socket error ";
  out.append(text::hex_u64(static_cast<std::uint64_t>(error)));
  return out;
}

std::string Endpoint::to_string() const {
  std::string out = host;
  out.push_back(':');
  out.append(std::to_string(port));
  return out;
}

Status Endpoint::parse(std::string_view text_value, Endpoint& out) noexcept {
  const auto colon = text_value.rfind(':');
  if (colon == std::string_view::npos) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  }
  const auto host_part = text_value.substr(0, colon);
  const auto port_part = text_value.substr(colon + 1);
  if (host_part.empty() || port_part.empty()) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  }
  std::uint64_t port = 0;
  if (auto st = text::parse_u64(port_part, port); !st.is_ok()) return st;
  if (port == 0 || port > 65535) return Status::make(Outcome::Invalid, Reason::ValueOutOfRange, port);
  out.host.assign(host_part);
  out.port = static_cast<std::uint16_t>(port);
  return Status::ok();
}

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) { other.handle_ = -1; }

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = -1;
  }
  return *this;
}

bool Socket::valid() const noexcept { return handle_ != -1; }

std::intptr_t Socket::release() noexcept {
  const std::intptr_t handle = handle_;
  handle_ = -1;
  return handle;
}

void Socket::close() noexcept {
  if (handle_ == -1) return;
  close_raw(to_raw(handle_));
  handle_ = -1;
}

void Socket::shutdown() noexcept {
  if (handle_ == -1) return;
  shutdown_raw(to_raw(handle_));
}

bool Socket::set_nodelay(bool enabled) noexcept {
  if (handle_ == -1) return false;
  const int value = enabled ? 1 : 0;
  return ::setsockopt(to_raw(handle_), IPPROTO_TCP, TCP_NODELAY,
                      reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
}

bool Socket::set_reuse_address(bool enabled) noexcept {
  if (handle_ == -1) return false;
  const int value = enabled ? 1 : 0;
  return ::setsockopt(to_raw(handle_), SOL_SOCKET, SO_REUSEADDR,
                      reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
}

Status Socket::wait_readable(std::uint32_t milliseconds, bool& readable) noexcept {
  readable = false;
  if (handle_ == -1) return Status::make(Outcome::Closed, Reason::ConnectionClosed);
  fd_set set;
  FD_ZERO(&set);
  FD_SET(to_raw(handle_), &set);
  timeval timeout;
  timeout.tv_sec = static_cast<long>(milliseconds / 1000u);
  timeout.tv_usec = static_cast<long>((milliseconds % 1000u) * 1000u);
#ifdef _WIN32
  const int rc = ::select(0, &set, nullptr, nullptr, &timeout);
#else
  const int rc = ::select(static_cast<int>(to_raw(handle_)) + 1, &set, nullptr, nullptr, &timeout);
#endif
  if (rc < 0) {
    return Status::make(Outcome::Unreachable, Reason::ConnectionClosed,
                        static_cast<std::uint64_t>(last_socket_error()));
  }
  readable = rc > 0 && FD_ISSET(to_raw(handle_), &set) != 0;
  return Status::ok();
}

Status Socket::write_all(std::string_view bytes) noexcept {
  if (handle_ == -1) return Status::make(Outcome::Closed, Reason::ConnectionClosed);
  std::size_t sent = 0;
  while (sent < bytes.size()) {
    const int chunk = static_cast<int>(
        std::min<std::size_t>(bytes.size() - sent, static_cast<std::size_t>(1) << 20));
    const int rc = ::send(to_raw(handle_), bytes.data() + sent, chunk, 0);
    if (rc <= 0) {
      const int error = last_socket_error();
      if (would_block(error)) continue;
      return Status::make(Outcome::Unreachable, Reason::ConnectionClosed,
                          static_cast<std::uint64_t>(error));
    }
    sent += static_cast<std::size_t>(rc);
  }
  return Status::ok();
}

Status Socket::read_some(std::string& out, std::size_t max_bytes, std::size_t& bytes_read) noexcept {
  bytes_read = 0;
  if (handle_ == -1) return Status::make(Outcome::Closed, Reason::ConnectionClosed);
  if (max_bytes == 0) return Status::ok();
  out.resize(max_bytes);
  const int chunk = static_cast<int>(std::min<std::size_t>(max_bytes, static_cast<std::size_t>(1) << 20));
  const int rc = ::recv(to_raw(handle_), out.data(), chunk, 0);
  if (rc == 0) {
    out.clear();
    return Status::ok();  // orderly peer close
  }
  if (rc < 0) {
    const int error = last_socket_error();
    out.clear();
    return Status::make(Outcome::Unreachable, Reason::ConnectionClosed,
                        static_cast<std::uint64_t>(error));
  }
  out.resize(static_cast<std::size_t>(rc));
  bytes_read = static_cast<std::size_t>(rc);
  return Status::ok();
}

Listener::~Listener() { stop(); }

Listener::Listener(Listener&& other) noexcept
    : socket_(std::move(other.socket_)),
      endpoint_(std::move(other.endpoint_)),
      port_(other.port_),
      stopping_(other.stopping_.load()) {
  other.port_ = 0;
}

Listener& Listener::operator=(Listener&& other) noexcept {
  if (this != &other) {
    stop();
    socket_ = std::move(other.socket_);
    endpoint_ = std::move(other.endpoint_);
    port_ = other.port_;
    stopping_.store(other.stopping_.load());
    other.port_ = 0;
  }
  return *this;
}

Status Listener::listen(const Endpoint& endpoint, Listener& out, std::uint32_t backlog) {
  if (auto st = initialize(); !st.is_ok()) return st;

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* results = nullptr;
  const std::string port_text = std::to_string(endpoint.port);
  if (::getaddrinfo(endpoint.host.c_str(), port_text.c_str(), &hints, &results) != 0 || results == nullptr) {
    return Status::make(Outcome::Unreachable, Reason::DependencyUnreachable);
  }
  Socket bound;
  Status result = Status::make(Outcome::Unreachable, Reason::DependencyUnreachable);
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    raw_socket handle = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalidSocket) continue;
    Socket socket(from_raw(handle));
    socket.set_reuse_address(true);
    if (::bind(handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) != 0) {
      continue;
    }
    if (::listen(handle, static_cast<int>(backlog)) != 0) {
      continue;
    }
    bound = std::move(socket);
    result = Status::ok();
    break;
  }
  ::freeaddrinfo(results);
  if (!result.is_ok()) return result;

  // Discover the effective port (relevant when the caller asked for port 0).
  sockaddr_in local{};
#ifdef _WIN32
  int local_length = sizeof(local);
#else
  socklen_t local_length = sizeof(local);
#endif
  if (::getsockname(to_raw(bound.handle()), reinterpret_cast<sockaddr*>(&local), &local_length) == 0) {
    out.port_ = ntohs(local.sin_port);
  } else {
    out.port_ = endpoint.port;
  }
  out.endpoint_ = endpoint;
  out.endpoint_.port = out.port_;
  out.socket_ = std::move(bound);
  out.stopping_.store(false);
  return Status::ok();
}

Status Listener::accept(Socket& out) noexcept {
  if (!socket_.valid()) return Status::make(Outcome::Closed, Reason::ConnectionClosed);
  sockaddr_in peer{};
#ifdef _WIN32
  int peer_length = sizeof(peer);
#else
  socklen_t peer_length = sizeof(peer);
#endif
  const raw_socket handle =
      ::accept(to_raw(socket_.handle()), reinterpret_cast<sockaddr*>(&peer), &peer_length);
  if (handle == kInvalidSocket) {
    if (stopping_.load()) return Status::make(Outcome::Closed, Reason::ShutdownInProgress);
    return Status::make(Outcome::Unreachable, Reason::ConnectionClosed,
                        static_cast<std::uint64_t>(last_socket_error()));
  }
  if (stopping_.load()) {
    close_raw(handle);
    return Status::make(Outcome::Closed, Reason::ShutdownInProgress);
  }
  Socket accepted(from_raw(handle));
  accepted.set_nodelay(true);
  out = std::move(accepted);
  return Status::ok();
}

void Listener::stop() noexcept {
  if (!socket_.valid()) return;
  const bool already = stopping_.exchange(true);
  if (already) return;
  // Wake a thread parked in accept(): shut the listener down and connect to it
  // once so that the parked accept() returns immediately. No polling and no
  // timeouts are involved.
  const Endpoint wake = endpoint_;
  shutdown_raw(to_raw(socket_.handle()));
  Socket probe;
  if (connect(wake, probe).is_ok()) {
    probe.close();
  }
  socket_.close();
}

Status connect(const Endpoint& endpoint, Socket& out) noexcept {
  if (auto st = initialize(); !st.is_ok()) return st;
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* results = nullptr;
  const std::string port_text = std::to_string(endpoint.port);
  if (::getaddrinfo(endpoint.host.c_str(), port_text.c_str(), &hints, &results) != 0 || results == nullptr) {
    return Status::make(Outcome::Unreachable, Reason::DependencyUnreachable);
  }
  Status result = Status::make(Outcome::Unreachable, Reason::DependencyUnreachable);
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    raw_socket handle = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalidSocket) continue;
    Socket socket(from_raw(handle));
    if (::connect(handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) != 0) {
      continue;
    }
    socket.set_nodelay(true);
    out = std::move(socket);
    result = Status::ok();
    break;
  }
  ::freeaddrinfo(results);
  return result;
}

}  // namespace sbf::net
