#pragma once

// Internal: shared connection registry used by the registry and witness
// services.
//
// Threading contract (documented in docs/OWNERSHIP_AUDIT.md):
//   * one thread per accepted connection, owning its socket and frame decoder;
//   * service state is guarded by a single mutex held only for the duration of a
//     state transition - never across a socket write and never across a
//     callback;
//   * shutdown sets a flag, shuts every live socket down (which unblocks the
//     blocked recv in the peer thread), then waits for the active count to reach
//     zero on a condition variable. No sleeps, no polling, no timeouts.

#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <vector>

#include "sbf/net.hpp"

namespace sbf::internal {

struct LiveConnection {
  std::shared_ptr<net::Socket> socket;
};

class ConnectionHub {
 public:
  // Registers a connection. The registration and the stopping check happen under
  // the same lock, so a connection can never slip in after begin_stop() has taken
  // its snapshot: it is either in the snapshot or it observes stopping_ and is
  // shut down immediately. Without this the peer thread would park forever in a
  // blocking read on a socket nobody will ever close.
  void add(const std::shared_ptr<net::Socket>& socket) {
    bool stopping = false;
    {
      std::lock_guard<std::mutex> guard(mutex_);
      ++active_;
      live_.push_back(LiveConnection{socket});
      stopping = stopping_;
    }
    if (stopping && socket) socket->shutdown();
  }

  void remove(const std::shared_ptr<net::Socket>& socket) {
    std::lock_guard<std::mutex> guard(mutex_);
    for (auto it = live_.begin(); it != live_.end(); ++it) {
      if (it->socket.get() == socket.get()) {
        live_.erase(it);
        break;
      }
    }
    if (active_ > 0) --active_;
    if (active_ == 0) drained_.notify_all();
  }

  bool stopping() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return stopping_;
  }

  // Marks the hub as stopping and shuts every live socket down so that blocked
  // reads return immediately.
  void begin_stop() {
    std::vector<std::shared_ptr<net::Socket>> victims;
    {
      std::lock_guard<std::mutex> guard(mutex_);
      if (stopping_) return;
      stopping_ = true;
      for (auto& entry : live_) victims.push_back(entry.socket);
    }
    for (auto& socket : victims) {
      if (socket) socket->shutdown();
    }
  }

  // Waits until every connection thread has deregistered. Called without any
  // other lock held.
  void wait_drained() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (active_ != 0) {
      drained_.wait(lock);
    }
    live_.clear();
  }

  std::size_t active() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return active_;
  }

 private:
  mutable std::mutex mutex_;
  std::condition_variable drained_;
  std::vector<LiveConnection> live_;
  std::size_t active_ = 0;
  bool stopping_ = false;
};

}  // namespace sbf::internal
