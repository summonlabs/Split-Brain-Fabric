#pragma once

// Real operating-system process control, used by the multiprocess proofs.
//
// Windows: CreateProcessW + TerminateProcess for an unblockable hard kill.
// POSIX:   posix_spawn + kill(SIGKILL).
//
// No shell is involved, so argument quoting is exact and a killed process cannot
// run cleanup code - which is the point of the crash proofs.

#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace sbf::test {

class Process {
 public:
  Process() = default;
  ~Process() { kill(); }
  Process(const Process&) = delete;
  Process& operator=(const Process&) = delete;

  Process(Process&& other) noexcept { *this = std::move(other); }

  Process& operator=(Process&& other) noexcept {
#ifdef _WIN32
    if (running()) kill();
    process_ = other.process_;
    other.process_ = nullptr;
#else
    if (running()) kill();
    pid_ = other.pid_;
    other.pid_ = -1;
#endif
    return *this;
  }

  // True once the child has exited, without blocking.
  bool exited() const {
#ifdef _WIN32
    if (process_ == nullptr) return true;
    return WaitForSingleObject(process_, 0) == WAIT_OBJECT_0;
#else
    if (pid_ <= 0) return true;
    int status = 0;
    const pid_t result = ::waitpid(pid_, &status, WNOHANG);
    return result == pid_;
#endif
  }

  // Starts the process. When output_path is non-empty the child's stdout and
  // stderr are redirected there so that a run can be inspected even after a
  // hard kill.
  bool start(const std::string& executable, const std::vector<std::string>& arguments,
             const std::string& output_path = {}) {
#ifdef _WIN32
    std::string command_line = quote(executable);
    for (const auto& argument : arguments) {
      command_line.push_back(' ');
      command_line.append(quote(argument));
    }
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    HANDLE output = nullptr;
    if (!output_path.empty()) {
      SECURITY_ATTRIBUTES attributes{};
      attributes.nLength = sizeof(attributes);
      attributes.bInheritHandle = TRUE;
      output = CreateFileA(output_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (output == INVALID_HANDLE_VALUE) return false;
      startup.dwFlags |= STARTF_USESTDHANDLES;
      startup.hStdOutput = output;
      startup.hStdError = output;
      startup.hStdInput = nullptr;
    }
    PROCESS_INFORMATION info{};
    std::vector<char> mutable_line(command_line.begin(), command_line.end());
    mutable_line.push_back('\0');
    const BOOL ok = CreateProcessA(nullptr, mutable_line.data(), nullptr, nullptr,
                                   output != nullptr ? TRUE : FALSE, CREATE_NO_WINDOW, nullptr,
                                   nullptr, &startup, &info);
    if (output != nullptr) CloseHandle(output);
    if (!ok) return false;
    CloseHandle(info.hThread);
    process_ = info.hProcess;
    return true;
#else
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(executable.c_str()));
    for (const auto& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
    argv.push_back(nullptr);
    pid_t pid = -1;
    if (posix_spawn(&pid, executable.c_str(), nullptr, nullptr, argv.data(), environ) != 0) {
      return false;
    }
    pid_ = pid;
    return true;
#endif
  }

  bool running() const {
#ifdef _WIN32
    return process_ != nullptr;
#else
    return pid_ > 0;
#endif
  }

  // Hard kill: no signal handler runs, nothing is flushed, no destructor.
  void kill() {
#ifdef _WIN32
    if (process_ != nullptr) {
      TerminateProcess(process_, 137);
      WaitForSingleObject(process_, INFINITE);
      CloseHandle(process_);
      process_ = nullptr;
    }
#else
    if (pid_ > 0) {
      ::kill(pid_, SIGKILL);
      int status = 0;
      ::waitpid(pid_, &status, 0);
      pid_ = -1;
    }
#endif
  }

  // Waits for a natural exit and returns the exit code.
  int wait() {
#ifdef _WIN32
    if (process_ == nullptr) return -1;
    WaitForSingleObject(process_, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(process_, &code);
    CloseHandle(process_);
    process_ = nullptr;
    return static_cast<int>(code);
#else
    if (pid_ <= 0) return -1;
    int status = 0;
    ::waitpid(pid_, &status, 0);
    pid_ = -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
#endif
  }

  std::uint64_t pid() const {
#ifdef _WIN32
    return process_ == nullptr ? 0 : static_cast<std::uint64_t>(GetProcessId(process_));
#else
    return pid_ <= 0 ? 0 : static_cast<std::uint64_t>(pid_);
#endif
  }

 private:
  static std::string quote(const std::string& value) {
    std::string out = "\"";
    for (const char c : value) {
      if (c == '"') out.push_back('\\');
      out.push_back(c);
    }
    out.push_back('"');
    return out;
  }

#ifdef _WIN32
  void* process_ = nullptr;
#else
  int pid_ = -1;
#endif
};

}  // namespace sbf::test
