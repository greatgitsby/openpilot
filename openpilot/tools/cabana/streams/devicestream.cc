#include "tools/cabana/streams/devicestream.h"

#include <arpa/inet.h>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cmath>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <poll.h>
#include <thread>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <utility>

#include "openpilot/cereal/services.h"
#include "tools/cabana/utils/util.h"

namespace {
std::atomic<unsigned> next_camera_server{0};
bool isStreamService(const std::string &name) {
  // Video payloads carry no plottable fields.
  return name.size() < 10 || name.compare(name.size() - 10, 10, "EncodeData") != 0;
}
}  // namespace

DeviceStream::DeviceStream(std::string dongle_id)
    : dongle_id_(std::move(dongle_id)), camera_server_("cabana-webrtc-" + std::to_string(getpid()) + "-" + std::to_string(next_camera_server++)) {}

DeviceStream::~DeviceStream() {
  stop();
  stopBridge();
}

void DeviceStream::setCamera(VisionStreamType type) {
  if (bridge_fd_ >= 0 && camera_type_ != type) {
    camera_type_ = type;
    sendControl('V', type, 0);
  }
}

void DeviceStream::sendJoystick(float gas, float steer) {
  auto percent = [](float value) { return (int8_t)std::lround(std::clamp(value, -1.0f, 1.0f) * 100); };
  sendControl('J', percent(gas), percent(steer));
}

void DeviceStream::sendControl(char kind, int8_t a, int8_t b) {
  const char command[] = {kind, (char)a, (char)b};
  if (bridge_fd_ >= 0) (void)!::write(bridge_fd_, command, sizeof(command));
}

void DeviceStream::stopBridge() {
  if (bridge_fd_ >= 0) ::close(bridge_fd_);
  bridge_fd_ = -1;
  if (bridge_pid <= 0) return;
  ::kill(bridge_pid, SIGTERM);
  // Reap off the UI thread: the helper closes its connection before exiting.
  std::thread([pid = bridge_pid]() {
    for (int i = 0; i < 30; ++i) {
      if (::waitpid(pid, nullptr, WNOHANG) != 0) return;
      usleep(100000);
    }
    ::kill(pid, SIGKILL);
    ::waitpid(pid, nullptr, 0);
  }).detach();
  bridge_pid = -1;
}

void DeviceStream::start() {
  if (remote()) {
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
      error(std::string("Failed to start WebRTC: ") + strerror(errno));
      return;
    }
    for (int fd : fds) ::fcntl(fd, F_SETFD, FD_CLOEXEC);  // dup2 gives the helper inheritable copies
    const std::string root = (executableDir() / "../../..").lexically_normal().string();
    bridge_pid = ::fork();
    if (bridge_pid == 0) {
      ::dup2(fds[1], STDIN_FILENO);
      ::dup2(fds[1], STDOUT_FILENO);
      if (::chdir(root.c_str()) == 0) {
        execlp("python3", "python3", "-m", "openpilot.tools.cabana.webrtc", dongle_id_.c_str(),
               "--server", camera_server_.c_str(), static_cast<char *>(nullptr));
      }
      _exit(127);
    }
    ::close(fds[1]);
    if (bridge_pid < 0) {
      ::close(fds[0]);
      error(std::string("Failed to start WebRTC: ") + strerror(errno));
      return;
    }
    bridge_fd_ = fds[0];
    ::fcntl(bridge_fd_, F_SETFL, O_NONBLOCK);
    std::signal(SIGPIPE, SIG_IGN);  // writes to an exited helper fail instead
  }
  LiveStream::start();
}

bool DeviceStream::readBridge(void *data, size_t size) {
  auto *out = static_cast<char *>(data);
  while (size > 0 && !exit_) {
    pollfd fd = {bridge_fd_, POLLIN, 0};
    if (::poll(&fd, 1, 100) <= 0) continue;
    ssize_t n = ::read(bridge_fd_, out, size);
    if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN)) return false;
    if (n > 0) {
      out += n;
      size -= n;
    }
  }
  return size == 0;
}

void DeviceStream::streamThread() {
  if (remote()) {
    // Packets from openpilot/tools/cabana/webrtc.py: size (including kind), kind, payload
    std::string failure = "WebRTC helper stopped. Check the terminal and reopen the stream to reconnect.";
    uint32_t size;
    char kind;
    while (readBridge(&size, sizeof(size)) && readBridge(&kind, 1)) {
      size = ntohl(size) - 1;
      if (kind == 'E' && size < 4096) {
        failure.resize(size);
        readBridge(failure.data(), size);
        break;
      }
      if (kind != 'C' || size == 0 || size % sizeof(capnp::word) || size > (1 << 20)) break;
      auto words = kj::heapArray<capnp::word>(size / sizeof(capnp::word));
      if (!readBridge(words.begin(), size)) break;
      try {
        handleEvent(words.asPtr());
      } catch (const kj::Exception &e) {
        failure = e.getDescription().cStr();
        break;
      }
    }
    if (!exit_) {
      ::shutdown(bridge_fd_, SHUT_RDWR);  // the helper exits once its connection closes
      postToMainThread([this, failure]() { error(failure); });
    }
    return;
  }

  std::unique_ptr<Context> context(Context::create());
  std::unique_ptr<Poller> poller(Poller::create());
  std::vector<std::unique_ptr<SubSocket>> sockets;
  for (const auto &[name, service] : services) {
    if (!isStreamService(name)) continue;
    auto socket = std::unique_ptr<SubSocket>(SubSocket::create(context.get(), name,
      "127.0.0.1", false, true, service.queue_size));
    if (!socket) continue;
    poller->registerSocket(socket.get());
    sockets.push_back(std::move(socket));
  }
  while (!exit_) {
    for (auto *socket : poller->poll(50)) {
      std::unique_ptr<Message> msg(socket->receive(true));
      if (msg) handleEvent(kj::ArrayPtr<capnp::word>((capnp::word*)msg->getData(), msg->getSize() / sizeof(capnp::word)));
    }
  }
}
