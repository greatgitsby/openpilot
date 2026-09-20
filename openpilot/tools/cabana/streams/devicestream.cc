#include "tools/cabana/streams/devicestream.h"

#include <arpa/inet.h>
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <poll.h>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
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
  if (bridge_fd_ < 0 || type > VISION_STREAM_WIDE_ROAD || camera_type_ == type) return;
  const uint8_t camera = type;
  if (sendControl(&camera, sizeof(camera))) camera_type_ = type;
}

bool DeviceStream::sendJoystick(float gas, float steer, bool cancel) {
  const int8_t command[] = {'J', (int8_t)std::lround(std::clamp(gas, -1.0f, 1.0f) * 100),
                           (int8_t)std::lround(std::clamp(steer, -1.0f, 1.0f) * 100), (int8_t)cancel};
  return sendControl(command, sizeof(command));
}

void DeviceStream::setJoystickMode(bool enabled) {
  const uint8_t command[] = {'M', (uint8_t)enabled};
  sendControl(command, sizeof(command));
}

bool DeviceStream::sendControl(const void *data, size_t size) {
  if (bridge_fd_ < 0) return false;
  int flags = MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif
  if (::send(bridge_fd_, data, size, flags) == (ssize_t)size) return true;
  // Never continue on a partially written control frame.
  ::shutdown(bridge_fd_, SHUT_RDWR);
  joystick_ready = false;
  joystick_status = "Control connection closed. Reconnect to continue.";
  return false;
}

void DeviceStream::stopBridge() {
  if (bridge_fd_ >= 0) {
    ::close(bridge_fd_);
    bridge_fd_ = -1;
  }
  if (bridge_pid <= 0) return;
  ::kill(bridge_pid, SIGTERM);
  for (int i = 0; i < 30; ++i) {
    int status = 0;
    pid_t r = ::waitpid(bridge_pid, &status, WNOHANG);
    if (r == bridge_pid || (r < 0 && errno == ECHILD)) {
      bridge_pid = -1;
      return;
    }
    usleep(100000);
  }
  ::kill(bridge_pid, SIGKILL);
  ::waitpid(bridge_pid, nullptr, 0);
  bridge_pid = -1;
}

void DeviceStream::start() {
  if (remote()) {
    int output[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, output) != 0) {
      error(std::string("Failed to start WebRTC: ") + strerror(errno));
      return;
    }
    const std::string root = (executableDir() / "../../..").lexically_normal().string();
    bridge_pid = ::fork();
    if (bridge_pid == 0) {
      ::close(output[0]);
      ::dup2(output[1], STDOUT_FILENO);
      ::dup2(output[1], STDIN_FILENO);
      ::close(output[1]);
      if (::chdir(root.c_str()) == 0) {
        ::setenv("PWD", root.c_str(), 1);
        execlp("python3", "python3", "-m", "openpilot.tools.cabana.webrtc", dongle_id_.c_str(),
               "--server", camera_server_.c_str(), static_cast<char *>(nullptr));
      }
      _exit(127);
    }
    ::close(output[1]);
    if (bridge_pid < 0) {
      ::close(output[0]);
      error(std::string("Failed to start WebRTC: ") + strerror(errno));
      return;
    }
    bridge_fd_ = output[0];
#ifdef SO_NOSIGPIPE
    int no_sigpipe = 1;
    ::setsockopt(bridge_fd_, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
#endif
    ::fcntl(bridge_fd_, F_SETFD, FD_CLOEXEC);
  }
  LiveStream::start();
}

bool DeviceStream::readPipe(void *data, size_t size) {
  auto *out = static_cast<char *>(data);
  while (size && !exit_) {
    pollfd fd{bridge_fd_, POLLIN, 0};
    int ready = ::poll(&fd, 1, 100);
    if (ready < 0 && errno == EINTR) continue;
    if (ready < 0) return false;
    if (ready == 0) continue;
    ssize_t n = ::read(bridge_fd_, out, size);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    out += n;
    size -= n;
  }
  return size == 0;
}

void DeviceStream::streamThread() {
  if (remote()) {
    std::string failure = "WebRTC helper stopped. Check the terminal and reopen the stream to reconnect.";
    while (!exit_) {
      uint32_t length;
      if (!readPipe(&length, sizeof(length))) break;
      length = ntohl(length);
      if (length < 1 || length > 1024 * 1024 + 1) break;
      char kind;
      if (!readPipe(&kind, 1)) break;
      --length;
      if (kind == 'J' && length >= 1) {
        std::string status(length, '\0');
        if (!readPipe(status.data(), length)) break;
        postToMainThread([this, status]() {
          joystick_ready = status[0] != 0;
          joystick_status = status.substr(1);
        });
        continue;
      }
      if (kind == 'E') {
        failure.resize(length);
        readPipe(failure.data(), length);
        break;
      }
      if (kind != 'C' || length == 0 || length % sizeof(capnp::word)) break;
      auto words = kj::heapArray<capnp::word>(length / sizeof(capnp::word));
      if (!readPipe(words.begin(), length)) break;
      try {
        handleEvent(words.asPtr());
      } catch (const kj::Exception &e) {
        failure = e.getDescription().cStr();
        break;
      }
    }
    if (!exit_) postToMainThread([this, failure]() { joystick_ready = false; joystick_status = failure; error(failure); });
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
