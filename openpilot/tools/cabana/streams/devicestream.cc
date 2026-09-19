#include "tools/cabana/streams/devicestream.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <poll.h>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include "openpilot/cereal/services.h"
#include "tools/cabana/utils/util.h"

DeviceStream::DeviceStream(std::string dongle_id)
    : dongle_id_(std::move(dongle_id)), camera_server_("cabana-webrtc-" + std::to_string(getpid())) {}

DeviceStream::~DeviceStream() {
  stop();
  stopBridge();
}

void DeviceStream::setCamera(VisionStreamType type) {
  if (bridge_fd_ < 0 || type > VISION_STREAM_WIDE_ROAD) return;
  const uint8_t camera = type;
  int flags = MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif
  if (::send(bridge_fd_, &camera, sizeof(camera), flags) < 0) {
    error(std::string("Failed to switch camera: ") + strerror(errno));
  }
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
    if (!exit_) postToMainThread([this, failure]() { error(failure); });
    return;
  }

  unsetenv("ZMQ");
  std::unique_ptr<Context> context(Context::create());
  std::unique_ptr<SubSocket> sock(SubSocket::create(context.get(), "can", "127.0.0.1", false, true, services.at("can").queue_size));
  while (!exit_) {
    std::unique_ptr<Message> msg(sock->receive(true));
    if (!msg) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      continue;
    }
    handleEvent(kj::ArrayPtr<capnp::word>((capnp::word*)msg->getData(), msg->getSize() / sizeof(capnp::word)));
  }
}
