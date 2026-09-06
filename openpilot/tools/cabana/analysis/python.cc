#include "tools/cabana/analysis/python.h"
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>
#include <sys/wait.h>
#include <unistd.h>
#include "common/util.h"

namespace cabana::analysis {
json11::Json pythonTask(const std::string &script, const json11::Json &request, double timeout_seconds) {
  char directory[] = "/tmp/cabana-analysis-XXXXXX";
  if (!mkdtemp(directory)) throw std::runtime_error("Cannot create analysis temporary directory");
  struct Cleanup { std::string directory; ~Cleanup() { std::error_code error; std::filesystem::remove_all(directory, error); } } cleanup{directory};
  std::string input = std::string(directory) + "/request.json", output = std::string(directory) + "/result.json";
  std::ofstream file(input); file << request.dump(); file.close();
  if (!file) throw std::runtime_error("Cannot write analysis request");
  pid_t child = fork();
  if (child < 0) throw std::runtime_error("Cannot start Python evaluator");
  if (child == 0) {
    setpgid(0, 0);
    execlp("python3", "python3", script.c_str(), input.c_str(), output.c_str(), static_cast<char *>(nullptr));
    _exit(127);
  }
  setpgid(child, child);
  auto deadline = std::chrono::steady_clock::now() + std::chrono::duration<double>(timeout_seconds);
  int status = 0;
  for (;;) {
    pid_t result = waitpid(child, &status, WNOHANG);
    if (result == child) break;
    if (result < 0) { if (errno == EINTR) continue; throw std::runtime_error("Cannot wait for Python evaluator"); }
    if (std::chrono::steady_clock::now() >= deadline) {
      kill(-child, SIGKILL); while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
      throw std::runtime_error("Python evaluation exceeded its time limit");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) throw std::runtime_error("Python helper exited unsuccessfully");
  std::string error;
  auto result = json11::Json::parse(util::read_file(output), error);
  if (!error.empty()) throw std::runtime_error("Invalid Python output: " + error);
  if (result["error"].is_string()) throw std::runtime_error(result["error"].string_value());
  return result;
}
}
