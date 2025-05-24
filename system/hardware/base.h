#pragma once

#include <cstdlib>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "cereal/gen/cpp/log.capnp.h"
#include "common/util.h"
#include "third_party/json11/json11.hpp"

struct ESIMProfile {
  std::string iccid;
  std::string isdpAid;
  std::string profileState;
  std::string profileNickname;
  std::string serviceProviderName;
  std::string profileName;
  std::string profileClass;
  bool enabled;

  ESIMProfile() = default;
  explicit ESIMProfile(const json11::Json& j) {
    iccid = j["iccid"].string_value();
    isdpAid = j["isdpAid"].string_value();
    profileState = j["profileState"].string_value();
    profileNickname = j["profileNickname"].string_value();
    serviceProviderName = j["serviceProviderName"].string_value();
    profileName = j["profileName"].string_value();
    profileClass = j["profileClass"].string_value();
    enabled = profileState == "enabled";
  }
};

// no-op base hw class
class HardwareNone {
public:
  static constexpr float MAX_VOLUME = 0.7;
  static constexpr float MIN_VOLUME = 0.2;

  static std::string get_os_version() { return ""; }
  static std::string get_name() { return ""; }
  static cereal::InitData::DeviceType get_device_type() { return cereal::InitData::DeviceType::UNKNOWN; }
  static int get_voltage() { return 0; }
  static int get_current() { return 0; }

  static std::string get_serial() { return "cccccc"; }

  static std::map<std::string, std::string> get_init_logs() {
    return {};
  }

  static void reboot() {}
  static void poweroff() {}
  static void set_brightness(int percent) {}
  static void set_ir_power(int percentage) {}
  static void set_display_power(bool on) {}

  static bool get_ssh_enabled() { return false; }
  static void set_ssh_enabled(bool enabled) {}

  static bool PC() { return false; }
  static bool TICI() { return false; }
  static bool AGNOS() { return false; }

  static std::vector<ESIMProfile> get_esim_profiles() { return {}; }
  static void switch_esim_profile(const std::string& iccid) {}
};
