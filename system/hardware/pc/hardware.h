#pragma once

#include <string>
#include <vector>
#include <unistd.h>

#include "system/hardware/base.h"

class HardwarePC : public HardwareNone {
private:
  static bool first_profile_active;

public:
  static std::string get_os_version() { return "openpilot for PC"; }
  static std::string get_name() { return "pc"; }
  static cereal::InitData::DeviceType get_device_type() { return cereal::InitData::DeviceType::PC; }
  static bool PC() { return true; }
  static bool TICI() { return util::getenv("TICI", 0) == 1; }
  static bool AGNOS() { return util::getenv("TICI", 0) == 1; }

  static std::vector<ESIMProfile> get_esim_profiles() {
    std::vector<ESIMProfile> profiles;
    ESIMProfile profile1;
    profile1.iccid = "89012345678901234567";
    profile1.profileNickname = "Test Profile 1";
    profile1.enabled = first_profile_active;
    profile1.profileState = first_profile_active ? "enabled" : "disabled";
    profiles.push_back(profile1);

    ESIMProfile profile2;
    profile2.iccid = "89012345678901234568";
    profile2.profileNickname = "Test Profile 2";
    profile2.enabled = !first_profile_active;
    profile2.profileState = !first_profile_active ? "enabled" : "disabled";
    profiles.push_back(profile2);

    return profiles;
  }

  static void switch_esim_profile(const std::string& iccid) {
    sleep(1);  // Simulate switching delay
    first_profile_active = !first_profile_active;  // Toggle active profile
  }
};

// Initialize static member
bool HardwarePC::first_profile_active = true;
