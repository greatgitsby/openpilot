#pragma once

// Compile-time guard for the Qualcomm Spectra (camera_kt) UAPI that camerad is
// built against. camerad and the kernel driver must agree on one exact UAPI
// snapshot; these static_asserts fail the build if camerad is accidentally
// compiled against the old AGNOS cam_*.h layout instead of the recent
// camera_kt UAPI. See the vamOS spectra migration plan (lane OUAPI / O2.1).

#include <cstddef>

#include "media/cam_defs.h"
#include "media/cam_sensor.h"

// Opcode drift: recent camera_kt added CAM_QUERY_CAP_V2, bumping OPCODE_MAX,
// which in turn shifts CAM_SENSOR_PROBE_CMD.
static_assert(CAM_COMMON_OPCODE_MAX == CAM_COMMON_OPCODE_BASE + 0xa,
              "unexpected CAM_COMMON_OPCODE_MAX: not the recent camera_kt UAPI");
static_assert(CAM_SENSOR_PROBE_CMD == CAM_COMMON_OPCODE_MAX + 1,
              "unexpected CAM_SENSOR_PROBE_CMD: not the recent camera_kt UAPI");

// Struct-size drift on the sensor power/probe and CSIPHY paths.
static_assert(sizeof(struct cam_cmd_i2c_info) == 8,
              "unexpected sizeof(cam_cmd_i2c_info): not the recent camera_kt UAPI");
static_assert(sizeof(struct i2c_rdwr_header) == 8,
              "unexpected sizeof(i2c_rdwr_header): not the recent camera_kt UAPI");
static_assert(sizeof(struct cam_cmd_unconditional_wait) == 8,
              "unexpected sizeof(cam_cmd_unconditional_wait): not the recent camera_kt UAPI");
static_assert(sizeof(struct cam_csiphy_info) == 24,
              "unexpected sizeof(cam_csiphy_info): not the recent camera_kt UAPI");

// Short UAPI identifier for startup logs, so a header/driver mismatch is
// obvious in device logs.
#define SPECTRA_UAPI_VERSION "camera_kt v1.0.3 (56b463c)"

static inline const char *spectra_uapi_version() {
  return SPECTRA_UAPI_VERSION;
}
