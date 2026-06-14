#pragma once

// Discovery of Qualcomm camera /dev/videoN nodes by sysfs name, rather than
// fragile /dev/v4l/by-path strings that can differ between the AGNOS kernel and
// the vamOS mainline + recent camera_kt driver. See the vamOS spectra migration
// plan (lane ONODES / O3.1, O3.2).

#include <fcntl.h>

// Open a /dev/videoN device whose /sys/class/video4linux/videoN/name starts
// with `name`. On match-miss, falls back to opening `by_path_fallback` (the
// legacy /dev/v4l/by-path string) if non-null. On total failure, logs every
// discovered video node + name and returns -1.
int open_v4l_video_by_name(const char *name, const char *by_path_fallback = nullptr,
                           int flags = O_RDWR | O_NONBLOCK);
