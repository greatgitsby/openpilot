# Vendored Qualcomm Spectra camera UAPI headers (camera_kt v1.0.3)

The `media/cam_*.h` headers here are the Qualcomm camera driver (Spectra) UAPI
headers that camerad's Spectra call sites (`system/camerad/cameras/spectra.cc`,
`camera_qcom2.cc`, the sensor drivers, etc.) compile against on the vamOS
mainline 6.18 kernel.

## Source

- Upstream: `qualcomm-linux/camera-driver` (camera_kt), tag/version **v1.0.3**
- Commit: **56b463c**
- Path in that tree: `camera_kt/include/uapi/camera/media/`

They were copied verbatim (17 headers: `cam_cpas.h`, `cam_custom.h`,
`cam_defs.h`, `cam_fd.h`, `cam_icp.h`, `cam_isp.h`, `cam_isp_ife.h`,
`cam_isp_sfe.h`, `cam_isp_tfe.h`, `cam_isp_vfe.h`, `cam_jpeg.h`, `cam_lrme.h`,
`cam_ope.h`, `cam_req_mgr.h`, `cam_sensor.h`, `cam_sync.h`, `cam_tfe.h`).

## Why vendored (stopgap)

The vamOS mainline kernel build does **not** yet install the Qualcomm camera UAPI
headers to `/usr/include`, so `#include "media/cam_req_mgr.h"` would otherwise
either fail to resolve or pick up the stale AGNOS 4.9 layout. To get a coherent
build on the comma four today, `system/camerad/SConscript` prepends this
directory to `CPPPATH` (via `PrependUnique`) so all camerad objects see the
v1.0.3 layout that the migrated call sites target.

This is a **stopgap**. Once the vamOS kernel build installs the camera_kt v1.0.3
headers to `/usr` (the normal `make headers_install` / techpack path), drop this
`CPPPATH` prepend and delete this directory so we track the on-device headers
directly.
