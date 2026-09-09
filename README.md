# eSIM download UI screenshot suite

PR: https://github.com/commaai/openpilot/pull/38813
Source commit: 1d4f2da5c1a6035f91869708ee0f26a87aab8fd2

27 screenshots at native mici resolution (536 × 240), plus 3 animated GIFs.
Rendered from the production widgets using demo profile data, mocked modem operations, and a synthetic camera surface. These are UI previews, not evidence of a real carrier download or device camera quality. No live activation codes or personal camera captures are included. The swipe-to-add experiment is excluded.

Coverage: active profiles, add profile, busy/disabled state, camera startup, hold prompt, invalid LPA feedback and timed reset, optional nickname empty/filled, installation dots, inactive profile actions, activation/move-to-top, rename, delete confirmation, no internet, download failure, timeout, and empty profile list.

The activation GIF invokes the same `_on_profile_clicked` handler used after download; modem activation is mocked. Error examples are injected through `_on_error`. Scanner feedback is driven through the completed QR result handler.

To regenerate, check out the source commit with dependencies/assets available and run `OFFSCREEN=1 xvfb-run -a python /path/to/capture.py` from that checkout. The script mocks device state and camera input, and performs no real eSIM operations.

The connectivity-check screenshot and offline alert now run through `_on_add_profile`, with mocked online/offline HTTP results. The offline path is verified to create an error dialog rather than a scanner.
