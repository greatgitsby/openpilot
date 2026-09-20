# Cabana

Cabana visualizes openpilot messages and raw CAN data. One use for this is creating and editing [CAN Dictionaries](http://socialledge.com/sjsu/index.php/DBC_Format) (DBC files), and the tool provides direct integration with [commaai/opendbc](https://github.com/commaai/opendbc) (a collection of DBC files), allowing you to load the DBC files direct from source, and save to your fork. In addition, you can load routes from [comma connect](https://connect.comma.ai).

## Usage Instructions

```bash
$ ./cabana -h
Usage: ./cabana [options] [route]

  route                     the drive to replay. find your drives at connect.comma.ai

Options:
  --help                    show this help
  --demo                    use a demo route instead of providing your own
  --auto                    Auto load the route from the best available source (no video):
                            internal, openpilotci, comma_api, car_segments, testing_closet
  --qcam                    load qcamera
  --wide-road               load wide road camera (alias: --ecam)
  --cabin                   load cabin camera (alias: --dcam)
  --layout [LAYOUT]         open a Cabana JSON layout file
  --stream                  read openpilot messages from local msgq (alias: --msgq)
  --msgq                    read openpilot messages from local msgq
  --panda                   read can messages from panda
  --panda-serial <serial>   read can messages from panda with given serial
  --socketcan <device>      read can messages from given SocketCAN device
  --webrtc <dongle-id>      live CAN and switchable camera video over Athena/WebRTC
  --data_dir <dir>          local directory with routes
  --no-vipc                 do not output video
  --no-cache                turn off the local route file cache
  --dbc <file>              dbc file to open
```

## Examples

### Running Cabana in Demo Mode
To run Cabana using a built-in demo route, use the following command:

```shell
cabana --demo
```

### Loading a Specific Route

To load a specific route for replay, provide the route as an argument:

```shell
cabana "5beb9b58bd12b691/0000010a--a51155e496"
```

Replace "5beb9b58bd12b691/0000010a--a51155e496" with your desired route identifier.


### Running Cabana with multiple cameras
To run Cabana with multiple cameras, use the following command:

```shell
cabana "5beb9b58bd12b691/0000010a--a51155e496" --cabin --wide-road
```

### Streaming openpilot Messages from a comma Device

Install this branch on the comma device and restart openpilot so manager and Athena
pick up the streaming changes. On the computer, activate the openpilot Python
environment (including the submodule and tools dependencies), then run from the
repository root:

```shell
python -m openpilot.tools.lib.auth
scons -j8 openpilot/tools/cabana/cabana
openpilot/tools/cabana/cabana --webrtc <dongle-id>
```

Use the 16-character device ID from comma Connect. You can also select
**Device > Athena** in the stream selector. Remote ZMQ (`--zmq`) has
been replaced; `--msgq` still reads local openpilot messages.

The connection carries raw CAN and video from Road, Driver, or Wide Road.
Choose the camera through the workspace’s Add widget menu. A remote source has
one camera pane; choosing another camera replaces that pane and keeps the same
connection without interrupting CAN. It is available onroad and
offroad, survives ignition changes, and has no five-minute session limit.
Camera processes start on demand offroad; the WebRTC daemon is always available
and the streaming encoder runs onroad. See the
[libdatachannel workarounds](../../system/webrtc/patches/README.md) for the
required native binding patches on both the computer and device. Only one viewer is supported: a new
connection replaces an existing viewer, including comma Connect.

Video always shows the live camera, even when CAN playback is paused or rewound.
Only remote CAN is recorded. Reopen the stream after a network disconnect.

While streaming from the device, Cabana will log the received messages to a local directory. By default, this directory is ~/cabana_live_stream/. You can change the log directory in Cabana by navigating to menu -> tools -> settings.

After disconnecting from the device, you can replay the logged messages from the stream selector dialog -> browse local route.

### Joystick controls over WebRTC

The Joystick dock appears beside the source inspectors. Drag its title bar to move or float it;
use View → Joystick to reopen it. Its position and visibility are saved.

For a car, enable **Device joystick mode** while offroad, then start the car.
Comma body uses its existing joystick mode. Select **Arm controls** in the dock,
then hold **W/S** for gas/brake and **A/D** for left/right steering, or drag the
mouse pad. Keyboard output is ±1.0 and the mouse pad ranges up to ±1.0, with a 0.20 minimum
for a displaced axis, matching Connect. The output limit defaults to 100%. Releasing the keys or mouse centers
the controls; Escape, focus loss, or hiding the dock disarms them. Arming is
never saved across sessions. Commands use Connect's `testJoystick` protocol at
20 Hz. The device must run the accompanying Athena and webrtcd changes.

### Streaming CAN Messages from Panda

To read CAN messages from a connected Panda, use the following command:

```shell
cabana --panda
```

### Using the Stream Selector Dialog

If you run Cabana without any arguments, a stream selector dialog will pop up, allowing you to choose the stream.

```shell
cabana
```

## Plotting and analysis

Cabana includes [openpilot analysis layouts](layouts), including
`tuning`, `longitudinal`, `torque`, and camera/debug presets. From this directory, try:

```shell
./cabana --demo --layout layouts/tuning.json
./cabana "5beb9b58bd12b691/0000010a--a51155e496" --layout layouts/tuning.json
./cabana --stream --layout layouts/longitudinal.json       # local replay or running openpilot
./cabana --webrtc <dongle-id> --layout layouts/CAN-bus-debug.json  # remote CAN and camera
```

`--layout` takes a file path relative to the directory where you run the command,
or an absolute path. Omitting its value leaves the saved session layout unchanged.

### Widgets and sources

Each chart, camera, CAN browser, openpilot browser, and CAN inspector is its own native
workspace tab. Drag a tab to dock it beside another widget, stack tabs, or float it in a
separate window. **Add widget** creates charts or opens a browser, inspector, or available
camera for the selected source. **View → Arrange widgets** restores an automatic arrangement.
The Default preset starts with message browsers, an empty chart, and an available camera.

Use **Sources → Add route or live source...** to open additional sources without replacing
existing ones. Select or rename a source in **Sources**. Browsers and CAN definitions belong
to their source; chart series retain their source assignment, so one chart can compare routes.
A saved source without a route can be assigned one through **Choose route for this source...**.

Open road and driver cameras as separate widgets to see both at once. Each camera has its
own **Fit/Fill** overlay: Fit shows the entire frame; Fill crops the edges to fill the widget.
The overlay stays at 34% opacity until hovered.

### Timeline

The bottom timeline shows a labeled track, ruler, filmstrip, and playhead for each source.
Click or drag a filmstrip to seek with preview frames. Select a track to control its playback;
**Space** plays or pauses, and **Left/Right** step to the previous or next camera frame.
The toolbar also provides frame stepping and playback speed. **View → Timeline** toggles
its visibility independently of camera widgets.

Check **Link** on routes to play and seek them together. Position each route at a matching
event, then choose **Timeline → Align current positions**, or edit each track's offset.
Workspace time equals route time plus that offset. The Timeline menu can loop the next ten
seconds or a start/end interval in workspace seconds. A playing linked group keeps its
alignment and loop while you select an independent source. Live sources offer **Go live**.

### Plotting signals

Browse openpilot messages as a tree of fields and array indices. Search for paths such as
`/carState/vEgo`, `/carControl/actuators/accel`, or `/modelV2/position/x/0`.
Double-click a numeric field to create a chart, or drag it onto an existing chart to overlay
series. openpilot fields do not require a DBC. For decoded CAN, load the source's DBC and
use **Manage Signals** in a chart's menu, or add a signal from the CAN inspector.

- Click a chart to seek; drag to zoom the shared time range.
- Shift-drag scrubs playback; Ctrl-drag pans; Ctrl-wheel zooms around the pointer
  (Cmd instead of Ctrl on macOS).
- Use **Fit loaded data** or **Follow playback** in a chart's menu to reset its time range.
- Click a legend entry to hide or show a series. Its context menu provides transforms and statistics.
- **Split Chart** separates overlaid series into individual chart widgets.

Transforms include scale/offset, derivative, trapezoidal integral, and moving average.
Statistics report sample count, minimum, maximum, and mean over the visible time range.
These operations affect plotted values only. **Export CSV...** in a chart's menu exports
visible series at their original timestamps, including calculated and transformed values.

### Workspaces, layouts, and functions

Use **Workspace: Default** to select, rename, duplicate, or create a blank workspace.
**Presets** creates named workspaces from Default, Live, or the bundled analysis layouts.
Live starts with message browsers, a CAN inspector, and a chart. A workspace remembers
widget arrangement, charts, equations, source assignments, camera settings, and timeline
links, offsets, loop settings, and each source’s CAN inspector tabs. Changes are saved when switching or exiting;
**Save workspaces** saves immediately. The first workspace cannot be deleted.

**Open workspace...** imports a workspace JSON file; **Save As...** exports one.
Enable **Include route references** to save route identifiers, local data directories,
and DBC file references. **Open saved routes** loads those sources explicitly; selecting
a workspace or starting Cabana does not open saved routes automatically. Workspaces
do not embed logs, video, or DBC contents; referenced files must remain accessible.
Without route references, a workspace can be reused with other routes.

`--layout` loads a chart layout, including signals, equations, titles, colors, limits,
and transforms. Older layouts are accepted, with their charts becoming individual widgets.
Missing openpilot fields show **No data** until samples arrive; decoded CAN needs the
matching DBC. Use workspace export to preserve the complete arrangement.

A chart's **Functions → New Function...** opens the Python function editor. Select a
primary signal and enter a body such as `return value * 2.23694` for speed in mph.
Additional inputs are available as `v1`, `v2`, and so on; Global code can define constants
or initial state. Saved functions appear in the signal browser and Functions menu.
Editing a function recalculates its plots and dependent functions.

### Local UX fixture

Generate two deterministic 15-second routes with CAN, speed signals, and labeled road/driver
videos for testing source selection, overlays, cameras, linked playback, and looping:

```shell
python -m openpilot.tools.cabana.tests.generate_ux_fixture /tmp/cabana-ux
```

Run this from the repository root with the openpilot Python environment and `ffmpeg`
(with libx265 and drawtext) installed. Import the generated `workspace.json` through the
workspace menu, then select **Open saved routes**. The directory also contains a reusable
`layout.json` and `fixture.dbc`. Rerunning replaces the generated fixture files.

Add `--routes 3` to check that a linked pair continues looping while an independent third
route is selected. The fixture includes two CAN messages per route for checking separate
inspector selections, plus engagement and alert intervals for the timeline ribbons.

## Additional Information

For more information, see the [openpilot wiki](https://github.com/commaai/openpilot/wiki/Cabana)
