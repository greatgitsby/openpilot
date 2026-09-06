# Cabana

Cabana is a tool for investigating routes, plotting cereal and CAN signals, and editing CAN dictionaries. One use for this is creating and editing [CAN Dictionaries](http://socialledge.com/sjsu/index.php/DBC_Format) (DBC files), and the tool provides direct integration with [commaai/opendbc](https://github.com/commaai/opendbc) (a collection of DBC files), allowing you to load the DBC files direct from source, and save to your fork. In addition, you can load routes from [comma connect](https://connect.comma.ai).

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
  --msgq                    read can messages from the msgq
  --panda                   read can messages from panda
  --panda-serial <serial>   read can messages from panda with given serial
  --socketcan <device>      read can messages from given SocketCAN device
  --zmq <ip-address>        read can messages from zmq at the specified ip-address
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

### Streaming CAN Messages from a comma Device

[SSH into your device](https://github.com/commaai/openpilot/wiki/SSH) and start the bridge with the following command:

```shell
cd /data/openpilot
./openpilot/cereal/messaging/bridge &
```

Then Run Cabana with the device's IP address:

```shell
cabana --zmq <ipaddress>
```

Replace &lt;ipaddress&gt; with your comma device's IP address.

While streaming from the device, Cabana will log the CAN messages to a local directory. By default, this directory is ~/cabana_live_stream/. You can change the log directory in Cabana by navigating to menu -> tools -> settings.

After disconnecting from the device, you can replay the logged CAN messages from the stream selector dialog -> browse local route.

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

## Additional Information

For more information, see the [openpilot wiki](https://github.com/commaai/openpilot/wiki/Cabana)

## Analysis workspace

Open **Analysis → Analysis workspace**, or launch with `--analysis`. CAN inspection and DBC editing remain available through the same window. Both workspaces use the same route, playback clock, and DBCs.

```sh
./cabana --analysis --demo
./cabana /path/to/rlog.zst --layout longitudinal
./cabana 'dongle_id/route_id/0:2/q' --analysis
./cabana --stream --buffer-seconds 60
./cabana --stream --address 192.168.43.1
./cabana /path/to/rlog --layout /path/to/layout.json --output /tmp/analysis.png
```

`--data-dir` and `--data_dir` select a directory of local route segments. Route suffixes `/q`, `/r`, and `/a` choose qlogs, rlogs, or automatic fallback. Direct log files can also be selected in the stream dialog. Remote streaming uses the cereal bridge on the device, as described above.

Search the signal sidebar, then double-click a signal to plot it. Ctrl-click selects multiple signals; drag them into a plot, or choose **Pane → Add selected signals**. The sidebar displays numeric or enum values at the playback cursor. Missing channels remain in layouts so they can resolve when additional data arrives. Deprecated fields are hidden by default.

Use the timeline, Play/Pause, speed and step controls to navigate. Ctrl-click a plot or drag its cursor to seek. Plots share their time range; wheel zoom and pan affect the shared viewport. **Time range** edits exact bounds, **Reset view** fits loaded data, and **Loop** repeats the selected interval. **Follow** tracks the current time during playback or streaming.

The **Pane** menu splits panes, adds plots/maps/logs/thumbnails/cameras, edits axis limits and curve styles, and removes panes. Curve settings include labels, color, visibility, scale/offset and first derivative with actual or fixed sample spacing. Use `+` to add a tab; a tab's context menu renames, reorders, duplicates or closes it.

**Custom series** evaluates Python with NumPy. `time` and `value` are the input arrays; additional channels become `v1`, `v2`, etc., aligned using their last sample at or before each input timestamp. `t(path)` and `v(path)` access named arrays. Return values, a scalar, or `(times, values)`. Preview shows the result before applying. Evaluation runs in a separate process with a 15-second timeout; errors appear in the workspace. Saved custom series recompute when data changes.

Log panes support text/source search, severity selection, route/boot/wall timestamps, context tooltips and click-to-seek. GPS panes support pan, zoom, follow and click-to-seek; **Streets** adds an optional cached OpenStreetMap road layer. Thumbnail and independently decoded road, wide-road, cabin and qcamera panes follow the same cursor.

Layouts save to JSON and autosave to `cabana-analysis.json` in Cabana's settings directory. **Analysis → Edit layout JSON** edits the source with validation before applying. Existing Jotpluggler JSON layouts and PlotJuggler XML layouts can be imported. Bundled presets are generated from the PlotJuggler layout data. Ctrl+F searches signals; Ctrl+S saves layouts; Ctrl+O opens layouts; Ctrl+N starts a layout; Ctrl+Z/Ctrl+Shift+Z undo/redo workspace changes when a text field is not focused.

`--output image.png` captures the loaded workspace and exits; add `--show` to keep it open. `--width` and `--height` set the window dimensions. For automated testing, `--test-state path.json` writes read-only UI geometry and analysis diagnostics.

## Testing analysis

```sh
scons openpilot/tools/cabana/cabana openpilot/tools/cabana/tests/test_analysis openpilot/tools/cabana/tests/test_cabana
openpilot/tools/cabana/tests/test_analysis
openpilot/tools/cabana/tests/test_cabana
python -m pytest -q openpilot/tools/cabana/tests/test_analysis_python.py
CABANA_E2E=1 python -m pytest -q openpilot/tools/cabana/tests/test_analysis_ui.py
```

The UI suite uses Xvfb, xdotool, Pillow, pytest, and FFmpeg with H.264/HEVC encoders. It generates its own logs and videos, isolates settings and messaging, drives real mouse/keyboard input, and checks screenshots, samples and playback state. It includes large logs, repeated seeks/tabs, malformed live packets, buffer rollover, Python timeout recovery, and simultaneous camera seeking.

See [validation evidence and limits](analysis/TESTING.md) for stress coverage and reference provenance.
