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
  --msgq                    read openpilot messages from local msgq (alias: --stream)
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

### Streaming from a comma Device

With this branch on the device, stream its raw CAN and one live camera over Athena/WebRTC:

```shell
python -m openpilot.tools.lib.auth   # once
cabana --webrtc <dongle-id>          # or Device > Athena in the stream selector
```

Add a camera widget to pick Road, Driver, or Wide Road; switching cameras keeps the CAN stream.
The session starts onroad or offroad, and one started offroad ends when the car starts. A new
connection replaces any other viewer, including comma Connect. `--msgq` reads local openpilot messages.

While streaming from the device, Cabana will log the received CAN messages to a local directory. By default, this directory is ~/cabana_live_stream/. You can change the log directory in Cabana by navigating to menu -> tools -> settings.

After disconnecting from the device, you can replay the logged messages from the stream selector dialog -> browse local route.

The **Joystick** dock drives a connected comma body: check **Arm controls**, then hold **W/S** and **A/D**
or drag the pad. Releasing centers the controls; Escape, focus loss, or hiding the dock disarms.

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

## Workspaces and plotting

A workspace holds sources and widgets. Open more routes, or a live source, from **Sources**; each
chart, camera, CAN browser, openpilot message browser, and CAN inspector is a tab that can be
docked, stacked, or floated. **Add widget** creates them for the selected source, and a chart can
compare signals from several sources.

The timeline at the bottom has a track per source. Click or drag a track to seek, **Space** plays
or pauses, and **Left/Right** step camera frames. Check **Link** on routes to play them together,
then use **Options → Align current positions** or edit a track's offset
(workspace time = route time + offset). **Options** can also loop an interval.

Double-click an openpilot field such as `/carState/vEgo` to chart it, or drag it onto a chart.
**Analysis → New Function...** defines a Python function of other series, e.g.
`return value * 2.23694` for mph.

**Workspace** selects, creates, duplicates, imports, and exports workspaces. Built-ins (Default,
Live, and the [bundled layouts](layouts)) reset on restart; duplicate one to keep changes. With
**Include route references**, a workspace also saves its routes and DBC paths, and
**Open saved routes** loads them. Logs and video are never embedded.

```shell
./cabana --demo --layout layouts/tuning.json
```

## Additional Information

For more information, see the [openpilot wiki](https://github.com/commaai/openpilot/wiki/Cabana)
