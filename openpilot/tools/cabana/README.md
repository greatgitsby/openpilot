# Cabana

Cabana is a tool developed to view raw CAN data. One use for this is creating and editing [CAN Dictionaries](http://socialledge.com/sjsu/index.php/DBC_Format) (DBC files), and the tool provides direct integration with [commaai/opendbc](https://github.com/commaai/opendbc) (a collection of DBC files), allowing you to load the DBC files direct from source, and save to your fork. In addition, you can load routes from [comma connect](https://connect.comma.ai).

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
Use **Add Widget → Road Camera**, **Wide Camera**, or **Cabin Camera** to place camera views in the current page. Cabana loads all available recorded cameras; a route without the selected camera shows “No camera frames available.” The legacy `--cabin` and `--wide-road` options remain accepted.

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

## Workspaces

The top workspace selector switches complete workspaces without changing the loaded route, playback position, speed, or linked time range. **Default** starts with Cabana's CAN reverse-engineering tools. **New blank** creates an empty workspace; **Add Widget** adds CAN Messages, Signal Details, Series Browser, Road/Wide/Cabin Camera, or a Plot. Each built-in widget appears once per page; plots can be added repeatedly.

Pages belong to the selected workspace. Use the new-page button or **Page** menu to organize, duplicate, and rename them. Drag widget tabs to split the page, group widgets as tabs, or float them into separate windows. Closing a widget removes it from that page. Closing the Series Browser leaves plots running.

**Workspace → Presets** and **Open** add workspaces to the selector; **Save As** exports the selected workspace. Workspaces, page contents, and docking arrangements persist across restarts. Existing single-workspace settings are retained as an Imported workspace.

The timeline and playback controls stay at the bottom of the main window across every workspace and page. Camera widgets share that controller and contain no separate playback controls.
