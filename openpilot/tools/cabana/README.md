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
  --webrtc <dongle-id>      live CAN and wide-road video over Athena/WebRTC
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
**Device > Athena / WebRTC** in the stream selector. Remote ZMQ (`--zmq`) has
been replaced; `--msgq` still reads local CAN.

The connection carries raw CAN and wide-road video. It is available onroad and
offroad, survives ignition changes, and has no five-minute session limit.
Camera processes start on demand offroad; the WebRTC daemon is always available
and the streaming encoder runs onroad. Only one viewer is supported: a new
connection replaces an existing viewer, including comma Connect.

Video always shows the live camera, even when CAN playback is paused or rewound.
Only CAN is recorded. Reopen the stream after a network disconnect. See
[TODO.md](../../../TODO.md) for hackathon caveats and follow-up work.

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
