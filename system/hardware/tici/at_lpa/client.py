import serial
import sys


DEFAULT_DEVICE = "/dev/ttyUSB2"
DEFAULT_BAUD = 9600
DEFAULT_TIMEOUT = 5.0
ISDR_AID = "A0000005591010FFFFFFFF8900000100"
ES10X_MSS = 120


class AtClient:
  def __init__(self, device: str, baud: int, timeout: float, verbose: bool) -> None:
    self.ser = serial.Serial(device, baudrate=baud, timeout=timeout)
    self.verbose = verbose
    self.channel: str | None = None
    self.ser.reset_input_buffer()

  def close(self) -> None:
    try:
      if self.channel:
        self.query(f"AT+CCHC={self.channel}")
        self.channel = None
    finally:
      self.ser.close()

  def send(self, cmd: str) -> None:
    if self.verbose:
      print(f">> {cmd}", file=sys.stderr)
    self.ser.write((cmd + "\r").encode("ascii"))

  def expect(self) -> list[str]:
    lines: list[str] = []
    while True:
      raw = self.ser.readline()
      if not raw:
        raise TimeoutError("AT command timed out")
      line = raw.decode(errors="ignore").strip()
      if not line:
        continue
      if self.verbose:
        print(f"<< {line}", file=sys.stderr)
      if line == "OK":
        return lines
      if line == "ERROR":
        raise RuntimeError("AT command failed")
      lines.append(line)

  def query(self, cmd: str) -> list[str]:
    self.send(cmd)
    return self.expect()

  def ensure_capabilities(self) -> None:
    self.query("AT")
    for command in ("AT+CCHO", "AT+CCHC", "AT+CGLA"):
      self.query(f"{command}=?")

  def open_isdr(self) -> None:
    for line in self.query(f'AT+CCHO="{ISDR_AID}"'):
      if line.startswith("+CCHO:") and (ch := line.split(":", 1)[1].strip()):
        self.channel = ch
        return
    raise RuntimeError("Failed to open ISD-R application")

  def send_apdu(self, apdu: bytes) -> tuple[bytes, int, int]:
    if not self.channel:
      raise RuntimeError("Logical channel is not open")
    hex_payload = apdu.hex().upper()
    for line in self.query(f'AT+CGLA={self.channel},{len(hex_payload)},"{hex_payload}"'):
      if line.startswith("+CGLA:"):
        parts = line.split(":", 1)[1].split(",", 1)
        if len(parts) == 2:
          data = bytes.fromhex(parts[1].strip().strip('"'))
          if len(data) >= 2:
            return data[:-2], data[-2], data[-1]
    raise RuntimeError("Missing +CGLA response")


def es10x_command(client: AtClient, data: bytes) -> bytes:
  response = bytearray()
  sequence = 0
  offset = 0
  while offset < len(data):
    chunk = data[offset : offset + ES10X_MSS]
    offset += len(chunk)
    is_last = offset == len(data)
    apdu = bytes([0x80, 0xE2, 0x91 if is_last else 0x11, sequence & 0xFF, len(chunk)]) + chunk
    segment, sw1, sw2 = client.send_apdu(apdu)
    response.extend(segment)
    while True:
      if sw1 == 0x61:  # More data available
        segment, sw1, sw2 = client.send_apdu(bytes([0x80, 0xC0, 0x00, 0x00, sw2 or 0]))
        response.extend(segment)
        continue
      if (sw1 & 0xF0) == 0x90:
        break
      raise RuntimeError(f"APDU failed with SW={sw1:02X}{sw2:02X}")
    sequence += 1
  return bytes(response)
