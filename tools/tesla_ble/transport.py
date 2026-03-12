"""BLE transport layer for Tesla vehicle communication.

Handles scanning for Tesla vehicles, BLE connections, and framed message I/O
using the bleak library. Messages are length-prefixed (2-byte big-endian) and
may be fragmented across multiple BLE writes/notifications.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import struct

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice

logger = logging.getLogger(__name__)

# Tesla BLE GATT identifiers
SERVICE_UUID = "00000211-b2d1-43f0-9b88-960cebf8b91e"
WRITE_UUID = "00000212-b2d1-43f0-9b88-960cebf8b91e"
READ_UUID = "00000213-b2d1-43f0-9b88-960cebf8b91e"

# Maximum BLE payload per write (conservative; real MTU may be larger)
MAX_FRAME_SIZE = 1024


def vin_to_ble_local_name(vin: str) -> str:
  """Compute the BLE local name Tesla advertises for a given VIN.

  Format: S<first-8-hex-chars-of-SHA1(VIN)>C
  """
  digest = hashlib.sha1(vin.encode('utf-8')).hexdigest()
  return f"S{digest[:16]}C"


async def scan_for_teslas(vin: str | None = None, timeout: float = 10.0) -> list[BLEDevice]:
  """Scan for nearby Tesla vehicles advertising the Tesla BLE service.

  If *vin* is provided, only return devices whose local name matches that VIN.
  """
  target_name = vin_to_ble_local_name(vin) if vin else None
  found: list[BLEDevice] = []

  devices = await BleakScanner.discover(timeout=timeout, service_uuids=[SERVICE_UUID])
  for device in devices:
    name = device.name or ''
    if target_name:
      if name == target_name:
        found.append(device)
    elif name.startswith('S') and name.endswith('C'):
      found.append(device)

  return found


class TeslaBLETransport:
  """Manages a BLE connection to a Tesla vehicle and provides framed message I/O."""

  def __init__(self) -> None:
    self._client: BleakClient | None = None
    self._rx_buffer = bytearray()
    self._rx_queue: asyncio.Queue[bytes] = asyncio.Queue()
    self._rx_expected_len: int | None = None

  # ------------------------------------------------------------------
  # Connection management
  # ------------------------------------------------------------------

  async def connect(self, device_or_address: BLEDevice | str, timeout: float = 15.0) -> None:
    """Connect to a Tesla vehicle over BLE and subscribe to notifications."""
    self._client = BleakClient(device_or_address, timeout=timeout)
    await self._client.connect()
    logger.info("BLE connected to %s", device_or_address)

    # Subscribe to indications on the read characteristic
    await self._client.start_notify(READ_UUID, self._on_notification)
    logger.debug("Subscribed to indications on %s", READ_UUID)

  async def disconnect(self) -> None:
    """Disconnect from the vehicle."""
    if self._client and self._client.is_connected:
      try:
        await self._client.stop_notify(READ_UUID)
      except Exception:
        pass
      await self._client.disconnect()
      logger.info("BLE disconnected")
    self._client = None

  @property
  def is_connected(self) -> bool:
    return self._client is not None and self._client.is_connected

  # ------------------------------------------------------------------
  # Framed message I/O
  # ------------------------------------------------------------------

  async def send(self, data: bytes) -> None:
    """Send a length-prefixed message, fragmenting if needed.

    The message is preceded by a 2-byte big-endian length prefix. If the total
    exceeds the BLE MTU, it is split into multiple writes.
    """
    if not self._client or not self._client.is_connected:
      raise ConnectionError("Not connected to vehicle")

    frame = struct.pack('>H', len(data)) + data
    mtu = self._client.mtu_size - 3 if self._client.mtu_size > 3 else 20
    chunk_size = min(mtu, MAX_FRAME_SIZE)

    for offset in range(0, len(frame), chunk_size):
      chunk = frame[offset:offset + chunk_size]
      await self._client.write_gatt_char(WRITE_UUID, chunk, response=True)
      logger.debug("TX chunk %d bytes (offset %d/%d)", len(chunk), offset, len(frame))

  async def receive(self, timeout: float = 10.0) -> bytes:
    """Wait for and return the next complete message from the vehicle."""
    return await asyncio.wait_for(self._rx_queue.get(), timeout=timeout)

  def _on_notification(self, _sender: int, data: bytearray) -> None:
    """Callback for BLE indications — reassembles length-prefixed messages."""
    self._rx_buffer.extend(data)

    # Process as many complete messages as possible
    while True:
      buf = self._rx_buffer

      # Need at least 2 bytes for the length prefix
      if len(buf) < 2:
        break

      msg_len = struct.unpack('>H', buf[:2])[0]

      if len(buf) < 2 + msg_len:
        break  # waiting for more data

      message = bytes(buf[2:2 + msg_len])
      self._rx_buffer = bytearray(buf[2 + msg_len:])
      self._rx_queue.put_nowait(message)
      logger.debug("RX complete message: %d bytes", msg_len)
