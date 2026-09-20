"""Lossless CAN batches and byte acknowledgements for the Cabana bridge."""
import struct
import zlib

CAN_PREFIX = b"CAN\0"
BATCH_PREFIX = b"CANZ"
MAX_BATCH_SIZE = 60 * 1024
CAN_WINDOW = 256 * 1024


def pack_can_batch(events):
  raw = b"".join(struct.pack("!I", len(event)) + event for event in events)
  if len(raw) > MAX_BATCH_SIZE:
    raise ValueError("CAN batch exceeds maximum size")
  return BATCH_PREFIX + zlib.compress(raw, level=1)


def unpack_can_batch(message):
  if not isinstance(message, bytes):
    return None
  if message.startswith(CAN_PREFIX):
    return [message[len(CAN_PREFIX):]]
  if not message.startswith(BATCH_PREFIX):
    return None
  decoder = zlib.decompressobj()
  raw = decoder.decompress(message[len(BATCH_PREFIX):], MAX_BATCH_SIZE + 1)
  if len(raw) > MAX_BATCH_SIZE or not decoder.eof or decoder.unused_data:
    raise ValueError("Invalid compressed CAN batch")
  events = []
  offset = 0
  while offset < len(raw):
    if len(raw) - offset < 4:
      raise ValueError("Truncated CAN batch header")
    size = struct.unpack_from("!I", raw, offset)[0]
    offset += 4
    if not size or size % 8 or size > len(raw) - offset:
      raise ValueError("Invalid CAN event size")
    events.append(raw[offset:offset + size])
    offset += size
  return events
