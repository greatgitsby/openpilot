"""Minimal protobuf wire-format encoder/decoder.

Implements just enough of the protobuf binary wire format to encode and decode
Tesla BLE protocol messages without needing protoc or .proto files.

Wire types:
  0 = Varint (int32, uint32, sint32, bool, enum)
  1 = 64-bit (fixed64, double) — not used by Tesla
  2 = Length-delimited (bytes, string, nested messages)
  5 = 32-bit (fixed32, float)
"""

from __future__ import annotations

import struct

WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_BYTES = 2
WIRE_32BIT = 5


def encode_varint(value: int) -> bytes:
  """Encode an unsigned integer as a protobuf varint."""
  if value < 0:
    # Protobuf encodes negative int32/int64 as 10-byte two's complement
    value = value & 0xFFFFFFFFFFFFFFFF
  parts = []
  while value > 0x7F:
    parts.append((value & 0x7F) | 0x80)
    value >>= 7
  parts.append(value & 0x7F)
  return bytes(parts)


def decode_varint(data: bytes | memoryview, offset: int = 0) -> tuple[int, int]:
  """Decode a varint from data at offset. Returns (value, new_offset)."""
  result = 0
  shift = 0
  while True:
    if offset >= len(data):
      raise ValueError("Unexpected end of data while decoding varint")
    b = data[offset]
    result |= (b & 0x7F) << shift
    offset += 1
    if (b & 0x80) == 0:
      break
    shift += 7
  return result, offset


def encode_field(field_number: int, wire_type: int, value: bytes | int) -> bytes:
  """Encode a single protobuf field."""
  tag = encode_varint((field_number << 3) | wire_type)
  if wire_type == WIRE_VARINT:
    return tag + encode_varint(value)
  elif wire_type == WIRE_BYTES:
    if isinstance(value, (str,)):
      value = value.encode('utf-8')
    return tag + encode_varint(len(value)) + value
  elif wire_type == WIRE_32BIT:
    return tag + struct.pack('<I', value & 0xFFFFFFFF)
  elif wire_type == WIRE_64BIT:
    return tag + struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF)
  else:
    raise ValueError(f"Unsupported wire type: {wire_type}")


def decode_fields(data: bytes | memoryview) -> dict[int, list[tuple[int, bytes | int]]]:
  """Decode all fields from a protobuf message.

  Returns dict mapping field_number -> list of (wire_type, value) tuples.
  For WIRE_VARINT: value is int
  For WIRE_BYTES: value is bytes
  For WIRE_32BIT: value is int (unsigned)
  For WIRE_64BIT: value is int (unsigned)
  """
  fields: dict[int, list[tuple[int, bytes | int]]] = {}
  offset = 0
  while offset < len(data):
    tag, offset = decode_varint(data, offset)
    field_number = tag >> 3
    wire_type = tag & 0x07

    if wire_type == WIRE_VARINT:
      value, offset = decode_varint(data, offset)
    elif wire_type == WIRE_BYTES:
      length, offset = decode_varint(data, offset)
      value = bytes(data[offset:offset + length])
      offset += length
    elif wire_type == WIRE_32BIT:
      value = struct.unpack('<I', data[offset:offset + 4])[0]
      offset += 4
    elif wire_type == WIRE_64BIT:
      value = struct.unpack('<Q', data[offset:offset + 8])[0]
      offset += 8
    else:
      raise ValueError(f"Unsupported wire type {wire_type} at offset {offset}")

    fields.setdefault(field_number, []).append((wire_type, value))

  return fields


def encode_message(fields: list[tuple[int, int, bytes | int]]) -> bytes:
  """Encode a protobuf message from a list of (field_number, wire_type, value) tuples."""
  return b''.join(encode_field(fn, wt, v) for fn, wt, v in fields)


def get_field(fields: dict[int, list], field_number: int, default=None):
  """Get the first value for a field number, or default."""
  entries = fields.get(field_number)
  if entries:
    return entries[0][1]
  return default


def get_bytes(fields: dict[int, list], field_number: int) -> bytes | None:
  """Get a bytes field value."""
  val = get_field(fields, field_number)
  return val if isinstance(val, bytes) else None


def get_int(fields: dict[int, list], field_number: int, default: int = 0) -> int:
  """Get an integer (varint) field value."""
  val = get_field(fields, field_number)
  return val if isinstance(val, int) else default


def encode_nested(field_number: int, inner_fields: list[tuple[int, int, bytes | int]]) -> tuple[int, int, bytes]:
  """Helper to encode a nested message as a (field_number, WIRE_BYTES, encoded) tuple."""
  return (field_number, WIRE_BYTES, encode_message(inner_fields))
