"""Minimal protobuf wire format encoder/decoder — no dependencies."""
import struct


def encode_varint(value):
  result = bytearray()
  while value > 127:
    result.append((value & 0x7F) | 0x80)
    value >>= 7
  result.append(value)
  return bytes(result)


def decode_varint(data, offset=0):
  result = 0
  shift = 0
  while True:
    byte = data[offset]
    result |= (byte & 0x7F) << shift
    offset += 1
    if not (byte & 0x80):
      break
    shift += 7
  return result, offset


def encode_field(field_number, value):
  """Encode a protobuf field. value is int (varint) or bytes (length-delimited)."""
  if isinstance(value, int):
    tag = encode_varint((field_number << 3) | 0)
    return tag + encode_varint(value)
  else:
    tag = encode_varint((field_number << 3) | 2)
    return tag + encode_varint(len(value)) + value


def decode_fields(data):
  """Decode protobuf bytes into list of (field_number, wire_type, value) tuples."""
  fields = []
  offset = 0
  while offset < len(data):
    tag, offset = decode_varint(data, offset)
    field_number = tag >> 3
    wire_type = tag & 0x07

    if wire_type == 0:  # varint
      value, offset = decode_varint(data, offset)
    elif wire_type == 2:  # length-delimited
      length, offset = decode_varint(data, offset)
      value = data[offset:offset + length]
      offset += length
    elif wire_type == 5:  # 32-bit fixed
      value = struct.unpack('<I', data[offset:offset + 4])[0]
      offset += 4
    elif wire_type == 1:  # 64-bit fixed
      value = struct.unpack('<Q', data[offset:offset + 8])[0]
      offset += 8
    else:
      break

    fields.append((field_number, wire_type, value))
  return fields


def get_field(fields, field_number):
  """Get first value for a field number, or None."""
  for fn, _, value in fields:
    if fn == field_number:
      return value
  return None
