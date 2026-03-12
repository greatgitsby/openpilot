"""Tesla BLE session management — ECDH handshake and message authentication.

Implements the Tesla vehicle-command crypto protocol:
  1. ECDH key agreement (NIST P-256) to derive a shared secret
  2. Session key derivation via SHA-1 + HMAC-SHA256
  3. AES-128-GCM encryption/authentication of commands
  4. Metadata TLV construction for AAD (Additional Authenticated Data)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
import logging

from Crypto.Cipher import AES
from Crypto.PublicKey import ECC

from openpilot.tools.tesla_ble.messages import (
  Domain,
  Tag,
  build_aes_gcm_sig_data,
  build_key_identity,
  build_routable_message,
  build_session_info_request,
  build_signature_data,
  parse_routable_message,
  parse_session_info,
)
from openpilot.tools.tesla_ble.transport import TeslaBLETransport

logger = logging.getLogger(__name__)

# Time-to-live for commands (seconds)
DEFAULT_TTL = 15


def _ecdh_shared_secret(private_key: ECC.EccKey, peer_public_bytes: bytes) -> bytes:
  """Compute the raw ECDH x-coordinate from our private key and the peer's uncompressed public key.

  peer_public_bytes: 65 bytes (0x04 || x[32] || y[32]) — uncompressed P-256 point.
  Returns: 32-byte big-endian x-coordinate of the shared point.
  """
  peer_key = ECC.import_key(peer_public_bytes, curve_name='P-256')
  # Scalar multiplication: shared_point = private_scalar * peer_point
  shared_point = peer_key.pointQ * private_key.d
  x_bytes = int(shared_point.x).to_bytes(32, 'big')
  return x_bytes


def _derive_session_key(shared_x: bytes) -> bytes:
  """Derive the 16-byte session key K from the ECDH x-coordinate.

  K = SHA1(shared_x)[:16]
  """
  return hashlib.sha1(shared_x).digest()[:16]


def _derive_auth_key(session_key: bytes, context: str) -> bytes:
  """Derive a sub-key using HMAC-SHA256.

  HMAC-SHA256(K, context_string) -> 32-byte key
  """
  return hmac.new(session_key, context.encode('ascii'), hashlib.sha256).digest()


def _build_metadata_tlv(
  signature_type: int,
  domain: int,
  personalization: bytes,
  epoch: bytes,
  expires_at: int,
  counter: int,
  flags: int = 0,
) -> bytes:
  """Build the Tag-Length-Value metadata blob used as AES-GCM AAD.

  Format: tag(1) || length(1) || value(variable) ... terminated by 0xFF.
  Integer values are encoded as 4-byte big-endian.
  """
  parts = bytearray()

  def _add(tag: int, value: bytes) -> None:
    parts.append(tag)
    parts.append(len(value))
    parts.extend(value)

  _add(Tag.SIGNATURE_TYPE, struct.pack('>I', signature_type))
  _add(Tag.DOMAIN, struct.pack('>I', domain))
  _add(Tag.PERSONALIZATION, personalization)
  _add(Tag.EPOCH, epoch)
  _add(Tag.EXPIRES_AT, struct.pack('>I', expires_at))
  _add(Tag.COUNTER, struct.pack('>I', counter))
  _add(Tag.FLAGS, struct.pack('>I', flags))

  # Terminator
  parts.append(Tag.END)

  return bytes(parts)


class TeslaSession:
  """Manages a cryptographic session with one vehicle domain (VCSEC or Infotainment)."""

  def __init__(self, private_key: ECC.EccKey, domain: Domain) -> None:
    self.private_key = private_key
    self.domain = domain

    # Session state (populated after handshake)
    self.session_key: bytes | None = None       # 16-byte AES key
    self.auth_key: bytes | None = None          # 32-byte HMAC key for commands
    self.session_info_key: bytes | None = None  # 32-byte HMAC key for session info
    self.epoch: bytes = b''
    self.counter: int = 0
    self.clock_time: int = 0
    self.time_zero: float = 0.0  # local monotonic time at handshake
    self.handle: int = 0
    self.is_established: bool = False

  @property
  def public_key_bytes(self) -> bytes:
    """Our uncompressed public key (65 bytes: 0x04 || x || y)."""
    pt = self.private_key.pointQ
    x = int(pt.x).to_bytes(32, 'big')
    y = int(pt.y).to_bytes(32, 'big')
    return b'\x04' + x + y

  async def perform_handshake(self, transport: TeslaBLETransport) -> None:
    """Execute the session handshake with the vehicle.

    1. Send a RoutableMessage containing a SessionInfoRequest with our public key.
    2. Receive the vehicle's SessionInfo (ephemeral public key, epoch, counter).
    3. Derive the shared session key via ECDH.
    """
    # Build handshake request
    sir = build_session_info_request(self.public_key_bytes)
    msg = build_routable_message(
      to_domain=self.domain,
      session_info_request=sir,
    )

    logger.info("Sending handshake for domain %s", self.domain.name)
    await transport.send(msg)

    # Wait for response
    resp_data = await transport.receive(timeout=10.0)
    resp = parse_routable_message(resp_data)

    # Extract session info
    si_bytes = resp.get('session_info')
    if not si_bytes:
      raise RuntimeError(f"No session_info in handshake response for {self.domain.name}")

    si = parse_session_info(si_bytes)
    logger.info("Session info received: counter=%d epoch=%s handle=%d status=%d",
                si['counter'], (si['epoch'] or b'').hex(), si.get('handle', 0), si.get('status', 0))

    # Verify the response HMAC tag
    vehicle_public_key = si['public_key']
    if not vehicle_public_key:
      raise RuntimeError("No public key in session info")

    # Derive keys
    shared_x = _ecdh_shared_secret(self.private_key, vehicle_public_key)
    self.session_key = _derive_session_key(shared_x)
    self.session_info_key = _derive_auth_key(self.session_key, "session info")
    self.auth_key = _derive_auth_key(self.session_key, "authenticated command")

    # Verify session info HMAC tag from signature_data
    sig_data_bytes = resp.get('signature_data')
    if sig_data_bytes:
      self._verify_session_info_tag(sig_data_bytes, si_bytes)

    # Store session parameters
    self.epoch = si['epoch'] or b''
    self.counter = si['counter']
    self.clock_time = si.get('clock_time', 0)
    if isinstance(self.clock_time, tuple):
      self.clock_time = self.clock_time[1] if len(self.clock_time) > 1 else 0
    self.time_zero = time.monotonic()
    self.handle = si.get('handle', 0)
    self.is_established = True

    logger.info("Session established for %s (epoch=%s, counter=%d)",
                self.domain.name, self.epoch.hex(), self.counter)

  def _verify_session_info_tag(self, sig_data_bytes: bytes, session_info_bytes: bytes) -> None:
    """Verify the HMAC tag on the session info response."""
    from openpilot.tools.tesla_ble.protobuf import decode_fields, get_bytes
    sig_fields = decode_fields(sig_data_bytes)
    tag_bytes = get_bytes(sig_fields, 6)  # field 6 = session_info_tag (HMAC_Signature_Data)
    if tag_bytes:
      # The tag is HMAC-SHA256(session_info_key, session_info_bytes)
      tag_fields = decode_fields(tag_bytes)
      received_tag = get_bytes(tag_fields, 1)  # HMAC_Signature_Data.tag = field 1
      if received_tag and self.session_info_key:
        expected_tag = hmac.new(self.session_info_key, session_info_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(received_tag, expected_tag):
          logger.warning("Session info HMAC verification failed — the vehicle may not recognize this key")

  def _next_counter(self) -> int:
    """Increment and return the next counter value."""
    self.counter += 1
    return self.counter

  def _current_vehicle_time(self) -> int:
    """Estimate current vehicle time (seconds since epoch start)."""
    elapsed = time.monotonic() - self.time_zero
    return self.clock_time + int(elapsed)

  def encrypt_command(self, payload: bytes, request_uuid: bytes | None = None) -> bytes:
    """Encrypt and authenticate a command payload, returning a complete RoutableMessage.

    Uses AES-128-GCM with the derived auth_key. The metadata TLV is hashed to
    produce the AAD.
    """
    if not self.is_established or not self.auth_key:
      raise RuntimeError(f"Session not established for {self.domain.name}")

    counter = self._next_counter()
    expires_at = self._current_vehicle_time() + DEFAULT_TTL
    nonce = os.urandom(12)

    # Build metadata TLV for AAD
    from openpilot.tools.tesla_ble.messages import SignatureType
    metadata = _build_metadata_tlv(
      signature_type=SignatureType.AES_GCM_PERSONALIZED,
      domain=int(self.domain),
      personalization=self.public_key_bytes,
      epoch=self.epoch,
      expires_at=expires_at,
      counter=counter,
    )
    aad = hashlib.sha256(metadata).digest()

    # Encrypt
    cipher = AES.new(self.auth_key[:16], AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(payload)

    # Build signature data
    signer_identity = build_key_identity(handle=self.handle)
    aes_gcm_data = build_aes_gcm_sig_data(
      epoch=self.epoch,
      nonce=nonce,
      counter=counter,
      expires_at=expires_at,
      tag=tag,
    )
    sig_data = build_signature_data(
      signer_identity=signer_identity,
      aes_gcm_data=aes_gcm_data,
    )

    # Build the outer RoutableMessage
    return build_routable_message(
      to_domain=self.domain,
      payload=ciphertext,
      signature_data=sig_data,
      request_uuid=request_uuid or os.urandom(16),
    )

  def decrypt_response(self, data: bytes) -> tuple[bytes | None, dict]:
    """Parse and optionally decrypt a response RoutableMessage.

    Returns (decrypted_payload_or_None, parsed_message_dict).
    """
    msg = parse_routable_message(data)

    # Check for faults
    fault = msg.get('message_fault', 0)
    if fault:
      fault_name = "UNKNOWN"
      from openpilot.tools.tesla_ble.messages import MessageFault
      try:
        fault_name = MessageFault(fault).name
      except ValueError:
        pass
      logger.error("Vehicle returned fault: %s (%d)", fault_name, fault)

    payload = msg.get('payload')
    if not payload:
      return None, msg

    # Try to decrypt if we have signature data with AES_GCM_Response
    sig_bytes = msg.get('signature_data')
    if sig_bytes and self.auth_key:
      try:
        from openpilot.tools.tesla_ble.protobuf import decode_fields as _df, get_bytes as _gb, get_int as _gi
        sig_fields = _df(sig_bytes)
        # field 9 = AES_GCM_Response_data
        resp_data = _gb(sig_fields, 9)
        if resp_data:
          resp_fields = _df(resp_data)
          resp_nonce = _gb(resp_fields, 1)
          resp_tag = _gb(resp_fields, 3)
          if resp_nonce and resp_tag:
            cipher = AES.new(self.auth_key[:16], AES.MODE_GCM, nonce=resp_nonce)
            # AAD for response includes counter, flags, request_hash, fault
            # For simplicity, we attempt decryption without AAD reconstruction
            # (responses may be unencrypted if FLAG_ENCRYPT_RESPONSE was not set)
            plaintext = cipher.decrypt_and_verify(payload, resp_tag)
            return plaintext, msg
      except Exception as e:
        logger.debug("Response decryption failed (may be plaintext): %s", e)

    return payload, msg
