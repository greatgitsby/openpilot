"""Key generation, storage, and loading for Tesla BLE authentication.

Keys are stored as PEM files organized by VIN:
  <key_dir>/<VIN>/private_key.pem

The default key directory is ~/.tesla_ble_keys/ on desktop or
/data/tesla_ble_keys/ on comma device.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from Crypto.PublicKey import ECC


def _default_key_dir() -> Path:
  """Return the default key storage directory."""
  # On comma device, use /data; otherwise use home directory
  if os.path.isdir('/data/openpilot'):
    return Path('/data/tesla_ble_keys')
  return Path.home() / '.tesla_ble_keys'


def get_key_dir(key_path: str | None = None) -> Path:
  """Resolve the key directory from an explicit path or the default."""
  if key_path:
    return Path(key_path)
  return _default_key_dir()


def generate_key_pair() -> ECC.EccKey:
  """Generate a new NIST P-256 private key."""
  return ECC.generate(curve='P-256')


def save_key(private_key: ECC.EccKey, vin: str, key_path: str | None = None) -> Path:
  """Save a private key as PEM for the given VIN. Returns the file path."""
  key_dir = get_key_dir(key_path) / vin
  key_dir.mkdir(parents=True, exist_ok=True)

  pem_path = key_dir / 'private_key.pem'
  pem_data = private_key.export_key(format='PEM')
  pem_path.write_text(pem_data)
  pem_path.chmod(0o600)

  return pem_path


def load_key(vin: str, key_path: str | None = None) -> ECC.EccKey:
  """Load a private key for the given VIN."""
  pem_path = get_key_dir(key_path) / vin / 'private_key.pem'
  if not pem_path.exists():
    raise FileNotFoundError(f"No key found for VIN {vin} at {pem_path}")
  pem_data = pem_path.read_text()
  return ECC.import_key(pem_data)


def has_key(vin: str, key_path: str | None = None) -> bool:
  """Check whether a key exists for the given VIN."""
  pem_path = get_key_dir(key_path) / vin / 'private_key.pem'
  return pem_path.exists()


def get_public_key_bytes(private_key: ECC.EccKey) -> bytes:
  """Extract the 65-byte uncompressed public key (0x04 || x || y)."""
  pt = private_key.pointQ
  x = int(pt.x).to_bytes(32, 'big')
  y = int(pt.y).to_bytes(32, 'big')
  return b'\x04' + x + y


def get_key_id(public_key_bytes: bytes) -> bytes:
  """Compute the key identifier (SHA-1 of the public key bytes)."""
  return hashlib.sha1(public_key_bytes).digest()
