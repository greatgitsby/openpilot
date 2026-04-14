"""Tesla BLE crypto — ECDH key exchange and AES-GCM encryption."""
import hashlib
import hmac
import os

from Crypto.PublicKey import ECC


def generate_key_pair():
  """Generate a NIST P-256 key pair. Returns (private_key, public_key_bytes).
  public_key_bytes is 65 bytes uncompressed (0x04 || x || y)."""
  key = ECC.generate(curve='P-256')
  # uncompressed point: 0x04 + 32 bytes x + 32 bytes y
  pub = b'\x04' + int(key.pointQ.x).to_bytes(32, 'big') + int(key.pointQ.y).to_bytes(32, 'big')
  return key, pub


def load_or_create_key(path):
  """Load a persistent key pair from disk, or create one."""
  try:
    with open(path, 'rb') as f:
      pem = f.read()
    key = ECC.import_key(pem)
  except (FileNotFoundError, ValueError):
    key = ECC.generate(curve='P-256')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
      f.write(key.export_key(format='PEM').encode() if isinstance(key.export_key(format='PEM'), str) else key.export_key(format='PEM'))

  pub = b'\x04' + int(key.pointQ.x).to_bytes(32, 'big') + int(key.pointQ.y).to_bytes(32, 'big')
  return key, pub


def ecdh_shared_key(private_key, peer_public_bytes):
  """Perform ECDH and derive the 16-byte shared key.
  K = SHA1(shared_secret)[:16]"""
  # parse uncompressed public key
  assert peer_public_bytes[0] == 0x04 and len(peer_public_bytes) == 65
  x = int.from_bytes(peer_public_bytes[1:33], 'big')
  y = int.from_bytes(peer_public_bytes[33:65], 'big')
  peer_point = ECC.EccPoint(x, y, curve='P-256')

  # ECDH: multiply peer's public point by our private scalar
  shared_point = peer_point * private_key.d
  shared_secret = int(shared_point.x).to_bytes(32, 'big')

  return hashlib.sha1(shared_secret).digest()[:16]



def derive_subkey(shared_key, purpose):
  """Derive a purpose-specific subkey: HMAC-SHA256(K, purpose)."""
  return hmac.new(shared_key, purpose.encode(), hashlib.sha256).digest()


def encrypt_gcm(key, counter, plaintext):
  """AES-128-GCM encrypt with 4-byte big-endian counter as nonce (VCSEC legacy).
  Returns (ciphertext_without_tag, tag) where tag is 16 bytes."""
  from Crypto.Cipher import AES
  nonce = counter.to_bytes(4, 'big')
  cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
  ciphertext, tag = cipher.encrypt_and_digest(plaintext)
  return ciphertext, tag


def encrypt_gcm_personalized(key, nonce, plaintext, aad):
  """AES-128-GCM encrypt with 12-byte nonce and AAD (infotainment).
  Returns (ciphertext_without_tag, tag) where tag is 16 bytes."""
  from Crypto.Cipher import AES
  cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
  cipher.update(aad)
  ciphertext, tag = cipher.encrypt_and_digest(plaintext)
  return ciphertext, tag


def key_id(public_key_bytes):
  """Key ID = first 4 bytes of SHA1(public_key)."""
  return hashlib.sha1(public_key_bytes).digest()[:4]
