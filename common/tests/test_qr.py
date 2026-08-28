import numpy as np
import pytest
import qrcode
from PIL import Image

from openpilot.common import qr

LEVELS = [qrcode.constants.ERROR_CORRECT_L, qrcode.constants.ERROR_CORRECT_M,
          qrcode.constants.ERROR_CORRECT_Q, qrcode.constants.ERROR_CORRECT_H]
LPA = "LPA:1$rsp.truphone.com$QRF-BETTERROAMING-PMRDGIR2EARDEIT5"


def make(data: str, version: int | None = None, level=qrcode.constants.ERROR_CORRECT_M, box: int = 6, border: int = 4):
  q = qrcode.QRCode(version=version, error_correction=level, box_size=box, border=border)
  q.add_data(data)
  q.make(fit=version is None)
  matrix = np.array(q.modules, dtype=bool)
  img = np.array(q.make_image().convert("L"), dtype=np.uint8)
  return matrix, img


@pytest.mark.parametrize("version", range(1, 41))
@pytest.mark.parametrize("level", LEVELS)
def test_all_versions(version, level):
  data = "".join(chr(ord("a") + i % 26) for i in range(version))
  matrix, img = make(data, version, level, box=3)
  assert qr.decode_matrix(matrix) == data
  assert qr.decode(img) == data


@pytest.mark.parametrize("data", ["0123456789012345", "HELLO WORLD $1.50", LPA, "こんにちは", "ünïcødé", "mixed 123 ABC xyz"])
def test_modes(data):
  matrix, img = make(data)
  assert qr.decode_matrix(matrix) == data
  assert qr.decode(img) == data


def test_error_correction():
  matrix, _ = make(LPA, level=qrcode.constants.ERROR_CORRECT_H)
  rng = np.random.default_rng(0)
  flipped = matrix.copy()
  for r, c in rng.integers(9, matrix.shape[0] - 9, size=(40, 2)):
    flipped[r, c] ^= True
  assert qr.decode_matrix(flipped) == LPA


@pytest.mark.parametrize("angle", [0, 90, 180, 270, 25, 110])
def test_rotation(angle):
  _, img = make(LPA, box=8, border=12)
  rotated = np.array(Image.fromarray(img).rotate(angle, resample=Image.BILINEAR, fillcolor=255))
  assert qr.decode(rotated) == LPA


def test_mirrored():
  _, img = make(LPA)
  assert qr.decode(img[:, ::-1]) == LPA


def test_perspective_and_noise():
  _, img = make(LPA, box=10, border=8)
  h, w = img.shape
  corners = [(40, 60), (w - 20, 30), (w - 60, h - 40), (30, h - 90)]
  # PIL wants the transform mapping output -> input, so solve for it
  src = [(0, 0), (w, 0), (w, h), (0, h)]
  H = qr._perspective(corners, src)
  warped = Image.fromarray(img).transform((w, h), Image.PERSPECTIVE, H.ravel()[:8], resample=Image.BILINEAR, fillcolor=255)
  arr = np.array(warped).astype(float)
  rng = np.random.default_rng(1)
  arr = arr * 0.6 + 60 + rng.normal(0, 12, arr.shape)  # low contrast + noise
  # uneven lighting
  arr += np.linspace(-40, 40, w)[None, :]
  assert qr.decode(np.clip(arr, 0, 255).astype(np.uint8)) == LPA


def test_no_code():
  rng = np.random.default_rng(2)
  assert qr.decode(rng.integers(0, 256, size=(240, 320), dtype=np.uint8)) is None
  assert qr.decode(np.full((240, 320), 200, dtype=np.uint8)) is None
