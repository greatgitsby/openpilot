"""Minimal QR code reader (ISO/IEC 18004). Only depends on numpy."""
import itertools
import numpy as np


class QRError(Exception):
  pass


# GF(256) with the QR polynomial x^8 + x^4 + x^3 + x^2 + 1
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
  _EXP[_i] = _x
  _LOG[_x] = _i
  _x <<= 1
  if _x & 0x100:
    _x ^= 0x11d
for _i in range(255, 512):
  _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
  if a == 0 or b == 0:
    return 0
  return _EXP[_LOG[a] + _LOG[b]]


def _gf_inv(a: int) -> int:
  return _EXP[255 - _LOG[a]]


def _poly_eval(p: list[int], x: int) -> int:
  # p is highest degree first
  y = 0
  for c in p:
    y = _gf_mul(y, x) ^ c
  return y


def _rs_correct(msg: list[int], nsym: int) -> list[int]:
  """Corrects up to nsym // 2 errors in a Reed-Solomon codeword, in place."""
  n = len(msg)
  syn = [_poly_eval(msg, _EXP[i]) for i in range(nsym)]
  if not any(syn):
    return msg

  # Berlekamp-Massey, sigma is lowest degree first
  sigma, prev, L, m, b = [1], [1], 0, 1, 1
  for r in range(nsym):
    d = syn[r]
    for i in range(1, L + 1):
      d ^= _gf_mul(sigma[i], syn[r - i])
    if d == 0:
      m += 1
      continue
    coef = _gf_mul(d, _gf_inv(b))
    shifted = [0] * m + prev
    saved = sigma[:]
    sigma = sigma + [0] * max(0, len(shifted) - len(sigma))
    for i, c in enumerate(shifted):
      sigma[i] ^= _gf_mul(coef, c)
    if 2 * L <= r:
      L, prev, b, m = r + 1 - L, saved, d, 1
    else:
      m += 1
  sigma = sigma[:L + 1]
  if 2 * L > nsym:
    raise QRError("too many errors")

  # Chien search: codeword position p has locator alpha^(n-1-p)
  positions = []
  for p in range(n):
    xinv_log = (255 - (n - 1 - p)) % 255
    v = 0
    for i, c in enumerate(sigma):
      if c:
        v ^= _EXP[_LOG[c] + (xinv_log * i) % 255]
    if v == 0:
      positions.append(p)
  if len(positions) != L:
    raise QRError("error locator mismatch")

  # solve syn[i] = sum_k e_k * X_k^i for the magnitudes e_k
  xlog = [(n - 1 - p) % 255 for p in positions]
  A = [[_EXP[(xlog[k] * i) % 255] for k in range(L)] + [syn[i]] for i in range(L)]
  for col in range(L):
    piv = next((r for r in range(col, L) if A[r][col]), None)
    if piv is None:
      raise QRError("singular")
    A[col], A[piv] = A[piv], A[col]
    inv = _gf_inv(A[col][col])
    A[col] = [_gf_mul(inv, v) for v in A[col]]
    for r in range(L):
      if r != col and A[r][col]:
        f = A[r][col]
        A[r] = [a ^ _gf_mul(f, c) for a, c in zip(A[r], A[col], strict=True)]
  for k, p in enumerate(positions):
    msg[p] ^= A[k][L]

  if any(_poly_eval(msg, _EXP[i]) for i in range(nsym)):
    raise QRError("uncorrectable")
  return msg


def _bch_encode(data: int, ec_bits: int, poly: int) -> int:
  v = data << ec_bits
  for shift in range(v.bit_length() - 1, ec_bits - 1, -1):
    if v >> shift & 1:
      v ^= poly << (shift - ec_bits)
  return (data << ec_bits) | v


_FORMATS = [_bch_encode(d, 10, 0x537) ^ 0x5412 for d in range(32)]


def _best_match(bits: int, codes: list[int], max_dist: int) -> int | None:
  best = min(range(len(codes)), key=lambda i: bin(bits ^ codes[i]).count("1"))
  return best if bin(bits ^ codes[best]).count("1") <= max_dist else None


# (ec codewords per block, block count) for levels L, M, Q, H, versions 1-40
_EC = [
  ((7, 1), (10, 1), (13, 1), (17, 1)), ((10, 1), (16, 1), (22, 1), (28, 1)), ((15, 1), (26, 1), (18, 2), (22, 2)),
  ((20, 1), (18, 2), (26, 2), (16, 4)), ((26, 1), (24, 2), (18, 4), (22, 4)), ((18, 2), (16, 4), (24, 4), (28, 4)),
  ((20, 2), (18, 4), (18, 6), (26, 5)), ((24, 2), (22, 4), (22, 6), (26, 6)), ((30, 2), (22, 5), (20, 8), (24, 8)),
  ((18, 4), (26, 5), (24, 8), (28, 8)), ((20, 4), (30, 5), (28, 8), (24, 11)), ((24, 4), (22, 8), (26, 10), (28, 11)),
  ((26, 4), (22, 9), (24, 12), (22, 16)), ((30, 4), (24, 9), (20, 16), (24, 16)), ((22, 6), (24, 10), (30, 12), (24, 18)),
  ((24, 6), (28, 10), (24, 17), (30, 16)), ((28, 6), (28, 11), (28, 16), (28, 19)), ((30, 6), (26, 13), (28, 18), (28, 21)),
  ((28, 7), (26, 14), (26, 21), (26, 25)), ((28, 8), (26, 16), (30, 20), (28, 25)), ((28, 8), (26, 17), (28, 23), (30, 25)),
  ((28, 9), (28, 17), (30, 23), (24, 34)), ((30, 9), (28, 18), (30, 25), (30, 30)), ((30, 10), (28, 20), (30, 27), (30, 32)),
  ((26, 12), (28, 21), (30, 29), (30, 35)), ((28, 12), (28, 23), (28, 34), (30, 37)), ((30, 12), (28, 25), (30, 34), (30, 40)),
  ((30, 13), (28, 26), (30, 35), (30, 42)), ((30, 14), (28, 28), (30, 38), (30, 45)), ((30, 15), (28, 29), (30, 40), (30, 48)),
  ((30, 16), (28, 31), (30, 43), (30, 51)), ((30, 17), (28, 33), (30, 45), (30, 54)), ((30, 18), (28, 35), (30, 48), (30, 57)),
  ((30, 19), (28, 37), (30, 51), (30, 60)), ((30, 19), (28, 38), (30, 53), (30, 63)), ((30, 20), (28, 40), (30, 56), (30, 66)),
  ((30, 21), (28, 43), (30, 59), (30, 70)), ((30, 22), (28, 45), (30, 62), (30, 74)), ((30, 24), (28, 47), (30, 65), (30, 77)),
  ((30, 25), (28, 49), (30, 68), (30, 81)),
]

# second alignment pattern coordinate for versions 2-40 (first is 6, last is dim - 7, rest evenly spaced)
_ALIGN2 = [18, 22, 26, 30, 34, 22, 24, 26, 28, 30, 32, 34, 26, 26, 26, 30, 30, 30, 34, 28, 26, 30, 28, 32, 30, 34,
           26, 30, 26, 30, 34, 30, 34, 30, 24, 28, 32, 26, 30]

_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

_MASKS = [
  lambda i, j: (i + j) % 2 == 0,
  lambda i, j: i % 2 == 0,
  lambda i, j: j % 3 == 0,
  lambda i, j: (i + j) % 3 == 0,
  lambda i, j: (i // 2 + j // 3) % 2 == 0,
  lambda i, j: (i * j) % 2 + (i * j) % 3 == 0,
  lambda i, j: ((i * j) % 2 + (i * j) % 3) % 2 == 0,
  lambda i, j: ((i + j) % 2 + (i * j) % 3) % 2 == 0,
]


def _alignment_positions(version: int) -> list[int]:
  if version < 2:
    return []
  dim = version * 4 + 17
  n = version // 7 + 2
  second = _ALIGN2[version - 2]
  step = (dim - 7 - second) // (n - 2) if n > 2 else 0
  return [6] + [second + k * step for k in range(n - 1)]


def _function_mask(version: int) -> np.ndarray:
  dim = version * 4 + 17
  func = np.zeros((dim, dim), dtype=bool)
  func[:9, :9] = func[:9, dim - 8:] = func[dim - 8:, :9] = True
  func[6, :] = func[:, 6] = True
  pos = _alignment_positions(version)
  for r, c in itertools.product(pos, pos):
    if (r, c) in ((6, 6), (6, dim - 7), (dim - 7, 6)):
      continue
    func[r - 2:r + 3, c - 2:c + 3] = True
  if version >= 7:
    func[:6, dim - 11:dim - 8] = func[dim - 11:dim - 8, :6] = True
  return func


def _read_format(m: np.ndarray) -> int:
  dim = m.shape[0]
  # most significant bit first
  a = [(8, i) for i in range(6)] + [(8, 7), (8, 8), (7, 8)] + [(5 - i, 8) for i in range(6)]
  b = [(dim - 1 - i, 8) for i in range(7)] + [(8, dim - 8 + i) for i in range(8)]
  best = None
  for coords in (a, b):
    bits = 0
    for r, c in coords:
      bits = bits << 1 | int(m[r, c])
    idx = _best_match(bits, _FORMATS, 3)
    if idx is not None and (best is None or bin(bits ^ _FORMATS[idx]).count("1") < best[1]):
      best = (idx, bin(bits ^ _FORMATS[idx]).count("1"))
  if best is None:
    raise QRError("bad format info")
  return best[0]


class _Bits:
  def __init__(self, data: list[int]):
    self._data = data
    self._pos = 0

  def remaining(self) -> int:
    return len(self._data) * 8 - self._pos

  def read(self, n: int) -> int:
    if n > self.remaining():
      raise QRError("bitstream underflow")
    v = 0
    for _ in range(n):
      v = v << 1 | (self._data[self._pos >> 3] >> (7 - (self._pos & 7))) & 1
      self._pos += 1
    return v


def _parse_data(data: list[int], version: int) -> str:
  bits = _Bits(data)
  out = bytearray()
  band = 0 if version <= 9 else 1 if version <= 26 else 2
  while bits.remaining() >= 4:
    mode = bits.read(4)
    if mode == 0:
      break
    if mode == 7:  # ECI, assume UTF-8
      first = bits.read(8)
      bits.read(0 if first < 0x80 else 8 if first < 0xC0 else 16)
    elif mode == 1:
      n = bits.read((10, 12, 14)[band])
      while n >= 3:
        out += b"%03d" % bits.read(10)
        n -= 3
      if n == 2:
        out += b"%02d" % bits.read(7)
      elif n == 1:
        out += b"%d" % bits.read(4)
    elif mode == 2:
      n = bits.read((9, 11, 13)[band])
      while n >= 2:
        v = bits.read(11)
        out += (_ALNUM[v // 45] + _ALNUM[v % 45]).encode()
        n -= 2
      if n:
        out += _ALNUM[bits.read(6)].encode()
    elif mode == 4:
      n = bits.read((8, 16, 16)[band])
      out += bytes(bits.read(8) for _ in range(n))
    elif mode == 8:
      n = bits.read((8, 10, 12)[band])
      for _ in range(n):
        v = bits.read(13)
        c = (v // 0xC0) << 8 | v % 0xC0
        c += 0x8140 if c < 0x1F00 else 0xC140
        out += c.to_bytes(2, "big").decode("shift_jis").encode()
    else:
      raise QRError(f"unsupported mode {mode}")
  try:
    return out.decode("utf-8")
  except UnicodeDecodeError:
    return out.decode("latin-1")


def decode_matrix(m: np.ndarray) -> str:
  """Decodes a square boolean module matrix (True = dark) without a quiet zone."""
  dim = m.shape[0]
  if m.shape != (dim, dim) or dim % 4 != 1 or not 21 <= dim <= 177:
    raise QRError("bad matrix size")
  version = (dim - 17) // 4

  fmt = _read_format(m)
  level = {1: 0, 0: 1, 3: 2, 2: 3}[fmt >> 3]
  mask = _MASKS[fmt & 7]
  func = _function_mask(version)

  bits = []
  col, upward = dim - 1, True
  while col > 0:
    if col == 6:
      col -= 1
    for k in range(dim):
      row = dim - 1 - k if upward else k
      for c in (col, col - 1):
        if not func[row, c]:
          bits.append(int(m[row, c]) ^ mask(row, c))
    col -= 2
    upward = not upward

  codewords = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits) - 7, 8)]
  ec, nblocks = _EC[version - 1][level]
  data_total = len(codewords) - ec * nblocks
  short = data_total // nblocks
  lens = [short + (1 if i >= nblocks - data_total % nblocks else 0) for i in range(nblocks)]
  blocks: list[list[int]] = [[] for _ in range(nblocks)]
  idx = 0
  for i in range(max(lens)):
    for b in range(nblocks):
      if i < lens[b]:
        blocks[b].append(codewords[idx])
        idx += 1
  for _ in range(ec):
    for b in range(nblocks):
      blocks[b].append(codewords[idx])
      idx += 1

  data: list[int] = []
  for block, n in zip(blocks, lens, strict=True):
    data += _rs_correct(block, ec)[:n]
  return _parse_data(data, version)


# ---- image processing ----

def _binarize(gray: np.ndarray) -> np.ndarray:
  h, w = gray.shape
  B = max(8, min(h, w) // 64)
  H, W = h // B, w // B
  if H < 1 or W < 1:
    raise QRError("image too small")
  blocks = gray[:H * B, :W * B].reshape(H, B, W, B).mean(axis=(1, 3))
  padded = np.pad(blocks, 2, mode="edge")
  cs = np.pad(np.cumsum(np.cumsum(padded, 0), 1), ((1, 0), (1, 0)))
  local = (cs[5:, 5:] - cs[:-5, 5:] - cs[5:, :-5] + cs[:-5, :-5]) / 25
  thr = np.repeat(np.repeat(local, B, 0), B, 1)
  out = np.zeros((h, w), dtype=bool)
  out[:H * B, :W * B] = gray[:H * B, :W * B] < thr
  return out


def _runs(line: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
  change = np.flatnonzero(line[1:] != line[:-1]) + 1
  starts = np.concatenate(([0], change))
  lengths = np.diff(np.concatenate((starts, [line.size])))
  return starts, lengths


def _ratio_ok(lengths: np.ndarray, ratios: tuple[int, ...]) -> np.ndarray:
  module = lengths.sum(axis=-1) / sum(ratios)
  ok = module >= 2
  for k, r in enumerate(ratios):
    ok &= np.abs(lengths[..., k] - r * module) <= r * module / 2
  return ok


def _find_patterns(binary: np.ndarray, ratios: tuple[int, ...]) -> list[tuple[float, float, float]]:
  """Finds dark/light run patterns with the given module ratios. Returns (x, y, module size)."""
  h, w = binary.shape
  padded = np.zeros((h, w + 2), dtype=bool)
  padded[:, 1:-1] = binary
  starts, lengths = _runs(padded.ravel())
  n, half = len(ratios), len(ratios) // 2
  if len(starts) < n:
    return []

  first = np.arange(len(starts) - n + 1)
  first = first[padded.ravel()[starts[first]]]
  L = np.stack([lengths[first + k] for k in range(n)], axis=1).astype(float)
  ok = _ratio_ok(L, ratios) & (starts[first] // (w + 2) == starts[first + n - 1] // (w + 2))
  first, L = first[ok], L[ok]
  rows = starts[first] // (w + 2)
  cxs = starts[first + half] % (w + 2) - 1 + L[:, half] / 2
  mods = L.sum(axis=1) / sum(ratios)

  # cheap vertical probe of the center run and the first light run before the full cross check
  probes = [(ratios[half] * 0.25, True), (ratios[half] / 2 + ratios[half + 1] / 2, False)]
  keep = np.ones(len(rows), dtype=bool)
  xi = cxs.astype(int)
  for off, dark in probes:
    for sign in (1, -1):
      y = np.rint(rows + sign * off * mods).astype(int)
      keep &= (y >= 0) & (y < h) & (binary[np.clip(y, 0, h - 1), xi] == dark)
  rows, cxs, mods = rows[keep], cxs[keep], mods[keep]

  found: list[list[float]] = []  # [x, y, module, count]
  for row, cx, hmod in zip(rows, cxs, mods, strict=True):
    for f in found:
      if abs(f[0] - cx) <= f[2] and abs(f[1] - row) <= f[2] * 2:
        f[3] += 1
        break
    else:
      v = _cross_check(binary[:, int(cx)], row, ratios, hmod)
      if v is None:
        continue
      cy, vmod = v
      hz = _cross_check(binary[int(cy), :], int(cx), ratios, vmod)
      if hz is None:
        continue
      found.append([hz[0], cy, (hmod + vmod) / 2, 1])
  found.sort(key=lambda f: -f[3])
  return [(f[0], f[1], f[2]) for f in found if f[3] >= 2]


def _cross_check(line: np.ndarray, pos: int, ratios: tuple[int, ...], expected: float) -> tuple[float, float] | None:
  span = int(expected * sum(ratios))
  lo = max(0, pos - span)
  line = line[lo:pos + span]
  pos -= lo
  starts, lengths = _runs(line)
  i = int(np.searchsorted(starts, pos, side="right")) - 1
  half = len(ratios) // 2
  if not line[starts[i]] or i - half < 0 or i + half >= len(starts):
    return None
  L = lengths[i - half:i + half + 1].astype(float)
  module = L.sum() / sum(ratios)
  if not _ratio_ok(L, ratios) or not 0.5 <= module / expected <= 2:
    return None
  return float(lo + starts[i] + L[half] / 2), float(module)


def _perspective(src: list[tuple[float, float]], dst: list[tuple[float, float]]) -> np.ndarray:
  A, b = [], []
  for (x, y), (u, v) in zip(src, dst, strict=True):
    A.append([x, y, 1, 0, 0, 0, -u * x, -u * y])
    b.append(u)
    A.append([0, 0, 0, x, y, 1, -v * x, -v * y])
    b.append(v)
  try:
    h = np.linalg.solve(np.array(A, dtype=float), np.array(b, dtype=float))
  except np.linalg.LinAlgError as e:
    raise QRError("degenerate geometry") from e
  return np.append(h, 1).reshape(3, 3)


def _transform(H: np.ndarray, pts: np.ndarray) -> np.ndarray:
  p = np.column_stack((pts, np.ones(len(pts)))) @ H.T
  return p[:, :2] / p[:, 2:3]


def _pick_finders(patterns: list[tuple[float, float, float]]) -> tuple[np.ndarray, np.ndarray, np.ndarray, float]:
  """Returns (top-left, top-right, bottom-left) centers and the module size of the most square-looking triple."""
  best = None
  for a, b, c in itertools.combinations(patterns[:10], 3):
    mods = sorted((a[2], b[2], c[2]))
    if mods[2] / mods[0] > 1.5:
      continue
    pts = [np.array(p[:2]) for p in (a, b, c)]
    d = [np.linalg.norm(pts[(i + 1) % 3] - pts[(i + 2) % 3]) for i in range(3)]
    tl = int(np.argmax(d))  # opposite the hypotenuse
    p1, p2 = pts[(tl + 1) % 3], pts[(tl + 2) % 3]
    v1, v2 = p1 - pts[tl], p2 - pts[tl]
    n1, n2 = np.linalg.norm(v1), np.linalg.norm(v2)
    if n1 == 0 or n2 == 0:
      continue
    cos = abs(np.dot(v1, v2)) / (n1 * n2)
    if cos > 0.35 or not 0.6 <= n1 / n2 <= 1.6:
      continue
    score = cos + abs(np.log(n1 / n2)) + np.log(mods[2] / mods[0])
    if best is not None and score >= best[0]:
      continue
    if v1[0] * v2[1] - v1[1] * v2[0] < 0:
      p1, p2 = p2, p1
    best = (score, pts[tl], p1, p2, float(sum(mods) / 3))
  if best is None:
    raise QRError("no finder patterns")
  return best[1:]


_ALIGN_TEMPLATE = np.ones((5, 5), dtype=bool)
_ALIGN_TEMPLATE[1:4, 1:4] = False
_ALIGN_TEMPLATE[2, 2] = True


def _locate_alignment(binary: np.ndarray, est: np.ndarray, module: float) -> np.ndarray | None:
  """Template matches the 5x5 alignment pattern around the estimated center."""
  h, w = binary.shape
  r = int(module * 5)
  ys = np.arange(max(0, int(est[1]) - r), min(h, int(est[1]) + r))
  xs = np.arange(max(0, int(est[0]) - r), min(w, int(est[0]) + r))
  offs = (np.arange(5) - 2) * module
  sy = np.rint(ys[:, None] + offs[None, :]).astype(int)
  sx = np.rint(xs[:, None] + offs[None, :]).astype(int)
  in_y, in_x = (sy[:, 0] >= 0) & (sy[:, -1] < h), (sx[:, 0] >= 0) & (sx[:, -1] < w)
  ys, sy, xs, sx = ys[in_y], sy[in_y], xs[in_x], sx[in_x]
  if len(ys) == 0 or len(xs) == 0:
    return None
  samples = binary[sy[:, None, :, None], sx[None, :, None, :]]
  score = (samples == _ALIGN_TEMPLATE).sum(axis=(2, 3))
  if score.max() < 23:
    return None
  hits = np.argwhere(score == score.max())
  centers = np.column_stack((xs[hits[:, 1]], ys[hits[:, 0]])).astype(float)
  closest = centers[np.argmin(np.linalg.norm(centers - est, axis=1))]
  return centers[np.linalg.norm(centers - closest, axis=1) <= module / 2].mean(axis=0)


def _sample(binary: np.ndarray, tl: np.ndarray, tr: np.ndarray, bl: np.ndarray, module: float, dim: int, use_alignment: bool) -> np.ndarray:
  src = [(3.5, 3.5), (dim - 3.5, 3.5), (3.5, dim - 3.5)]
  dst = [tuple(tl), tuple(tr), tuple(bl)]
  H = _perspective(src + [(dim - 3.5, dim - 3.5)], dst + [tuple(tr + bl - tl)])
  if use_alignment and dim > 21:
    est = _transform(H, np.array([[dim - 6.5, dim - 6.5]]))[0]
    align = _locate_alignment(binary, est, module)
    if align is not None:
      H = _perspective(src + [(dim - 6.5, dim - 6.5)], dst + [tuple(align)])

  rows, cols = np.mgrid[0:dim, 0:dim]
  pts = _transform(H, np.column_stack((cols.ravel() + 0.5, rows.ravel() + 0.5)))
  xy = np.rint(pts).astype(int)
  h, w = binary.shape
  if (xy < 0).any() or (xy[:, 0] >= w).any() or (xy[:, 1] >= h).any():
    raise QRError("code extends outside image")
  return binary[xy[:, 1], xy[:, 0]].reshape(dim, dim)


def decode(gray: np.ndarray) -> str | None:
  """Decodes the QR code in a 2D uint8 grayscale image. Returns None if nothing could be decoded."""
  try:
    binary = _binarize(gray)
    tl, tr, bl, module = _pick_finders(_find_patterns(binary, (1, 1, 3, 1, 1)))
  except QRError:
    return None

  d = (np.linalg.norm(tr - tl) + np.linalg.norm(bl - tl)) / 2
  dim = int(round((d / module + 7 - 17) / 4)) * 4 + 17
  for cand in (dim, dim - 4, dim + 4):
    if not 21 <= cand <= 177:
      continue
    for use_alignment in (True, False):
      try:
        m = _sample(binary, tl, tr, bl, module, cand, use_alignment)
      except QRError:
        continue
      for mat in (m, m.T):
        try:
          return decode_matrix(mat)
        except QRError:
          pass
  return None
