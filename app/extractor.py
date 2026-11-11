"""Safe, bounded firmware unpacking. Archive members are written as plain data files
(never executed, no symlinks, no device nodes, no path traversal)."""
from __future__ import annotations

import gzip
import math
import os
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import zipfile
from collections import Counter
from pathlib import Path


class LimitReached(Exception):
    """Raised internally when a size / file-count quota is hit."""


class Budget:
    def __init__(self, max_files: int, max_bytes: int) -> None:
        self.max_files, self.max_bytes = max_files, max_bytes
        self.files = 0
        self.bytes = 0
        self.skipped = 0
        self.notes: list[str] = []
        self.incomplete = False

    def add_file(self) -> None:
        self.files += 1
        if self.files > self.max_files:
            raise LimitReached("file-count limit reached")

    def add_bytes(self, n: int) -> None:
        self.bytes += n
        if self.bytes > self.max_bytes:
            raise LimitReached("extracted-size limit reached")


def safe_join(root: Path, name: str) -> Path | None:
    name = str(name).replace("\\", "/")
    if not name or "\x00" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    dest = root.joinpath(*parts)
    try:
        dest.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return None
    return dest


def _copy_limited(src, dest: Path, budget: Budget) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as out:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            budget.add_bytes(len(chunk))
            out.write(chunk)


# ---------------------------------------------------------------- signatures
def _valid_squashfs(blob: bytes, off: int) -> bool:
    if off + 96 > len(blob):
        return False
    try:
        block_size = struct.unpack_from("<I", blob, off + 12)[0]
        major = struct.unpack_from("<H", blob, off + 28)[0]
    except struct.error:
        return False
    return major in (3, 4) and 4096 <= block_size <= 1 << 20 and block_size & (block_size - 1) == 0


def find_squashfs(blob: bytes) -> int | None:
    for magic in (b"hsqs", b"sqsh"):
        start = 0
        while True:
            off = blob.find(magic, start)
            if off < 0:
                break
            if _valid_squashfs(blob, off):
                return off
            start = off + 1
    return None


def detect_signatures(blob: bytes) -> list[dict]:
    hits: list[dict] = []
    sq = find_squashfs(blob)
    if sq is not None:
        hits.append({"name": "SquashFS", "offset": sq})
    if blob[:4] in (b"\x45\x3d\xcd\x28", b"\x28\xcd\x3d\x45"):
        hits.append({"name": "CramFS", "offset": 0})
    for name, pat in (("UBI", b"UBI#"),):
        off = blob.find(pat)
        if off >= 0:
            hits.append({"name": name, "offset": off})
    for pat in (b"\x85\x19\x01\xe0", b"\x85\x19\x02\xe0", b"\x85\x19\x03\x20", b"\x19\x85\xe0\x01", b"\x19\x85\xe0\x02"):
        off = blob.find(pat)
        if off >= 0:
            hits.append({"name": "JFFS2", "offset": off})
            break
    if len(blob) > 1082 and blob[1080:1082] == b"\x53\xef":
        hits.append({"name": "ext2/3/4", "offset": 1024})
    if blob[:4] == b"\x27\x05\x19\x56":
        hits.append({"name": "U-Boot uImage", "offset": 0})
    for name, pat in (("Device tree (FDT)", b"\xd0\x0d\xfe\xed"), ("gzip stream", b"\x1f\x8b\x08"), ("ZIP", b"PK\x03\x04")):
        off = blob.find(pat)
        if off >= 0:
            hits.append({"name": name, "offset": off})
    if blob[:4] == b"\x7fELF":
        hits.append({"name": "ELF", "offset": 0})
    if blob[:6] in (b"070701", b"070702"):
        hits.append({"name": "CPIO (newc)", "offset": 0})
    return hits


def entropy_of(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in Counter(data).values()), 3)


def entropy_profile(blob: bytes, bins: int = 48) -> list[float]:
    if not blob:
        return []
    size = max(4096, len(blob) // bins)
    out = []
    for i in range(0, len(blob), size):
        out.append(entropy_of(blob[i:i + min(size, 65536)]))
        if len(out) >= bins:
            break
    return out


# ---------------------------------------------------------------- extractors
def _extract_zip(src: Path, dest: Path, budget: Budget) -> None:
    with zipfile.ZipFile(src) as z:
        for info in z.infolist():
            target = safe_join(dest, info.filename)
            if target is None:
                budget.skipped += 1
                continue
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                budget.skipped += 1
                continue
            budget.add_file()
            try:
                with z.open(info) as s:
                    _copy_limited(s, target, budget)
            except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
                budget.skipped += 1


def _extract_tar(src: Path, dest: Path, budget: Budget) -> None:
    with tarfile.open(src, "r:*") as t:
        for m in t:
            target = safe_join(dest, m.name)
            if target is None:
                budget.skipped += 1
                continue
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not m.isfile():  # symlinks, hardlinks, devices, fifos
                budget.skipped += 1
                continue
            budget.add_file()
            s = t.extractfile(m)
            if s is None:
                budget.skipped += 1
                continue
            try:
                with s:
                    _copy_limited(s, target, budget)
            except OSError:
                budget.skipped += 1


def _extract_gzip(src: Path, dest: Path, budget: Budget) -> None:
    name = src.name
    out_name = name[:-3] if name.lower().endswith(".gz") else name + ".out"
    target = safe_join(dest, out_name) or dest / "decompressed.bin"
    budget.add_file()
    with gzip.open(src, "rb") as s:
        _copy_limited(s, target, budget)


def _align4(v: int) -> int:
    return (v + 3) & ~3


def _extract_cpio(src: Path, dest: Path, budget: Budget) -> None:
    blob = src.read_bytes()
    pos = 0
    while pos + 110 <= len(blob):
        if blob[pos:pos + 6] not in (b"070701", b"070702"):
            break
        try:
            f = [int(blob[pos + 6 + i * 8: pos + 14 + i * 8], 16) for i in range(13)]
        except ValueError:
            break
        mode, size, namesize = f[1], f[6], f[11]
        name_start = pos + 110
        name_end = name_start + namesize
        data_start = _align4(name_end)
        data_end = data_start + size
        if namesize < 1 or data_end > len(blob):
            break
        name = blob[name_start:name_end].split(b"\0", 1)[0].decode("utf-8", "replace")
        pos = _align4(data_end)
        if name == "TRAILER!!!":
            break
        target = safe_join(dest, name)
        kind = mode & 0o170000
        if target is None:
            budget.skipped += 1
        elif kind == 0o040000:
            target.mkdir(parents=True, exist_ok=True)
        elif kind == 0o100000:
            budget.add_file()
            budget.add_bytes(size)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob[data_start:data_end])
        else:
            budget.skipped += 1


def _extract_squashfs(src: Path, dest: Path, offset: int, budget: Budget) -> str:
    tool = shutil.which("unsquashfs")
    if not tool:
        budget.notes.append("SquashFS detected but 'unsquashfs' (squashfs-tools) is not installed; filesystem not reconstructed.")
        budget.incomplete = True
        return "SquashFS (not extracted)"
    carved: Path | None = None
    image = src
    if offset:
        fd, tmp = tempfile.mkstemp(suffix=".sqfs")
        with os.fdopen(fd, "wb") as out, open(src, "rb") as s:
            s.seek(offset)
            shutil.copyfileobj(s, out)
        carved = image = Path(tmp)
    try:
        subprocess.run([tool, "-f", "-no-progress", "-d", str(dest), str(image)],
                       capture_output=True, timeout=120, check=False)
        # unsquashfs may create symlinks: strip them, they are never followed.
        for root, dirs, files in os.walk(dest):
            for n in list(dirs) + files:
                p = Path(root, n)
                if p.is_symlink():
                    p.unlink()
        return "SquashFS (unsquashfs)"
    except (subprocess.TimeoutExpired, OSError):
        budget.notes.append("unsquashfs failed or timed out.")
        budget.incomplete = True
        return "SquashFS (extraction failed)"
    finally:
        if carved:
            carved.unlink(missing_ok=True)


def extract_any(src: Path, dest: Path, budget: Budget, depth: int = 0) -> str:
    """Unpack `src` into `dest`. Returns a human-readable container label."""
    dest.mkdir(parents=True, exist_ok=True)
    head = src.read_bytes()[:4096] if src.stat().st_size else b""
    try:
        if zipfile.is_zipfile(src):
            _extract_zip(src, dest, budget)
            label = "ZIP archive"
        elif head[:6] in (b"070701", b"070702"):
            _extract_cpio(src, dest, budget)
            label = "CPIO archive (newc)"
        elif tarfile.is_tarfile(src):
            _extract_tar(src, dest, budget)
            label = "TAR archive"
        elif head[:2] == b"\x1f\x8b":
            _extract_gzip(src, dest, budget)
            label = "gzip stream"
        else:
            blob = src.read_bytes()
            sq = find_squashfs(blob)
            if sq is not None:
                label = _extract_squashfs(src, dest, sq, budget)
            else:
                budget.add_file()
                shutil.copyfile(src, dest / "firmware-image.bin")
                label = "Raw firmware image"
                budget.notes.append("No supported container found; image kept as one raw file.")
    except LimitReached as e:
        budget.incomplete = True
        budget.notes.append(f"Extraction stopped: {e}.")
        return "Partially extracted"
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, gzip.BadGzipFile) as e:
        budget.incomplete = True
        budget.notes.append(f"Extraction error ({type(e).__name__}); falling back to raw file.")
        budget.add_file()
        shutil.copyfile(src, dest / "firmware-image.bin")
        return "Raw firmware image"

    if depth < 2:  # multi-stage packaging (e.g. ZIP -> rootfs.tar.gz)
        for p in sorted(dest.rglob("*")):
            if budget.incomplete or not p.is_file() or p.is_symlink():
                continue
            try:
                with open(p, "rb") as fh:
                    magic = fh.read(4)
                is_nested = (
                    p.name.lower().endswith((".tar", ".tar.gz", ".tgz", ".cpio", ".sqfs", ".squashfs", ".gz"))
                    and (magic[:2] == b"\x1f\x8b" or magic[:4] in (b"hsqs", b"sqsh", b"PK\x03\x04") or tarfile.is_tarfile(p))
                )
            except OSError:
                continue
            if is_nested:
                sub = p.with_name(p.name + "_extracted")
                try:
                    extract_any(p, sub, budget, depth + 1)
                    p.unlink()
                except OSError:
                    pass
    return label
