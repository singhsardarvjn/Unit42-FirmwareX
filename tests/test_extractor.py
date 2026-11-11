import gzip
import io
import stat
import tarfile
import zipfile

from app.extractor import Budget, detect_signatures, entropy_of, entropy_profile, extract_any, safe_join


def new_budget(files=1000, size=10_000_000):
    return Budget(files, size)


def test_safe_join_rejects_unsafe_paths(tmp_path):
    for bad in ["../x", "a/../../x", "/etc/passwd", "C:\\win\\x", "", "a\x00b", "..\\x"]:
        assert safe_join(tmp_path, bad) is None
    assert safe_join(tmp_path, "etc/config.txt") == tmp_path / "etc" / "config.txt"
    assert safe_join(tmp_path, "./a//b") == tmp_path / "a" / "b"


def test_zip_extraction_and_traversal_skipped(tmp_path):
    src = tmp_path / "f.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.writestr("etc/a.txt", "hello")
        z.writestr("../evil.txt", "bad")
        z.writestr("/abs.txt", "bad")
    b = new_budget()
    out = tmp_path / "out"
    assert extract_any(src, out, b) == "ZIP archive"
    assert (out / "etc" / "a.txt").read_text() == "hello"
    assert not (tmp_path / "evil.txt").exists()
    assert b.skipped == 2


def test_zip_symlink_skipped(tmp_path):
    src = tmp_path / "f.zip"
    with zipfile.ZipFile(src, "w") as z:
        info = zipfile.ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, "/etc/passwd")
        z.writestr("ok.txt", "x")
    out = tmp_path / "out"
    b = new_budget()
    extract_any(src, out, b)
    assert not (out / "link").exists() and (out / "ok.txt").exists()
    assert b.skipped == 1


def test_tar_gz_extraction_skips_links_and_devices(tmp_path):
    src = tmp_path / "f.tar.gz"
    with tarfile.open(src, "w:gz") as t:
        data = b"content"
        ti = tarfile.TarInfo("bin/tool")
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
        sym = tarfile.TarInfo("bin/link")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "/etc/passwd"
        t.addfile(sym)
        esc = tarfile.TarInfo("../../escape")
        esc.size = 1
        t.addfile(esc, io.BytesIO(b"x"))
    out = tmp_path / "out"
    b = new_budget()
    assert extract_any(src, out, b) == "TAR archive"
    assert (out / "bin" / "tool").read_bytes() == b"content"
    assert not (out / "bin" / "link").exists()
    assert b.skipped == 2


def test_gzip_single_file(tmp_path):
    src = tmp_path / "fw.bin.gz"
    src.write_bytes(gzip.compress(b"firmware-bytes"))
    out = tmp_path / "out"
    assert extract_any(src, out, new_budget()) == "gzip stream"
    assert (out / "fw.bin").read_bytes() == b"firmware-bytes"


def test_nested_archive_is_unpacked(tmp_path):
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w:gz") as t:
        d = b"deep"
        ti = tarfile.TarInfo("etc/deep.txt")
        ti.size = len(d)
        t.addfile(ti, io.BytesIO(d))
    src = tmp_path / "outer.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.writestr("rootfs.tar.gz", inner.getvalue())
    out = tmp_path / "out"
    extract_any(src, out, new_budget())
    assert (out / "rootfs.tar.gz_extracted" / "etc" / "deep.txt").read_bytes() == b"deep"


def test_cpio_newc(tmp_path):
    def entry(name, data, mode=0o100644):
        nm = name.encode() + b"\0"
        h = "070701" + "".join("%08X" % v for v in [1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0])
        out = h.encode() + nm
        out += b"\0" * ((4 - len(out) % 4) % 4) + data
        return out + b"\0" * ((4 - len(out) % 4) % 4)

    src = tmp_path / "f.cpio"
    src.write_bytes(entry("etc/x.conf", b"abc") + entry("TRAILER!!!", b""))
    out = tmp_path / "out"
    assert extract_any(src, out, new_budget()) == "CPIO archive (newc)"
    assert (out / "etc" / "x.conf").read_bytes() == b"abc"


def test_raw_image_kept_as_single_file(tmp_path):
    src = tmp_path / "raw.bin"
    src.write_bytes(b"\x00\x01\x02" * 100)
    b = new_budget()
    out = tmp_path / "out"
    assert extract_any(src, out, b) == "Raw firmware image"
    assert (out / "firmware-image.bin").exists() and b.notes


def test_file_count_limit_marks_incomplete(tmp_path):
    src = tmp_path / "many.zip"
    with zipfile.ZipFile(src, "w") as z:
        for i in range(10):
            z.writestr(f"f{i}.txt", "x")
    b = Budget(3, 10_000)
    assert extract_any(src, tmp_path / "out", b) == "Partially extracted"
    assert b.incomplete


def test_size_limit_stops_zip_bomb(tmp_path):
    src = tmp_path / "bomb.zip"
    with zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("big.bin", b"\0" * 5_000_000)
    b = Budget(100, 100_000)
    extract_any(src, tmp_path / "out", b)
    assert b.incomplete and b.bytes <= 100_000 + 1024 * 1024


def test_corrupt_zip_falls_back_to_raw(tmp_path):
    src = tmp_path / "bad.zip"
    src.write_bytes(b"PK\x03\x04" + b"garbage" * 50)
    b = new_budget()
    extract_any(src, tmp_path / "out", b)
    assert (tmp_path / "out").exists()


def test_signature_detection_and_entropy():
    import struct
    sq = bytearray(200)
    sq[0:4] = b"hsqs"
    struct.pack_into("<I", sq, 12, 131072)
    struct.pack_into("<H", sq, 28, 4)
    blob = b"\0" * 64 + bytes(sq)
    names = [s["name"] for s in detect_signatures(blob)]
    assert "SquashFS" in names
    assert "SquashFS" not in [s["name"] for s in detect_signatures(b"hsqs" + b"\0" * 300)]  # invalid header
    assert entropy_of(b"\0" * 1000) == 0.0
    assert entropy_of(bytes(range(256)) * 4) == 8.0
    assert len(entropy_profile(b"\x01" * 100000)) <= 48
