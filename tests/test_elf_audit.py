import pytest

from app.elf_audit import ElfAuditError, audit_elf, hardening_score, is_elf
from app.samples import build_elf


def audit(tmp_path, **kw):
    arch = kw.pop("arch", "MIPS")
    p = tmp_path / "bin"
    p.write_bytes(build_elf(arch, **kw))
    return audit_elf(p)


@pytest.mark.parametrize("arch,bits,endian,label", [
    ("MIPS", 32, "big", "MIPS"), ("ARM32", 32, "little", "ARM32"),
    ("ARM64", 64, "little", "ARM64"), ("x86_64", 64, "little", "x86_64"), ("x86", 32, "little", "x86"),
])
def test_architecture_bits_endianness(tmp_path, arch, bits, endian, label):
    a = audit(tmp_path, arch=arch)
    assert (a["architecture"], a["bits"], a["endianness"]) == (label, bits, endian)


def test_mipsel_detected(tmp_path):
    assert audit(tmp_path, arch="MIPS", little=True)["architecture"] == "MIPSEL"


def test_unhardened_binary(tmp_path):
    a = audit(tmp_path, nx=False, relro="none", canary=False, kind="exec")
    assert a["nx"] is False and a["pie"] is False and a["relro"] == "none"
    assert a["stack_canary"] is False and a["fortify"] is False
    assert a["writable_executable_segment"] is False
    assert hardening_score(a) == 0


def test_fully_hardened_pie_binary(tmp_path):
    a = audit(tmp_path, kind="pie", nx=True, relro="full", canary=True, fortify=True)
    assert a["nx"] is True and a["pie"] is True and a["relro"] == "full"
    assert a["stack_canary"] and a["fortify"]
    assert hardening_score(a) == 5


def test_partial_relro_and_wx(tmp_path):
    a = audit(tmp_path, relro="partial", wx=True)
    assert a["relro"] == "partial" and a["writable_executable_segment"] is True


def test_shared_library_is_not_pie(tmp_path):
    a = audit(tmp_path, kind="lib", needed=())
    assert a["is_library"] and a["kind"] == "shared library" and a["pie"] is False
    assert a["interpreter"] is None


def test_imports_and_needed_libs(tmp_path):
    a = audit(tmp_path, imports=["strcpy", "system"], needed=("libc.so.6", "libm.so.6"))
    assert {"strcpy", "system"} <= set(a["imports"])
    assert a["needed"] == ["libc.so.6", "libm.so.6"]
    assert a["interpreter"] == "/lib/ld.so.1"


def test_stripped_flag(tmp_path):
    assert audit(tmp_path, symtab=False)["stripped"] is True
    assert audit(tmp_path, symtab=True)["stripped"] is False


def test_non_elf_returns_none_and_corrupt_raises(tmp_path):
    p = tmp_path / "t.txt"
    p.write_text("hello")
    assert audit_elf(p) is None and not is_elf(p)
    bad = tmp_path / "bad"
    bad.write_bytes(b"\x7fELF\x02\x01\x01" + b"\xff" * 40)
    with pytest.raises(ElfAuditError):
        audit_elf(bad)
