"""Builds small *synthetic* ELF files and a demo firmware ZIP.

Nothing here is real firmware or real malware: the ELF files are structurally valid
headers with symbol tables only (no code), and every credential is an obvious dummy.
They exist so the analyser, tests and dashboard can be demonstrated offline.
"""
from __future__ import annotations

import base64
import hashlib
import io
import struct
import zipfile

MACHINES = {"MIPS": 8, "ARM32": 40, "ARM64": 183, "x86_64": 62, "x86": 3}


def _align(n: int, a: int = 8) -> int:
    return (n + a - 1) // a * a


class _StrTab:
    def __init__(self) -> None:
        self.data = bytearray(b"\0")
        self.offsets: dict[str, int] = {}

    def add(self, s: str) -> int:
        if s not in self.offsets:
            self.offsets[s] = len(self.data)
            self.data += s.encode() + b"\0"
        return self.offsets[s]


def build_elf(
    arch: str = "MIPS",
    *,
    little: bool | None = None,
    kind: str = "exec",  # exec | pie | lib
    imports: tuple[str, ...] | list[str] = (),
    nx: bool = True,
    relro: str = "none",  # none | partial | full
    canary: bool = False,
    fortify: bool = False,
    wx: bool = False,
    symtab: bool = False,
    needed: tuple[str, ...] = ("libc.so.6",),
    filler: bytes = b"",
) -> bytes:
    bits = 64 if arch in ("ARM64", "x86_64") else 32
    if little is None:
        little = arch != "MIPS"
    e = "<" if little else ">"
    machine = MACHINES[arch]
    etype = 2 if kind == "exec" else 3
    has_interp = kind in ("exec", "pie")

    imps = list(imports)
    if canary:
        imps.append("__stack_chk_fail")
    if fortify:
        imps.append("__memcpy_chk")

    ehsize, phsize, shsize, symsize = (52, 32, 40, 16) if bits == 32 else (64, 56, 64, 24)
    dynsize = 8 if bits == 32 else 16

    dynstr = _StrTab()
    for n in needed:
        dynstr.add(n)
    for n in imps:
        dynstr.add(n)

    interp = b"/lib/ld.so.1\0" if has_interp else b""

    phnum = 3 + (1 if has_interp else 0) + (1 if relro != "none" else 0)  # LOAD, DYNAMIC, STACK
    pos = ehsize + phsize * phnum
    interp_off = pos
    pos = _align(pos + len(interp))
    dynstr_off = pos
    pos = _align(pos + len(dynstr.data))
    dynsym_off = pos
    nsyms = 1 + len(imps)
    pos = _align(pos + nsyms * symsize)

    dyn_entries = [(1, dynstr.offsets[n]) for n in needed]
    dyn_entries += [(5, dynstr_off), (6, dynsym_off)]
    if relro == "full":
        dyn_entries.append((24, 0))  # DT_BIND_NOW
    dyn_entries.append((0, 0))
    dynamic_off = pos
    pos = _align(pos + len(dyn_entries) * dynsize)

    strtab = _StrTab()
    symtab_off = strtab_off = 0
    if symtab:
        strtab.add("main")
        symtab_off = pos
        pos = _align(pos + 2 * symsize)
        strtab_off = pos
        pos = _align(pos + len(strtab.data))

    filler_off = pos
    pos = _align(pos + len(filler))

    shstr = _StrTab()
    names = [".dynstr", ".dynsym", ".dynamic"] + ([".symtab", ".strtab"] if symtab else []) + [".shstrtab"]
    for n in names:
        shstr.add(n)
    shstr_off = pos
    pos = _align(pos + len(shstr.data))
    shoff = pos
    shnum = 1 + len(names)
    total = shoff + shnum * shsize
    buf = bytearray(total)

    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if little else 2, 1, 0]) + b"\0" * 8
    if bits == 32:
        hdr = struct.pack(e + "HHIIIIIHHHHHH", etype, machine, 1, 0, ehsize, shoff, 0, ehsize, phsize, phnum, shsize, shnum, shnum - 1)
    else:
        hdr = struct.pack(e + "HHIQQQIHHHHHH", etype, machine, 1, 0, ehsize, shoff, 0, ehsize, phsize, phnum, shsize, shnum, shnum - 1)
    buf[0:ehsize] = ident + hdr

    def ph(ptype: int, flags: int, off: int, size: int) -> bytes:
        if bits == 32:
            return struct.pack(e + "IIIIIIII", ptype, off, off, off, size, size, flags, 8)
        return struct.pack(e + "IIQQQQQQ", ptype, flags, off, off, off, size, size, 8)

    phdrs = []
    if has_interp:
        phdrs.append(ph(3, 4, interp_off, len(interp)))
    phdrs.append(ph(1, 7 if wx else 5, 0, total))
    phdrs.append(ph(2, 6, dynamic_off, len(dyn_entries) * dynsize))
    phdrs.append(ph(0x6474E551, 6 if nx else 7, 0, 0))
    if relro != "none":
        phdrs.append(ph(0x6474E552, 4, 0, 0))
    for i, p in enumerate(phdrs):
        buf[ehsize + i * phsize: ehsize + (i + 1) * phsize] = p

    buf[interp_off: interp_off + len(interp)] = interp
    buf[dynstr_off: dynstr_off + len(dynstr.data)] = dynstr.data

    def sym(name_off: int, defined: bool) -> bytes:
        info, shndx = (0x12, 3 if defined else 0)
        if bits == 32:
            return struct.pack(e + "IIIBBH", name_off, 0, 0, info, 0, shndx)
        return struct.pack(e + "IBBHQQ", name_off, info, 0, shndx, 0, 0)

    syms = bytes(symsize) + b"".join(sym(dynstr.offsets[n], False) for n in imps)
    buf[dynsym_off: dynsym_off + len(syms)] = syms

    dyn = b"".join(struct.pack(e + ("II" if bits == 32 else "QQ"), t, v) for t, v in dyn_entries)
    buf[dynamic_off: dynamic_off + len(dyn)] = dyn
    if symtab:
        st = bytes(symsize) + sym(strtab.offsets["main"], True)
        buf[symtab_off: symtab_off + len(st)] = st
        buf[strtab_off: strtab_off + len(strtab.data)] = strtab.data
    buf[filler_off: filler_off + len(filler)] = filler
    buf[shstr_off: shstr_off + len(shstr.data)] = shstr.data

    def sh(name: str, stype: int, off: int, size: int, link: int = 0, info: int = 0, entsize: int = 0) -> bytes:
        n = shstr.offsets[name]
        if bits == 32:
            return struct.pack(e + "IIIIIIIIII", n, stype, 0, off, off, size, link, info, 8, entsize)
        return struct.pack(e + "IIQQQQIIQQ", n, stype, 0, off, off, size, link, info, 8, entsize)

    secs = [
        bytes(shsize),
        sh(".dynstr", 3, dynstr_off, len(dynstr.data)),
        sh(".dynsym", 11, dynsym_off, len(syms), link=1, info=1, entsize=symsize),
        sh(".dynamic", 6, dynamic_off, len(dyn), link=1, entsize=dynsize),
    ]
    if symtab:
        secs.append(sh(".symtab", 2, symtab_off, 2 * symsize, link=5, info=1, entsize=symsize))
        secs.append(sh(".strtab", 3, strtab_off, len(strtab.data)))
    secs.append(sh(".shstrtab", 3, shstr_off, len(shstr.data)))
    for i, s in enumerate(secs):
        buf[shoff + i * shsize: shoff + (i + 1) * shsize] = s
    return bytes(buf)


def _dummy_pem() -> bytes:
    body = base64.b64encode(hashlib.sha256(b"firmwarex-demo-not-a-real-key").digest() * 3).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----\n").encode()


def sample_files() -> dict[str, bytes]:
    return {
        "bin/httpd": build_elf(
            "MIPS", kind="exec", nx=True, relro="none", canary=False,
            imports=["strcpy", "sprintf", "system", "popen", "getenv", "recv", "memcpy", "MD5_Init", "printf"],
            filler=b"Server: demo-httpd/1.0\nDEMO api_key=DEMO_NOT_A_REAL_KEY_123456\n",
        ),
        "bin/busybox": build_elf(
            "ARM32", kind="exec", nx=True, relro="partial", canary=False, symtab=True,
            imports=["strcat", "system", "fgets", "read", "gets"],
        ),
        "sbin/sshd": build_elf(
            "ARM32", kind="pie", nx=True, relro="full", canary=True, fortify=True,
            imports=["strncpy", "read", "write", "snprintf"],
        ),
        "usr/sbin/upnpd": build_elf(
            "ARM64", kind="exec", nx=False, relro="none", wx=True,
            imports=["sscanf", "strcpy", "nvram_get", "execve"],
        ),
        "lib/libcrypto_old.so": build_elf(
            "ARM64", kind="lib", nx=True, relro="partial", canary=True,
            imports=["RC4", "DES_ecb_encrypt", "SHA1_Init", "memcpy"], needed=(),
        ),
        "etc/config/system": (
            b"hostname=demo-router\n"
            b"admin_password=DemoPassw0rd!\n"
            b"hash_algorithm=MD5\n"
            b"cipher=des\n"
        ),
        "etc/shadow": b"root:$1$demo$AbCdEfGhIjKlMnOpQrStU.:19000:0:99999:7:::\nnobody:*:19000:0:99999:7:::\n",
        "etc/ssl/private/server.key": _dummy_pem(),
        "www/index.html": b"<html><body><h1>Demo router</h1></body></html>\n",
    }


def build_sample_firmware_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sample_files().items():
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buf.getvalue()
