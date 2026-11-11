"""Static ELF inspection (never executes the file)."""
from __future__ import annotations

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

PT_X, PT_W = 1, 2


class ElfAuditError(Exception):
    pass


def _arch(machine: str, little: bool) -> str:
    return {
        "EM_MIPS": "MIPSEL" if little else "MIPS",
        "EM_ARM": "ARM32",
        "EM_AARCH64": "ARM64",
        "EM_X86_64": "x86_64",
        "EM_386": "x86",
        "EM_PPC": "PowerPC",
        "EM_PPC64": "PowerPC64",
        "EM_RISCV": "RISC-V",
    }.get(machine, str(machine).replace("EM_", ""))


def is_elf(path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def audit_elf(path) -> dict | None:
    """Return the hardening matrix + imported symbols, or None if not an ELF."""
    try:
        with open(path, "rb") as fh:
            if fh.read(4) != b"\x7fELF":
                return None
            fh.seek(0)
            elf = ELFFile(fh)
            little = elf.little_endian
            etype = str(elf["e_type"])
            nx = None
            relro_hdr = False
            bind_now = False
            interp = None
            wx = False
            needed: list[str] = []

            for seg in elf.iter_segments():
                ptype, flags = str(seg["p_type"]), int(seg["p_flags"])
                if ptype == "PT_GNU_STACK":
                    nx = not bool(flags & 1)
                elif ptype == "PT_GNU_RELRO":
                    relro_hdr = True
                elif ptype == "PT_INTERP":
                    try:
                        interp = seg.get_interp_name()
                    except Exception:
                        interp = "?"
                elif ptype == "PT_LOAD" and flags & 1 and flags & 2:
                    wx = True
                elif ptype == "PT_DYNAMIC":
                    try:
                        for tag in seg.iter_tags():
                            t = str(tag.entry.d_tag)
                            if t == "DT_BIND_NOW":
                                bind_now = True
                            elif t == "DT_FLAGS" and tag.entry.d_val & 8:
                                bind_now = True
                            elif t == "DT_FLAGS_1" and tag.entry.d_val & 1:
                                bind_now = True
                            elif t == "DT_NEEDED":
                                needed.append(tag.needed)
                    except Exception:
                        pass

            imports: set[str] = set()
            for sec_name in (".dynsym", ".symtab"):
                sec = elf.get_section_by_name(sec_name)
                if isinstance(sec, SymbolTableSection):
                    for i, sym in enumerate(sec.iter_symbols()):
                        if i > 50000:
                            break
                        if sym["st_shndx"] == "SHN_UNDEF" and sym.name:
                            imports.add(sym.name.split("@")[0])

            is_lib = etype == "ET_DYN" and interp is None
            relro = "full" if relro_hdr and bind_now else "partial" if relro_hdr else "none"
            return {
                "architecture": _arch(str(elf["e_machine"]), little),
                "endianness": "little" if little else "big",
                "bits": elf.elfclass,
                "elf_type": etype,
                "kind": "shared library" if is_lib else "executable",
                "is_library": is_lib,
                "interpreter": interp,
                "needed": needed[:32],
                "nx": nx,
                "pie": (etype == "ET_DYN" and interp is not None),
                "relro": relro,
                "stack_canary": bool(imports & {"__stack_chk_fail", "__stack_chk_guard"}),
                "fortify": any(i.startswith("__") and i.endswith("_chk") for i in imports),
                "stripped": elf.get_section_by_name(".symtab") is None,
                "writable_executable_segment": wx,
                "imports": sorted(imports),
            }
    except ElfAuditError:
        raise
    except Exception as e:  # corrupt / truncated ELF
        raise ElfAuditError(f"{type(e).__name__}: {e}") from e


def hardening_score(b: dict) -> int:
    """0-5: NX, PIE (executables only), full RELRO, canary, FORTIFY."""
    checks = [b.get("nx") is True, b.get("relro") == "full", b.get("stack_canary"), b.get("fortify")]
    checks.append(True if b.get("is_library") else bool(b.get("pie")))
    return sum(1 for c in checks if c)
