#!/usr/bin/env python3
"""Build an Android AArch64 ChaCha20/zlib wrapper around a normal UPX .so.

The inner file is produced by this checkout's standard ``upx`` binary.  This
tool then implements the observed non-UPX outer layer: zlib compress the inner
ELF, encrypt it with ChaCha20-IETF, and embed its material in an Android
wrapper.  The wrapper's record intentionally uses the same 0x58-byte layout
that the static recovery tooling observed in the reference family.

Only JNI_OnLoad is forwarded.  This is appropriate for libraries that use
JNI_OnLoad/RegisterNatives.  A library whose public native C ABI is called
directly needs explicit per-symbol forwarding thunks and is rejected by policy
at integration time rather than silently producing an incomplete wrapper.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ELF_MAGIC = b"\x7fELF"
EM_AARCH64 = 183
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_SYMENT = 11
DT_INIT = 12
DT_INIT_ARRAY = 25
DT_INIT_ARRAYSZ = 27
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_PREINIT_ARRAY = 16
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
RECORD_SIZE = 0x58
RECORD_VERSION = 1
DEFAULT_MAX_BRIDGE = 64 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[2]
RUNTIME_SOURCE = Path(__file__).resolve().parent / "runtime" / "custom_upx_android_loader.c"
EXPORT_MAP = Path(__file__).resolve().parent / "runtime" / "exports.map"


class PackError(RuntimeError):
    """Raised for invalid inputs, toolchain failures, or layout mismatches."""


@dataclass(frozen=True)
class ProgramHeader:
    index: int
    p_type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int


@dataclass(frozen=True)
class ElfImage:
    entry: int
    program_headers: tuple[ProgramHeader, ...]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rotl32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def chacha20_ietf_xor(key: bytes, nonce: bytes, counter: int, source: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise PackError("ChaCha20-IETF requires a 32-byte key and 12-byte nonce")
    constants = struct.unpack("<4I", b"expand 32-byte k")
    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)
    result = bytearray(len(source))
    block_counter = counter
    for offset in range(0, len(source), 64):
        state = list(constants + key_words + (block_counter,) + nonce_words)
        working = state.copy()
        for _ in range(10):
            for a, b, c, d in (
                (0, 4, 8, 12),
                (1, 5, 9, 13),
                (2, 6, 10, 14),
                (3, 7, 11, 15),
                (0, 5, 10, 15),
                (1, 6, 11, 12),
                (2, 7, 8, 13),
                (3, 4, 9, 14),
            ):
                working[a] = (working[a] + working[b]) & 0xFFFFFFFF
                working[d] = rotl32(working[d] ^ working[a], 16)
                working[c] = (working[c] + working[d]) & 0xFFFFFFFF
                working[b] = rotl32(working[b] ^ working[c], 12)
                working[a] = (working[a] + working[b]) & 0xFFFFFFFF
                working[d] = rotl32(working[d] ^ working[a], 8)
                working[c] = (working[c] + working[d]) & 0xFFFFFFFF
                working[b] = rotl32(working[b] ^ working[c], 7)
        stream = struct.pack(
            "<16I", *((working[index] + state[index]) & 0xFFFFFFFF for index in range(16))
        )
        block = source[offset : offset + 64]
        result[offset : offset + len(block)] = bytes(
            value ^ mask for value, mask in zip(block, stream)
        )
        block_counter = (block_counter + 1) & 0xFFFFFFFF
    return bytes(result)


def parse_elf(image: bytes) -> ElfImage:
    if len(image) < 64 or image[:4] != ELF_MAGIC or image[4] != 2 or image[5] != 1:
        raise PackError("input is not a little-endian ELF64 file")
    e_type, e_machine = struct.unpack_from("<HH", image, 16)
    if e_type != ET_DYN or e_machine != EM_AARCH64:
        raise PackError(f"input must be AArch64 ET_DYN, got type={e_type} machine={e_machine}")
    entry, phoff = struct.unpack_from("<QQ", image, 24)
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    if phentsize != 56 or phoff + phentsize * phnum > len(image):
        raise PackError("input has malformed ELF64 program headers")
    headers: list[ProgramHeader] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", image, offset
        )
        if p_type == PT_LOAD and p_offset + p_filesz > len(image):
            raise PackError(f"PT_LOAD[{index}] extends beyond the file")
        headers.append(ProgramHeader(index, p_type, flags, p_offset, p_vaddr, p_filesz, p_memsz))
    return ElfImage(entry, tuple(headers))


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise PackError(f"alignment must be a positive power of two, got {alignment}")
    return (value + alignment - 1) & -alignment


def dynamic_entries(image: bytes, elf: ElfImage) -> dict[int, list[int]]:
    """Read one bounded PT_DYNAMIC table without relying on section headers."""
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    entries: dict[int, list[int]] = {}
    dynamic_count = 0
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, _flags, p_offset, _p_vaddr, _paddr, p_filesz, _p_memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", image, offset
        )
        if p_type != PT_DYNAMIC:
            continue
        dynamic_count += 1
        if p_offset + p_filesz > len(image) or p_filesz % 16:
            raise PackError("input has a malformed PT_DYNAMIC segment")
        for entry_offset in range(p_offset, p_offset + p_filesz, 16):
            tag, value = struct.unpack_from("<QQ", image, entry_offset)
            entries.setdefault(tag, []).append(value)
    if dynamic_count != 1:
        raise PackError(f"input must have exactly one PT_DYNAMIC, found {dynamic_count}")
    return entries


def one_dynamic(entries: dict[int, list[int]], tag: int, label: str) -> int:
    values = entries.get(tag, [])
    if len(values) != 1:
        raise PackError(f"input must have exactly one {label}, found {len(values)}")
    return values[0]


def first_initialization_target(
    image: bytes, elf: ElfImage, entries: dict[int, list[int]]
) -> tuple[int, str]:
    """Find a file-backed UPX initialization target for a sectionless ELF."""
    direct = entries.get(DT_INIT, [])
    if direct:
        target = one_dynamic(entries, DT_INIT, "DT_INIT")
        if not target:
            raise PackError("sectionless input DT_INIT is zero")
        rva_to_offset(elf, target, 4)
        return target, "DT_INIT"

    for array_tag, size_tag, name in (
        (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, "DT_PREINIT_ARRAY"),
        (DT_INIT_ARRAY, DT_INIT_ARRAYSZ, "DT_INIT_ARRAY"),
    ):
        arrays = entries.get(array_tag, [])
        if not arrays:
            continue
        array_rva = one_dynamic(entries, array_tag, name)
        if one_dynamic(entries, size_tag, f"{name}SZ") < 8:
            raise PackError(f"sectionless input {name}SZ is smaller than one pointer")
        rva_to_offset(elf, array_rva, 8)
        rela_rva = one_dynamic(entries, DT_RELA, "DT_RELA")
        rela_size = one_dynamic(entries, DT_RELASZ, "DT_RELASZ")
        if rela_size % 24:
            raise PackError("sectionless input DT_RELASZ is not a multiple of Elf64_Rela")
        rela_offset = rva_to_offset(elf, rela_rva, rela_size)
        for entry_offset in range(rela_offset, rela_offset + rela_size, 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", image, entry_offset)
            if r_offset != array_rva:
                continue
            if (r_info & 0xFFFFFFFF) != 1027:  # R_AARCH64_RELATIVE
                raise PackError(f"sectionless input {name}[0] relocation is not R_AARCH64_RELATIVE")
            if r_addend < 0:
                raise PackError(f"sectionless input {name}[0] relocation has a negative addend")
            rva_to_offset(elf, r_addend, 4)
            return r_addend, f"{name}[0] R_AARCH64_RELATIVE"
        raise PackError(f"sectionless input has no DT_RELA entry for {name}[0]")
    raise PackError("sectionless input has no DT_INIT, DT_PREINIT_ARRAY, or DT_INIT_ARRAY hook")


def synthesize_section_table_for_upx(image: bytes) -> tuple[bytes, dict[str, Any]]:
    """Build a marked minimal section table only when recovery elided one.

    UPX uses section metadata to find the shared-library compression boundary.
    A recovered historical bridge can lack its non-loadable section-table tail;
    this function derives only the metadata UPX needs from PT_LOAD/PT_DYNAMIC
    and appends it after EOF. It changes only the ELF header's section-table
    fields in the original extent; segment contents and program headers remain
    byte-for-byte identical.
    """
    elf = parse_elf(image)
    shoff = struct.unpack_from("<Q", image, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", image, 58)
    if shoff or shentsize or shnum or shstrndx:
        if shoff == 0 or shentsize != 64 or shnum == 0 or shstrndx >= shnum:
            raise PackError("input has malformed partial ELF section-table metadata")
        if shoff + shentsize * shnum > len(image):
            raise PackError("input ELF section table extends past end of file")
        return image, {
            "applied": False,
            "reason": "input_has_valid_section_table",
            "source_size": len(image),
            "canonical_size": len(image),
            "source_sha256": sha256(image),
            "canonical_sha256": sha256(image),
        }

    entries = dynamic_entries(image, elf)
    strtab_rva = one_dynamic(entries, DT_STRTAB, "DT_STRTAB")
    strtab_size = one_dynamic(entries, 10, "DT_STRSZ")
    symtab_rva = one_dynamic(entries, DT_SYMTAB, "DT_SYMTAB")
    syment = one_dynamic(entries, DT_SYMENT, "DT_SYMENT")
    hash_rva = one_dynamic(entries, DT_HASH, "DT_HASH")
    rela_rva = one_dynamic(entries, DT_RELA, "DT_RELA")
    rela_size = one_dynamic(entries, DT_RELASZ, "DT_RELASZ")
    if syment != 24 or rela_size % 24:
        raise PackError("sectionless input has unsupported DT_SYMENT or DT_RELASZ")
    hash_offset = rva_to_offset(elf, hash_rva, 8)
    bucket_count, chain_count = struct.unpack_from("<II", image, hash_offset)
    if chain_count == 0 or chain_count > 1_000_000:
        raise PackError(f"sectionless input has invalid DT_HASH symbol count: {chain_count}")
    hash_size = 8 + 4 * (bucket_count + chain_count)
    if hash_size > len(image):
        raise PackError("sectionless input DT_HASH size is unreasonable")
    strtab_offset = rva_to_offset(elf, strtab_rva, strtab_size)
    symtab_offset = rva_to_offset(elf, symtab_rva, chain_count * syment)
    rela_offset = rva_to_offset(elf, rela_rva, rela_size)
    rva_to_offset(elf, hash_rva, hash_size)

    dynamic_headers = [header for header in elf.program_headers if header.p_type == PT_DYNAMIC]
    if len(dynamic_headers) != 1:
        raise PackError(f"sectionless input must have exactly one PT_DYNAMIC, found {len(dynamic_headers)}")
    init_target, init_kind = first_initialization_target(image, elf, entries)
    executable_loads = [
        header
        for header in elf.program_headers
        if header.p_type == PT_LOAD
        and header.flags & 0x1  # PF_X
        and header.memsz
        and header.offset + header.filesz <= len(image)
    ]
    if not executable_loads:
        raise PackError("sectionless input has no executable PT_LOAD")
    entry_candidate = elf.entry if elf.entry else init_target
    candidates = [init_target]
    try:
        rva_to_offset(elf, entry_candidate, 4)
    except PackError:
        pass
    else:
        candidates.append(entry_candidate)
    text_rva = min(candidates)
    text_header = next(
        (
            header
            for header in executable_loads
            if header.vaddr <= text_rva < header.vaddr + header.filesz
        ),
        None,
    )
    if text_header is None:
        raise PackError("sectionless input initialization target is not inside an executable PT_LOAD")
    text_offset = rva_to_offset(elf, text_rva, 4)
    text_size = text_header.vaddr + text_header.filesz - text_rva

    array_rva: int | None = None
    array_size: int | None = None
    array_kind: int | None = None
    for tag, size_tag, section_type in (
        (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, SHT_PREINIT_ARRAY),
        (DT_INIT_ARRAY, DT_INIT_ARRAYSZ, SHT_INIT_ARRAY),
    ):
        if tag in entries:
            array_rva = one_dynamic(entries, tag, "initialization array")
            array_size = one_dynamic(entries, size_tag, "initialization array size")
            array_kind = section_type
            rva_to_offset(elf, array_rva, array_size)
            break
    if array_rva is None or array_size is None or array_kind is None:
        raise PackError("sectionless input normalization currently requires an initialization array")

    names = b"\0.text\0.dynsym\0.dynstr\0.hash\0.rela.dyn\0.init_array\0.dynamic\0.shstrtab\0"
    name_offsets: dict[str, int] = {}
    for name in (".text", ".dynsym", ".dynstr", ".hash", ".rela.dyn", ".init_array", ".dynamic", ".shstrtab"):
        encoded = name.encode("ascii") + b"\0"
        name_offsets[name] = names.index(encoded)
    sections: list[tuple[int, int, int, int, int, int, int, int, int, int]] = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (name_offsets[".text"], SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, text_rva, text_offset, text_size, 0, 0, 4, 0),
        (name_offsets[".dynsym"], SHT_DYNSYM, SHF_ALLOC, symtab_rva, symtab_offset, chain_count * syment, 3, 0, 8, syment),
        (name_offsets[".dynstr"], SHT_STRTAB, SHF_ALLOC, strtab_rva, strtab_offset, strtab_size, 0, 0, 1, 0),
        (name_offsets[".hash"], SHT_HASH, SHF_ALLOC, hash_rva, hash_offset, hash_size, 2, 0, 4, 4),
        (name_offsets[".rela.dyn"], SHT_RELA, SHF_ALLOC, rela_rva, rela_offset, rela_size, 2, 0, 8, 24),
        (name_offsets[".init_array"], array_kind, SHF_ALLOC | SHF_WRITE, array_rva, rva_to_offset(elf, array_rva, array_size), array_size, 0, 0, 8, 8),
        (name_offsets[".dynamic"], SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, dynamic_headers[0].vaddr, dynamic_headers[0].offset, dynamic_headers[0].filesz, 3, 0, 8, 16),
        (name_offsets[".shstrtab"], SHT_STRTAB, 0, 0, 0, len(names), 0, 0, 1, 0),
    ]
    section_table_offset = align_up(len(image), 8)
    string_table_offset = section_table_offset + len(sections) * 64
    data = bytearray(image)
    data.extend(b"\0" * (string_table_offset + len(names) - len(data)))
    for index, section in enumerate(sections):
        struct.pack_into("<IIQQQQIIQQ", data, section_table_offset + index * 64, *section)
    struct.pack_into("<Q", data, section_table_offset + 8 * 64 + 24, string_table_offset)
    data[string_table_offset : string_table_offset + len(names)] = names
    struct.pack_into("<Q", data, 40, section_table_offset)
    struct.pack_into("<HHH", data, 58, 64, len(sections), 8)
    canonical = bytes(data)
    allowed_header_mutations = set(range(40, 48)) | set(range(58, 64))
    unexpected_mutations = [
        offset
        for offset, (before, after) in enumerate(zip(image, canonical))
        if before != after and offset not in allowed_header_mutations
    ]
    if unexpected_mutations:
        raise PackError(
            "section-table normalization changed bytes outside permitted ELF header fields: "
            + ", ".join(f"{offset:#x}" for offset in unexpected_mutations[:8])
        )
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    if canonical[phoff : phoff + phentsize * phnum] != image[phoff : phoff + phentsize * phnum]:
        raise PackError("section-table normalization changed an ELF program header")
    if canonical[dynamic_headers[0].offset : dynamic_headers[0].offset + dynamic_headers[0].filesz] != image[
        dynamic_headers[0].offset : dynamic_headers[0].offset + dynamic_headers[0].filesz
    ]:
        raise PackError("section-table normalization changed PT_DYNAMIC bytes")
    return canonical, {
        "applied": True,
        "reason": "source_recovery_elided_non_loadable_section_table",
        "source_size": len(image),
        "canonical_size": len(canonical),
        "source_sha256": sha256(image),
        "canonical_sha256": sha256(canonical),
        "section_table_offset": f"{section_table_offset:#x}",
        "section_count": len(sections),
        "string_table_offset": f"{string_table_offset:#x}",
        "modified_source_header_ranges": ["0x28-0x2f", "0x3a-0x3f"],
        "program_headers_byte_for_byte": True,
        "pt_dynamic_bytes_byte_for_byte": True,
        "initialization_target": f"{init_target:#x}",
        "initialization_target_kind": init_kind,
        "text_section_rva": f"{text_rva:#x}",
    }


def require_input_contract(image: bytes, symbol_name: bytes) -> None:
    """Require the loader-visible entries used by UPX and the outer wrapper."""
    elf = parse_elf(image)
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    dynamic: dict[int, list[int]] = {}
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _p_memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", image, offset
        )
        if p_type != 2:  # PT_DYNAMIC
            continue
        if p_offset + p_filesz > len(image) or p_filesz % 16:
            raise PackError("input has a malformed PT_DYNAMIC segment")
        for entry_offset in range(p_offset, p_offset + p_filesz, 16):
            tag, value = struct.unpack_from("<QQ", image, entry_offset)
            dynamic.setdefault(tag, []).append(value)
    strtab_rva = dynamic.get(5, [None])[0]  # DT_STRTAB
    symtab_rva = dynamic.get(6, [None])[0]  # DT_SYMTAB
    syment = dynamic.get(11, [24])[0]  # DT_SYMENT
    hash_rva = dynamic.get(4, [None])[0]  # DT_HASH
    if strtab_rva is None or symtab_rva is None or hash_rva is None or syment != 24:
        raise PackError("input must have DT_HASH, DT_STRTAB, and 24-byte DT_SYMTAB entries")
    hash_offset = rva_to_offset(elf, hash_rva, 8)
    _bucket_count, chain_count = struct.unpack_from("<II", image, hash_offset)
    if chain_count == 0 or chain_count > 1_000_000:
        raise PackError(f"input has an invalid DT_HASH symbol count: {chain_count}")
    init_values = dynamic.get(12, [])  # DT_INIT
    if init_values:
        if len(init_values) != 1 or not init_values[0]:
            raise PackError("input DT_INIT must occur exactly once and have a non-zero file-backed target")
        try:
            rva_to_offset(elf, init_values[0], 4)
        except PackError as exc:
            raise PackError("input DT_INIT target is not file-backed by one PT_LOAD") from exc
    else:
        # Match PackLinuxElf64::invert_pt_dynamic(): when DT_INIT is absent,
        # the shared-object packer hooks the first PREINIT/INIT array slot.
        array_choice: tuple[int, int, str] | None = None
        for array_tag, size_tag, name in (
            (32, 33, "DT_PREINIT_ARRAY"),
            (25, 27, "DT_INIT_ARRAY"),
        ):
            arrays = dynamic.get(array_tag, [])
            if not arrays:
                continue
            sizes = dynamic.get(size_tag, [])
            if len(arrays) != 1 or len(sizes) != 1 or sizes[0] < 8:
                raise PackError(
                    f"input {name} must occur once with one {name}SZ value of at least 8 bytes"
                )
            array_choice = (arrays[0], sizes[0], name)
            break
        if array_choice is None:
            raise PackError(
                "input must provide a replaceable DT_INIT or first DT_PREINIT_ARRAY/DT_INIT_ARRAY "
                "slot for upstream UPX shared-object packing"
            )
        array_rva, _array_size, array_name = array_choice
        try:
            # A zero slot remains valid: its R_AARCH64_RELATIVE relocation's
            # addend supplies the runtime target.
            rva_to_offset(elf, array_rva, 8)
        except PackError as exc:
            raise PackError(f"input {array_name}[0] is not file-backed by one PT_LOAD") from exc
    for index in range(chain_count):
        symbol_offset = rva_to_offset(elf, symtab_rva + index * syment, syment)
        name_offset = struct.unpack_from("<I", image, symbol_offset)[0]
        name_rva = strtab_rva + name_offset
        name_raw = rva_to_offset(elf, name_rva, 1)
        name_end = image.find(b"\0", name_raw)
        if name_end < 0:
            raise PackError("input has an unterminated dynamic symbol name")
        if image[name_raw:name_end] == symbol_name:
            return
    raise PackError(
        "input does not export JNI_OnLoad in DT_HASH/.dynsym; this minimal wrapper only "
        "supports JNI_OnLoad/RegisterNatives libraries"
    )


def rva_to_offset(elf: ElfImage, rva: int, size: int) -> int:
    for header in elf.program_headers:
        if header.p_type == PT_LOAD and header.vaddr <= rva and rva + size <= header.vaddr + header.filesz:
            return header.offset + rva - header.vaddr
    raise PackError(f"RVA {rva:#x}+{size:#x} is not backed by one PT_LOAD")


def find_outer_record(image: bytes, ciphertext: bytes, bridge: bytes) -> dict[str, Any]:
    """Find and prove the emitted 0x58-byte record by its payload and layout."""
    elf = parse_elf(image)
    matches: list[dict[str, Any]] = []
    for header in elf.program_headers:
        if header.p_type != PT_LOAD or header.filesz < RECORD_SIZE:
            continue
        limit = header.offset + header.filesz - RECORD_SIZE
        for raw_offset in range(header.offset, limit + 1, 4):
            version, flags = struct.unpack_from("<II", image, raw_offset)
            if version != RECORD_VERSION or flags != 0:
                continue
            record_rva = header.vaddr + raw_offset - header.offset
            source_rva, end_rva = struct.unpack_from("<QQ", image, raw_offset + 0x08)
            ciphertext_length, bridge_length = struct.unpack_from("<II", image, raw_offset + 0x18)
            if (
                ciphertext_length != len(ciphertext)
                or bridge_length != len(bridge)
            ):
                continue
            # Before the post-link normalization below, lld stores zero in
            # these data slots and puts the link-time RVAs in RELA addends.
            # The adjacent incbin payload is enough to identify that one
            # provisional record without trusting those unresolved fields.
            expected_source_rva = record_rva + RECORD_SIZE
            expected_end_rva = expected_source_rva + ciphertext_length
            if (source_rva, end_rva) not in (
                (0, 0),
                (expected_source_rva, expected_end_rva),
            ):
                continue
            try:
                ciphertext_offset = rva_to_offset(elf, expected_source_rva, ciphertext_length)
            except PackError:
                continue
            if image[ciphertext_offset : ciphertext_offset + ciphertext_length] != ciphertext:
                continue
            matches.append(
                {
                    "metadata_rva": record_rva,
                    "metadata_file_offset": raw_offset,
                    "ciphertext_rva": expected_source_rva,
                    "ciphertext_file_offset": ciphertext_offset,
                    "ciphertext_length": ciphertext_length,
                    "bridge_length": bridge_length,
                    "pt_load_index": header.index,
                }
            )
    if len(matches) != 1:
        raise PackError(f"expected one emitted custom-UPX record, found {len(matches)}")
    return matches[0]


def normalize_record_rva_relocations(image: bytes, record: dict[str, Any]) -> bytes:
    """Persist metadata RVAs both on disk and in AArch64 RELATIVE addends.

    lld leaves data slots that reference a local ET_DYN symbol zero-filled and
    emits R_AARCH64_RELATIVE relocations.  The runtime result is correct, but
    an offline decoder needs the pre-relocation RVA values too.  Retaining the
    same values in the slots and RELA addends gives both consumers the intended
    representation: the dynamic linker writes ``load_bias + rva`` at runtime,
    while an offline tool reads ``rva`` directly from the file.
    """
    data = bytearray(image)
    elf = parse_elf(data)
    metadata_rva = record["metadata_rva"]
    metadata_offset = record["metadata_file_offset"]
    source_rva = record["ciphertext_rva"]
    end_rva = source_rva + record["ciphertext_length"]
    targets = {
        metadata_rva + 0x08: source_rva,
        metadata_rva + 0x10: end_rva,
    }
    found: set[int] = set()
    if len(data) < 64:
        raise PackError("linked wrapper is too short for ELF64 header")
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum = struct.unpack_from("<HH", data, 58)
    if shentsize != 64 or shoff + shentsize * shnum > len(data):
        raise PackError("linked wrapper has malformed ELF64 section headers")
    for index in range(shnum):
        section_offset = shoff + index * shentsize
        section_type = struct.unpack_from("<I", data, section_offset + 4)[0]
        if section_type != 4:  # SHT_RELA
            continue
        rela_offset, rela_size = struct.unpack_from("<QQ", data, section_offset + 24)
        rela_entry_size = struct.unpack_from("<Q", data, section_offset + 56)[0]
        if rela_entry_size != 24 or rela_offset + rela_size > len(data) or rela_size % rela_entry_size:
            raise PackError("linked wrapper has malformed SHT_RELA extent")
        for entry_offset in range(rela_offset, rela_offset + rela_size, rela_entry_size):
            r_offset, r_info, _addend = struct.unpack_from("<QQq", data, entry_offset)
            if r_offset not in targets:
                continue
            if (r_info & 0xFFFFFFFF) != 1027:  # R_AARCH64_RELATIVE
                raise PackError(
                    f"metadata relocation at {r_offset:#x} is not R_AARCH64_RELATIVE"
                )
            struct.pack_into("<q", data, entry_offset + 16, targets[r_offset])
            found.add(r_offset)
    if found != set(targets):
        raise PackError(
            "missing expected R_AARCH64_RELATIVE metadata relocations: "
            + ", ".join(f"{target:#x}" for target in sorted(set(targets) - found))
        )
    struct.pack_into("<Q", data, metadata_offset + 0x08, source_rva)
    struct.pack_into("<Q", data, metadata_offset + 0x10, end_rva)
    # Recheck that the patched values remain raw-file backed as one range.
    rva_to_offset(elf, source_rva, record["ciphertext_length"])
    return bytes(data)


def parse_hex(value: str | None, expected_size: int, label: str) -> bytes:
    if value is None:
        return secrets.token_bytes(expected_size)
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise PackError(f"{label} must be hexadecimal") from exc
    if len(decoded) != expected_size:
        raise PackError(f"{label} must contain exactly {expected_size} bytes")
    return decoded


def run(command: list[str], *, cwd: Path | None = None) -> None:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if completed.returncode:
        raise PackError(
            "command failed:\n"
            f"  {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )


def discover_ndk() -> Path | None:
    configured = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    if configured:
        path = Path(configured)
        if path.is_dir():
            return path
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        ndk_root = Path(local_app_data) / "Android" / "Sdk" / "ndk"
        if ndk_root.is_dir():
            versions = sorted((path for path in ndk_root.iterdir() if path.is_dir()), reverse=True)
            if versions:
                return versions[0]
    return None


def as_asm_path(path: Path) -> str:
    rendered = path.resolve().as_posix()
    if '"' in rendered:
        raise PackError("assembly .incbin path cannot contain a double quote")
    return rendered


def emit_payload_assembly(path: Path, ciphertext_path: Path, ciphertext: bytes, bridge: bytes,
                          key: bytes, nonce: bytes) -> None:
    key_directive = ", ".join(f"0x{value:02x}" for value in key)
    nonce_directive = ", ".join(f"0x{value:02x}" for value in nonce)
    # The two RVA fields deliberately retain link-time virtual addresses on
    # disk.  They therefore receive normal R_AARCH64_RELATIVE relocations at
    # load time.  Keep the record in writable data, as the observed family
    # does, so Android's loader never has to write a read-only text segment.
    source = f""".section .data.custom_upx,\"aw\",@progbits
.balign 8
.global custom_upx_outer_record
.hidden custom_upx_outer_record
.type custom_upx_outer_record, %object
custom_upx_outer_record:
  .word {RECORD_VERSION}
  .word 0
  .quad custom_upx_outer_record + {RECORD_SIZE}
  .quad custom_upx_outer_record + {RECORD_SIZE} + {len(ciphertext)}
  .word {len(ciphertext)}
  .word {len(bridge)}
  .word 0
  .word 0
  .word 0
  .byte {key_directive}
  .byte {nonce_directive}
  .incbin \"{as_asm_path(ciphertext_path)}\"
.size custom_upx_outer_record, . - custom_upx_outer_record
"""
    path.write_text(source, encoding="ascii")


def resolve_upx(path: Path | None) -> Path:
    candidates = [path] if path else [ROOT / "build-custom-upx" / "upx.exe", ROOT / "build" / "upx.exe"]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate.resolve()
    raise PackError("cannot find a built UPX binary; pass --upx explicitly")


def resolve_clang(ndk: Path, api: int) -> Path:
    suffix = ".cmd" if os.name == "nt" else ""
    candidate = (
        ndk
        / "toolchains"
        / "llvm"
        / "prebuilt"
        / ("windows-x86_64" if os.name == "nt" else "linux-x86_64")
        / "bin"
        / f"aarch64-linux-android{api}-clang{suffix}"
    )
    if not candidate.is_file():
        raise PackError(f"Android NDK compiler was not found: {candidate}")
    return candidate


def write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="ascii")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="unpacked AArch64 Android ET_DYN shared object")
    parser.add_argument("--output", type=Path, required=True, help="outer custom-UPX Android shared object")
    parser.add_argument("--upx", type=Path, help="built standard UPX executable from this checkout")
    parser.add_argument("--ndk", type=Path, help="Android NDK root; defaults to ANDROID_NDK_HOME or SDK/ndk")
    parser.add_argument("--api", type=int, default=21, help="Android minimum API level (default: 21)")
    parser.add_argument("--key-hex", help="fixed 32-byte ChaCha20 key for reproducible test vectors")
    parser.add_argument("--nonce-hex", help="fixed 12-byte ChaCha20 nonce for reproducible test vectors")
    parser.add_argument("--zlib-level", type=int, default=9, choices=range(0, 10))
    parser.add_argument("--max-bridge", type=lambda value: int(value, 0), default=DEFAULT_MAX_BRIDGE)
    parser.add_argument("--receipt", type=Path, help="JSON receipt (defaults to OUTPUT plus .json)")
    parser.add_argument("--work-dir", type=Path, help="persist intermediate bridge/ciphertext/build files here")
    parser.add_argument(
        "--upx-arg",
        action="append",
        default=[],
        help="additional argument passed to standard UPX; may be repeated",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.api < 21:
        raise PackError("--api must be at least 21 for android_dlopen_ext")
    if args.max_bridge <= 0:
        raise PackError("--max-bridge must be positive")
    input_path = args.input.resolve()
    output_path = args.output.resolve()
    receipt_path = (args.receipt or args.output.with_suffix(args.output.suffix + ".json")).resolve()
    if not input_path.is_file():
        raise PackError(f"input does not exist: {input_path}")
    if output_path in {input_path, receipt_path} or receipt_path == input_path:
        raise PackError("input, output, and receipt paths must be distinct")
    if output_path == receipt_path:
        raise PackError("output and receipt paths must be distinct")
    source_input = input_path.read_bytes()
    parse_elf(source_input)
    upx = resolve_upx(args.upx)
    ndk = (args.ndk or discover_ndk())
    if ndk is None or not ndk.is_dir():
        raise PackError("Android NDK not found; pass --ndk explicitly")
    clang = resolve_clang(ndk.resolve(), args.api)
    key = parse_hex(args.key_hex, 32, "--key-hex")
    nonce = parse_hex(args.nonce_hex, 12, "--nonce-hex")

    temporary_context: tempfile.TemporaryDirectory[str] | None = None
    if args.work_dir:
        work_dir = args.work_dir.resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
    else:
        temporary_context = tempfile.TemporaryDirectory(prefix="custom-upx-android-")
        work_dir = Path(temporary_context.name)
    try:
        original, canonicalization = synthesize_section_table_for_upx(source_input)
        require_input_contract(original, b"JNI_OnLoad")
        canonical_input_path = input_path
        if canonicalization["applied"]:
            canonical_input_path = work_dir / "input.for-upx.so"
            canonical_input_path.write_bytes(original)
        bridge_path = work_dir / "inner.upx.so"
        ciphertext_path = work_dir / "outer.ciphertext.bin"
        payload_assembly = work_dir / "outer_payload.S"
        upx_command = [
            str(upx),
            "--best",
            *args.upx_arg,
            "-o",
            str(bridge_path),
            str(canonical_input_path),
        ]
        run(upx_command)
        bridge = bridge_path.read_bytes()
        parse_elf(bridge)
        if len(bridge) > args.max_bridge:
            raise PackError(f"UPX bridge exceeds --max-bridge: {len(bridge):#x}>{args.max_bridge:#x}")
        compressed = zlib.compress(bridge, args.zlib_level)
        ciphertext = chacha20_ietf_xor(key, nonce, 0, compressed)
        if len(ciphertext) > 0xFFFFFFFF or len(bridge) > 0xFFFFFFFF:
            raise PackError("custom record supports bridge and ciphertext lengths up to 4 GiB")
        ciphertext_path.write_bytes(ciphertext)
        emit_payload_assembly(payload_assembly, ciphertext_path, ciphertext, bridge, key, nonce)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        compiler_command = [
            str(clang),
            "-fPIC",
            "-fvisibility=hidden",
            "-fstack-protector-strong",
            "-O2",
            "-shared",
            "-Wl,-z,relro,-z,now",
            f"-Wl,--version-script={EXPORT_MAP.resolve()}",
            f"-Wl,-soname,{output_path.name}",
            "-o",
            str(output_path),
            str(RUNTIME_SOURCE.resolve()),
            str(payload_assembly),
            "-ldl",
            "-lz",
        ]
        run(compiler_command)
        provisional_outer = output_path.read_bytes()
        provisional_record = find_outer_record(provisional_outer, ciphertext, bridge)
        outer = normalize_record_rva_relocations(provisional_outer, provisional_record)
        output_path.write_bytes(outer)
        outer_elf = parse_elf(outer)
        record = find_outer_record(outer, ciphertext, bridge)
        metadata_offset = record["metadata_file_offset"]
        embedded_key = outer[metadata_offset + 0x2C : metadata_offset + 0x4C]
        embedded_nonce = outer[metadata_offset + 0x4C : metadata_offset + 0x58]
        encrypted = outer[
            record["ciphertext_file_offset"] : record["ciphertext_file_offset"] + record["ciphertext_length"]
        ]
        validated_compressed = chacha20_ietf_xor(embedded_key, embedded_nonce, 0, encrypted)
        if validated_compressed != compressed or zlib.decompress(validated_compressed) != bridge:
            raise PackError("post-link static outer-stage verification failed")

        receipt = {
            "schema": "custom_upx.android_wrapper_pack.v1",
            "status": "ok",
            "source_input": {
                "path": str(input_path),
                "size": len(source_input),
                "sha256": sha256(source_input),
            },
            "input": {
                "path": str(canonical_input_path),
                "size": len(original),
                "sha256": sha256(original),
                "kind": "upx_canonical_input",
            },
            "input_canonicalization": canonicalization,
            "inner_upx": {
                "upx_path": str(upx),
                "upx_sha256": sha256(upx.read_bytes()),
                "command": upx_command,
                "bridge_size": len(bridge),
                "bridge_sha256": sha256(bridge),
            },
            "outer_custom_chacha_zlib": {
                "record_version": RECORD_VERSION,
                "record_size": RECORD_SIZE,
                "record": {
                    key: (f"{value:#x}" if isinstance(value, int) else value)
                    for key, value in record.items()
                },
                "chacha20": {
                    "variant": "IETF-96-bit-nonce",
                    "counter": 0,
                    "key_sha256": sha256(key),
                    "nonce_sha256": sha256(nonce),
                },
                "zlib": {
                    "level": args.zlib_level,
                    "compressed_size": len(compressed),
                    "compressed_sha256": sha256(compressed),
                    "header": compressed[:2].hex(),
                },
                "post_link_static_verification": True,
            },
            "outer_wrapper": {
                "path": str(output_path),
                "size": len(outer),
                "sha256": sha256(outer),
                "entry_rva": f"{outer_elf.entry:#x}",
                "exports": ["JNI_OnLoad"],
                "runtime_handoff": "memfd_create + android_dlopen_ext + inner JNI_OnLoad",
            },
            "compatibility": {
                "architecture": "AArch64",
                "minimum_android_api": args.api,
                "direct_native_c_abi_forwarding": False,
                "requires_jni_onload_register_natives": True,
            },
        }
        write_receipt(receipt_path, receipt)
    finally:
        if temporary_context is not None:
            temporary_context.cleanup()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PackError, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"error: {exc}")
