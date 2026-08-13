#!/usr/bin/env python3
"""Verify one custom Android UPX pack/recovery round trip without execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any


ELF_MAGIC = b"\x7fELF"
EM_AARCH64 = 183
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
DT_INIT = 12
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33
DT_INIT_ARRAY = 25
DT_INIT_ARRAYSZ = 27


class VerifyError(RuntimeError):
    """Raised if one static pack/recovery invariant does not hold."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_elf(image: bytes) -> tuple[int, int, list[tuple[int, int, int, int, int, int, int, int]]]:
    if len(image) < 64 or image[:4] != ELF_MAGIC or image[4] != 2 or image[5] != 1:
        raise VerifyError("input is not a little-endian ELF64 file")
    e_type, e_machine = struct.unpack_from("<HH", image, 16)
    if e_type != ET_DYN or e_machine != EM_AARCH64:
        raise VerifyError(f"input must be AArch64 ET_DYN, got type={e_type} machine={e_machine}")
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    if phentsize != 56 or phoff + phentsize * phnum > len(image):
        raise VerifyError("ELF program-header table is malformed")
    return (
        phoff,
        phnum,
        [struct.unpack_from("<IIQQQQQQ", image, phoff + index * phentsize) for index in range(phnum)],
    )


def rva_to_offset(
    headers: list[tuple[int, int, int, int, int, int, int, int]], rva: int, size: int
) -> int:
    for p_type, _flags, offset, vaddr, _paddr, filesz, _memsz, _align in headers:
        if p_type == PT_LOAD and vaddr <= rva and rva + size <= vaddr + filesz:
            return offset + rva - vaddr
    raise VerifyError(f"RVA {rva:#x}+{size:#x} is not file-backed by one PT_LOAD")


def initialization_hook(
    image: bytes, headers: list[tuple[int, int, int, int, int, int, int, int]]
) -> dict[str, int | str]:
    """Select the same initialization hook order as the UPX SO packer."""
    dynamic: dict[int, list[tuple[int, int]]] = {}
    for p_type, _flags, offset, _vaddr, _paddr, filesz, _memsz, _align in headers:
        if p_type != PT_DYNAMIC:
            continue
        if filesz % 16 or offset + filesz > len(image):
            raise VerifyError("PT_DYNAMIC is malformed")
        for entry in range(offset, offset + filesz, 16):
            tag, value = struct.unpack_from("<QQ", image, entry)
            dynamic.setdefault(tag, []).append((entry, value))
    direct = dynamic.get(DT_INIT, [])
    if direct:
        if len(direct) != 1 or not direct[0][1]:
            raise VerifyError(f"expected one non-zero DT_INIT, found {[value for _offset, value in direct]}")
        return {"kind": "DT_INIT", "value": direct[0][1]}
    for array_tag, size_tag, name in (
        (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, "DT_PREINIT_ARRAY"),
        (DT_INIT_ARRAY, DT_INIT_ARRAYSZ, "DT_INIT_ARRAY"),
    ):
        arrays = dynamic.get(array_tag, [])
        if not arrays:
            continue
        sizes = dynamic.get(size_tag, [])
        if len(arrays) != 1 or len(sizes) != 1 or sizes[0][1] < 8:
            raise VerifyError(f"{name} is not a valid one-slot initialization hook")
        array_rva = arrays[0][1]
        array_offset = rva_to_offset(headers, array_rva, 8)
        return {
            "kind": name,
            "array_rva": array_rva,
            "array_size": sizes[0][1],
            "first_slot": struct.unpack_from("<Q", image, array_offset)[0],
        }
    raise VerifyError("no replaceable DT_INIT, DT_PREINIT_ARRAY, or DT_INIT_ARRAY hook")


def dynamic_exports(image: bytes, headers: list[tuple[int, int, int, int, int, int, int, int]]) -> list[str]:
    dynamic: dict[int, int] = {}
    for p_type, _flags, offset, _vaddr, _paddr, filesz, _memsz, _align in headers:
        if p_type != PT_DYNAMIC:
            continue
        for entry in range(offset, offset + filesz, 16):
            tag, value = struct.unpack_from("<QQ", image, entry)
            dynamic.setdefault(tag, value)
    required = (4, 5, 6, 11)
    if any(tag not in dynamic for tag in required) or dynamic[11] != 24:
        raise VerifyError("outer wrapper lacks DT_HASH/DT_STRTAB/DT_SYMTAB")
    hash_offset = rva_to_offset(headers, dynamic[4], 8)
    _bucket_count, chain_count = struct.unpack_from("<II", image, hash_offset)
    if chain_count > 1_000_000:
        raise VerifyError("outer wrapper DT_HASH has an unreasonable symbol count")
    exports: list[str] = []
    for index in range(chain_count):
        symbol_offset = rva_to_offset(headers, dynamic[6] + 24 * index, 24)
        name_offset, info, _other, shndx, _value, _size = struct.unpack_from(
            "<IBBHQQ", image, symbol_offset
        )
        if shndx == 0 or (info >> 4) not in (1, 2):  # undefined, local, or non-exported
            continue
        name_start = rva_to_offset(headers, dynamic[5] + name_offset, 1)
        name_end = image.find(b"\0", name_start)
        if name_end < 0:
            raise VerifyError("outer wrapper has an unterminated dynamic symbol name")
        exports.append(image[name_start:name_end].decode("ascii"))
    return sorted(exports)


def assert_file_backed(
    image: bytes,
    headers: list[tuple[int, int, int, int, int, int, int, int]],
    rva: int,
    size: int,
    label: str,
) -> int:
    try:
        return rva_to_offset(headers, rva, size)
    except VerifyError as exc:
        raise VerifyError(f"{label} is not file-backed by one outer PT_LOAD") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--wrapper", type=Path, required=True)
    parser.add_argument("--pack-receipt", type=Path, required=True)
    parser.add_argument("--recovered", type=Path, required=True)
    parser.add_argument("--recovered-bridge", type=Path, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--recovery-receipt", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    original = args.original.read_bytes()
    wrapper = args.wrapper.read_bytes()
    recovered = args.recovered.read_bytes()
    recovered_bridge = args.recovered_bridge.read_bytes()
    bridge = args.bridge.read_bytes()
    pack_receipt = json.loads(args.pack_receipt.read_text(encoding="ascii"))
    recovery_receipt = json.loads(args.recovery_receipt.read_text(encoding="ascii"))

    _original_phoff, _original_phnum, original_headers = parse_elf(original)
    _wrapper_phoff, _wrapper_phnum, wrapper_headers = parse_elf(wrapper)
    _recovered_phoff, _recovered_phnum, recovered_headers = parse_elf(recovered)
    record = pack_receipt["outer_custom_chacha_zlib"]["record"]
    metadata_rva = int(record["metadata_rva"], 0)
    ciphertext_rva = int(record["ciphertext_rva"], 0)
    ciphertext_length = int(record["ciphertext_length"], 0)
    assert_file_backed(wrapper, wrapper_headers, metadata_rva, 0x58, "metadata")
    assert_file_backed(wrapper, wrapper_headers, ciphertext_rva, ciphertext_length, "ciphertext")

    if pack_receipt["input"]["sha256"] != sha256(original):
        raise VerifyError("pack receipt input SHA-256 does not match --original")
    if pack_receipt["outer_wrapper"]["sha256"] != sha256(wrapper):
        raise VerifyError("pack receipt wrapper SHA-256 does not match --wrapper")
    if pack_receipt["inner_upx"]["bridge_sha256"] != sha256(bridge):
        raise VerifyError("pack receipt bridge SHA-256 does not match --bridge")
    if recovery_receipt["bridge"]["sha256"] != sha256(recovered_bridge):
        raise VerifyError("recovery receipt bridge SHA-256 does not match --recovered-bridge")
    if recovery_receipt["output"]["sha256"] != sha256(recovered):
        raise VerifyError("recovery receipt output SHA-256 does not match --recovered")

    if dynamic_exports(wrapper, wrapper_headers) != ["JNI_OnLoad"]:
        raise VerifyError("outer wrapper exports must be exactly JNI_OnLoad")
    if recovered_bridge != bridge:
        raise VerifyError("static recovered bridge differs from the emitted UPX bridge")
    if recovered != original:
        raise VerifyError("static recovered ELF differs from the original input")
    if original_headers != recovered_headers:
        raise VerifyError("recovered program headers differ from original program headers")
    for index, original_header in enumerate(original_headers):
        p_type, _flags, offset, _vaddr, _paddr, filesz, _memsz, _align = original_header
        if p_type == PT_LOAD and original[offset : offset + filesz] != recovered[offset : offset + filesz]:
            raise VerifyError(f"recovered PT_LOAD[{index}] bytes differ from the original")
    original_init_hook = initialization_hook(original, original_headers)
    recovered_init_hook = initialization_hook(recovered, recovered_headers)
    if original_init_hook != recovered_init_hook:
        raise VerifyError(
            f"initialization hook mismatch: original={original_init_hook} recovered={recovered_init_hook}"
        )
    if original[40:64] != recovered[40:64]:
        raise VerifyError("ELF section-table metadata differs after recovery")
    if recovery_receipt["output"]["sha256"] != sha256(original):
        raise VerifyError("recovery receipt SHA-256 does not match the original input")

    report: dict[str, Any] = {
        "schema": "custom_upx.android_round_trip_verification.v1",
        "status": "ok",
        "original_sha256": sha256(original),
        "wrapper_sha256": sha256(wrapper),
        "bridge_sha256": sha256(bridge),
        "metadata_rva": f"{metadata_rva:#x}",
        "ciphertext_rva": f"{ciphertext_rva:#x}",
        "ciphertext_length": ciphertext_length,
        "exports": ["JNI_OnLoad"],
        "initialization_hook": original_init_hook,
        "program_headers_byte_for_byte": True,
        "pt_load_bytes_byte_for_byte": True,
        "section_table_metadata_byte_for_byte": True,
        "full_file_byte_for_byte": True,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, VerifyError, ValueError, KeyError) as exc:
        raise SystemExit(f"error: {exc}")
