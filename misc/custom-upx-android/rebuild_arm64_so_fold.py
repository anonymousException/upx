#!/usr/bin/env python3
"""Rebuild the AArch64 shared-object fold stub with an Android NDK toolchain.

UPX embeds this relocatable ELF plus a compact section/symbol/relocation index
in src/stub/arm64-linux.elf-so_fold.h.  The historical Makefile requires old
cross-binutils that are not distributed with current Android NDKs.  This tool
reproduces the same object preparation with LLVM and emits the index directly
from ELF metadata, so the host packer still uses its normal ElfLinker path.
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path


class BuildError(RuntimeError):
    """A deterministic build or validation failure."""


ELF64_EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_SHDR = struct.Struct("<IIQQQQIIQQ")
ELF64_SYM = struct.Struct("<IBBHQQ")
ELF64_RELA = struct.Struct("<QQq")

SHT_SYMTAB = 2
SHT_RELA = 4
SHN_UNDEF = 0
SHN_ABS = 0xFFF1
STB_GLOBAL = 1
STB_WEAK = 2
STT_SECTION = 3

RELOCATION_NAMES = {
    0x118: "R_AARCH64_CONDBR19",
    0x11A: "R_AARCH64_JUMP26",
    0x11B: "R_AARCH64_CALL26",
}


def run(command: list[str], *, cwd: Path) -> None:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if completed.returncode:
        rendered = subprocess.list2cmdline(command)
        raise BuildError(
            f"command failed ({completed.returncode}): {rendered}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )


def tool(ndk_bin: Path, name: str) -> Path:
    candidate = ndk_bin / name
    if not candidate.is_file():
        raise BuildError(f"missing NDK tool: {candidate}")
    return candidate


def read_c_string(blob: bytes, offset: int) -> str:
    if offset >= len(blob):
        raise BuildError(f"string-table offset {offset:#x} is out of bounds")
    end = blob.find(b"\0", offset)
    if end < 0:
        raise BuildError("unterminated ELF string")
    return blob[offset:end].decode("ascii", "strict")


def elf_index(blob: bytes) -> tuple[list[dict[str, int | str]], list[dict[str, int | str]]]:
    if len(blob) < ELF64_EHDR.size:
        raise BuildError("stub object is shorter than an ELF64 header")
    ident, _, _, _, _, _, shoff, _, _, _, _, shentsize, shnum, shstrndx = ELF64_EHDR.unpack_from(blob)
    if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
        raise BuildError("stub object is not ELF64 little-endian")
    if shentsize != ELF64_SHDR.size or not shnum or shstrndx >= shnum:
        raise BuildError("stub object has an invalid section table")
    if shoff + shnum * shentsize > len(blob):
        raise BuildError("stub section table is out of bounds")

    raw_sections = [ELF64_SHDR.unpack_from(blob, shoff + index * shentsize) for index in range(shnum)]
    shstr = raw_sections[shstrndx]
    shstr_offset, shstr_size = shstr[4], shstr[5]
    if shstr_offset + shstr_size > len(blob):
        raise BuildError("stub section-name string table is out of bounds")
    shstr_blob = blob[shstr_offset:shstr_offset + shstr_size]

    sections: list[dict[str, int | str]] = []
    for index, fields in enumerate(raw_sections):
        name_offset, section_type, _, address, offset, size, link, info, alignment, entry_size = fields
        if offset + size > len(blob) and section_type != 8:  # SHT_NOBITS has no file backing.
            raise BuildError(f"section {index} exceeds the object bounds")
        sections.append(
            {
                "index": index,
                "name": read_c_string(shstr_blob, name_offset),
                "type": section_type,
                "address": address,
                "offset": offset,
                "size": size,
                "link": link,
                "info": info,
                "alignment": alignment,
                "entry_size": entry_size,
            }
        )
    return sections, raw_sections  # Raw fields are needed for string-table lookup.


def build_loader_index(blob: bytes) -> bytes:
    """Create the objdump-compatible text trailer consumed by ElfLinker."""

    sections, _ = elf_index(blob)
    selected_sections = [
        section
        for section in sections
        if section["index"]
        and section["type"] not in (SHT_RELA, SHT_SYMTAB, 3)  # relocation/symbol/string tables
        and not str(section["name"]).startswith(".")
    ]
    section_by_index = {int(section["index"]): section for section in sections}

    symtabs = [section for section in sections if section["type"] == SHT_SYMTAB]
    if len(symtabs) != 1:
        raise BuildError(f"expected exactly one symbol table, found {len(symtabs)}")
    symtab = symtabs[0]
    strtab_index = int(symtab["link"])
    if strtab_index not in section_by_index:
        raise BuildError("symbol table references a missing string table")
    strtab = section_by_index[strtab_index]
    strtab_data = blob[int(strtab["offset"]):int(strtab["offset"]) + int(strtab["size"])]
    entry_size = int(symtab["entry_size"])
    if entry_size != ELF64_SYM.size or int(symtab["size"]) % entry_size:
        raise BuildError("invalid ELF64 symbol table layout")

    symbols: list[dict[str, int | str]] = []
    symtab_offset = int(symtab["offset"])
    for offset in range(0, int(symtab["size"]), entry_size):
        name_offset, info, _, shndx, value, _ = ELF64_SYM.unpack_from(blob, symtab_offset + offset)
        name = read_c_string(strtab_data, name_offset) if name_offset else ""
        symbols.append(
            {
                "name": name,
                "binding": info >> 4,
                "type": info & 0x0F,
                "shndx": shndx,
                "value": value,
            }
        )

    trailer: list[str] = [
        "Sections:\n",
        "Idx Name          Size      VMA               LMA               File off  Algn  Flags\n",
    ]
    for output_index, section in enumerate(selected_sections):
        trailer.append(
            f"{output_index:3d} {section['name']:<13} {int(section['size']):08x}  "
            f"{int(section['address']):016x}  {int(section['address']):016x}  "
            f"{int(section['offset']):08x}  2**{(int(section['alignment']).bit_length() - 1):d}  CONTENTS\n"
        )

    trailer.append("SYMBOL TABLE:\n")
    emitted_symbols: set[str] = set()
    for section in selected_sections:
        name = str(section["name"])
        emitted_symbols.add(name)
        trailer.append(f"0000000000000000 l    d  {name} 0 {name}\n")

    for symbol in symbols:
        name = str(symbol["name"])
        if not name or name in emitted_symbols or name.startswith("$"):
            continue
        if int(symbol["type"]) == STT_SECTION:
            continue
        if int(symbol["binding"]) not in (STB_GLOBAL, STB_WEAK):
            continue
        shndx = int(symbol["shndx"])
        if shndx == SHN_UNDEF:
            section_name = "*UND*"
        elif shndx == SHN_ABS:
            section_name = "*ABS*"
        elif shndx in section_by_index:
            section_name = str(section_by_index[shndx]["name"])
        else:
            raise BuildError(f"symbol {name} has unsupported section index {shndx}")
        emitted_symbols.add(name)
        kind = "g     F" if int(symbol["type"]) == 2 else "g      "
        trailer.append(f"{int(symbol['value']):016x} {kind} {section_name} 0 {name}\n")

    for section in sections:
        if section["type"] != SHT_RELA or not int(section["size"]):
            continue
        target_index = int(section["info"])
        if target_index not in section_by_index:
            raise BuildError(f"relocation section {section['name']} has a missing target")
        target_name = str(section_by_index[target_index]["name"])
        if target_name not in {str(item["name"]) for item in selected_sections}:
            continue
        if int(section["entry_size"]) != ELF64_RELA.size or int(section["size"]) % ELF64_RELA.size:
            raise BuildError(f"invalid relocation table layout for {section['name']}")
        trailer.extend(["\n", f"RELOCATION RECORDS FOR [{target_name}]:\n", "OFFSET           TYPE              VALUE\n"])
        reloc_offset = int(section["offset"])
        for offset in range(0, int(section["size"]), ELF64_RELA.size):
            r_offset, r_info, addend = ELF64_RELA.unpack_from(blob, reloc_offset + offset)
            symbol_index, relocation_type = r_info >> 32, r_info & 0xFFFFFFFF
            if symbol_index >= len(symbols):
                raise BuildError(f"relocation references invalid symbol index {symbol_index}")
            relocation_name = RELOCATION_NAMES.get(relocation_type)
            if relocation_name is None:
                raise BuildError(f"unsupported AArch64 relocation type {relocation_type:#x}")
            symbol_name = str(symbols[symbol_index]["name"])
            if not symbol_name:
                symbol_shndx = int(symbols[symbol_index]["shndx"])
                if symbol_shndx not in section_by_index:
                    raise BuildError("anonymous relocation symbol has no section")
                symbol_name = str(section_by_index[symbol_shndx]["name"])
            if addend > 0:
                symbol_name += f"+0x{addend:016x}"
            elif addend < 0:
                symbol_name += f"-0x{-addend:016x}"
            trailer.append(f"{r_offset:016x} {relocation_name:<20} {symbol_name}\n")

    return "".join(trailer).encode("ascii")


def compile_stub(repo: Path, ndk_bin: Path, work_dir: Path) -> Path:
    clang = tool(ndk_bin, "clang.exe")
    objcopy = tool(ndk_bin, "llvm-objcopy.exe")
    linker = tool(ndk_bin, "ld.lld.exe")
    source_dir = repo / "src" / "stub" / "src"
    objects = work_dir / "objects"
    objects.mkdir(parents=True, exist_ok=True)
    common = [
        "--target=aarch64-linux-gnu",
        "-nostdinc",
        "-DDAISY_CHAIN=1",
        "-I",
        str(source_dir),
        "-fno-exceptions",
        "-fno-asynchronous-unwind-tables",
        "-Wall",
        "-Wextra",
        "-Wcast-align",
        "-Wcast-qual",
        "-Wstrict-prototypes",
        "-Wwrite-strings",
        "-Werror",
    ]

    def compile_source(source: str, output: str, *extra: str) -> Path:
        destination = objects / output
        run([str(clang), *common, *extra, "-c", str(source_dir / source), "-o", str(destination)], cwd=repo)
        return destination

    fold = compile_source("arm64-linux.elf-so_fold.S", "arm64-linux.elf-so_fold.o")
    run([str(objcopy), "-R", ".text", "-R", ".comment", "-R", ".note", "-R", ".note.GNU-stack", "-R", ".reginfo", str(fold)], cwd=repo)
    expand = compile_source("arm64-expand.S", "arm64-expand.o")
    help_umf = compile_source("arm64-linux.elf-help_umf.S", "arm64-linux.elf-help_umf.o")
    upxfd = compile_source("upxfd_linux.c", "arm64-linux.elf-upxfd_linux.o", "-O")
    run([str(objcopy), "--rename-section", ".text=UMF_LINUX", "-R", ".comment", "-R", ".data", "-R", ".bss", "-R", ".note.GNU-stack", str(upxfd)], cwd=repo)
    so_main = compile_source("arm64-linux.elf-so_main.c", "arm64-linux.elf-so_main.o", "-O")
    run([str(objcopy), "--rename-section", ".text=SO_MAIN", "-R", ".comment", "-R", ".note", "-R", ".note.GNU-stack", "-R", ".reginfo", str(so_main)], cwd=repo)
    run([str(objcopy), "-R", ".comment", "-R", ".note", "-R", ".note.GNU-stack", "-R", ".reginfo", str(so_main)], cwd=repo)

    combined = work_dir / "arm64-linux.elf-so_fold.bin"
    run(
        [
            str(linker),
            "-r",
            "-m",
            "aarch64elf",
            "-T",
            str(source_dir / "arm64-linux.elf-so_fold.lds"),
            "-Map",
            str(work_dir / "arm64-linux.elf-so_fold.map"),
            "-o",
            str(combined),
            str(fold),
            str(expand),
            str(help_umf),
            str(upxfd),
            str(so_main),
        ],
        cwd=repo,
    )
    return combined


def validate_stub(blob: bytes, trailer: bytes) -> None:
    required = (
        b"my_memcpy",
        b"memcpy",
        b"upx_so_main",
        b"HUMF_L",
        b"UMF_LINUX",
        b"SO_MAIN",
        b"LZMA_DEC30",
    )
    for item in required:
        if item not in trailer:
            raise BuildError(f"generated loader index lacks required symbol or section {item.decode()}")
    if b"my_memcpy\n" not in trailer or b"*UND* 0 my_memcpy" in trailer:
        raise BuildError("my_memcpy is not resolved by the generated fold stub")
    if b"RELOCATION RECORDS FOR [SO_MAIN]:" not in trailer or b" my_memcpy\n" not in trailer:
        raise BuildError("SO_MAIN does not retain the my_memcpy relocation")
    if b"R_AARCH64_CALL26" not in trailer or b"R_AARCH64_JUMP26" not in trailer:
        raise BuildError("generated loader index lacks required branch relocations")
    sections, _ = elf_index(blob)
    names = {str(section["name"]) for section in sections}
    if not {"HUMF_L", "UMF_LINUX", "SO_MAIN"}.issubset(names):
        raise BuildError("generated fold object lacks a required selected loader section")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--ndk", type=Path, required=True, help="Android NDK root")
    parser.add_argument("--output", type=Path, help="header path (default: src/stub/arm64-linux.elf-so_fold.h)")
    parser.add_argument("--work-dir", type=Path, help="persistent directory for intermediate build artifacts")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    output = (args.output or repo / "src" / "stub" / "arm64-linux.elf-so_fold.h").resolve()
    ndk_bin = (args.ndk.resolve() / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64" / "bin")
    if not (repo / "src" / "stub" / "src" / "arm64-linux.elf-so_fold.S").is_file():
        raise BuildError(f"not an UPX source tree: {repo}")
    if not ndk_bin.is_dir():
        raise BuildError(f"NDK LLVM bin directory does not exist: {ndk_bin}")

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if args.work_dir:
        work_dir = args.work_dir.resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
    else:
        temporary = tempfile.TemporaryDirectory(prefix="upx-arm64-so-fold-")
        work_dir = Path(temporary.name)
    try:
        combined = compile_stub(repo, ndk_bin, work_dir)
        stripped = work_dir / "arm64-linux.elf-so_fold.stripped.bin"
        shutil.copyfile(combined, stripped)
        objcopy = tool(ndk_bin, "llvm-objcopy.exe")
        run(
            [
                str(objcopy),
                "-R",
                ".text",
                "-R",
                ".data",
                "-R",
                ".bss",
                "-R",
                ".comment",
                "-R",
                ".note",
                "-R",
                ".note.GNU-stack",
                "-R",
                ".reginfo",
                "-R",
                ".gnu.attributes",
                "-R",
                ".MIPS.abiflags",
                "-R",
                ".riscv.attributes",
                "-R",
                ".mdebug.eabi32",
                "-R",
                ".gcc_compiled_long32",
                str(stripped),
            ],
            cwd=repo,
        )
        run(
            [
                str(objcopy),
                "--strip-unneeded",
                "--keep-symbol=_start",
                "--keep-symbol=upx_main2",
                "--keep-symbol=upx_so_main",
                str(stripped),
            ],
            cwd=repo,
        )
        raw = stripped.read_bytes()
        trailer = build_loader_index(raw)
        validate_stub(raw, trailer)
        embedded = raw + trailer
        raw_path = work_dir / "arm64-linux.elf-so_fold.with-index.bin"
        raw_path.write_bytes(embedded)
        run(
            [
                sys.executable,
                str(repo / "src" / "stub" / "scripts" / "bin2h.py"),
                "--ident=stub_arm64_linux_elf_so_fold",
                str(raw_path),
                str(output),
            ],
            cwd=repo,
        )
        header = output.read_bytes()
        if f"{len(embedded)} (0x{len(embedded):x}) bytes".encode() not in header:
            raise BuildError("generated header has an unexpected embedded size")
        print(f"rebuilt {output}")
        print(f"embedded bytes: {len(embedded)}; ELF bytes: {len(raw)}; index bytes: {len(trailer)}")
        print(f"header CRC32: {zlib.crc32(embedded) & 0xFFFFFFFF:08x}")
        return 0
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuildError, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"error: {exc}")
