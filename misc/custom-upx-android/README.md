# Custom UPX Android Wrapper

This directory adds a maintainable Android AArch64 wrapper around the standard
UPX Linux shared-library format.  It is intentionally separate from `src/`:
the inner file is created by the unmodified upstream UPX packer, while the
outer ChaCha20/zlib layer is not an upstream UPX feature or file format.

## What It Implements

The packer performs these stages:

```text
input AArch64 Android ET_DYN .so
  -> standard UPX --best shared-object bridge
  -> zlib wrapper stream
  -> ChaCha20-IETF (32-byte key, 12-byte nonce, counter 0)
  -> AArch64 Android JNI wrapper .so
```

The runtime wrapper decodes the bridge into a `memfd`, loads it with
`android_dlopen_ext(ANDROID_DLEXT_USE_LIBRARY_FD)`, resolves `JNI_OnLoad`, and
then invokes the inner library's JNI entry point.

The metadata record is exactly `0x58` bytes and follows the recovered sample
family layout:

| Offset | Meaning |
| ---: | --- |
| `0x00` | `u32` record version (`1`) |
| `0x08` | `u64` ciphertext RVA |
| `0x10` | `u64` ciphertext-end RVA |
| `0x18` | `u32` ciphertext length |
| `0x1c` | `u32` zlib output capacity / bridge length |
| `0x2c` | 32-byte ChaCha20 key |
| `0x4c` | 12-byte nonce |
| `0x58` | ciphertext starts |

The packer normalizes the record's source/end RVA fields after linking and
keeps matching `R_AARCH64_RELATIVE` addends for Android's dynamic linker.  An
external static recovery tool must use ELF `PT_LOAD` RVA-to-file-offset
conversion.  It must never index raw file bytes directly by RVA.

## Build The Upstream Packer

Initialize the pinned third-party submodules before building.  On Windows:

```powershell
Set-Location D:\git\upx
git submodule update --init --recursive
py -3 misc\custom-upx-android\rebuild_arm64_so_fold.py `
  --repo D:\git\upx `
  --ndk C:\Users\admin\AppData\Local\Android\Sdk\ndk\27.0.12077973 `
  --work-dir D:\git\upx\build-custom-upx\arm64-so-fold-rebuild
cmake -S . -B build-custom-upx -G Ninja -DCMAKE_BUILD_TYPE=Release `
  -DUPX_CONFIG_DISABLE_GITREV=ON -DUPX_CONFIG_DISABLE_SANITIZE=ON `
  -DUPX_CONFIG_DISABLE_WERROR=ON
cmake --build build-custom-upx --target upx --parallel 4
```

## Pack An Android Library

The input must be an unpacked AArch64 `ET_DYN` Android library which exports
`JNI_OnLoad` through the traditional `DT_HASH` dynamic-symbol table and uses
`RegisterNatives`. It must also provide a file-backed initialization hook that
upstream UPX can replace while the shared-object loader restores the compressed
image: one non-zero `DT_INIT`, or the first file-backed slot of
`DT_PREINIT_ARRAY` / `DT_INIT_ARRAY` (the slot may be zero on disk when its
`R_AARCH64_RELATIVE` relocation supplies the runtime target). This input
contract is checked before packing using UPX's order: `DT_INIT`, then
`DT_PREINIT_ARRAY`, then `DT_INIT_ARRAY`. Link with `void _init(void) {}` only
when none of those appropriate hooks already exists. The NDK must contain an
AArch64 clang wrapper. The default discovery checks `ANDROID_NDK_HOME` and the
Android SDK NDK directory, but passing `--ndk` is most explicit.

```powershell
py -3 D:\git\upx\misc\custom-upx-android\pack_custom_upx_android.py `
  D:\path\to\libtarget.so `
  --output D:\path\to\libtarget.custom-upx.so `
  --upx D:\git\upx\build-custom-upx\upx.exe `
  --ndk C:\Users\admin\AppData\Local\Android\Sdk\ndk\27.0.12077973
```

By default the key and nonce come from `secrets.token_bytes`.  Supply fixed
values only for reproducible test vectors:

```powershell
  --key-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f `
  --nonce-hex 000000090000004a00000000
```

The output receipt records the bridge hash, final wrapper hash, metadata RVA,
raw file offsets, and independent post-link decryption/decompression proof.
It intentionally stores only SHA-256 hashes of the key and nonce.

If a historical static recovery deliberately elided an unavailable,
non-loadable section-table tail, the packer writes a separate
`input.for-upx.so` only in its work directory. This canonical input appends a
minimal, derived section table because upstream UPX needs section metadata to
choose the shared-object compression boundary. It changes only the source ELF
header's section-table fields (`e_shoff`, `e_shentsize`, `e_shnum`, and
`e_shstrndx`); program headers, `PT_DYNAMIC`, and every pre-existing segment
body are verified byte-for-byte unchanged. The receipt labels this path as
canonicalization, so the generated section table is never presented as a
byte-for-byte recovery of missing original file bytes.

When using a persistent `--work-dir`, clear or choose a new directory before
rerunning the same command: upstream UPX intentionally refuses to overwrite
the previously generated `inner.upx.so` bridge. `--android-shlib` is a legacy
compatibility hint in the current upstream AArch64 path; normal `--best`
packing is the supported command shown here.

## Static Verification

Use the metadata RVA from the receipt with the external static recovery tool:

```powershell
py -3 D:\OneDrive\OLLVM\unpack_custom_upx_static.py `
  D:\path\to\libtarget.custom-upx.so `
  --metadata-rva 0xYOUR_RECEIPT_METADATA_RVA `
  --mode shared-object `
  --output D:\path\to\libtarget.recovered.so
```

## Reproducible Round Trip

The fixture deliberately provides `DT_HASH`, `JNI_OnLoad`, `DT_INIT`, and a
compressible executable payload so it exercises upstream's AArch64
shared-object bridge instead of merely testing the outer wrapper. The same
packer and static recovery path also support upstream's `DT_PREINIT_ARRAY[0]`
and `DT_INIT_ARRAY[0]` hook forms.

```powershell
$ndk = 'C:\Users\admin\AppData\Local\Android\Sdk\ndk\27.0.12077973'
$root = 'D:\git\upx\build-custom-upx\custom-upx-fixture'

powershell -ExecutionPolicy Bypass -File `
  D:\git\upx\misc\custom-upx-android\tests\build_jni_fixture.ps1 `
  -Ndk $ndk -Output "$root\libjni-fixture-code-payload.so"

py -3 D:\git\upx\misc\custom-upx-android\pack_custom_upx_android.py `
  "$root\libjni-fixture-code-payload.so" `
  --output "$root\final\libjni-fixture.custom-upx.so" `
  --upx D:\git\upx\build-custom-upx\upx.exe --ndk $ndk `
  --key-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f `
  --nonce-hex 000000090000004a00000000 `
  --work-dir "$root\final\work"

py -3 D:\OneDrive\OLLVM\unpack_custom_upx_static.py `
  "$root\final\libjni-fixture.custom-upx.so" `
  --metadata-rva 0x46d8 --mode shared-object `
  --output "$root\final\libjni-fixture.recovered.so" `
  --bridge-output "$root\final\libjni-fixture.recovered-bridge.so" `
  --bridge-oracle "$root\final\work\inner.upx.so"

py -3 D:\git\upx\misc\custom-upx-android\tests\verify_round_trip.py `
  --original "$root\libjni-fixture-code-payload.so" `
  --wrapper "$root\final\libjni-fixture.custom-upx.so" `
  --pack-receipt "$root\final\libjni-fixture.custom-upx.so.json" `
  --recovered "$root\final\libjni-fixture.recovered.so" `
  --recovered-bridge "$root\final\libjni-fixture.recovered-bridge.so" `
  --bridge "$root\final\work\inner.upx.so" `
  --recovery-receipt "$root\final\libjni-fixture.recovered.so.json"
```

The verifier proves statically that the wrapper is AArch64 `ET_DYN`, exports
only `JNI_OnLoad`, stores its metadata and ciphertext in file-backed
`PT_LOAD`, and recovers the bridge, every original `PT_LOAD`, selected
initialization hook (`DT_INIT` or an init-array first slot), ELF section-table
metadata, and the entire original input byte-for-byte. It does not execute the
target or use IDA, Unicorn, or a runtime memory dump.

For a source that needed section-table canonicalization, verify against the
receipt's `input.path` (`input.for-upx.so`) rather than the sectionless source
recovery. This proves a complete byte-for-byte round trip of the deterministic
canonical ELF. The separate recovery receipt documents the original
loadable/runtime reconstruction boundary.

The wrapper does not reproduce OLLVM CFF, fake export tables, anti-debugging,
or sample-specific key derivation.  Those techniques are orthogonal to UPX and
would make the implementation less reviewable without changing the normal
UPX recovery path.

Only `JNI_OnLoad` is exported and forwarded.  Do not use this wrapper for a
library whose consumers call exported C/C++ APIs directly unless matching
forwarding thunks have been explicitly designed and tested.
