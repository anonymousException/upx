/*
 * Minimal Android AArch64 runtime for the custom ChaCha20/zlib UPX wrapper.
 *
 * The host packer emits custom_upx_outer_record in payload.S.  This loader
 * decrypts and inflates the normal UPX-packed inner shared object, then asks
 * Android's dynamic linker to load it from a sealed-in anonymous fd.
 *
 * This deliberately implements only the useful JNI handoff.  It does not
 * reproduce sample-specific CFF, fake exports, or anti-analysis behavior.
 */

#include <android/dlext.h>
#include <dlfcn.h>
#include <errno.h>
#include <jni.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <zlib.h>

#define CUSTOM_UPX_RECORD_VERSION 1u
#define CUSTOM_UPX_RECORD_SIZE 0x58u
#define CUSTOM_UPX_MAX_BRIDGE_SIZE (64u * 1024u * 1024u)
#define MFD_CLOEXEC 0x0001u

struct __attribute__((packed)) custom_upx_outer_record {
    uint32_t version;
    uint32_t flags;
    uint64_t ciphertext_rva;
    uint64_t ciphertext_end_rva;
    uint32_t ciphertext_length;
    uint32_t bridge_length;
    uint32_t reserved[3];
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t ciphertext[];
};

_Static_assert(sizeof(struct custom_upx_outer_record) == CUSTOM_UPX_RECORD_SIZE,
               "custom UPX record layout changed");

extern const struct custom_upx_outer_record custom_upx_outer_record
    __attribute__((visibility("hidden")));

typedef jint (*jni_onload_fn)(JavaVM *, void *);

static pthread_mutex_t g_load_lock = PTHREAD_MUTEX_INITIALIZER;
static void *g_inner_handle;
static jni_onload_fn g_inner_jni_onload;
static int g_load_failed;

static uint32_t rotl32(uint32_t value, unsigned count) {
    return (value << count) | (value >> (32u - count));
}

static void quarter_round(uint32_t state[16], unsigned a, unsigned b, unsigned c, unsigned d) {
    state[a] += state[b];
    state[d] = rotl32(state[d] ^ state[a], 16);
    state[c] += state[d];
    state[b] = rotl32(state[b] ^ state[c], 12);
    state[a] += state[b];
    state[d] = rotl32(state[d] ^ state[a], 8);
    state[c] += state[d];
    state[b] = rotl32(state[b] ^ state[c], 7);
}

static uint32_t load32_le(const uint8_t *source) {
    return ((uint32_t)source[0]) | ((uint32_t)source[1] << 8) |
           ((uint32_t)source[2] << 16) | ((uint32_t)source[3] << 24);
}

static void store32_le(uint8_t *destination, uint32_t value) {
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8);
    destination[2] = (uint8_t)(value >> 16);
    destination[3] = (uint8_t)(value >> 24);
}

static void chacha20_ietf_xor(const uint8_t key[32], const uint8_t nonce[12],
                              uint32_t counter, const uint8_t *source,
                              uint8_t *destination, size_t size) {
    static const uint8_t constants[16] = "expand 32-byte k";
    size_t offset = 0;

    while (offset < size) {
        uint32_t state[16];
        uint32_t working[16];
        uint8_t stream[64];
        size_t block_size = size - offset;
        if (block_size > sizeof(stream)) {
            block_size = sizeof(stream);
        }

        state[0] = load32_le(constants + 0);
        state[1] = load32_le(constants + 4);
        state[2] = load32_le(constants + 8);
        state[3] = load32_le(constants + 12);
        for (unsigned index = 0; index != 8; ++index) {
            state[4 + index] = load32_le(key + 4 * index);
        }
        state[12] = counter;
        state[13] = load32_le(nonce + 0);
        state[14] = load32_le(nonce + 4);
        state[15] = load32_le(nonce + 8);
        memcpy(working, state, sizeof(state));
        for (unsigned round = 0; round != 10; ++round) {
            quarter_round(working, 0, 4, 8, 12);
            quarter_round(working, 1, 5, 9, 13);
            quarter_round(working, 2, 6, 10, 14);
            quarter_round(working, 3, 7, 11, 15);
            quarter_round(working, 0, 5, 10, 15);
            quarter_round(working, 1, 6, 11, 12);
            quarter_round(working, 2, 7, 8, 13);
            quarter_round(working, 3, 4, 9, 14);
        }
        for (unsigned index = 0; index != 16; ++index) {
            store32_le(stream + 4 * index, working[index] + state[index]);
        }
        for (size_t index = 0; index != block_size; ++index) {
            destination[offset + index] = source[offset + index] ^ stream[index];
        }
        ++counter;
        offset += block_size;
    }
}

static int inflate_exact(const uint8_t *source, size_t source_size, uint8_t *destination,
                         size_t destination_size) {
    z_stream stream;
    int result;

    if (source_size > UINT_MAX || destination_size > UINT_MAX) {
        return -1;
    }
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef *)source;
    stream.avail_in = (uInt)source_size;
    stream.next_out = destination;
    stream.avail_out = (uInt)destination_size;
    result = inflateInit(&stream);
    if (result != Z_OK) {
        return -1;
    }
    result = inflate(&stream, Z_FINISH);
    if (inflateEnd(&stream) != Z_OK) {
        return -1;
    }
    if (result != Z_STREAM_END || stream.avail_in != 0 || stream.total_out != destination_size) {
        return -1;
    }
    return 0;
}

static int write_all(int fd, const uint8_t *data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        ssize_t written = write(fd, data + offset, size - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int create_memfd(void) {
#if defined(SYS_memfd_create)
    return (int)syscall(SYS_memfd_create, "custom-upx", MFD_CLOEXEC);
#else
    return (int)syscall(279, "custom-upx", MFD_CLOEXEC);
#endif
}

static int load_inner_locked(void) {
    const struct custom_upx_outer_record *record = &custom_upx_outer_record;
    uint8_t *compressed = NULL;
    uint8_t *bridge = NULL;
    android_dlextinfo extinfo;
    void *handle = NULL;
    jni_onload_fn jni_onload = NULL;
    int fd = -1;
    int status = -1;

    if (record->version != CUSTOM_UPX_RECORD_VERSION || record->flags != 0 ||
        record->ciphertext_length == 0 || record->bridge_length == 0 ||
        record->ciphertext_length > CUSTOM_UPX_MAX_BRIDGE_SIZE ||
        record->bridge_length > CUSTOM_UPX_MAX_BRIDGE_SIZE ||
        record->ciphertext_end_rva - record->ciphertext_rva != record->ciphertext_length) {
        return -1;
    }
    compressed = (uint8_t *)malloc(record->ciphertext_length);
    bridge = (uint8_t *)malloc(record->bridge_length);
    if (compressed == NULL || bridge == NULL) {
        goto done;
    }
    chacha20_ietf_xor(record->key, record->nonce, 0, record->ciphertext, compressed,
                      record->ciphertext_length);
    if (inflate_exact(compressed, record->ciphertext_length, bridge, record->bridge_length) != 0 ||
        memcmp(bridge, "\177ELF", 4) != 0) {
        goto done;
    }
    fd = create_memfd();
    if (fd < 0 || write_all(fd, bridge, record->bridge_length) != 0) {
        goto done;
    }
    memset(&extinfo, 0, sizeof(extinfo));
    extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    extinfo.library_fd = fd;
    handle = android_dlopen_ext("libcustom_upx_inner.so", RTLD_NOW | RTLD_LOCAL, &extinfo);
    if (handle == NULL) {
        goto done;
    }
    jni_onload = (jni_onload_fn)dlsym(handle, "JNI_OnLoad");
    if (jni_onload == NULL) {
        goto done;
    }
    g_inner_handle = handle;
    g_inner_jni_onload = jni_onload;
    handle = NULL;
    status = 0;

done:
    if (fd >= 0) {
        close(fd);
    }
    if (handle != NULL) {
        dlclose(handle);
    }
    free(bridge);
    free(compressed);
    return status;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    jni_onload_fn jni_onload;

    pthread_mutex_lock(&g_load_lock);
    if (g_inner_jni_onload == NULL && !g_load_failed) {
        if (load_inner_locked() != 0) {
            g_load_failed = 1;
        }
    }
    jni_onload = g_inner_jni_onload;
    pthread_mutex_unlock(&g_load_lock);

    if (jni_onload == NULL) {
        return JNI_ERR;
    }
    return jni_onload(vm, reserved);
}
