#include <jni.h>

/* Standard UPX's shared-object path requires a replaceable DT_INIT hook. */
void _init(void) {}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_6;
}
