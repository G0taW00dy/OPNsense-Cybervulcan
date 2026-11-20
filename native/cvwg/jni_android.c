// JNI string helpers for exports_vpn_android.go (cgo cannot call through
// the JNIEnv function table directly). Built for GOOS=android only.
#include <jni.h>

const char* cv_jstring_chars(JNIEnv* env, jstring s) {
    return (*env)->GetStringUTFChars(env, s, NULL);
}

void cv_jstring_release(JNIEnv* env, jstring s, const char* c) {
    (*env)->ReleaseStringUTFChars(env, s, c);
}

jstring cv_new_jstring(JNIEnv* env, const char* c) {
    return (*env)->NewStringUTF(env, c);
}
