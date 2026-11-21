package au.cybervulcan.opnsense

/**
 * JNI entry points into libcvwg.so (native/cvwg/exports_vpn_android.go).
 *
 * The Dart side opens the same library with dart:ffi; System.loadLibrary
 * returns the already-loaded instance, so there is one Go runtime per
 * process. The VPN service calls these directly so the VPN keeps working
 * (and can be stopped) when the Flutter engine is gone.
 */
object CvNative {
    /** Null when the library is missing from this build. */
    val loadError: String? = try {
        System.loadLibrary("cvwg")
        null
    } catch (e: Throwable) {
        e.message ?: "libcvwg.so missing"
    }

    /** Hands [fd] to Go (Go owns and closes it). Returns {"up":true} or {"error":"..."}. */
    external fun vpnStart(fd: Int, json: String): String

    /** Session status JSON (see vpn_glue.go vpnStatus). */
    external fun vpnStatus(): String

    external fun vpnStop()
}
