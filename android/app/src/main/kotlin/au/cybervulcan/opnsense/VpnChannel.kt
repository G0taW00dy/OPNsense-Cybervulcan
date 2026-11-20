package au.cybervulcan.opnsense

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodChannel
import org.json.JSONArray
import org.json.JSONObject

/**
 * MethodChannel "cybervulcan/vpn" (Dart: lib/src/platform/vpn_modes.dart).
 *
 *  prepare            -> true when the user has allowed this app's VPN (asks once)
 *  start {mode, routes, allowed, dns, mtu, transport} -> null, or error "vpn_failed"
 *  stop               -> null
 *  status             -> {running, mode, lastError, native: {..Go status..}}
 *  otherVpnActive     -> true when some other app's VPN is connected
 */
class VpnChannel(private val activity: Activity, messenger: BinaryMessenger) {
    companion object {
        const val REQUEST_PREPARE = 7302
    }

    private var pendingPrepare: MethodChannel.Result? = null

    init {
        MethodChannel(messenger, "cybervulcan/vpn").setMethodCallHandler { call, result ->
            when (call.method) {
                "prepare" -> prepare(result)
                "start" -> {
                    val routes = call.argument<List<String>>("routes") ?: emptyList()
                    val allowed = call.argument<List<String>>("allowed") ?: routes
                    val cfg = JSONObject()
                        .put("mode", call.argument<String>("mode") ?: "home")
                        .put("routes", JSONArray(routes))
                        .put("allowed", JSONArray(allowed))
                        .put("dns", call.argument<String>("dns") ?: "")
                        .put("mtu", call.argument<Int>("mtu") ?: 1280)
                        .put("transport", call.argument<String>("transport") ?: "wireguard")
                    if (VpnService.prepare(activity) != null) {
                        result.error("vpn_not_allowed", "Allow Cybervulcan's VPN first.", null)
                    } else {
                        CybervulcanVpnService.start(activity, cfg.toString())
                        result.success(null)
                    }
                }
                "stop" -> {
                    CybervulcanVpnService.stop(activity)
                    result.success(null)
                }
                "status" -> result.success(status())
                "otherVpnActive" -> result.success(otherVpnActive(activity))
                else -> result.notImplemented()
            }
        }
    }

    private fun prepare(result: MethodChannel.Result) {
        val intent = VpnService.prepare(activity)
        if (intent == null) {
            result.success(true)
            return
        }
        if (pendingPrepare != null) {
            result.error("busy", "Already asking for VPN permission.", null)
            return
        }
        pendingPrepare = result
        try {
            @Suppress("DEPRECATION")
            activity.startActivityForResult(intent, REQUEST_PREPARE)
        } catch (e: Exception) {
            pendingPrepare = null
            result.success(false)
        }
    }

    /** Called from MainActivity.onActivityResult. Returns true when handled. */
    fun onActivityResult(requestCode: Int, resultCode: Int): Boolean {
        if (requestCode != REQUEST_PREPARE) return false
        val r = pendingPrepare ?: return true
        pendingPrepare = null
        r.success(resultCode == Activity.RESULT_OK)
        return true
    }

    private fun status(): Map<String, Any?> {
        val native = if (CvNative.loadError == null) {
            try {
                CvNative.vpnStatus()
            } catch (e: Throwable) {
                null
            }
        } else null
        return mapOf(
            "running" to CybervulcanVpnService.running,
            "mode" to CybervulcanVpnService.mode,
            "lastError" to CybervulcanVpnService.lastError,
            "native" to native,
        )
    }

    /**
     * Whether another app's VPN is connected. Android allows one VPN at a
     * time (per user), so while ours runs the answer is false.
     */
    private fun otherVpnActive(context: Context): Boolean {
        if (CybervulcanVpnService.running) return false
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
        @Suppress("DEPRECATION")
        return cm.allNetworks.any { n ->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    }
}
