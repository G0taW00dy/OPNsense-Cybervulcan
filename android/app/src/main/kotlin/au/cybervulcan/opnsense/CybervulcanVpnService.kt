package au.cybervulcan.opnsense

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.system.OsConstants
import org.json.JSONArray
import org.json.JSONObject

/**
 * System VPN for the remote-access modes "Home devices only" and
 * "Everything via home".
 *
 * The interface's packets are handled in Go (package vpn): a netstack
 * terminates each flow and re-opens it through the app's WireGuard tunnel to
 * the router. That tunnel's own UDP socket lives in this app's process, so
 * the whole app is excluded from the VPN (addDisallowedApplication) -
 * otherwise the tunnel would route into itself. The app's own traffic never
 * needed the VPN: router API calls already go through the tunnel's loopback
 * forwarder, and the at-home check must see the real network.
 *
 * Lifecycle: started by the app (MethodChannel "cybervulcan/vpn") with the
 * routes; Go owns the interface fd. It keeps running without the Flutter
 * engine (foreground service, notification). Stop: the app, the notification
 * button, the system (onRevoke - another VPN app took the slot, or the user
 * disconnected in Settings) or Always-on VPN restarts (last settings reused;
 * traffic waits until the app has the tunnel up again).
 */
class CybervulcanVpnService : VpnService() {

    companion object {
        const val ACTION_START = "au.cybervulcan.opnsense.vpn.START"
        const val ACTION_STOP = "au.cybervulcan.opnsense.vpn.STOP"
        const val EXTRA_CONFIG = "config"

        private const val CHANNEL_ID = "home_link"
        private const val NOTIFICATION_ID = 7301
        private const val PREFS = "cybervulcan_vpn"
        private const val KEY_LAST_CONFIG = "last_config"

        // Interface address. The netstack accepts any destination, so this
        // only has to be a private address unlikely to be a real LAN.
        private const val IFACE_ADDRESS = "10.233.233.1"

        @Volatile
        var running = false
            private set

        @Volatile
        var mode = ""
            private set

        @Volatile
        var lastError: String? = null
            private set

        fun start(context: Context, config: String) {
            lastError = null // a stale error must not look like this start failing
            context.startService(
                Intent(context, CybervulcanVpnService::class.java)
                    .setAction(ACTION_START)
                    .putExtra(EXTRA_CONFIG, config)
            )
        }

        fun stop(context: Context) {
            if (!running) return
            context.startService(Intent(context, CybervulcanVpnService::class.java).setAction(ACTION_STOP))
        }
    }

    private val handler = Handler(Looper.getMainLooper())
    private var lastTransportUp: Boolean? = null
    private val refresh = object : Runnable {
        override fun run() {
            if (!running) return
            val up = try {
                JSONObject(CvNative.vpnStatus()).optBoolean("transportUp", false)
            } catch (e: Throwable) {
                false
            }
            if (up != lastTransportUp) {
                lastTransportUp = up
                notifyStatus(up)
            }
            handler.postDelayed(this, 15_000)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            stopSelf()
            return START_NOT_STICKY
        }
        // ACTION_START from the app, or SERVICE_INTERFACE / null from
        // Always-on VPN: reuse the last settings.
        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val config = intent?.getStringExtra(EXTRA_CONFIG)
            ?: prefs.getString(KEY_LAST_CONFIG, null)
        if (config == null) {
            lastError = "Open Cybervulcan and choose what remote access carries first."
            stopSelf()
            return START_NOT_STICKY
        }
        prefs.edit().putString(KEY_LAST_CONFIG, config).apply()
        val err = startVpn(config)
        if (err != null) {
            lastError = err
            stopVpn()
            stopSelf()
        }
        return START_NOT_STICKY
    }

    /** Returns a plain-English error, or null when the VPN is up. */
    private fun startVpn(config: String): String? {
        CvNative.loadError?.let { return "The remote-access library is missing from this build ($it)." }
        val cfg = try {
            JSONObject(config)
        } catch (e: Exception) {
            return "Bad VPN settings."
        }
        val newMode = cfg.optString("mode", "home")
        val mtu = cfg.optInt("mtu", 1280)
        val routes = cfg.optJSONArray("routes") ?: JSONArray()
        val dns = cfg.optString("dns", "")

        if (running) {
            CvNative.vpnStop() // closes the old interface
            running = false
        }
        val builder = Builder()
            .setSession(if (newMode == "everything") "Cybervulcan - everything via home" else "Cybervulcan - home devices")
            .setMtu(mtu)
            .addAddress(IFACE_ADDRESS, 32)
            .setBlocking(true)
            .setConfigureIntent(openAppIntent())
        try {
            builder.addDisallowedApplication(packageName)
            var anyV4 = false
            for (i in 0 until routes.length()) {
                val parts = routes.getString(i).split("/")
                val addr = parts[0]
                val prefix = parts.getOrNull(1)?.toInt() ?: (if (addr.contains(':')) 128 else 32)
                builder.addRoute(addr, prefix)
                if (!addr.contains(':')) anyV4 = true
            }
            if (!anyV4) return "No home devices to route."
            if (dns.isNotEmpty()) builder.addDnsServer(dns)
        } catch (e: Exception) {
            return "Invalid route or DNS server: ${e.message}"
        }
        if (newMode != "everything") {
            // Split tunnel: IPv6 keeps using the normal network. (With no
            // IPv6 route Android would otherwise block IPv6 for all apps.)
            builder.allowFamily(OsConstants.AF_INET6)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false) // metered only if the real network is
        }
        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            null
        } ?: return "Android did not allow the VPN (permission not granted or revoked)."

        // Go owns the fd from here on and closes it on stop.
        val goCfg = JSONObject()
            .put("mode", newMode)
            .put("mtu", mtu)
            .put("transport", cfg.optString("transport", "wireguard"))
            .put("allowed", cfg.optJSONArray("allowed") ?: JSONArray())
        if (dns.isNotEmpty()) goCfg.put("dns", dns)
        val reply = try {
            JSONObject(CvNative.vpnStart(pfd.detachFd(), goCfg.toString()))
        } catch (e: Throwable) {
            return "The VPN could not start: ${e.message}"
        }
        if (reply.has("error")) return "The VPN could not start: ${reply.getString("error")}"

        running = true
        mode = newMode
        lastError = null
        lastTransportUp = null
        goForeground()
        handler.removeCallbacks(refresh)
        handler.post(refresh)
        return null
    }

    private fun stopVpn() {
        handler.removeCallbacks(refresh)
        if (CvNative.loadError == null) {
            try {
                CvNative.vpnStop()
            } catch (e: Throwable) {
                // Library state is gone anyway.
            }
        }
        running = false
        mode = ""
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    override fun onRevoke() {
        lastError = "The VPN was turned off by Android (another VPN app started, or it was disconnected in Settings)."
        stopVpn()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        if (running) stopVpn()
        super.onDestroy()
    }

    // ------------------------------------------------------------ notification

    private fun modeLabel() = if (mode == "everything") "Everything" else "Home devices only"

    private fun openAppIntent(): PendingIntent = PendingIntent.getActivity(
        this, 0,
        Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )

    private fun buildNotification(transportUp: Boolean): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Home link (VPN)", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "Shown while the phone uses the VPN to reach home"
                    setShowBadge(false)
                }
            )
        }
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, CybervulcanVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setSmallIcon(R.drawable.ic_stat_opn)
            .setContentTitle(if (transportUp) "Connected to home - ${modeLabel()}" else "Home link waiting - ${modeLabel()}")
            .setContentText(
                if (transportUp) "Tap to open Cybervulcan"
                else "Remote access is not connected - open Cybervulcan"
            )
            .setContentIntent(openAppIntent())
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Disconnect", stop).build())
            .build()
    }

    private fun goForeground() {
        val n = buildNotification(transportUp = true)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                // VPN apps may use systemExempted (the VPN is established by now).
                startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } else {
                startForeground(NOTIFICATION_ID, n)
            }
        } catch (e: Exception) {
            // Not fatal: Android keeps a bound VpnService alive anyway; we
            // just lose the persistent notification.
        }
    }

    private fun notifyStatus(transportUp: Boolean) {
        try {
            getSystemService(NotificationManager::class.java)
                .notify(NOTIFICATION_ID, buildNotification(transportUp))
        } catch (e: Exception) {
            // Notifications disabled: nothing to update.
        }
    }
}
