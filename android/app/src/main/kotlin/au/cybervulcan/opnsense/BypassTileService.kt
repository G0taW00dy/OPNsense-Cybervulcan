package au.cybervulcan.opnsense

import android.annotation.SuppressLint
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import es.antonborri.home_widget.HomeWidgetBackgroundIntent
import es.antonborri.home_widget.HomeWidgetLaunchIntent
import es.antonborri.home_widget.HomeWidgetPlugin

/**
 * Quick Settings tile for the whole-house VPN bypass.
 *
 * - Active tile (bypass ON): tap turns bypass OFF in the background via the
 *   Dart callback (no UI needed - that is the safe direction).
 * - Inactive tile: tap opens the app's confirmation dialog, because turning
 *   bypass ON affects everyone on the VPN network.
 */
class BypassTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        render(pending = false)
    }

    override fun onClick() {
        super.onClick()
        val bypass = HomeWidgetPlugin.getData(this).getString(ExitWidgetProvider.KEY_BYPASS, "?")
        if (bypass == "1") {
            HomeWidgetBackgroundIntent
                .getBroadcast(this, Uri.parse(ExitWidgetProvider.URI_BYPASS_OFF))
                .send()
            render(pending = true)
        } else {
            if (isLocked) unlockAndRun { openConfirm() } else openConfirm()
        }
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openConfirm() {
        val uri = Uri.parse(ExitWidgetProvider.URI_BYPASS_CONFIRM)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                HomeWidgetLaunchIntent.getActivity(this, MainActivity::class.java, uri),
            )
        } else {
            val intent = Intent(this, MainActivity::class.java).apply {
                action = LAUNCH_ACTION
                data = uri
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun render(pending: Boolean) {
        val tile = qsTile ?: return
        val data = HomeWidgetPlugin.getData(this)
        val bypass = data.getString(ExitWidgetProvider.KEY_BYPASS, "?")
        val until = data.getString(ExitWidgetProvider.KEY_BYPASS_UNTIL, "") ?: ""
        tile.label = "VPN bypass"
        when {
            pending -> {
                tile.state = Tile.STATE_UNAVAILABLE
                setSubtitle(tile, "Turning off...")
            }
            bypass == "1" -> {
                tile.state = Tile.STATE_ACTIVE
                setSubtitle(tile, if (until.isNotEmpty()) "Whole house until $until" else "Whole house ON")
            }
            bypass == "0" -> {
                tile.state = Tile.STATE_INACTIVE
                setSubtitle(tile, "Off (whole house)")
            }
            else -> {
                tile.state = Tile.STATE_INACTIVE
                setSubtitle(tile, "Open app to set up")
            }
        }
        tile.updateTile()
    }

    private fun setSubtitle(tile: Tile, text: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) tile.subtitle = text
    }

    companion object {
        /** home_widget's launch action, so the app receives the deep link. */
        const val LAUNCH_ACTION = "es.antonborri.home_widget.action.LAUNCH"
    }
}
