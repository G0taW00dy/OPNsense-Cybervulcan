package au.cybervulcan.opnsense

import android.appwidget.AppWidgetManager
import android.content.ComponentName
import android.content.Context
import android.content.SharedPreferences
import android.graphics.Color
import android.net.Uri
import android.service.quicksettings.TileService
import android.view.View
import android.widget.RemoteViews
import es.antonborri.home_widget.HomeWidgetBackgroundIntent
import es.antonborri.home_widget.HomeWidgetLaunchIntent
import es.antonborri.home_widget.HomeWidgetProvider

/**
 * Home-screen widget: shows the current exit and a whole-house bypass toggle.
 * Data is written from Dart (lib/src/platform/android_widget.dart) via home_widget.
 *
 * Bypass OFF runs in the background (Dart callback). Bypass ON always opens
 * the app's "affects everyone" confirmation dialog.
 */
class ExitWidgetProvider : HomeWidgetProvider() {

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray,
        widgetData: SharedPreferences,
    ) {
        val exit = widgetData.getString(KEY_EXIT, null) ?: "Open app to set up"
        val health = widgetData.getString(KEY_HEALTH, null) ?: "notConfigured"
        val bypass = widgetData.getString(KEY_BYPASS, "?")
        val until = widgetData.getString(KEY_BYPASS_UNTIL, "") ?: ""
        val updated = widgetData.getString(KEY_UPDATED, "") ?: ""

        appWidgetIds.forEach { id ->
            val views = RemoteViews(context.packageName, R.layout.exit_widget).apply {
                setTextViewText(R.id.widget_exit, exit)
                setInt(R.id.widget_dot, "setColorFilter", healthColor(health))
                setTextViewText(
                    R.id.widget_updated,
                    if (updated.isNotEmpty()) "Updated $updated" else "",
                )

                // Tapping the widget body opens the app.
                setOnClickPendingIntent(
                    R.id.widget_root,
                    HomeWidgetLaunchIntent.getActivity(context, MainActivity::class.java),
                )

                when (bypass) {
                    "1" -> {
                        setViewVisibility(R.id.widget_bypass, View.VISIBLE)
                        setTextViewText(
                            R.id.widget_bypass,
                            if (until.isNotEmpty()) "Bypass ON until $until - tap to end" else "Bypass ON - tap to end",
                        )
                        setOnClickPendingIntent(
                            R.id.widget_bypass,
                            HomeWidgetBackgroundIntent.getBroadcast(context, Uri.parse(URI_BYPASS_OFF)),
                        )
                    }
                    "0" -> {
                        setViewVisibility(R.id.widget_bypass, View.VISIBLE)
                        setTextViewText(R.id.widget_bypass, "VPN bypass (whole house)...")
                        setOnClickPendingIntent(
                            R.id.widget_bypass,
                            HomeWidgetLaunchIntent.getActivity(
                                context, MainActivity::class.java, Uri.parse(URI_BYPASS_CONFIRM),
                            ),
                        )
                    }
                    else -> setViewVisibility(R.id.widget_bypass, View.GONE)
                }

                setOnClickPendingIntent(
                    R.id.widget_refresh,
                    HomeWidgetBackgroundIntent.getBroadcast(context, Uri.parse(URI_REFRESH)),
                )
            }
            appWidgetManager.updateAppWidget(id, views)
        }

        // Keep the Quick Settings tile in sync with the same data.
        TileService.requestListeningState(
            context, ComponentName(context, BypassTileService::class.java),
        )
    }

    companion object {
        const val KEY_EXIT = "cv_exit"
        const val KEY_HEALTH = "cv_health"
        const val KEY_BYPASS = "cv_bypass"
        const val KEY_BYPASS_UNTIL = "cv_bypass_until"
        const val KEY_UPDATED = "cv_updated"

        const val URI_BYPASS_CONFIRM = "cybervulcan://bypass/confirm"
        const val URI_BYPASS_OFF = "cybervulcan://bypass/off"
        const val URI_REFRESH = "cybervulcan://refresh"

        fun healthColor(health: String): Int = when (health) {
            "ok" -> Color.parseColor("#2ECC71")
            "warning" -> Color.parseColor("#F5A623")
            "problem" -> Color.parseColor("#E5484D")
            "bypass" -> Color.parseColor("#9B5DE5")
            else -> Color.parseColor("#8A8F98")
        }
    }
}
