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
        val title = widgetData.getString(KEY_TITLE, null)
            ?: widgetData.getString(KEY_EXIT, null) ?: "Cybervulcan"
        val status = widgetData.getString(KEY_STATUS, null) ?: "OPEN THE APP"
        val detail = widgetData.getString(KEY_DETAIL, null) ?: ""
        val where = widgetData.getString(KEY_WHERE, null)
        val health = widgetData.getString(KEY_HEALTH, null) ?: "notConfigured"
        val bypass = widgetData.getString(KEY_BYPASS, "?")
        val until = widgetData.getString(KEY_BYPASS_UNTIL, "") ?: ""
        val updated = widgetData.getString(KEY_UPDATED, "") ?: ""

        appWidgetIds.forEach { id ->
            val views = RemoteViews(context.packageName, R.layout.exit_widget).apply {
                val color = healthColor(health)
                setTextViewText(R.id.widget_exit, title)
                setTextViewText(R.id.widget_status, status)
                setTextColor(R.id.widget_status, color)
                setInt(R.id.widget_dot, "setColorFilter", color)
                setTextViewText(R.id.widget_detail, detail)
                setViewVisibility(R.id.widget_detail, if (detail.isEmpty()) View.GONE else View.VISIBLE)
                setTextViewText(
                    R.id.widget_updated,
                    where ?: if (updated.isNotEmpty()) "Updated $updated" else "",
                )
                // Greyed art while the router is out of reach.
                setInt(R.id.widget_art, "setImageAlpha", if (health == "stale") 90 else 255)

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
                            if (until.isNotEmpty()) "Bypass on until $until · tap to end" else "Bypass on · tap to end",
                        )
                        setOnClickPendingIntent(
                            R.id.widget_bypass,
                            HomeWidgetBackgroundIntent.getBroadcast(context, Uri.parse(URI_BYPASS_OFF)),
                        )
                    }
                    "0" -> {
                        setViewVisibility(R.id.widget_bypass, View.VISIBLE)
                        setTextViewText(R.id.widget_bypass, "VPN bypass…")
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
        const val KEY_STATUS = "cv_status"
        const val KEY_TITLE = "cv_title"
        const val KEY_DETAIL = "cv_detail"
        const val KEY_WHERE = "cv_where"

        const val URI_BYPASS_CONFIRM = "cybervulcan://bypass/confirm"
        const val URI_BYPASS_OFF = "cybervulcan://bypass/off"
        const val URI_REFRESH = "cybervulcan://refresh"

        fun healthColor(health: String): Int = when (health) {
            "ok" -> Color.parseColor("#2ECC71")
            "warning" -> Color.parseColor("#F5A623")
            "problem" -> Color.parseColor("#FF6B6F")
            "bypass" -> Color.parseColor("#B794F4")
            else -> Color.parseColor("#8A8F98")
        }
    }
}
