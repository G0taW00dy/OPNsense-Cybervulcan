package au.cybervulcan.opnsense

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File

class MainActivity : FlutterActivity() {
    private fun updatesDir(): File = File(cacheDir, "updates").apply { mkdirs() }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "au.cybervulcan.opnsense/updater")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    // Folder the Dart side downloads the APK into (app cache, not shared storage).
                    "updatesDir" -> result.success(updatesDir().absolutePath)

                    // Android 8+: "Install unknown apps" must be allowed for this app.
                    "canInstall" -> result.success(
                        Build.VERSION.SDK_INT < Build.VERSION_CODES.O ||
                            packageManager.canRequestPackageInstalls()
                    )

                    "openInstallSettings" -> {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                            startActivity(
                                Intent(
                                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                    Uri.parse("package:$packageName")
                                )
                            )
                        }
                        result.success(null)
                    }

                    // Opens the system installer for an APK inside updatesDir() only.
                    "installApk" -> {
                        val path = call.argument<String>("path")
                        val dir = updatesDir().canonicalPath + File.separator
                        val file = path?.let { File(it) }
                        if (file == null || !file.isFile || !file.canonicalPath.startsWith(dir) ||
                            !file.name.endsWith(".apk")
                        ) {
                            result.error("bad_path", "Update file not found", null)
                        } else {
                            val uri = FileProvider.getUriForFile(this, "$packageName.updates", file)
                            val intent = Intent(Intent.ACTION_VIEW)
                                .setDataAndType(uri, "application/vnd.android.package-archive")
                                .addFlags(
                                    Intent.FLAG_GRANT_READ_URI_PERMISSION or
                                        Intent.FLAG_ACTIVITY_NEW_TASK
                                )
                            startActivity(intent)
                            result.success(true)
                        }
                    }

                    else -> result.notImplemented()
                }
            }
    }
}
