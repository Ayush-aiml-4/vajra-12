package com.vajra.companion.identity

import android.content.Context
import android.os.Build
import android.provider.Settings
import java.util.Locale

/**
 * Resolves a privacy-respecting, user-friendly Android device name.
 * Respects Android 29..34 privacy boundaries without requesting dangerous permissions.
 *
 * Checks Settings.Global.DEVICE_NAME or Settings.Secure.BLUETOOTH_NAME if safely accessible without extra permissions;
 * otherwise constructs a clean manufacturer + model label (e.g. "Google Pixel 8", "Samsung Galaxy S23"),
 * falling back safely to "Android Device".
 */
object DeviceNaming {
    const val DEFAULT_ANDROID_NAME = "Android Device"

    fun resolveDeviceName(context: Context? = null): String {
        if (context != null) {
            try {
                val globalName = Settings.Global.getString(context.contentResolver, "device_name")?.trim()
                if (!globalName.isNullOrEmpty() && globalName.length in 2..64) {
                    return globalName
                }
            } catch (_: Exception) {
                // Ignore restricted access
            }

            try {
                val secureName = Settings.Secure.getString(context.contentResolver, "bluetooth_name")?.trim()
                if (!secureName.isNullOrEmpty() && secureName.length in 2..64) {
                    return secureName
                }
            } catch (_: Exception) {
                // Ignore restricted access
            }
        }

        val manufacturer = Build.MANUFACTURER?.trim().orEmpty()
        val model = Build.MODEL?.trim().orEmpty()

        if (model.isNotEmpty()) {
            val formatted = if (manufacturer.isNotEmpty() && !model.lowercase(Locale.ROOT).startsWith(manufacturer.lowercase(Locale.ROOT))) {
                val capManufacturer = manufacturer.replaceFirstChar {
                    if (it.isLowerCase()) it.titlecase(Locale.ROOT) else it.toString()
                }
                "$capManufacturer $model"
            } else {
                model
            }
            val cleaned = formatted.trim().take(64)
            if (cleaned.length >= 2) {
                return cleaned
            }
        }

        return DEFAULT_ANDROID_NAME
    }
}
