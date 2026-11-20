package com.hexo141.liquidglass.device

import android.content.Context
import android.os.Build
import android.provider.Settings
import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell
import java.io.File

/**
 * Hardware / OS details of the device adbd is running on.
 *
 * Two sources:
 * - [fromLocal] reads this process' own build props, so the cards are never empty (and stay
 *   meaningful while there is no connection yet).
 * - [fromAdb] runs `getprop` / `uname -r` / `getenforce` through the ADB connection, which is the
 *   authoritative answer once connected (and stays correct if the daemon is on another device).
 */
data class DeviceInfo(
    val deviceName: String,
    val chipset: String,
    /** GPU model, e.g. "Adreno (TM) 730"; the GPU engine matches on this. */
    val gpu: String,
    /** Raw release string, e.g. "15" — engines match on this. */
    val androidRelease: String,
    val androidVersion: String,
    val kernel: String,
    val selinux: String,
    /** `ro.product.device` (e.g. "OP6113L1"); the CVE-2026-64560 payload gates on it. */
    val codename: String = "Unknown",
    /** `ro.build.fingerprint`; the CVE-2026-64560 payload only accepts one exact build. */
    val fingerprint: String = "Unknown",
) {
    companion object {
        private const val UNKNOWN = "Unknown"

        /**
         * One shell round trip with a marker before every query: `getprop <missing>` prints
         * nothing at all, so markers keep the fields aligned no matter which prop is absent.
         */
        private const val MARKER = "@@"

        private val QUERIES = listOf(
            "getprop ro.product.manufacturer",
            "getprop ro.product.model",
            "getprop ro.soc.manufacturer",
            "getprop ro.soc.model",
            "getprop ro.board.platform",
            "getprop ro.hardware",
            "getprop ro.build.version.release",
            "getprop ro.build.version.sdk",
            "uname -r",
            "getenforce",
            "cat /sys/class/kgsl/kgsl-3d0/gpu_model 2>/dev/null",
            "getprop ro.hardware.egl",
            "getprop ro.product.device",
            "getprop ro.build.fingerprint",
            // MTK / Exynos: Mali exposes its model here (Qualcomm's KGSL node does not exist).
            "cat /proc/mali/version 2>/dev/null",
            // Last resort: SurfaceFlinger prints "GLES: ARM, Mali-G57, OpenGL ES 3.2 ...".
            "dumpsys SurfaceFlinger 2>/dev/null | grep -m1 GLES",
        )

        private val COMMAND: String =
            QUERIES.joinToString("; ") { "echo '$MARKER'; $it" }

        // ---------------------------------------------------------------- over ADB

        @Throws(Exception::class)
        fun fromAdb(manager: AbsAdbConnectionManager): DeviceInfo {
            val output = AdbShell.exec(manager, COMMAND)
            val fields = output.split(MARKER).map { it.trim() }
            fun field(index: Int): String = fields.getOrNull(index).orEmpty()

            return DeviceInfo(
                deviceName = deviceName(field(1), field(2)),
                chipset = chipset(field(3), field(4), field(5), field(6)),
                gpu = gpu(field(11), field(12), field(15), field(16)),
                androidRelease = field(7),
                androidVersion = androidVersion(field(7), field(8)),
                kernel = field(9).ifEmpty { UNKNOWN },
                selinux = field(10).ifEmpty { UNKNOWN },
                codename = field(13).ifEmpty { UNKNOWN },
                fingerprint = field(14).ifEmpty { UNKNOWN },
            )
        }

        // ---------------------------------------------------------------- locally

        fun fromLocal(context: Context): DeviceInfo {
            val customName = runCatching {
                Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME)
            }.getOrNull()?.trim().orEmpty()
            val manufacturer = Build.MANUFACTURER?.trim().orEmpty()
            val model = Build.MODEL?.trim().orEmpty()

            val socModel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                Build.SOC_MODEL?.trim().orEmpty()
            } else {
                ""
            }
            val socManufacturer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                Build.SOC_MANUFACTURER?.trim().orEmpty()
            } else {
                ""
            }

            return DeviceInfo(
                deviceName = customName.ifEmpty { deviceName(manufacturer, model) },
                chipset = chipset(socManufacturer, socModel,
                    Build.BOARD?.trim().orEmpty(), Build.HARDWARE?.trim().orEmpty()),
                gpu = localGpu(),
                androidRelease = Build.VERSION.RELEASE.orEmpty(),
                androidVersion = androidVersion(Build.VERSION.RELEASE, Build.VERSION.SDK_INT.toString()),
                kernel = System.getProperty("os.version")?.trim().orEmpty().ifEmpty { UNKNOWN },
                selinux = localSelinux(),
                codename = Build.DEVICE?.trim().orEmpty().ifEmpty { UNKNOWN },
                fingerprint = Build.FINGERPRINT?.trim().orEmpty().ifEmpty { UNKNOWN },
            )
        }

        /** KGSL (Qualcomm) or the Mali driver node; never a board codename. */
        private fun localGpu(): String {
            val kgsl = runCatching {
                File("/sys/class/kgsl/kgsl-3d0/gpu_model").readText().trim()
            }.getOrNull().orEmpty()
            if (kgsl.isNotEmpty()) return kgsl

            val mali = runCatching {
                File("/proc/mali/version").readText().trim()
            }.getOrNull().orEmpty()
            if (mali.isNotEmpty()) return mali

            /* Build.HARDWARE is the board platform ("mt6853", "qcom"), not a GPU model —
             * showing it here is how "meow" ended up in the GPU card. */
            return UNKNOWN
        }

        /** SELinux mode from selinuxfs: 1 = enforcing, 0 = permissive. */
        private fun localSelinux(): String {
            if (!File("/sys/fs/selinux").exists()) return "Disabled"
            val enforcing = runCatching {
                File("/sys/fs/selinux/enforce").readText().trim()
            }.getOrNull()
            return when (enforcing) {
                "1" -> "Enforcing"
                "0" -> "Permissive"
                else -> UNKNOWN
            }
        }

        // ---------------------------------------------------------------- helpers

        /** e.g. "Android 15 (API 35)". */
        private fun androidVersion(release: String, sdk: String): String {
            val version = release.trim()
            val api = sdk.trim()
            return when {
                version.isEmpty() && api.isEmpty() -> UNKNOWN
                version.isEmpty() -> "API $api"
                api.isEmpty() -> "Android $version"
                else -> "Android $version (API $api)"
            }
        }

        private fun deviceName(manufacturer: String, model: String): String = when {
            model.isEmpty() -> UNKNOWN
            manufacturer.isEmpty() || model.startsWith(manufacturer, ignoreCase = true) -> model
            else -> "$manufacturer $model"
        }

        /**
         * GPU label, in decreasing order of trust:
         *  1. KGSL `gpu_model` — Qualcomm only ("Adreno (TM) 730").
         *  2. `/proc/mali/version` — MTK / Exynos ("Mali-G57 r0p1").
         *  3. SurfaceFlinger's `GLES:` line — "GLES: ARM, Mali-G57, OpenGL ES 3.2 ...".
         *  4. `ro.hardware.egl` — but only when it actually names a GPU vendor. On ColorOS
         *     this prop can be an internal board codename ("meow"), which used to leak into
         *     the GPU card on every MediaTek device because the KGSL node does not exist there.
         */
        private fun gpu(
            gpuModel: String,
            hardwareEgl: String,
            maliVersion: String,
            glesLine: String,
        ): String {
            if (gpuModel.isNotEmpty() && !gpuModel.equals(UNKNOWN, ignoreCase = true)) {
                return gpuModel
            }
            maliVersion.lineSequence()
                .map { it.trim() }
                .firstOrNull { it.contains("Mali", ignoreCase = true) }
                ?.let { return it }

            glesModel(glesLine)?.let { return it }

            val egl = hardwareEgl.trim()
            if (egl.isNotEmpty() && GPU_VENDORS.any { egl.contains(it, ignoreCase = true) }) {
                return egl
            }
            return UNKNOWN
        }

        private val GPU_VENDORS = listOf("adreno", "mali", "powervr", "immortalis", "xclipse")

        /** "GLES: ARM, Mali-G57, OpenGL ES 3.2 ..." -> "Mali-G57". */
        private fun glesModel(line: String): String? {
            val body = line.substringAfter("GLES:", "").trim()
            if (body.isEmpty()) return null
            return body.split(',')
                .map { it.trim() }
                .firstOrNull { model -> GPU_VENDORS.any { model.contains(it, ignoreCase = true) } }
        }

        private fun chipset(
            socManufacturer: String,
            socModel: String,
            boardPlatform: String,
            hardware: String,
        ): String {
            if (socModel.isNotEmpty() && !socModel.equals(UNKNOWN, ignoreCase = true)) {
                return when {
                    socManufacturer.isEmpty() || socModel.startsWith(socManufacturer, ignoreCase = true) ->
                        socModel
                    else -> "$socManufacturer $socModel"
                }
            }
            // Older releases (and some OEMs) only fill in the board/hardware props.
            return listOf(boardPlatform, hardware)
                .firstOrNull { it.isNotEmpty() && !it.equals(UNKNOWN, ignoreCase = true) }
                ?: UNKNOWN
        }
    }
}
