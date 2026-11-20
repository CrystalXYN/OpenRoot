package com.hexo141.liquidglass.bootimg

import android.content.Context
import java.io.File

/**
 * Profiles parsed on the device, kept in app-private storage next to the bundled ones.
 *
 * One file per release (`<release>.glk1`), because the release is the key the payload matches on:
 * saving the same kernel twice overwrites the earlier copy instead of piling up duplicates. The
 * selection is a single release string in preferences; `null` means "use the bundled profile".
 */
object ProfileStore {

    private const val DIR = "parsed_profiles"
    private const val PREFS = "parsed_profiles"
    private const val KEY_SELECTED = "selected"
    private const val KEY_META_PREFIX = "meta:"
    private const val SUFFIX = ".glk1"

    /**
     * CVE-2026-98260 reads a second, differently shaped profile for the same release: link-time
     * addresses in HOCON instead of offsets in a binary blob. Both live side by side and share the
     * release key, so selecting a release selects both formats at once.
     */
    private const val C98260_SUFFIX = ".c98260"

    data class Entry(
        val release: String,
        val file: File,
        /** Name of the boot.img this profile came from, for the list subtitle. */
        val sourceName: String,
        val savedAt: Long,
    )

    private fun dir(context: Context): File =
        File(context.filesDir, DIR).apply { mkdirs() }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun file(context: Context, release: String): File =
        File(dir(context), release.replace('/', '_') + SUFFIX)

    /** Every parsed profile, newest first. */
    fun list(context: Context): List<Entry> =
        dir(context).listFiles { f -> f.isFile && f.name.endsWith(SUFFIX) }
            ?.mapNotNull { file ->
                val release = file.name.removeSuffix(SUFFIX)
                val meta = prefs(context).getString(KEY_META_PREFIX + release, null)
                val source = meta?.substringBefore('|').orEmpty()
                val savedAt = meta?.substringAfter('|')?.toLongOrNull() ?: file.lastModified()
                Entry(release, file, source, savedAt)
            }
            ?.sortedByDescending { it.savedAt }
            .orEmpty()

    fun entry(context: Context, release: String): Entry? =
        list(context).firstOrNull { it.release == release }

    /**
     * Writes [bytes] for [release]. [activate] is false for imported offsets whose release does
     * not match the running kernel: silently making them active would aim the payload at the wrong
     * build, so the user has to pick it explicitly from the list instead.
     */
    fun save(context: Context, release: String, bytes: ByteArray, sourceName: String, activate: Boolean = true) {
        file(context, release).writeBytes(bytes)
        val editor = prefs(context).edit()
            .putString(KEY_META_PREFIX + release, "$sourceName|${System.currentTimeMillis()}")
        if (activate) editor.putString(KEY_SELECTED, release)
        editor.apply()
    }

    fun load(context: Context, release: String): ByteArray? =
        file(context, release).takeIf { it.isFile }?.readBytes()

    private fun c98260File(context: Context, release: String): File =
        File(dir(context), release.replace('/', '_') + C98260_SUFFIX)

    /** Writes the CVE-2026-98260 profile that came from the same parse; no selection change. */
    fun saveC98260(context: Context, release: String, text: String) {
        c98260File(context, release).writeText(text)
    }

    /** {@code null} when this release has no parsed 98260 profile and the bundled table applies. */
    fun loadC98260(context: Context, release: String): String? =
        c98260File(context, release).takeIf { it.isFile }?.readText()

    fun deleteC98260(context: Context, release: String) {
        c98260File(context, release).delete()
    }

    fun active(context: Context): String? = prefs(context).getString(KEY_SELECTED, null)

    /**
     * Makes [release] active, or clears the selection when it is null.
     *
     * Bundled releases are accepted: they are not files in [dir], but they are still a profile the
     * user can point an engine at.
     */
    fun select(context: Context, release: String?) {
        prefs(context).edit().apply {
            if (release.isNullOrEmpty()) remove(KEY_SELECTED) else putString(KEY_SELECTED, release)
        }.apply()
    }

    fun delete(context: Context, release: String) {
        file(context, release).delete()
        c98260File(context, release).delete()
        prefs(context).edit().apply {
            remove(KEY_META_PREFIX + release)
            if (prefs(context).getString(KEY_SELECTED, null) == release) remove(KEY_SELECTED)
        }.apply()
    }
}
