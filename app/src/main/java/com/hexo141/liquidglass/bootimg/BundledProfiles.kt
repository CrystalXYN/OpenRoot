package com.hexo141.liquidglass.bootimg

import android.content.Context

/**
 * The profiles shipped inside the APK (`assets/kernel_profiles/<release>.bin`).
 *
 * They serve two purposes: the exact-match fallback the app has always used, and the template a
 * freshly parsed `boot.img` borrows its run tuning from. Decoding all of them takes a few
 * milliseconds, so the result is cached for the process lifetime.
 */
object BundledProfiles {

    private const val DIR = "kernel_profiles"
    private const val SUFFIX = ".bin"

    @Volatile
    private var cache: List<Glk1Profile>? = null

    fun releases(context: Context): List<String> =
        runCatching {
            context.assets.list(DIR)
                ?.filter { it.endsWith(SUFFIX) }
                ?.map { it.removeSuffix(SUFFIX) }
                ?.sorted()
                .orEmpty()
        }.getOrDefault(emptyList())

    /** Decoded bundled profiles; a file that cannot be read is skipped rather than failing all. */
    fun templates(context: Context): List<Glk1Profile> {
        cache?.let { return it }
        val decoded = releases(context).mapNotNull { release ->
            bytes(context, release)?.let { raw ->
                runCatching { Glk1Codec.decode(raw) }.getOrNull()
            }
        }
        cache = decoded
        return decoded
    }

    /** Raw bytes of the bundled profile for [release], or null when it is not shipped. */
    fun bytes(context: Context, release: String): ByteArray? =
        runCatching {
            context.assets.open("$DIR/$release$SUFFIX").use { it.readBytes() }
        }.getOrNull()
}
