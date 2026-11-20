package com.hexo141.liquidglass.bootimg

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * One kernel profile in the binary layout the payload reads (`profile/profile/binary.h`, v2).
 *
 * Sections are name → key → value; a key that is absent means "not provided", which is different
 * from a provided 0 (the payload has runtime fallbacks for the optional ones). Values are signed
 * 64-bit on the wire, so negative numbers such as `caps_value = -1` survive bit-exactly.
 */
data class Glk1Profile(
    val release: String,
    val sections: LinkedHashMap<String, LinkedHashMap<String, Long>>,
) {
    /** One section, or an empty map when the profile does not carry it. */
    operator fun get(section: String): Map<String, Long> =
        sections[section] ?: emptyMap()

    fun value(section: String, key: String): Long? = sections[section]?.get(key)

    /** Release shortened for the UI; `uname -r` strings get long. */
    fun shortRelease(): String = release
}

/**
 * Reader/writer for the payload's binary profile (version 2, object sections).
 *
 * ```
 * u32 magic 0x0D000721, u16 version, u16 frontend, u16 backend, u16 middleware,
 * u16 release_len, u16 pad, release,
 * u16 section_count, per section: u8 name_len, name, u32 entry_count,
 *                                per entry: u8 key_len, key, i64 value
 * ```
 *
 * The header is padded to 16 bytes, matching the C struct's 4-byte alignment.
 */
object Glk1Codec {

    const val MAGIC = 0x0D000721.toInt()
    private const val VERSION: Int = 2
    private const val FRONTEND_ROOT_CHILD: Int = 1
    private const val BACKEND_CVE_2026_43499: Int = 1
    private const val NO_MIDDLEWARE: Int = 1
    private const val HEADER_SIZE = 16

    fun encode(profile: Glk1Profile): ByteArray {
        val release = profile.release.toByteArray(Charsets.UTF_8)
        require(release.size <= 0xFFFF) { "release too long" }

        val out = ByteArrayOutputStream(8 * 1024)
        val header = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        header.putInt(MAGIC)
        header.putShort(VERSION.toShort())
        header.putShort(FRONTEND_ROOT_CHILD.toShort())
        header.putShort(BACKEND_CVE_2026_43499.toShort())
        header.putShort(NO_MIDDLEWARE.toShort())
        header.putShort(release.size.toShort())
        header.putShort(0)
        out.write(header.array())
        out.write(release)

        out.writeU16(profile.sections.size)
        profile.sections.forEach { (section, entries) ->
            val name = section.toByteArray(Charsets.UTF_8)
            require(name.size <= 0xFF) { "section name too long: $section" }
            out.write(name.size)
            out.write(name)
            out.writeU32(entries.size)
            entries.forEach { (key, value) ->
                val keyBytes = key.toByteArray(Charsets.UTF_8)
                require(keyBytes.size <= 0xFF) { "key too long: $key" }
                out.write(keyBytes.size)
                out.write(keyBytes)
                out.writeU64(value)
            }
        }
        return out.toByteArray()
    }

    /** Parses a profile file; throws [IllegalArgumentException] when it is not a v2 document. */
    fun decode(bytes: ByteArray): Glk1Profile {
        require(bytes.size >= HEADER_SIZE + 2) { "profile too short" }
        val header = ByteBuffer.wrap(bytes, 0, HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        require(header.int == MAGIC) { "not a kernel profile" }
        val version = header.short.toInt()
        require(version == VERSION) { "unsupported profile version $version" }
        header.short // frontend
        header.short // backend
        header.short // middleware
        val releaseLength = header.short.toInt()
        header.short // padding

        var pos = HEADER_SIZE
        require(pos + releaseLength <= bytes.size) { "truncated release" }
        val release = bytes.decodeToString(pos, pos + releaseLength)
        pos += releaseLength

        val sectionCount = readU16(bytes, pos); pos += 2
        val sections = LinkedHashMap<String, LinkedHashMap<String, Long>>(sectionCount)
        repeat(sectionCount) {
            val nameLength = readU8(bytes, pos); pos += 1
            val name = bytes.decodeToString(pos, pos + nameLength); pos += nameLength
            val entryCount = readU32(bytes, pos); pos += 4
            val entries = LinkedHashMap<String, Long>(entryCount)
            repeat(entryCount) {
                val keyLength = readU8(bytes, pos); pos += 1
                val key = bytes.decodeToString(pos, pos + keyLength); pos += keyLength
                entries[key] = readI64(bytes, pos); pos += 8
            }
            sections[name] = entries
        }
        return Glk1Profile(release, sections)
    }

    private fun ByteArrayOutputStream.writeU16(value: Int) {
        write(value and 0xFF)
        write((value ushr 8) and 0xFF)
    }

    private fun ByteArrayOutputStream.writeU32(value: Int) {
        write(value and 0xFF)
        write((value ushr 8) and 0xFF)
        write((value ushr 16) and 0xFF)
        write((value ushr 24) and 0xFF)
    }

    private fun ByteArrayOutputStream.writeU64(value: Long) {
        var v = value
        repeat(8) {
            write((v and 0xFF).toInt())
            v = v ushr 8
        }
    }

    private fun readU8(bytes: ByteArray, at: Int): Int = bytes[at].toInt() and 0xFF

    private fun readU16(bytes: ByteArray, at: Int): Int =
        readU8(bytes, at) or (readU8(bytes, at + 1) shl 8)

    private fun readU32(bytes: ByteArray, at: Int): Int =
        readU8(bytes, at) or (readU8(bytes, at + 1) shl 8) or
            (readU8(bytes, at + 2) shl 16) or (readU8(bytes, at + 3) shl 24)

    private fun readI64(bytes: ByteArray, at: Int): Long {
        var value = 0L
        for (i in 7 downTo 0) value = (value shl 8) or readU8(bytes, at + i).toLong()
        return value
    }
}
