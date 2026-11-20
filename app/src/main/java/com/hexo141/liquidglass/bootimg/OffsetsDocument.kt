package com.hexo141.liquidglass.bootimg

/**
 * A self-contained, human-readable export of the offsets parsed from one kernel image.
 *
 * Why a separate format instead of copying the GLK1 `.bin`: the binary blob only carries values.
 * It cannot say which value came from BTF/kallsyms, which was borrowed from a bundled template,
 * which was synthesised from `selinux_state`, or which was deliberately omitted. Exporting values
 * without that provenance is how a foreign build's absolute address gets mistaken for a real one.
 *
 * So every field is labelled, and the file is never trusted blindly on import: the schema, the
 * release, the section shape and every numeric value are checked. Files with an unknown format are
 * refused rather than guessed at.
 *
 * Deliberately plain JVM (no Android types, no JSON library): the host unit tests exercise the
 * same encoder/decoder the app uses.
 */
class OffsetsError(message: String) : IllegalArgumentException(message)

data class OffsetsDocument(
    val release: String,
    /** What was parsed: a boot.img name, an OTA URL, or "imported". */
    val source: String,
    /** Epoch milliseconds; informational only, never used for validation. */
    val exportedAt: Long,
    val imageSha256: String?,
    /** The full GLK1 section map, byte-for-byte what [Glk1Codec.encode] would write. */
    val offsets: LinkedHashMap<String, LinkedHashMap<String, Long>>,
    val provenance: Provenance,
    /** The CVE-2026-98260 snapshot from the same parse, when one was produced. */
    val c98260Hocon: String?,
) {

    data class Provenance(
        /** `section.key` values proven by this image (BTF / kallsyms). */
        val derived: List<String> = emptyList(),
        /** `section.key` values borrowed from the closest bundled profile. */
        val inherited: List<String> = emptyList(),
        /** `section.key` -> how it was computed (e.g. `selinux_state+0x0 (BTF enforcing offset)`). */
        val synthesized: Map<String, String> = emptyMap(),
        val missing: List<String> = emptyList(),
        val blocked: List<String> = emptyList(),
        val notes: List<String> = emptyList(),
        /** `parsed` (provenance is exact) or `imported` (per-field provenance is unknown). */
        val origin: String = "parsed",
    )

    fun toProfile(): Glk1Profile = Glk1Profile(release, offsets)

    fun toBytes(): ByteArray = encode(this)

    /**
     * Import gate, kept here so the host tests exercise exactly what the app enforces.
     *
     * Two classes of file are refused outright: ones whose `offset.*` values were inherited from
     * a bundled template (they belong to another kernel build - the bug fixed in the previous
     * round), and ones that still list unresolved required offsets.
     */
    fun validateForImport() {
        val inheritedAddresses = provenance.inherited.filter { it.startsWith("offset.") }
        if (inheritedAddresses.isNotEmpty()) {
            throw OffsetsError(
                "refusing to import: ${inheritedAddresses.size} symbol offsets were inherited " +
                    "from a bundled template ($inheritedAddresses); they belong to another build",
            )
        }
        if (provenance.blocked.isNotEmpty()) {
            throw OffsetsError(
                "refusing to import: required offsets unresolved " +
                    "(${provenance.blocked.joinToString()})",
            )
        }
    }

    /** Filename for ACTION_CREATE_DOCUMENT; releases can contain slashes. */
    fun suggestedName(): String =
        "openroot-offsets-" + release.replace(Regex("[^A-Za-z0-9._-]"), "_") + ".json"

    companion object {
        const val FORMAT = "openroot-offsets/v1"
        private const val MAX_BYTES = 2 * 1024 * 1024
        const val MAX_DEPTH = 24

        /** Builds a document from a live parse, so every field keeps its real provenance. */
        fun fromBuild(
            build: BootProfileBuilder.ProfileBuild,
            source: String,
            imageSha256: String?,
            c98260Hocon: String?,
            now: Long = System.currentTimeMillis(),
        ): OffsetsDocument {
            val sections = LinkedHashMap<String, LinkedHashMap<String, Long>>()
            build.profile.sections.forEach { (section, entries) ->
                sections[section] = LinkedHashMap(entries)
            }
            val synthesized = LinkedHashMap<String, String>()
            build.notes.forEach { note ->
                if (note.contains("selinux_state+") && note.contains("BTF")) {
                    synthesized["offset.selinux_enforcing"] = note
                }
            }
            return OffsetsDocument(
                release = build.profile.release,
                source = source,
                exportedAt = now,
                imageSha256 = imageSha256,
                offsets = sections,
                provenance = Provenance(
                    derived = build.derived.distinct(),
                    inherited = build.inherited.distinct(),
                    synthesized = synthesized,
                    missing = build.missing,
                    blocked = build.blocked,
                    notes = build.notes,
                    origin = "parsed",
                ),
                c98260Hocon = c98260Hocon,
            )
        }

        /** Builds a document from an already-saved profile whose per-field provenance is lost. */
        fun fromSavedProfile(
            profile: Glk1Profile,
            source: String,
            c98260Hocon: String?,
            now: Long = System.currentTimeMillis(),
        ): OffsetsDocument {
            val sections = LinkedHashMap<String, LinkedHashMap<String, Long>>()
            profile.sections.forEach { (section, entries) ->
                sections[section] = LinkedHashMap(entries)
            }
            return OffsetsDocument(
                release = profile.release,
                source = source,
                exportedAt = now,
                imageSha256 = null,
                offsets = sections,
                provenance = Provenance(
                    notes = listOf(
                        "导出自已保存的 profile：逐字段来源不可考，请按「已验证」而非「本机解析」对待",
                        "此文件的 offsets 仍属于它自己的 build；导入到别的 release 会打偏",
                    ),
                    origin = "imported",
                ),
                c98260Hocon = c98260Hocon,
            )
        }

        fun decode(bytes: ByteArray): OffsetsDocument {
            if (bytes.size > MAX_BYTES) {
                throw OffsetsError("offsets 文件超过 ${MAX_BYTES / 1024} KiB，拒绝解析")
            }
            val text = String(bytes, Charsets.UTF_8)
            val root = Json.parse(text, MAX_DEPTH)
            if (root !is Map<*, *>) throw OffsetsError("offsets 文件顶层必须是对象")

            val format = root.string("format")
                ?: throw OffsetsError("缺少 format 字段（不是 openroot offsets 文件）")
            if (format != FORMAT) {
                throw OffsetsError("不支持的 format '$format'；本版本只接受 $FORMAT，不猜测其他格式")
            }
            val release = root.string("release")
                ?: throw OffsetsError("缺少 release 字段")
            if (release.isBlank()) throw OffsetsError("release 为空")
            val source = root.string("source") ?: "imported"
            val exportedAt = root.long("exported_at") ?: 0L
            val imageSha256 = root.string("image_sha256")

            val offsetsRaw = root["offsets"]
                ?: throw OffsetsError("缺少 offsets 段")
            if (offsetsRaw !is Map<*, *>) throw OffsetsError("offsets 段必须是对象")
            val offsets = LinkedHashMap<String, LinkedHashMap<String, Long>>()
            offsetsRaw.forEach { (sectionKey, entriesRaw) ->
                if (sectionKey !is String || sectionKey.isEmpty()) {
                    throw OffsetsError("offsets 段含有非法的 section 名")
                }
                if (entriesRaw !is Map<*, *>) {
                    throw OffsetsError("offsets.$sectionKey 必须是对象")
                }
                val entries = LinkedHashMap<String, Long>()
                entriesRaw.forEach { (key, raw) ->
                    if (key !is String || key.isEmpty()) {
                        throw OffsetsError("offsets.$sectionKey 含有非法的 key")
                    }
                    entries[key] = when (raw) {
                        is Long -> raw
                        else -> throw OffsetsError("offsets.$sectionKey.$key 不是整数")
                    }
                }
                offsets[sectionKey] = entries
            }
            val offsetSection = offsets["offset"]
                ?: throw OffsetsError("缺少 offset 段（符号偏移是该文件的主要内容）")
            if (offsetSection.isEmpty()) throw OffsetsError("offset 段为空")

            val provRaw = root["provenance"]
            val provenance = if (provRaw == null) {
                Provenance(origin = "imported")
            } else {
                if (provRaw !is Map<*, *>) throw OffsetsError("provenance 必须是对象")
                val synthesized = LinkedHashMap<String, String>()
                (provRaw["synthesized"] as? Map<*, *>)?.forEach { (k, v) ->
                    if (k is String && v is String) synthesized[k] = v
                }
                Provenance(
                    derived = provRaw.strings("derived"),
                    inherited = provRaw.strings("inherited"),
                    synthesized = synthesized,
                    missing = provRaw.strings("missing"),
                    blocked = provRaw.strings("blocked"),
                    notes = provRaw.strings("notes"),
                    origin = provRaw.string("origin") ?: "imported",
                )
            }
            val hocon = root.string("c98260_hocon")

            return OffsetsDocument(
                release = release,
                source = source,
                exportedAt = exportedAt,
                imageSha256 = imageSha256,
                offsets = offsets,
                provenance = provenance,
                c98260Hocon = hocon,
            )
        }

        fun encode(doc: OffsetsDocument): ByteArray {
            val root = LinkedHashMap<String, Any?>()
            root["format"] = FORMAT
            root["release"] = doc.release
            root["source"] = doc.source
            root["exported_at"] = doc.exportedAt
            root["image_sha256"] = doc.imageSha256
            root["provenance"] = linkedMapOf<String, Any?>(
                "origin" to doc.provenance.origin,
                "derived" to doc.provenance.derived,
                "inherited" to doc.provenance.inherited,
                "synthesized" to LinkedHashMap(doc.provenance.synthesized),
                "missing" to doc.provenance.missing,
                "blocked" to doc.provenance.blocked,
                "notes" to doc.provenance.notes,
            )
            val sections = LinkedHashMap<String, Any?>()
            doc.offsets.forEach { (section, entries) ->
                sections[section] = LinkedHashMap<String, Any?>(entries)
            }
            root["offsets"] = sections
            root["c98260_hocon"] = doc.c98260Hocon
            return Json.write(root).toByteArray(Charsets.UTF_8)
        }

        private fun Map<*, *>.string(key: String): String? = this[key] as? String
        private fun Map<*, *>.long(key: String): Long? = this[key] as? Long
        private fun Map<*, *>.strings(key: String): List<String> =
            (this[key] as? List<*>)?.filterIsInstance<String>() ?: emptyList()
    }
}

/** Tiny strict JSON reader/writer: objects, arrays, strings, integers, booleans, null. */
private object Json {

    fun write(value: Any?): String = buildString { appendValue(value, this, 0) }

    private fun appendValue(value: Any?, out: StringBuilder, depth: Int) {
        if (depth > OffsetsDocument.MAX_DEPTH) error("JSON 嵌套过深")
        when (value) {
            null -> out.append("null")
            is String -> appendString(value, out)
            is Boolean -> out.append(if (value) "true" else "false")
            is Long, is Int -> out.append(value.toString())
            is Map<*, *> -> {
                out.append('{')
                var first = true
                value.forEach { (k, v) ->
                    if (k !is String) error("JSON 对象的 key 必须是字符串")
                    if (!first) out.append(',')
                    first = false
                    appendString(k, out)
                    out.append(':')
                    appendValue(v, out, depth + 1)
                }
                out.append('}')
            }
            is List<*> -> {
                out.append('[')
                var first = true
                value.forEach { v ->
                    if (!first) out.append(',')
                    first = false
                    appendValue(v, out, depth + 1)
                }
                out.append(']')
            }
            else -> error("不支持的 JSON 类型: ${value.javaClass.simpleName}")
        }
    }

    private fun appendString(s: String, out: StringBuilder) {
        out.append('"')
        s.forEach { c ->
            when (c) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                '\b' -> out.append("\\b")
                '\u000C' -> out.append("\\f")
                else -> if (c < ' ') {
                    out.append("\\u%04x".format(c.code))
                } else out.append(c)
            }
        }
        out.append('"')
    }

    fun parse(text: String, maxDepth: Int): Any? {
        val p = Parser(text, maxDepth)
        val value = p.value(0)
        p.skipWs()
        if (p.pos != text.length) p.fail("尾部有多余内容")
        return value
    }

    private class Parser(private val s: String, private val maxDepth: Int) {
        var pos = 0

        fun fail(msg: String): Nothing =
            throw OffsetsError("offsets JSON 解析失败（位置 $pos）：$msg")

        fun skipWs() {
            while (pos < s.length && s[pos] in " \t\r\n") pos++
        }

        private fun expect(c: Char) {
            if (pos >= s.length || s[pos] != c) fail("期望 '$c'")
            pos++
        }

        fun value(depth: Int): Any? {
            if (depth > maxDepth) fail("嵌套过深")
            skipWs()
            if (pos >= s.length) fail("意外结束")
            return when (s[pos]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> { literal("true"); true }
                'f' -> { literal("false"); false }
                'n' -> { literal("null"); null }
                '-', in '0'..'9' -> num()
                else -> fail("非法字符 '${s[pos]}'")
            }
        }

        private fun literal(word: String) {
            if (!s.startsWith(word, pos)) fail("期望 $word")
            pos += word.length
        }

        private fun obj(depth: Int): Map<String, Any?> {
            expect('{')
            val map = LinkedHashMap<String, Any?>()
            skipWs()
            if (pos < s.length && s[pos] == '}') { pos++; return map }
            while (true) {
                skipWs()
                if (pos >= s.length || s[pos] != '"') fail("对象 key 必须是字符串")
                val key = str()
                skipWs()
                expect(':')
                map[key] = value(depth + 1)
                skipWs()
                if (pos >= s.length) fail("对象未闭合")
                when (s[pos]) {
                    ',' -> pos++
                    '}' -> { pos++; return map }
                    else -> fail("期望 ',' 或 '}'")
                }
            }
        }

        private fun arr(depth: Int): List<Any?> {
            expect('[')
            val list = ArrayList<Any?>()
            skipWs()
            if (pos < s.length && s[pos] == ']') { pos++; return list }
            while (true) {
                list.add(value(depth + 1))
                skipWs()
                if (pos >= s.length) fail("数组未闭合")
                when (s[pos]) {
                    ',' -> pos++
                    ']' -> { pos++; return list }
                    else -> fail("期望 ',' 或 ']'")
                }
            }
        }

        private fun str(): String {
            expect('"')
            val out = StringBuilder()
            while (pos < s.length) {
                val c = s[pos++]
                when {
                    c == '"' -> return out.toString()
                    c == '\\' -> {
                        if (pos >= s.length) fail("转义未完成")
                        when (val e = s[pos++]) {
                            '"' -> out.append('"')
                            '\\' -> out.append('\\')
                            '/' -> out.append('/')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000C')
                            'u' -> {
                                if (pos + 4 > s.length) fail("\\u 转义不完整")
                                val hex = s.substring(pos, pos + 4)
                                val code = hex.toIntOrNull(16) ?: fail("非法 \\u 转义")
                                out.append(code.toChar())
                                pos += 4
                            }
                            else -> fail("非法转义 '\\$e'")
                        }
                    }
                    c < ' ' -> fail("字符串含未转义控制字符")
                    else -> out.append(c)
                }
            }
            fail("字符串未闭合")
        }

        private fun num(): Long {
            val start = pos
            if (s[pos] == '-') pos++
            if (pos >= s.length) fail("数字不完整")
            if (s[pos] == '0') {
                pos++
            } else {
                if (s[pos] !in '1'..'9') fail("非法数字")
                while (pos < s.length && s[pos] in '0'..'9') pos++
            }
            // Offsets are integers; a fractional/exponent number is a corrupted value, not a guess.
            if (pos < s.length && (s[pos] == '.' || s[pos] == 'e' || s[pos] == 'E')) {
                fail("offsets 只允许整数，遇到小数/指数")
            }
            return s.substring(start, pos).toLongOrNull() ?: fail("整数超出 int64 范围")
        }
    }
}
