package com.hexo141.liquidglass.bootimg

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Host-side tests for the offsets export/import format; no Android types involved. */
class OffsetsDocumentTest {

    private fun sections(): LinkedHashMap<String, LinkedHashMap<String, Long>> = linkedMapOf(
        "meta" to linkedMapOf("kernel_major" to 6L, "recommend_shizuku" to 1L),
        "task_struct" to linkedMapOf("cred" to 2080L, "pid" to 1560L),
        "offset" to linkedMapOf(
            "init_task" to 0x215e780L,
            "selinux_enforcing" to 0x239c620L,
            "empty_zero_page" to 0x2351000L,
        ),
        "kernel" to linkedMapOf("mm_struct_sz" to 1024L),
    )

    private fun build() = BootProfileBuilder.ProfileBuild(
        profile = Glk1Profile("6.6.118-my-device", sections()),
        templateRelease = "6.6.118-bundled",
        derived = listOf("offset.init_task", "offset.selinux_enforcing", "task_struct.cred"),
        inherited = listOf("meta.recommend_shizuku", "kernel.mm_struct_sz"),
        missing = listOf("cred.copy_size"),
        blocked = emptyList(),
        notes = listOf(
            "selinux_enforcing 无独立符号 => selinux_state+0x0 (BTF enforcing offset)",
            "template note with \"quotes\" and a newline\nsecond line",
        ),
    )

    private fun expectError(block: () -> Unit): String {
        return try {
            block()
            fail("应当拒绝但没有")
            ""
        } catch (e: OffsetsError) {
            e.message ?: ""
        }
    }

    @Test
    fun `round trip keeps sections provenance and hocon`() {
        val hocon = "{\n  release = \"6.6.118-my-device\"\n  offset = {\n    task_cred = 2080\n  }\n}"
        val doc = OffsetsDocument.fromBuild(
            build(), "boot.img", "ab".repeat(32), hocon, now = 1700000000000L,
        )
        val back = OffsetsDocument.decode(doc.toBytes())

        assertEquals(doc.release, back.release)
        assertEquals("boot.img", back.source)
        assertEquals(1700000000000L, back.exportedAt)
        assertEquals("ab".repeat(32), back.imageSha256)
        assertEquals(doc.offsets, back.offsets)
        assertEquals(doc.provenance.derived, back.provenance.derived)
        assertEquals(doc.provenance.inherited, back.provenance.inherited)
        assertEquals(doc.provenance.missing, back.provenance.missing)
        assertEquals(doc.provenance.blocked, back.provenance.blocked)
        assertEquals(doc.provenance.notes, back.provenance.notes)
        assertEquals("parsed", back.provenance.origin)
        assertEquals(hocon, back.c98260Hocon)
        assertTrue(back.provenance.synthesized.containsKey("offset.selinux_enforcing"))
    }

    @Test
    fun `decoded sections encode back to the same glk1 profile`() {
        val doc = OffsetsDocument.fromBuild(build(), "ota.zip", null, null)
        val bytes = Glk1Codec.encode(doc.toProfile())
        val profile = Glk1Codec.decode(bytes)
        assertEquals(doc.release, profile.release)
        assertEquals(doc.offsets, profile.sections)
    }

    @Test
    fun `unknown format is refused not guessed`() {
        val raw = String(OffsetsDocument.fromBuild(build(), "boot.img", null, null).toBytes())
            .replace("openroot-offsets/v1", "openroot-offsets/v99")
        val msg = expectError { OffsetsDocument.decode(raw.toByteArray()) }
        assertTrue(msg.contains("不支持的 format"))
    }

    @Test
    fun `blank release is refused`() {
        val good = String(OffsetsDocument.fromBuild(build(), "boot.img", null, null).toBytes())
        val msg = expectError {
            OffsetsDocument.decode(
                good.replace("\"release\":\"6.6.118-my-device\"", "\"release\":\"  \"").toByteArray(),
            )
        }
        assertTrue(msg.contains("release 为空"))
    }

    @Test
    fun `empty offset section is refused`() {
        val doc = OffsetsDocument.fromBuild(build(), "boot.img", null, null)
        val emptied = doc.copy(
            offsets = linkedMapOf("offset" to linkedMapOf(), "meta" to linkedMapOf("kernel_major" to 6L)),
        )
        val msg = expectError { OffsetsDocument.decode(emptied.toBytes()) }
        assertTrue(msg.contains("offset 段为空"))
    }

    @Test
    fun `missing offset section is refused`() {
        val doc = OffsetsDocument.fromBuild(build(), "boot.img", null, null)
        val without = doc.copy(offsets = linkedMapOf("meta" to linkedMapOf("kernel_major" to 6L)))
        val msg = expectError { OffsetsDocument.decode(without.toBytes()) }
        assertTrue(msg.contains("缺少 offset 段"))
    }

    @Test
    fun `a non integer value is refused`() {
        val raw = String(OffsetsDocument.fromBuild(build(), "boot.img", null, null).toBytes())
            .replace(Regex("\"init_task\":-?[0-9]+"), "\"init_task\":1.5")
        assertTrue(raw.contains("\"init_task\":1.5"))
        val msg = expectError { OffsetsDocument.decode(raw.toByteArray()) }
        assertTrue(msg.contains("整数") || msg.contains("解析失败"))
    }

    @Test
    fun `saved profile export is marked as imported`() {
        val doc = OffsetsDocument.fromSavedProfile(
            Glk1Profile("6.1.134-other", sections()), "saved profile", null,
        )
        val back = OffsetsDocument.decode(doc.toBytes())
        assertEquals("imported", back.provenance.origin)
        assertTrue(back.provenance.derived.isEmpty())
        assertTrue(back.provenance.notes.any { it.contains("来源不可考") })
        assertNull(back.imageSha256)
    }

    @Test
    fun `strings with quotes newlines and unicode survive`() {
        val weird = build().copy(
            profile = Glk1Profile("6.6.118-\"quoted\"\n中文\\path", sections()),
        )
        val doc = OffsetsDocument.fromBuild(weird, "boot\"with\nnewline", null, null)
        val back = OffsetsDocument.decode(doc.toBytes())
        assertEquals(weird.profile.release, back.release)
        assertEquals("boot\"with\nnewline", back.source)
    }

    @Test
    fun `oversized input is refused`() {
        val msg = expectError { OffsetsDocument.decode(ByteArray(3 * 1024 * 1024)) }
        assertTrue(msg.contains("超过"))
    }

    @Test
    fun `clean parse export passes the import gate`() {
        OffsetsDocument.decode(
            OffsetsDocument.fromBuild(build(), "boot.img", null, null).toBytes(),
        ).validateForImport()
    }

    @Test
    fun `import gate refuses inherited symbol addresses`() {
        val original = OffsetsDocument.fromBuild(build(), "boot.img", null, null)
        val doc = original.copy(
            provenance = original.provenance.copy(
                inherited = listOf("meta.recommend_shizuku", "offset.selinux_enforcing"),
            ),
        )
        val msg = expectError { OffsetsDocument.decode(doc.toBytes()).validateForImport() }
        assertTrue(msg.contains("another build"))
    }

    @Test
    fun `import gate refuses unresolved required offsets`() {
        val original = OffsetsDocument.fromBuild(build(), "boot.img", null, null)
        val doc = original.copy(
            provenance = original.provenance.copy(blocked = listOf("offset.init_task")),
        )
        val msg = expectError { OffsetsDocument.decode(doc.toBytes()).validateForImport() }
        assertTrue(msg.contains("unresolved"))
    }
}
