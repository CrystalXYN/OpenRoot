package com.hexo141.liquidglass.bootimg

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression tests for the "absolute addresses must never be inherited" rule.
 *
 * A bundled profile is a snapshot of *one* kernel build. Its `offset.*` entries are
 * `symbol - image_base` for that build only; carrying one into a freshly parsed image
 * points the payload at an unrelated kernel address. Everything in that section must
 * therefore be proven again from the image being parsed.
 */
class BootProfileBuilderTest {

    /** A small stand-in for the link-time base; offsets stay inside u32 like the real thing. */
    private val imageBase = 0x1000L

    /** The value found in 6.6.118...g21be90ecfb5e-4k.bin, i.e. a *different* build. */
    private val foreignSelinuxOffset = 0x236A2E0L

    private fun template(): Glk1Profile = Glk1Profile(
        release = "6.6.118-android15-8-g21be90ecfb5e-ab15480137-4k",
        sections = linkedMapOf(
            "meta" to linkedMapOf(
                "kernel_major" to 6L, "recommend_shizuku" to 1L,
                "fallback_route" to 0L, "safe_mode" to 0L,
            ),
            "task_struct" to linkedMapOf(
                "cred" to 0x5a0L, "real_cred" to 0x5a8L, "pid" to 0x4c0L,
            ),
            "cred" to linkedMapOf(
                "copy_size" to 0x88L, "usage_offset" to 0L, "caps_offset" to 0x30L,
                "ref_count" to 4L, "ref0_offset" to 0L, "ref1_offset" to 8L,
                "ref2_offset" to 16L, "ref3_offset" to 24L,
                "ref0_image" to 0L, "ref1_image" to 0L, "ref2_image" to 0L,
                "ref3_image" to 0L,
            ),
            "offset" to linkedMapOf(
                "init_task" to 0x211e280L,
                "init_cred" to 0x2130748L,
                "empty_zero_page" to 0x2240000L,
                "root_task_group" to 0x2317580L,
                "selinux_enforcing" to foreignSelinuxOffset,
                "selinux_blob_sizes" to 0x167b5d0L,
                "security_hook_heads" to 0x22a89d8L,
                "slide_nfulnl_logger" to 0x2112260L,
                "slide_loggers_0_1" to 0x21121b0L,
                "slide_boot_id" to 0x2379ed8L,
            ),
            "kernel" to linkedMapOf(
                "kernel_phys_load" to 0xa8000000L, "kernel_phys_offset" to 0x80000000L,
                "compact_waiter" to 1L, "kernelsnitch_collisions" to 16L,
                "mm_struct_sz" to 1024L,
            ),
        ),
    )

    private fun info(
        release: String = "6.6.118-my-device",
        symbols: Map<String, Long>? = null,
        selinuxEnforcingOffset: Long? = null,
    ) = BootImageParser.ExtractedKernelInfo(
        release = release,
        imageSha256 = "00".repeat(32),
        imageBytes = 64 * 1024 * 1024,
        imageBase = imageBase,
        hasBtf = selinuxEnforcingOffset != null,
        structOffsets = null,
        symbols = symbols,
        selinuxStateEnforcingOffset = selinuxEnforcingOffset,
    )

    private fun build(
        symbols: Map<String, Long>? = null,
        selinuxEnforcingOffset: Long? = null,
        release: String = "6.6.118-my-device",
    ) = BootProfileBuilder.build(
        info(release, symbols, selinuxEnforcingOffset),
        "boot.img",
        listOf(template()),
    )!!

    @Test
    fun `a symbol missing from the image must not inherit the template address`() {
        val result = build(symbols = mapOf("init_task" to imageBase + 0x211e280L))

        assertNull(
            "0x236A2E0 belongs to another build; a failed lookup must leave the key absent",
            result.profile.value("offset", "selinux_enforcing"),
        )
        assertTrue(
            "the unresolved address must be reported instead of silently written",
            result.blocked.contains("offset.selinux_enforcing"),
        )
    }

    @Test
    fun `selinux_enforcing is synthesized from selinux_state plus the BTF enforcing offset`() {
        val expected = 0x239C620L
        val result = build(
            symbols = mapOf("selinux_state" to imageBase + expected),
            selinuxEnforcingOffset = 0L,
        )

        assertEquals(expected, result.profile.value("offset", "selinux_enforcing"))
        assertTrue(result.derived.contains("offset.selinux_enforcing"))
        assertTrue(
            "the synthesis must be labelled so it is not mistaken for a real symbol",
            result.notes.any { it.contains("BTF") && it.contains("selinux_state") },
        )
        assertTrue(result.blocked.none { it.contains("selinux_enforcing") })
    }

    @Test
    fun `security_hook_heads missing on 6_12 static-call is optional`() {
        val allButHooks = linkedMapOf(
            "init_task" to imageBase + 0x211e280L,
            "init_cred" to imageBase + 0x2130748L,
            "empty_zero_page" to imageBase + 0x2240000L,
            "root_task_group" to imageBase + 0x2317580L,
            "selinux_enforcing" to imageBase + 0x225afd8L,
            "selinux_blob_sizes" to imageBase + 0x167b5d0L,
            "nfulnl_logger" to imageBase + 0x2112260L,
            "loggers" to imageBase + 0x21121b0L,
            "random_boot_id" to imageBase + 0x2379ed8L,
        )
        val result = build(symbols = allButHooks, release = "6.12.69-my-device")

        assertNull(result.profile.value("offset", "security_hook_heads"))
        assertTrue(result.blocked.isEmpty())
        assertTrue(result.notes.any { it.contains("optional") })
    }

    @Test
    fun `every address in the profile comes from the image, never the template`() {
        val symbols = linkedMapOf(
            "init_task" to imageBase + 0x1111111L,
            "init_cred" to imageBase + 0x2222222L,
            "empty_zero_page" to imageBase + 0x3333333L,
            "root_task_group" to imageBase + 0x4444444L,
            "selinux_enforcing" to imageBase + 0x225afd8L,
            "selinux_blob_sizes" to imageBase + 0x6666666L,
            "security_hook_heads" to imageBase + 0x7777777L,
            "nfulnl_logger" to imageBase + 0x8888888L,
            "loggers" to imageBase + 0x9999999L,
            "random_boot_id" to imageBase + 0xaaaaaaL,
        )
        val result = build(symbols = symbols)

        assertTrue(result.blocked.isEmpty())
        assertEquals(
            "template value must not survive a successful lookup either",
            0x225afd8L,
            result.profile.value("offset", "selinux_enforcing"),
        )
        assertEquals(0x1111111L, result.profile.value("offset", "init_task"))
        assertTrue(result.profile.get("offset").all { (_, v) -> v in 0..0xFFFF_FFFFL })
    }
}
