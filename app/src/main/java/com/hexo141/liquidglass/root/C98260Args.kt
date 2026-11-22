package com.hexo141.liquidglass.root

/**
 * The 98260 payload's own command line, minus the switches this app already owns.
 *
 * `--slide` and `--kaslr-only` live on the KASLR card, `--selinux-only` is the chip on the row,
 * `--profile` is staged from the parsed snapshot, and `--color` / `--no-ksu` are fixed by the
 * runner. The rest of `-h` is reachable from [toArgs]. Only switches the packaged payload actually
 * parses are listed: a field here that `native-posix/cve98260.c` does not know makes it print
 * "unknown argument" and exit before doing anything.
 *
 * `--poke*` is an independent endpoint: the payload writes eight zero bytes per address and exits
 * without touching SELinux or cred. Its targets are the "clearing is the safe direction" globals -
 * `panic_on_oops`, `kptr_restrict`, `perf_event_paranoid` / `unprivileged_bpf_disabled`.
 */
enum class C98260Mode {
    /** The normal chain: SELinux off, forged cred, root handoff. */
    FULL,

    /** `--lmap-only`: calibration A + B, print `page_offset`, exit. */
    LMAP,

    /** `--cred-only`: watch one `prepare_creds()` allocation through ftrace, exit. */
    CRED,

    /** `--poke…`: one eight-byte zero write per address, exit. */
    POKE,

    /** `--check-target`: address gate only, no UAF. */
    CHECK,

    /** `--dump-config`: print the active profile, no device work. */
    DUMP,
}

/**
 * One argument sheet's worth of state.
 *
 * [toArgs] is the only place that turns it into a command line, so the preview under the form and
 * the string handed to the runner are guaranteed to be the same thing.
 */
data class C98260Args(
    /**
     * Which parsed snapshot to stage as `--profile`. Empty means "the one matching `uname -r`",
     * which is the automatic behaviour that existed before the picker. The runner pushes the file,
     * so this never appears in [toArgs].
     */
    val profileRelease: String = "",
    val mode: C98260Mode = C98260Mode.FULL,
    /** `--poke-panic`: clear `panic_on_oops` (and `panic_timeout` in the same eight bytes). */
    val pokePanic: Boolean = true,
    /** `--poke-kptr`: clear `kptr_restrict` and the `perf_event_paranoid` / `bpf` slot. */
    val pokeKptr: Boolean = true,
    /** `--poke`: runtime addresses, absolute, straight from `/proc/kallsyms`. */
    val pokeAbsolute: String = "",
    /** `--poke-link`: link-time addresses; the payload adds the slide it calibrated. */
    val pokeLink: String = "",
    /** `--poke-retry`: 1..20, clamped again by the payload. */
    val pokeRetry: Int = 3,
    /** `--skip-selinux-check`: write 0 without reading `enforce` first. */
    val skipSelinuxCheck: Boolean = false,
    /** `--page-offset`: override calibration B with a value leaked earlier. */
    val pageOffset: String = "",
    /** `--netshell-port`: TCP root shell port, 9826 by default. */
    val netshellPort: String = "",
    /** `--va-bits`: 39 by default; 48-bit kernels need 48 or the slide window is wrong. */
    val vaBits: String = "",
    /** `--max-slide`: slide window upper bound, for custom kernels outside the formula. */
    val maxSlide: String = "",
    /** `--set key=0x…`, one per line: override a profile field without editing the snapshot. */
    val setOverrides: String = "",
) {
    /** True when this run is expected to produce root, so its outcome belongs in the history. */
    val attemptsEscalation: Boolean get() = mode == C98260Mode.FULL

    fun toArgs(): List<String> {
        val out = mutableListOf<String>()
        when (mode) {
            C98260Mode.FULL -> {
                if (skipSelinuxCheck) out += "--skip-selinux-check"
                port()?.let { out += listOf("--netshell-port", it) }
            }
            C98260Mode.LMAP -> out += "--lmap-only"
            C98260Mode.CRED -> out += "--cred-only"
            C98260Mode.POKE -> {
                // panic_on_oops goes first on purpose: if a later address is wrong and oopses,
                // only that task dies instead of the whole device.
                if (pokePanic) out += "--poke-panic"
                if (pokeKptr) out += "--poke-kptr"
                hexList(pokeAbsolute).forEach { out += listOf("--poke", it) }
                hexList(pokeLink).forEach { out += listOf("--poke-link", it) }
                if (pokeRetry != 3) out += listOf("--poke-retry", pokeRetry.coerceIn(1, 20).toString())
            }
            C98260Mode.CHECK -> out += "--check-target"
            C98260Mode.DUMP -> out += "--dump-config"
        }

        // Calibration overrides. --page-offset is rejected next to --lmap-only, whose entire point
        // is to measure it; the other two are legal anywhere calibration runs.
        if (mode != C98260Mode.LMAP && mode != C98260Mode.DUMP) {
            hexList(pageOffset).firstOrNull()?.let { out += listOf("--page-offset", it) }
        }
        if (mode != C98260Mode.DUMP) {
            vaBits.trim().toIntOrNull()?.takeIf { it in 32..52 }
                ?.let { out += listOf("--va-bits", it.toString()) }
            hexList(maxSlide).firstOrNull()?.let { out += listOf("--max-slide", it) }
            overrides().forEach { out += listOf("--set", it) }
        }
        return out
    }

    /** What the sheet shows under the form; empty when the run needs no extra arguments. */
    fun preview(): String = toArgs().joinToString(" ")

    private fun port(): String? =
        netshellPort.trim().toIntOrNull()?.takeIf { it in 1..65535 }?.toString()

    /**
     * `--set` takes `key=value` pairs, one flag each. Lines without a `=` are dropped here rather
     * than handed to a parser that would reject the whole run.
     */
    private fun overrides(): List<String> =
        setOverrides.split(',', '\n', ';')
            .map { it.trim() }
            .filter { it.contains('=') && it.substringBefore('=').isNotBlank() }

    private companion object {
        /**
         * Addresses are typed one per line (or comma separated). `strtoull(…, 0)` on the payload
         * side reads a bare `ffffffc0…` as 0, so the `0x` prefix is added here rather than being
         * left to a parse that silently produces zero.
         */
        fun hexList(raw: String): List<String> =
            raw.split(',', '\n', ' ', '\t', ';')
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .mapNotNull { token ->
                    val body = token.removePrefix("0x").removePrefix("0X")
                    val hex = body.takeWhile { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
                    if (hex.isEmpty() || hex != body) null else "0x" + hex.lowercase()
                }
    }
}
