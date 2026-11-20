package com.hexo141.liquidglass.bootimg

/**
 * The per-build snapshot **CVE-2026-98260** needs, in the HOCON layout its payload parses.
 *
 * This is a different set of numbers from [Glk1Profile], and deliberately so:
 *
 * - GLK1 stores symbol offsets relative to the kernel image base (`symbol - imageBase`) and is
 *   consumed by the 43499 payload, which adds the base back at run time.
 * - This profile stores **link-time virtual addresses** (`0xffffffc0...`) because the 98260 payload
 *   computes `address = link + KASLR slide` itself; feeding it an offset would resolve to the
 *   kernel image header instead of the symbol.
 * - It also needs three call sites, not symbols: `do_timer_create+0xA8` (where `k_itimer` is
 *   allocated) and `prepare_creds+0x24` (where `struct cred` is allocated). Those deltas are
 *   properties of the code path, not of the build, which is why they are constants here.
 *
 * Everything else — `struct cred` layout, `task_struct.cred`, `sizeof(struct k_itimer)` — comes
 * from the image's own BTF, so a new KMI only needs a parsed `boot.img`, not a new binary.
 */
data class Cve98260Profile(
    val release: String,
    val pageOffset: Long,
    val timerLink: Long,
    val credLink: Long,
    val selinuxLink: Long,
    val userNs: Long,
    val rootUser: Long,
    val groups: Long,
    val ucounts: Long,
    val taskAllocLink: Long,
    val taskCred: Long,
    val taskStructSize: Long,
    val kitimerNode: Long,
    val kitimerSize: Long,
    val credSize: Long,
    val credUid: Long,
    val credCapInh: Long,
    val credCapPerm: Long,
    val credCapEff: Long,
    val credCapBset: Long,
    val credCapAmb: Long,
    val credOffSecurity: Long,
    val credOffUser: Long,
    val credOffUserNs: Long,
    val credOffUcounts: Long,
    val credOffGroups: Long,
) {

    /**
     * The exact shape the payload's `profile_load_hocon()` reads: `key = value` lines, `offset {}`
     * braces ignored, values as hex. The parser requires at least 20 applied fields, so every
     * field this class carries has to be written even when it is zero.
     */
    fun toHocon(sourceName: String): String = buildString {
        appendLine("{")
        appendLine("  release = \"$release\"")
        appendLine("  vuln_type = \"cve-2026-98260\"")
        appendLine("  page_offset = ${hex(pageOffset)}")
        appendLine("  offset = {")
        appendLine("    timer_link = ${hex(timerLink)}")
        appendLine("    cred_link = ${hex(credLink)}")
        appendLine("    selinux_link = ${hex(selinuxLink)}")
        appendLine("    user_ns = ${hex(userNs)}")
        appendLine("    root_user = ${hex(rootUser)}")
        appendLine("    groups = ${hex(groups)}")
        appendLine("    ucounts = ${hex(ucounts)}")
        appendLine("    task_alloc_link = ${hex(taskAllocLink)}")
        appendLine("    task_cred = $taskCred")
        appendLine("    task_struct_size = $taskStructSize")
        appendLine("    kitimer_node = $kitimerNode")
        appendLine("    kitimer_size = $kitimerSize")
        appendLine("    cred_size = $credSize")
        appendLine("    cred_uid = $credUid")
        appendLine("    cred_cap_inheritable = $credCapInh")
        appendLine("    cred_cap_permitted = $credCapPerm")
        appendLine("    cred_cap_effective = $credCapEff")
        appendLine("    cred_cap_bset = $credCapBset")
        appendLine("    cred_cap_ambient = $credCapAmb")
        appendLine("    cred_security = $credOffSecurity")
        appendLine("    cred_user = $credOffUser")
        appendLine("    cred_user_ns = $credOffUserNs")
        appendLine("    cred_ucounts = $credOffUcounts")
        appendLine("    cred_groups = $credOffGroups")
        appendLine("  }")
        appendLine("  _source = \"img:$sourceName\"")
        append("}")
    }

    private fun hex(value: Long): String = "0x" + java.lang.Long.toHexString(value)

    companion object {

        /** Reads back what [toHocon] wrote; other keys are ignored like the payload does. */
        fun parse(text: String): Cve98260Profile? {
            val values = LinkedHashMap<String, String>()
            text.lineSequence().forEach { raw ->
                val line = raw.substringBefore('#').substringBefore("//")
                val eq = line.indexOf('=')
                if (eq < 0) return@forEach
                val key = line.substring(0, eq)
                    .trim { it == ' ' || it == '\t' || it == '{' || it == '\n' || it == '\r' }
                val value = line.substring(eq + 1)
                    .trim { it == ' ' || it == '\t' || it == '"' || it == ',' || it == '}' || it == '\r' }
                if (key.isEmpty() || value.isEmpty()) return@forEach
                values[key.removePrefix("offset.")] = value
            }
            // Only a `0x` prefix means hex, exactly like the payload's strtoull(..., 0): reading
            // "2104" as hex would turn every decimal geometry field into a different number.
            // Unsigned on purpose: kernel addresses start with 0xffffffff and do not fit in a
            // signed Long, so `toLongOrNull(16)` rejects them while `parseUnsignedLong` returns
            // the same bit pattern the payload holds.
            fun long(key: String): Long? = values[key]?.let {
                runCatching {
                    if (it.startsWith("0x") || it.startsWith("0X")) {
                        java.lang.Long.parseUnsignedLong(it.substring(2), 16)
                    } else {
                        it.toLong()
                    }
                }.getOrNull()
            }
            val release = values["release"]?.trim('"') ?: return null
            val pageOffset = long("page_offset") ?: return null
            val timerLink = long("timer_link") ?: return null
            val credLink = long("cred_link") ?: return null
            val selinuxLink = long("selinux_link") ?: return null
            val userNs = long("user_ns") ?: return null
            val rootUser = long("root_user") ?: return null
            val groups = long("groups") ?: return null
            val ucounts = long("ucounts") ?: return null
            val taskCred = long("task_cred") ?: return null
            val taskStructSize = long("task_struct_size") ?: return null
            val kitimerNode = long("kitimer_node") ?: return null
            val kitimerSize = long("kitimer_size") ?: return null
            val credSize = long("cred_size") ?: return null
            val credUid = long("cred_uid") ?: return null
            fun cred(key: String): Long = long(key) ?: 0L
            return Cve98260Profile(
                release = release,
                pageOffset = pageOffset,
                timerLink = timerLink,
                credLink = credLink,
                selinuxLink = selinuxLink,
                userNs = userNs,
                rootUser = rootUser,
                groups = groups,
                ucounts = ucounts,
                taskAllocLink = long("task_alloc_link") ?: 0,
                taskCred = taskCred,
                taskStructSize = taskStructSize,
                kitimerNode = kitimerNode,
                kitimerSize = kitimerSize,
                credSize = credSize,
                credUid = credUid,
                credCapInh = cred("cred_cap_inheritable"),
                credCapPerm = cred("cred_cap_permitted"),
                credCapEff = cred("cred_cap_effective"),
                credCapBset = cred("cred_cap_bset"),
                credCapAmb = cred("cred_cap_ambient"),
                credOffSecurity = cred("cred_security"),
                credOffUser = cred("cred_user"),
                credOffUserNs = cred("cred_user_ns"),
                credOffUcounts = cred("cred_ucounts"),
                credOffGroups = cred("cred_groups"),
            )
        }
    }
}
