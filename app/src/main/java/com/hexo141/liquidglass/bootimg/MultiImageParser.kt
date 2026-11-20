package com.hexo141.liquidglass.bootimg

/**
 * Picks the kernel out of the images the user handed over.
 *
 * One `boot.img` normally carries everything a profile needs. MTK layouts are the exception: the
 * kernel may sit behind a vendor header, and `vendor_boot.img` may be the only file with a valid
 * container header at all. The Profile tab therefore lets the user pick both at once; each image
 * is unpacked on its own and the most complete result wins.
 *
 * The winner has to be a single image: release, BTF and kallsyms describe one build, so mixing
 * fields from two different kernels would produce a profile that fails at the worst moment.
 */
object MultiImageParser {

    data class Candidate(val sourceName: String, val info: BootImageParser.ExtractedKernelInfo)

    /**
     * @param files display name + raw bytes, in the order the user picked them
     * @param log receives one line per step; the Profile tab routes it into the Log tab
     */
    fun select(files: List<Pair<String, ByteArray>>, log: (String) -> Unit): Candidate {
        require(files.isNotEmpty()) { "No image selected" }
        val failures = mutableListOf<String>()
        var best: Candidate? = null
        var bestScore = -1

        files.forEach { (name, bytes) ->
            log("$name - ${bytes.size / 1024} KB")
            // A vendor_boot image is a valid pick, it just holds no kernel: say so instead of
            // failing it, otherwise the expected case looks like a parse error.
            val vendor = BootImageParser().vendorBootInfo(bytes)
            if (vendor != null) {
                log("  vendor_boot v${vendor.version}, ${vendor.pageSize} B pages")
                log("  vendor ramdisk ${vendor.ramdiskBytes / 1024} KB, " +
                    "dtb ${vendor.dtbBytes / 1024} KB")
                if (vendor.kernelAddr != 0L) {
                    log("  kernel_addr 0x" + vendor.kernelAddr.toString(16))
                }
                log("  no kernel section - the kernel is read from boot.img")
                return@forEach
            }
            val info = try {
                BootImageParser().parse(bytes)
            } catch (error: Exception) {
                val message = error.message ?: error.javaClass.simpleName
                log("  [~] $message")
                failures += "$name: $message"
                null
            }
            if (info != null) {
                log("  ${info.container}, kernel ${info.imageBytes / 1024} KB")
                log("  release ${info.release ?: "not found"}")
                log("  BTF ${if (info.hasBtf) "found" else "missing"}, ${info.symbolCount} symbols")
                info.notes.forEach { log("  note: $it") }
                val score = (if (info.release != null) 1 else 0) +
                    (if (info.hasBtf) 2 else 0) +
                    (if (info.symbols != null) 2 else 0)
                if (score > bestScore) {
                    best = Candidate(name, info)
                    bestScore = score
                }
            }
        }

        val chosen = best
            ?: throw BootImageParser.ImgExtractError(failures.joinToString("; "))
        if (files.size > 1) log("kernel source: ${chosen.sourceName}")
        return chosen
    }
}
