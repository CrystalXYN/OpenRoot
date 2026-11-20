package com.hexo141.liquidglass.bootimg

/**
 * Android sparse image — the container factory firmware and partition dumps usually come in.
 *
 * A sparse file is a table of chunks (raw runs, fill runs, skipped regions) instead of a plain
 * byte stream, which is why a `vendor_boot.img` unpacked from an OTA starts with `3A FF 26 ED`
 * rather than `ANDROID!`. Expanding it here keeps the rest of the parser working on a normal
 * image, no matter which form the user picked.
 */
internal object SparseImage {

    /** 0xED26FF3A, kept as a Long because [u32] is unsigned. */
    private const val MAGIC = 0xED26FF3AL
    private const val TYPE_RAW = 0xCAC1
    private const val TYPE_FILL = 0xCAC2
    private const val TYPE_DONT_CARE = 0xCAC3
    private const val TYPE_CRC32 = 0xCAC4

    /** The expansion lands in one array, so the size has to stay inside a phone's memory. */
    private const val MAX_EXPANDED = 256L * 1024 * 1024

    fun looksSparse(raw: ByteArray): Boolean = raw.size >= 28 && u32(raw, 0) == MAGIC

    fun expand(raw: ByteArray): ByteArray {
        if (raw.size < 28) throw BootImageParser.ImgExtractError("sparse 头部不完整")
        val headerSize = u16(raw, 8).toLong()
        val chunkHeaderSize = u16(raw, 10).toLong()
        val blockSize = u32(raw, 12)
        val totalBlocks = u32(raw, 16)
        val totalChunks = u32(raw, 20)
        if (headerSize < 28 || headerSize > raw.size) {
            throw BootImageParser.ImgExtractError("sparse 头部长度异常（$headerSize）")
        }
        if (chunkHeaderSize < 12) {
            throw BootImageParser.ImgExtractError("sparse chunk 头长度异常（$chunkHeaderSize）")
        }
        if (blockSize !in 512L..65536L || blockSize and (blockSize - 1) != 0L) {
            throw BootImageParser.ImgExtractError("sparse 块大小异常（$blockSize）")
        }
        val expanded = totalBlocks * blockSize
        if (expanded <= 0 || expanded > MAX_EXPANDED) {
            throw BootImageParser.ImgExtractError(
                "sparse 展开后为 ${expanded / (1024 * 1024)} MB，超出上限"
            )
        }

        val out = ByteArray(expanded.toInt())
        var pos = headerSize.toInt()
        var written = 0L
        var index = 0L
        while (index < totalChunks) {
            if (pos + chunkHeaderSize > raw.size) {
                throw BootImageParser.ImgExtractError("sparse chunk 表被截断")
            }
            val type = u16(raw, pos)
            val blocks = u32(raw, pos + 4)
            val chunkSize = u32(raw, pos + 8)
            val dataStart = pos + chunkHeaderSize.toInt()
            val bytes = blocks * blockSize
            if (chunkSize < chunkHeaderSize || pos + chunkSize > raw.size) {
                throw BootImageParser.ImgExtractError("sparse chunk 长度越界")
            }
            if (written + bytes > out.size) {
                throw BootImageParser.ImgExtractError("sparse chunk 超出声明的镜像大小")
            }
            when (type) {
                TYPE_RAW -> {
                    if (dataStart + bytes > raw.size) {
                        throw BootImageParser.ImgExtractError("sparse 原始块被截断")
                    }
                    System.arraycopy(raw, dataStart, out, written.toInt(), bytes.toInt())
                    written += bytes
                }
                TYPE_FILL -> {
                    if (dataStart + 4 > raw.size) {
                        throw BootImageParser.ImgExtractError("sparse 填充块缺少填充值")
                    }
                    // The fill value is four bytes repeated over the whole run.
                    val v0 = raw[dataStart]
                    val v1 = raw[dataStart + 1]
                    val v2 = raw[dataStart + 2]
                    val v3 = raw[dataStart + 3]
                    var i = written.toInt()
                    val end = (written + bytes).toInt()
                    while (i < end) {
                        out[i] = v0
                        if (i + 1 < end) out[i + 1] = v1
                        if (i + 2 < end) out[i + 2] = v2
                        if (i + 3 < end) out[i + 3] = v3
                        i += 4
                    }
                    written += bytes
                }
                TYPE_DONT_CARE -> written += bytes // the array is already zeroed
                TYPE_CRC32 -> Unit
                else -> throw BootImageParser.ImgExtractError(
                    "未知的 sparse chunk 类型 0x" + type.toString(16)
                )
            }
            pos += chunkSize.toInt()
            index++
        }
        return out
    }

    private fun u16(d: ByteArray, o: Int): Int =
        (d[o].toInt() and 0xFF) or ((d[o + 1].toInt() and 0xFF) shl 8)

    private fun u32(d: ByteArray, o: Int): Long =
        ((d[o].toInt() and 0xFF).toLong()) or
            ((d[o + 1].toInt() and 0xFF).toLong() shl 8) or
            ((d[o + 2].toInt() and 0xFF).toLong() shl 16) or
            ((d[o + 3].toInt() and 0xFF).toLong() shl 24)
}
