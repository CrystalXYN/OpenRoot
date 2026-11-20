package com.hexo141.liquidglass.bootimg

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream
import org.tukaani.xz.XZInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * Reads the kernel partition straight out of an OTA, so the user does not have to unpack one first.
 *
 * Two containers are accepted, both detected from the first four bytes:
 *
 * - `payload.bin` (`CrAU`) - the raw update payload;
 * - an OTA zip that stores `payload.bin` uncompressed, which is what every A/B OTA does.
 *
 * The file is read at random offsets and never loaded whole: a full OTA is several gigabytes,
 * while the `boot` partition inside it is tens of megabytes. Only the ZIP central directory, the
 * payload manifest and the operations that belong to the requested partition are touched.
 *
 * Supported operations are the ones a full OTA uses for a whole partition: `REPLACE`,
 * `REPLACE_XZ`, `REPLACE_BZ`, `ZERO` and `DISCARD`. Delta operations (`SOURCE_COPY`,
 * `SOURCE_BSDIFF`, `BROTLI_BSDIFF`, `PUFFDIFF`, `MOVE`) need the *source* image and are rejected
 * by name instead of producing a half-written partition.
 *
 * Mirrors `tools/ota_boot_extract.c` in the desktop package; keep the two in step.
 *
 * Deliberately free of Android types: [OtaPayloadExtractor] owns the `ContentResolver` side,
 * and the parsing below runs in plain JVM unit tests.
 */
object OtaPayloadReader {

    /** Partition that carries the kernel on every non-MTK layout. */
    const val DEFAULT_PARTITION = "boot"

    private val PAYLOAD_MAGIC = byteArrayOf('C'.code.toByte(), 'r'.code.toByte(), 'A'.code.toByte(), 'U'.code.toByte())

    /** Same ceiling the screen applies to a picked image; the extracted partition has to fit it. */
    private const val MAX_PART_IMAGE = 128 * 1024 * 1024

    /** One operation's compressed blob; a single `REPLACE_XZ` is at most a few tens of MB. */
    private const val MAX_OP_DATA = 64 * 1024 * 1024

    private const val MAX_MANIFEST = 64 * 1024 * 1024
    private const val MAX_CD_SIZE = 64 * 1024 * 1024

    /** ZIP trailers live in the last 64 KiB (22 byte EOCD + up to 64 KiB of comment). */
    private const val TAIL_SIZE = 64 * 1024

    private const val ZIP64_MARK = 0xFFFFFFFFL

    private const val EOCD_SIG = 0x06054b50
    private const val ZIP64_LOC_SIG = 0x07064b50
    private const val ZIP64_EOCD_SIG = 0x06064b50
    private const val CEN_SIG = 0x02014b50
    private const val LOC_SIG = 0x04034b50

    /** `payload.bin` inside an OTA zip. */
    private const val PAYLOAD_ENTRY = "payload.bin"

    // update_metadata.proto InstallOperation.Type
    private const val OP_REPLACE = 0
    private const val OP_REPLACE_BZ = 1
    private const val OP_MOVE = 2
    private const val OP_BSDIFF = 3
    private const val OP_SOURCE_COPY = 4
    private const val OP_SOURCE_BSDIFF = 5
    private const val OP_ZERO = 6
    private const val OP_DISCARD = 7
    private const val OP_REPLACE_XZ = 8
    private const val OP_PUFFDIFF = 9
    private const val OP_BROTLI_BSDIFF = 10

    /** Everything this reader refuses, with the reason written for the Log tab. */
    class OtaError(message: String) : RuntimeException(message)

    /**
     * Extracts [partition] from [uri].
     *
     * @return the partition image, or `null` when [uri] is not an OTA at all - the caller then
     *   falls back to treating it as a plain `boot.img`.
     * @throws OtaError when the file *is* an OTA but cannot be read (delta payload, missing
     *   partition, unsupported container)
     */
    /** Random-access read over a container; [offset] is absolute from the start of the file. */
    interface Source {
        val size: Long
        fun read(offset: Long, length: Int): ByteArray
    }

    /**
     * Extracts [partition] from [source].
     *
     * @return the partition image, or `null` when the container is not an OTA at all - the caller
     *   then falls back to treating it as a plain `boot.img`.
     * @throws OtaError when the file *is* an OTA but cannot be read (delta payload, missing
     *   partition, unsupported container)
     */
    fun extract(
        source: Source,
        partition: String = DEFAULT_PARTITION,
        log: (String) -> Unit = {},
    ): ByteArray? {
        if (source.size < 4) return null
        val magic = source.read(0, 4)
        val direct = magic.contentEquals(PAYLOAD_MAGIC)
        val zipped = magic[0] == 'P'.code.toByte() && magic[1] == 'K'.code.toByte()
        if (!direct && !zipped) return null

        val payloadOffset = if (direct) {
            log("OTA: payload.bin, ${source.size / (1024 * 1024)} MB")
            0L
        } else {
            locatePayload(source, log)
        }
        val manifest = readManifest(source, payloadOffset, log)
        val part = manifest.partitions.firstOrNull { it.name == partition }
            ?: throw OtaError(
                "payload has no '$partition' partition; available: " +
                    manifest.partitions.joinToString { it.name }.ifEmpty { "none" },
            )
        log("  $partition: ${part.ops.size} ops, block_size ${manifest.blockSize}")

        val imageSize = part.imageSize(manifest.blockSize)
        if (imageSize <= 0) throw OtaError("partition '$partition' has zero length")
        if (imageSize > MAX_PART_IMAGE) {
            throw OtaError(
                "partition '$partition' is ${imageSize / (1024 * 1024)} MB; " +
                    "the limit is ${MAX_PART_IMAGE / (1024 * 1024)} MB",
            )
        }

        val dataBase = payloadOffset + manifest.headerBytes +
            manifest.manifestBytes + manifest.signatureBytes
        return extractPartition(source, dataBase, manifest, part, partition, imageSize, log)
    }

    // ---------------------------------------------------------------- zip

    /** Offset of `payload.bin`'s data inside the zip. */
    private fun locatePayload(src: Source, log: (String) -> Unit): Long {
        val tailLength = minOf(src.size, TAIL_SIZE.toLong()).toInt()
        val tail = src.read(src.size - tailLength, tailLength)
        val eocd = findEocd(tail) ?: throw OtaError("OTA zip has no End Of Central Directory")

        var cdOffset = u32(tail, eocd + 16).toLong() and 0xFFFFFFFFL
        var cdSize = u32(tail, eocd + 12).toLong() and 0xFFFFFFFFL
        if (cdOffset == ZIP64_MARK || cdSize == ZIP64_MARK) {
            if (eocd < 20 || i32(tail, eocd - 20) != ZIP64_LOC_SIG) {
                throw OtaError("OTA zip is zip64 but the locator is missing")
            }
            // Everything inside a zip is little-endian, including the zip64 locator and record;
            // only the payload header (below) is big-endian.
            val recordOffset = le64(tail, eocd - 20 + 8)
            val record = src.read(recordOffset, 56)
            if (i32(record, 0) != ZIP64_EOCD_SIG) throw OtaError("bad zip64 End Of Central Directory")
            cdSize = le64(record, 40)
            cdOffset = le64(record, 48)
        }
        if (cdSize <= 0 || cdSize > MAX_CD_SIZE || cdOffset + cdSize > src.size) {
            throw OtaError("invalid zip central directory (off=$cdOffset size=$cdSize)")
        }

        val cd = src.read(cdOffset, cdSize.toInt())
        val entry = findEntry(cd, PAYLOAD_ENTRY)
            ?: throw OtaError("OTA zip has no $PAYLOAD_ENTRY")
        if (entry.method != 0) {
            throw OtaError("$PAYLOAD_ENTRY must be Stored, found compression method ${entry.method}")
        }
        if (entry.localOffset >= src.size) throw OtaError("bad local header offset for $PAYLOAD_ENTRY")

        val probeLength = minOf(src.size - entry.localOffset, 30L + 4096L).toInt()
        val local = src.read(entry.localOffset, probeLength)
        if (i32(local, 0) != LOC_SIG) throw OtaError("cannot parse local file header for $PAYLOAD_ENTRY")
        val dataOffset = 30 + u16(local, 26) + u16(local, 28)
        if (dataOffset > probeLength) throw OtaError("cannot parse local file header for $PAYLOAD_ENTRY")

        log("OTA: ${PAYLOAD_ENTRY} at offset ${entry.localOffset + dataOffset}, " +
            "${entry.uncompressedSize / (1024 * 1024)} MB")
        return entry.localOffset + dataOffset
    }

    /** Scans backwards for the EOCD signature; the comment is what makes it not-always-last. */
    private fun findEocd(tail: ByteArray): Int? {
        var position = tail.size - 22
        while (position >= 0) {
            if (i32(tail, position) == EOCD_SIG) return position
            position--
        }
        return null
    }

    private class ZipEntry(
        val method: Int,
        val uncompressedSize: Long,
        val localOffset: Long,
    )

    /** Walks the central directory for [name]; resolves a zip64 extra when the sizes overflow. */
    private fun findEntry(cd: ByteArray, name: String): ZipEntry? {
        var position = 0
        while (position + 46 <= cd.size && i32(cd, position) == CEN_SIG) {
            val method = u16(cd, position + 10)
            var compressed = u32(cd, position + 20).toLong() and 0xFFFFFFFFL
            var uncompressed = u32(cd, position + 24).toLong() and 0xFFFFFFFFL
            val nameLength = u16(cd, position + 28)
            val extraLength = u16(cd, position + 30)
            val commentLength = u16(cd, position + 32)
            var localOffset = u32(cd, position + 42).toLong() and 0xFFFFFFFFL
            val nameStart = position + 46
            if (nameStart + nameLength > cd.size) break

            if (nameLength == name.length && matches(cd, nameStart, name)) {
                if (uncompressed == ZIP64_MARK || compressed == ZIP64_MARK || localOffset == ZIP64_MARK) {
                    val extraStart = nameStart + nameLength
                    val extraEnd = minOf(extraStart + extraLength, cd.size)
                    var cursor = extraStart
                    while (cursor + 4 <= extraEnd) {
                        val id = u16(cd, cursor)
                        val size = u16(cd, cursor + 2)
                        val data = cursor + 4
                        if (data + size > extraEnd) break
                        if (id == 0x0001) {
                            var field = data
                            if (uncompressed == ZIP64_MARK && field + 8 <= data + size) {
                                uncompressed = le64(cd, field)
                                field += 8
                            }
                            if (compressed == ZIP64_MARK && field + 8 <= data + size) {
                                compressed = le64(cd, field)
                                field += 8
                            }
                            if (localOffset == ZIP64_MARK && field + 8 <= data + size) {
                                localOffset = le64(cd, field)
                            }
                            break
                        }
                        cursor = data + size
                    }
                }
                return ZipEntry(method, uncompressed, localOffset)
            }
            position = nameStart + nameLength + extraLength + commentLength
        }
        return null
    }

    private fun matches(data: ByteArray, start: Int, text: String): Boolean {
        if (start < 0 || start + text.length > data.size) return false
        for (index in text.indices) {
            if (data[start + index] != text[index].code.toByte()) return false
        }
        return true
    }

    // ---------------------------------------------------------------- payload

    private class Extent(val startBlock: Long, val numBlocks: Long)

    private class Operation(
        val type: Int,
        val dataOffset: Long,
        val dataLength: Long,
        val extents: List<Extent>,
    )

    private class Partition(val name: String, val ops: List<Operation>) {
        /** Highest block any operation writes, in bytes. */
        fun imageSize(blockSize: Int): Long {
            var end = 0L
            ops.forEach { op ->
                op.extents.forEach { extent ->
                    val last = (extent.startBlock + extent.numBlocks) * blockSize
                    if (last > end) end = last
                }
            }
            return end
        }
    }

    private class Manifest(
        val blockSize: Int,
        val partitions: List<Partition>,
        val headerBytes: Long,
        val manifestBytes: Long,
        val signatureBytes: Long,
    )

    private fun readManifest(src: Source, payloadOffset: Long, log: (String) -> Unit): Manifest {
        if (payloadOffset + 20 > src.size) throw OtaError("payload header is truncated")
        // v1 ends after the manifest size; the signature size only exists from v2 on. Read the
        // short form first so a v1 payload never trips the bounds check.
        val head = src.read(payloadOffset, 20)
        if (!head.copyOfRange(0, 4).contentEquals(PAYLOAD_MAGIC)) {
            throw OtaError("not a payload.bin (bad magic)")
        }
        val version = be64(head, 4)
        val manifestSize = be64(head, 12)
        val headerBytes = if (version >= 2) 24L else 20L
        val signatureSize = if (version >= 2) {
            be32(src.read(payloadOffset + 20, 4), 0)
        } else {
            0L
        }
        if (manifestSize <= 0 || manifestSize > MAX_MANIFEST) {
            throw OtaError("implausible manifest size $manifestSize")
        }
        if (payloadOffset + headerBytes + manifestSize > src.size) {
            throw OtaError("manifest runs past the end of the file")
        }
        val bytes = src.read(payloadOffset + headerBytes, manifestSize.toInt())
        val manifest = parseManifest(bytes, headerBytes, manifestSize, signatureSize)
        log("OTA: payload v$version, ${manifest.partitions.size} partitions, " +
            "block_size ${manifest.blockSize}")
        return manifest
    }

    private fun parseManifest(
        data: ByteArray,
        headerBytes: Long,
        manifestBytes: Long,
        signatureBytes: Long,
    ): Manifest {
        var blockSize = 4096
        val partitions = ArrayList<Partition>()
        val reader = Proto(data)
        while (reader.next()) {
            when {
                reader.field == 3 && reader.wire == 0 ->
                    if (reader.number > 0) blockSize = reader.number.toInt()
                reader.field == 13 && reader.wire == 2 ->
                    parsePartition(reader.bytes)?.let { partitions += it }
            }
        }
        if (blockSize <= 0 || blockSize > (1 shl 20)) {
            throw OtaError("implausible block_size $blockSize")
        }
        return Manifest(blockSize, partitions, headerBytes, manifestBytes, signatureBytes)
    }

    private fun parsePartition(data: ByteArray): Partition? {
        var name: String? = null
        val ops = ArrayList<Operation>()
        val reader = Proto(data)
        while (reader.next()) {
            when {
                reader.field == 1 && reader.wire == 2 ->
                    name = String(reader.bytes, Charsets.UTF_8)
                reader.field == 8 && reader.wire == 2 ->
                    parseOperation(reader.bytes)?.let { ops += it }
            }
        }
        val resolved = name ?: return null
        return Partition(resolved, ops)
    }

    private fun parseOperation(data: ByteArray): Operation? {
        var type = -1
        var dataOffset = 0L
        var dataLength = 0L
        val extents = ArrayList<Extent>()
        val reader = Proto(data)
        while (reader.next()) {
            when {
                reader.field == 1 && reader.wire == 0 -> type = reader.number.toInt()
                reader.field == 2 && reader.wire == 0 -> dataOffset = reader.number
                reader.field == 3 && reader.wire == 0 -> dataLength = reader.number
                reader.field == 6 && reader.wire == 2 ->
                    parseExtent(reader.bytes)?.let { extents += it }
            }
        }
        if (type < 0 || extents.isEmpty()) return null
        return Operation(type, dataOffset, dataLength, extents)
    }

    private fun parseExtent(data: ByteArray): Extent? {
        var start = 0L
        var count = 0L
        val reader = Proto(data)
        while (reader.next()) {
            when {
                reader.field == 1 && reader.wire == 0 -> start = reader.number
                reader.field == 2 && reader.wire == 0 -> count = reader.number
            }
        }
        if (count <= 0) return null
        return Extent(start, count)
    }

    // ---------------------------------------------------------------- apply

    private fun extractPartition(
        src: Source,
        dataBase: Long,
        manifest: Manifest,
        part: Partition,
        name: String,
        imageSize: Long,
        log: (String) -> Unit,
    ): ByteArray {
        val blockSize = manifest.blockSize
        // ZERO / DISCARD regions are never written, so a zero-filled image is the result.
        val image = ByteArray(imageSize.toInt())

        part.ops.forEachIndexed { index, op ->
            val data = when (op.type) {
                OP_ZERO, OP_DISCARD -> null
                OP_REPLACE, OP_REPLACE_XZ, OP_REPLACE_BZ -> {
                    if (op.dataLength <= 0 || op.dataLength > MAX_OP_DATA) {
                        throw OtaError("bad data_length ${op.dataLength} in $name op $index")
                    }
                    val raw = src.read(dataBase + op.dataOffset, op.dataLength.toInt())
                    when (op.type) {
                        OP_REPLACE -> raw
                        OP_REPLACE_XZ -> inflate(raw, op.uncompressedSize(blockSize), "XZ") { bytes ->
                            XZInputStream(ByteArrayInputStream(bytes))
                        }
                        else -> inflate(raw, op.uncompressedSize(blockSize), "BZip2") { bytes ->
                            BZip2CompressorInputStream(ByteArrayInputStream(bytes))
                        }
                    }
                }
                else -> throw OtaError(
                    "unsupported payload operation type ${op.type} (${opName(op.type)}) in $name - " +
                        "this is a delta OTA; use a full OTA or tools/ota_boot_extract.c",
                )
            } ?: return@forEachIndexed

            var offset = 0
            op.extents.forEach { extent ->
                val bytes = extent.numBlocks * blockSize
                val seek = extent.startBlock * blockSize
                if (seek < 0 || seek + bytes > imageSize) {
                    throw OtaError("extent outside the '$name' partition in op $index")
                }
                val take = minOf(bytes, (data.size - offset).toLong())
                if (take > 0) {
                    System.arraycopy(data, offset, image, seek.toInt(), take.toInt())
                    offset += take.toInt()
                }
            }
        }

        log("  $name: ${imageSize / (1024 * 1024)} MB extracted")
        return image
    }

    private fun Operation.uncompressedSize(blockSize: Int): Long {
        var total = 0L
        extents.forEach { total += it.numBlocks * blockSize }
        return total
    }

    /** Decompresses one operation blob, refusing anything that grows past its extents. */
    private inline fun inflate(
        data: ByteArray,
        expected: Long,
        label: String,
        open: (ByteArray) -> java.io.InputStream,
    ): ByteArray {
        if (expected <= 0 || expected > MAX_OP_DATA) {
            throw OtaError("implausible uncompressed size $expected for a $label blob")
        }
        val out = ByteArrayOutputStream(minOf(expected, 1L shl 20).toInt())
        open(data).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (out.size().toLong() + read > expected) {
                    throw OtaError("$label blob expands past its $expected byte extents")
                }
                out.write(buffer, 0, read)
            }
        }
        return out.toByteArray()
    }

    private fun opName(type: Int): String = when (type) {
        OP_MOVE -> "MOVE"
        OP_BSDIFF -> "BSDIFF"
        OP_SOURCE_COPY -> "SOURCE_COPY"
        OP_SOURCE_BSDIFF -> "SOURCE_BSDIFF"
        OP_PUFFDIFF -> "PUFFDIFF"
        OP_BROTLI_BSDIFF -> "BROTLI_BSDIFF"
        else -> "type $type"
    }

    // ---------------------------------------------------------------- protobuf wire reader

    /**
     * Minimal protobuf wire decoder.
     *
     * The manifest is a few hundred kilobytes of nested messages, and pulling in a protobuf
     * runtime (plus generated classes for a schema that ships with AOSP, not with this app) would
     * cost more than the hundred lines it takes to walk the wire format.
     */
    private class Proto(private val data: ByteArray) {
        private var position = 0
        var field = 0
        var wire = 0
        var number = 0L
        var bytes: ByteArray = ByteArray(0)

        fun next(): Boolean {
            if (position >= data.size) return false
            val tag = varint()
            field = (tag ushr 3).toInt()
            wire = (tag and 7L).toInt()
            when (wire) {
                0 -> number = varint()
                1 -> skip(8)
                2 -> {
                    val length = varint()
                    if (length < 0 || length > data.size - position) {
                        throw OtaError("malformed protobuf: length $length past the message end")
                    }
                    bytes = data.copyOfRange(position, position + length.toInt())
                    position += length.toInt()
                }
                5 -> skip(4)
                else -> throw OtaError("unsupported protobuf wire type $wire")
            }
            return true
        }

        private fun skip(count: Int) {
            if (count > data.size - position) throw OtaError("malformed protobuf: truncated field")
            position += count
        }

        private fun varint(): Long {
            var result = 0L
            var shift = 0
            while (true) {
                if (position >= data.size) throw OtaError("malformed protobuf: truncated varint")
                val byte = data[position++].toInt() and 0xFF
                result = result or ((byte.toLong() and 0x7F) shl shift)
                if (byte and 0x80 == 0) return result
                shift += 7
                if (shift > 63) throw OtaError("malformed protobuf: varint too long")
            }
        }
    }

    // ---------------------------------------------------------------- byte helpers

    private fun u16(data: ByteArray, offset: Int): Int {
        if (offset < 0 || offset + 2 > data.size) throw OtaError("truncated buffer at $offset")
        return (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)
    }

    private fun u32(data: ByteArray, offset: Int): Int {
        if (offset < 0 || offset + 4 > data.size) throw OtaError("truncated buffer at $offset")
        return (data[offset].toInt() and 0xFF) or
            ((data[offset + 1].toInt() and 0xFF) shl 8) or
            ((data[offset + 2].toInt() and 0xFF) shl 16) or
            ((data[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun i32(data: ByteArray, offset: Int): Int = u32(data, offset)

    /** Little-endian 64-bit (zip fields); the payload header uses [be64]. */
    private fun le64(data: ByteArray, offset: Int): Long {
        if (offset < 0 || offset + 8 > data.size) throw OtaError("truncated buffer at $offset")
        var value = 0L
        for (index in 7 downTo 0) value = (value shl 8) or (data[offset + index].toLong() and 0xFF)
        return value
    }

    private fun be32(data: ByteArray, offset: Int): Long {
        if (offset < 0 || offset + 4 > data.size) throw OtaError("truncated buffer at $offset")
        var value = 0L
        for (index in 0 until 4) value = (value shl 8) or (data[offset + index].toLong() and 0xFF)
        return value
    }

    private fun be64(data: ByteArray, offset: Int): Long {
        if (offset < 0 || offset + 8 > data.size) throw OtaError("truncated buffer at $offset")
        var value = 0L
        for (index in 0 until 8) value = (value shl 8) or (data[offset + index].toLong() and 0xFF)
        return value
    }
}
