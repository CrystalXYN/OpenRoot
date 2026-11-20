package com.hexo141.liquidglass.bootimg

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.tukaani.xz.LZMA2Options
import org.tukaani.xz.XZOutputStream
import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Covers the parts of the OTA reader that do not need a device: the zip lookup, the payload
 * manifest walk and each operation type, including the ones that must be refused.
 */
class OtaPayloadReaderTest {

    private val blockSize = 4096

    @Test
    fun `replace writes the extents`() {
        val data = bytes(0, blockSize * 2)
        val payload = buildPayload(
            partition = "boot",
            ops = listOf(replaceOp(offset = 0, length = data.size.toLong(), startBlock = 0, blocks = 2)),
            data = data,
        )

        val image = OtaPayloadReader.extract(Bytes(payload))!!

        assertArrayEquals(data, image)
    }

    @Test
    fun `zero and discard leave zero filled holes`() {
        val block = bytes(1, blockSize)
        val ops = listOf(
            replaceOp(offset = 0, length = block.size.toLong(), startBlock = 0, blocks = 1),
            zeroOp(startBlock = 1, blocks = 1, type = 6),
            zeroOp(startBlock = 2, blocks = 1, type = 7),
        )
        val payload = buildPayload("boot", ops, block)

        val image = OtaPayloadReader.extract(Bytes(payload))!!

        assertEquals(blockSize * 3, image.size)
        assertArrayEquals(block, image.copyOfRange(0, blockSize))
        assertTrue(image.copyOfRange(blockSize, blockSize * 3).all { it == 0.toByte() })
    }

    @Test
    fun `replace_xz is decompressed before it is written`() {
        val data = bytes(7, blockSize * 4)
        val compressed = xz(data)
        val op = replaceOp(0, compressed.size.toLong(), 0, 4, type = 8)
        val payload = buildPayload("boot", listOf(op), compressed)

        assertArrayEquals(data, OtaPayloadReader.extract(Bytes(payload)))
    }

    @Test
    fun `replace_bz is decompressed before it is written`() {
        val data = bytes(9, blockSize * 2)
        val compressed = bz2(data)
        val op = replaceOp(0, compressed.size.toLong(), 0, 2, type = 1)
        val payload = buildPayload("boot", listOf(op), compressed)

        assertArrayEquals(data, OtaPayloadReader.extract(Bytes(payload)))
    }

    @Test
    fun `payload inside a stored zip is located`() {
        val data = bytes(3, blockSize)
        val payload = buildPayload("boot", listOf(replaceOp(0, data.size.toLong(), 0, 1)), data)
        val zip = storedZip(
            // A real OTA carries metadata before payload.bin; the reader must walk the central
            // directory, not assume the payload starts at offset 0.
            "META-INF/com/android/metadata" to "ota-type=AB\n".toByteArray(),
            "payload.bin" to payload,
        )

        assertArrayEquals(data, OtaPayloadReader.extract(Bytes(zip)))
    }

    @Test
    fun `delta operations are refused by name`() {
        val op = vi(1, 4) + vi(2, 0) + vi(3, 16) + ld(6, vi(1, 0) + vi(2, 1))
        val payload = buildPayload("boot", listOf(op), ByteArray(16))

        try {
            OtaPayloadReader.extract(Bytes(payload))
            fail("a SOURCE_COPY operation must not produce an image")
        } catch (error: OtaPayloadReader.OtaError) {
            assertTrue(error.message!!.contains("SOURCE_COPY"))
        }
    }

    @Test
    fun `a missing partition lists what the payload has`() {
        val payload = buildPayload("vendor_boot", listOf(replaceOp(0, 16, 0, 1)), ByteArray(16))

        try {
            OtaPayloadReader.extract(Bytes(payload))
            fail("extracting a partition the payload does not have must fail")
        } catch (error: OtaPayloadReader.OtaError) {
            assertTrue(error.message!!.contains("vendor_boot"))
            assertTrue(error.message!!.contains("available"))
        }
    }

    @Test
    fun `a plain image is not mistaken for an OTA`() {
        val boot = ByteArray(2048) { (it and 0xFF).toByte() }
        assertNull(OtaPayloadReader.extract(Bytes(boot)))
    }

    // ---------------------------------------------------------------- fixtures

    private class Bytes(private val data: ByteArray) : OtaPayloadReader.Source {
        override val size: Long get() = data.size.toLong()

        override fun read(offset: Long, length: Int): ByteArray {
            require(offset >= 0 && length >= 0 && offset + length <= data.size) {
                "read past end: $offset+$length > ${data.size}"
            }
            return data.copyOfRange(offset.toInt(), offset.toInt() + length)
        }
    }

    private fun bytes(seed: Int, count: Int): ByteArray =
        ByteArray(count) { ((it + seed) and 0xFF).toByte() }

    private fun buildPayload(
        partition: String,
        ops: List<ByteArray>,
        data: ByteArray,
    ): ByteArray {
        val part = ld(1, partition.toByteArray()) + ops.map { ld(8, it) }.reduce { a, b -> a + b }
        val manifest = vi(3, blockSize.toLong()) + ld(13, part)
        val header = "CrAU".toByteArray() +
            be64(2) + be64(manifest.size.toLong()) + be32(0)
        return header + manifest + data
    }

    private fun replaceOp(
        offset: Long,
        length: Long,
        startBlock: Long,
        blocks: Long,
        type: Int = 0,
    ): ByteArray = vi(1, type.toLong()) +
        vi(2, offset) +
        vi(3, length) +
        ld(6, vi(1, startBlock) + vi(2, blocks))

    private fun zeroOp(startBlock: Long, blocks: Long, type: Int): ByteArray =
        vi(1, type.toLong()) + ld(6, vi(1, startBlock) + vi(2, blocks))

    private fun storedZip(vararg entries: Pair<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            entries.forEach { (name, content) ->
                val entry = ZipEntry(name)
                entry.method = ZipEntry.STORED
                entry.size = content.size.toLong()
                entry.compressedSize = content.size.toLong()
                entry.crc = CRC32().also { it.update(content) }.value
                zip.putNextEntry(entry)
                zip.write(content)
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private fun xz(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        XZOutputStream(out, LZMA2Options()).use { it.write(data) }
        return out.toByteArray()
    }

    private fun bz2(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        BZip2CompressorOutputStream(out).use { it.write(data) }
        return out.toByteArray()
    }

    // protobuf wire helpers

    private fun varint(value: Long): ByteArray {
        var remaining = value
        val out = ByteArrayOutputStream()
        while (true) {
            val byte = (remaining and 0x7F).toInt()
            remaining = remaining ushr 7
            if (remaining == 0L) {
                out.write(byte)
                break
            }
            out.write(byte or 0x80)
        }
        return out.toByteArray()
    }

    private fun vi(field: Int, value: Long): ByteArray =
        varint(((field shl 3) or 0).toLong()) + varint(value)

    private fun ld(field: Int, content: ByteArray): ByteArray =
        varint(((field shl 3) or 2).toLong()) + varint(content.size.toLong()) + content

    private fun be64(value: Long): ByteArray =
        ByteArray(8) { index -> ((value ushr (56 - index * 8)) and 0xFF).toByte() }

    private fun be32(value: Long): ByteArray =
        ByteArray(4) { index -> ((value ushr (24 - index * 8)) and 0xFF).toByte() }
}
