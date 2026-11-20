package com.hexo141.liquidglass.bootimg

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Exercises the HTTP Range path against a real local server, no Android classes involved. */
class HttpRangeSourceTest {

    private lateinit var server: HttpServer
    private lateinit var data: ByteArray
    private val requests = AtomicInteger()
    @Volatile private var ignoreRange = false

    private val url: String get() = "http://127.0.0.1:${server.address.port}/ota.zip"

    @Before
    fun setUp() {
        data = ByteArray(10_000) { (it and 0xFF).toByte() }
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/ota.zip", ::serve)
        server.start()
    }

    @After
    fun tearDown() {
        server.stop(0)
    }

    @Test
    fun `probe learns the total length and reads exact ranges`() {
        val source = HttpRangeSource(url)
        val logs = mutableListOf<String>()
        val sourceWithLog = HttpRangeSource(url) { logs += it }

        assertEquals(data.size.toLong(), source.size)
        assertArrayEquals(data.copyOfRange(1234, 1734), source.read(1234, 500))
        assertArrayEquals(data.copyOfRange(0, 4), sourceWithLog.read(0, 4))
        assertTrue(logs.any { it.contains("HTTP Range enabled") })
        source.close()
        sourceWithLog.close()
    }

    @Test
    fun `reads larger than one chunk are stitched from several requests`() {
        val big = ByteArray(6 * 1024 * 1024) { (it and 0xFF).toByte() }
        data = big
        requests.set(0)

        val source = HttpRangeSource(url)
        assertArrayEquals(big, source.read(0, big.size))
        // 4 MiB chunks: at least two range requests besides the probe.
        assertTrue("expected multiple range requests, got ${requests.get()}", requests.get() >= 2)
        source.close()
    }

    @Test
    fun `a server that ignores Range is refused instead of downloading the whole file`() {
        ignoreRange = true
        val source = HttpRangeSource(url) // probe: 200 + Content-Length is still a usable length

        try {
            source.read(100, 10)
            fail("a 200 response to a ranged read must be refused")
        } catch (error: OtaPayloadReader.OtaError) {
            assertTrue(error.message!!.contains("ignored the Range header"))
        }
        source.close()
    }

    @Test
    fun `a full OTA zip served over HTTP is parsed end to end`() {
        val boot = ByteArray(4096) { (it * 7 and 0xFF).toByte() }
        val payload = buildPayload("boot", listOf(replaceOp(0, boot.size.toLong(), 0, 1)), boot)
        data = storedZip(
            "META-INF/com/android/metadata" to "ota-type=AB\n".toByteArray(),
            "payload.bin" to payload,
        )
        val logs = mutableListOf<String>()

        val image = HttpRangeSource(url) { logs += it }.use { source ->
            OtaPayloadReader.extract(source, log = { logs += it })!!
        }

        assertArrayEquals(boot, image)
        assertTrue(logs.any { it.contains("HTTP Range enabled") })
        assertTrue("expected download progress lines", logs.any { it.contains("HTTP: +") })
    }

    // ---------------------------------------------------------------- local server

    private fun serve(exchange: HttpExchange) {
        requests.incrementAndGet()
        val range = exchange.requestHeaders.getFirst("Range")
        if (ignoreRange || range == null) {
            exchange.sendResponseHeaders(200, data.size.toLong())
            // The client stops reading as soon as it has the one byte it asked for.
            try {
                exchange.responseBody.use { it.write(data) }
            } catch (_: IOException) {
            }
            return
        }
        val match = Regex("""bytes=(\d+)-(\d+)""").find(range)
        if (match == null) {
            exchange.sendResponseHeaders(416, -1)
            exchange.close()
            return
        }
        val start = match.groupValues[1].toInt()
        val end = match.groupValues[2].toInt()
        val length = end - start + 1
        exchange.responseHeaders.add("Content-Range", "bytes $start-$end/${data.size}")
        exchange.sendResponseHeaders(206, length.toLong())
        exchange.responseBody.use { it.write(data, start, length) }
    }

    // ---------------------------------------------------------------- fixtures

    private fun buildPayload(partition: String, ops: List<ByteArray>, blob: ByteArray): ByteArray {
        val part = ld(1, partition.toByteArray()) + ops.map { ld(8, it) }.reduce { a, b -> a + b }
        val manifest = vi(3, 4096) + ld(13, part)
        val header = "CrAU".toByteArray() + be64(2) + be64(manifest.size.toLong()) + be32(0)
        return header + manifest + blob
    }

    private fun replaceOp(offset: Long, length: Long, startBlock: Long, blocks: Long): ByteArray =
        vi(1, 0) + vi(2, offset) + vi(3, length) +
            ld(6, vi(1, startBlock) + vi(2, blocks))

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

    private fun vi(field: Int, value: Long): ByteArray = varint((field shl 3).toLong()) + varint(value)

    private fun ld(field: Int, content: ByteArray): ByteArray =
        varint(((field shl 3) or 2).toLong()) + varint(content.size.toLong()) + content

    private fun be64(value: Long): ByteArray =
        ByteArray(8) { index -> ((value ushr (56 - index * 8)) and 0xFF).toByte() }

    private fun be32(value: Long): ByteArray =
        ByteArray(4) { index -> ((value ushr (24 - index * 8)) and 0xFF).toByte() }
}
