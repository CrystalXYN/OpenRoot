package com.hexo141.liquidglass.bootimg

import java.io.Closeable
import java.net.HttpURLConnection
import java.net.URL

/**
 * Random access to an OTA over HTTP Range requests.
 *
 * This is the on-device counterpart of `http_read()` in `tools/ota_boot_extract.c`: the file is
 * never downloaded whole, only the ZIP trailer, central directory, payload manifest and the ops
 * belonging to the requested partition are fetched. A server that ignores `Range` is rejected
 * rather than silently downloading a multi-gigabyte package.
 *
 * Deliberately free of Android types so it can be exercised against a local JVM HTTP server.
 */
class HttpRangeSource(
    private val url: String,
    private val log: (String) -> Unit = {},
) : OtaPayloadReader.Source, Closeable {

    /** Total object length, learned from `Content-Range` of a `bytes=0-0` probe. */
    override val size: Long = probeSize()

    private var downloaded = 0L
    private var closed = false

    /** Bytes pulled over the wire since this source was opened, for the Log tab. */
    val downloadedBytes: Long get() = downloaded

    override fun read(offset: Long, length: Int): ByteArray {
        check(!closed) { "HTTP source is closed" }
        if (offset < 0 || length < 0 || offset > size - length) {
            throw OtaPayloadReader.OtaError(
                "read out of range: start=$offset want=$length length=$size",
            )
        }
        if (length == 0) return ByteArray(0)

        val out = ByteArray(length)
        var done = 0
        while (done < length) {
            // Chunked so one request never allocates more than a few MB and a stalled transfer
            // cannot hold the whole parse hostage.
            val want = minOf(MAX_RANGE_CHUNK, length - done)
            val chunk = range(offset + done, want)
            System.arraycopy(chunk.bytes, 0, out, done, chunk.bytes.size)
            done += chunk.bytes.size
        }
        downloaded += length
        log("  HTTP: +${length / (1024 * 1024)} MB (total ${downloaded / (1024 * 1024)} MB)")
        return out
    }

    override fun close() {
        closed = true
    }

    private class Reply(val bytes: ByteArray, val total: Long?, val contentLength: Long, val code: Int)

    private fun probeSize(): Long {
        val reply = range(0, 1)
        if (reply.total != null && reply.total > 0) {
            log("OTA: remote ${reply.total / (1024 * 1024)} MB, HTTP Range enabled")
            return reply.total
        }
        // A 200 with Content-Length gives a usable length, but every later start>0 read will be
        // refused by range(); warn now so the eventual failure is not a surprise.
        if (reply.code == 200 && reply.contentLength > 0) {
            log("[~] server ignored Range on probe; extraction will likely fail")
            return reply.contentLength
        }
        throw OtaPayloadReader.OtaError("cannot determine remote file length (no Content-Range)")
    }

    /**
     * One `Range: bytes=start-(start+want-1)` GET.
     *
     * Reading stops as soon as [want] bytes arrived: a server that ignores Range and answers the
     * probe with the whole 4 GB OTA must not be allowed to fill the heap.
     */
    private fun range(start: Long, want: Int): Reply {
        val end = start + want - 1
        val connection = try {
            URL(url).openConnection()
        } catch (error: Exception) {
            throw OtaPayloadReader.OtaError("cannot open OTA URL: ${error.message}")
        }
        if (connection !is HttpURLConnection) {
            throw OtaPayloadReader.OtaError("only http/https OTA links are supported")
        }
        connection.connectTimeout = CONNECT_TIMEOUT_MS
        connection.readTimeout = READ_TIMEOUT_MS
        connection.instanceFollowRedirects = true
        connection.requestMethod = "GET"
        connection.setRequestProperty("Range", "bytes=$start-$end")
        // Same reasoning as the C tool: a gzipped transfer would break byte offsets.
        connection.setRequestProperty("Accept-Encoding", "identity")
        connection.setRequestProperty("User-Agent", USER_AGENT)

        try {
            val code = connection.responseCode
            if (code !in 200..299) {
                throw OtaPayloadReader.OtaError("HTTP status $code for bytes=$start-$end")
            }
            if (start > 0 && code == 200) {
                throw OtaPayloadReader.OtaError(
                    "server ignored the Range header (returned 200); full OTA download refused",
                )
            }
            val total = parseContentRange(connection.getHeaderField("Content-Range"))
            val contentLength = connection.getHeaderFieldLong("Content-Length", -1L)

            val buffer = ByteArray(want)
            var done = 0
            connection.inputStream.use { stream ->
                while (done < want) {
                    val read = stream.read(buffer, done, want - done)
                    if (read < 0) break
                    done += read
                }
            }
            if (done != want) {
                throw OtaPayloadReader.OtaError("short read at $start: got $done, want $want")
            }
            return Reply(buffer, total, contentLength, code)
        } catch (error: java.io.IOException) {
            throw OtaPayloadReader.OtaError("HTTP request failed: ${error.message}")
        } finally {
            connection.disconnect()
        }
    }

    /** `bytes 0-0/67109038` → 67109038; a wildcard instead of a total means unknown. */
    private fun parseContentRange(header: String?): Long? {
        val value = header?.trim()?.substringAfter('/') ?: return null
        return value.toLongOrNull()?.takeIf { it > 0 }
    }

    private companion object {
        const val MAX_RANGE_CHUNK = 4 * 1024 * 1024
        const val CONNECT_TIMEOUT_MS = 15_000
        const val READ_TIMEOUT_MS = 30_000
        const val USER_AGENT =
            "Dalvik/2.1.0 (Linux; U; Android 15; OpenRoot OTA profile parser)"
    }
}
