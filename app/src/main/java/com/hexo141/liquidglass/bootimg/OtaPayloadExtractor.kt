package com.hexo141.liquidglass.bootimg

import android.content.ContentResolver
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.Closeable
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * Android side of [OtaPayloadReader]: opens a picked document for random access.
 *
 * All the ZIP, protobuf and operation handling lives in [OtaPayloadReader], which has no Android
 * dependencies and is covered by JVM tests. This object only deals with `content://` URIs and the
 * file descriptor behind them.
 */
object OtaPayloadExtractor {

    /** Partition that carries the kernel on every non-MTK layout. */
    const val DEFAULT_PARTITION = OtaPayloadReader.DEFAULT_PARTITION

    /**
     * Extracts [partition] from [uri].
     *
     * @return the partition image, or `null` when [uri] is not an OTA at all - the caller then
     *   falls back to treating it as a plain `boot.img`.
     * @throws OtaPayloadReader.OtaError when the file *is* an OTA but cannot be read
     */
    fun extractKernel(
        resolver: ContentResolver,
        uri: Uri,
        partition: String = DEFAULT_PARTITION,
        log: (String) -> Unit = {},
    ): ByteArray? {
        val source = openSource(resolver, uri)
        if (source == null) {
            // A provider that hands out a pipe cannot be seeked, and an OTA is far too large to
            // buffer. Only complain when the file actually is an OTA; anything else is simply
            // "not an OTA" and the caller parses it as a plain image.
            if (looksLikeOta(resolver, uri)) {
                throw OtaPayloadReader.OtaError(
                    "this document cannot be read at random offsets; copy the OTA to local " +
                        "storage and pick it again",
                )
            }
            return null
        }
        return source.use { OtaPayloadReader.extract(it, partition, log) }
    }

    /** Absolute reads over a document; the fd stays open until [close]. */
    private class DocumentSource(
        private val stream: FileInputStream,
        private val pfd: ParcelFileDescriptor,
        override val size: Long,
    ) : OtaPayloadReader.Source, Closeable {
        private val channel: FileChannel = stream.channel

        override fun read(offset: Long, length: Int): ByteArray {
            if (offset < 0 || length < 0 || offset > size - length) {
                throw OtaPayloadReader.OtaError("read past end of file: $offset+$length > $size")
            }
            val buffer = ByteBuffer.allocate(length)
            var position = offset
            while (buffer.hasRemaining()) {
                val read = channel.read(buffer, position)
                if (read <= 0) throw OtaPayloadReader.OtaError("unexpected end of file at $position")
                position += read
            }
            return buffer.array()
        }

        override fun close() {
            runCatching { stream.close() }
            runCatching { pfd.close() }
        }
    }

    /**
     * Opens [uri] for random access.
     *
     * Returns `null` when the provider hands out a stream rather than a seekable file: an OTA is
     * gigabytes, so the caller must fall back to asking for a `boot.img` instead of buffering it.
     */
    private fun openSource(resolver: ContentResolver, uri: Uri): DocumentSource? {
        val pfd = runCatching { resolver.openFileDescriptor(uri, "r") }.getOrNull() ?: return null
        val stream = FileInputStream(pfd.fileDescriptor)
        val size = runCatching { pfd.statSize }.getOrDefault(-1L)
        if (size <= 0) {
            runCatching { stream.close() }
            runCatching { pfd.close() }
            return null
        }
        return DocumentSource(stream, pfd, size)
    }

    /** First four bytes only; used to tell "an OTA we cannot seek" from "not an OTA". */
    private fun looksLikeOta(resolver: ContentResolver, uri: Uri): Boolean =
        runCatching {
            resolver.openInputStream(uri)?.use { input ->
                val head = ByteArray(4)
                var read = 0
                while (read < 4) {
                    val count = input.read(head, read, 4 - read)
                    if (count < 0) break
                    read += count
                }
                if (read < 4) {
                    false
                } else {
                    (head[0] == 'C'.code.toByte() && head[1] == 'r'.code.toByte()) ||
                        (head[0] == 'P'.code.toByte() && head[1] == 'K'.code.toByte())
                }
            } ?: false
        }.getOrDefault(false)
}
