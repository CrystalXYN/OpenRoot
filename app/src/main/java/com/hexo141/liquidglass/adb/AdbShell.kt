package com.hexo141.liquidglass.adb

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException

/** Runs shell commands through the ADB connection. */
object AdbShell {

    /** Chunk size used when streaming a file into `cat`; each write waits for the daemon's READY. */
    private const val PUSH_CHUNK = 32 * 1024

    /** A shell command that stops producing output for this long is treated as stuck. */
    private const val IDLE_TIMEOUT_MS = 15_000L

    /**
     * @param command command line, executed by the daemon's shell (`shell:<command>`)
     * @param timeoutMs how long the command may stay silent before the stream is closed
     * @return everything the command wrote to stdout, decoded as UTF-8
     */
    @Throws(Exception::class)
    fun exec(
        manager: AbsAdbConnectionManager,
        command: String,
        timeoutMs: Long = IDLE_TIMEOUT_MS,
    ): String {
        // A Shizuku grant is the same shell uid adbd gives us; prefer it when the user paired
        // through Shizuku instead of the in-app flow.
        if (ShizukuShell.isAuthorized()) return ShizukuShell.exec(command, timeoutMs)
        val stream = manager.openStream("shell:$command")
        val watchdog = StreamWatchdog(stream, timeoutMs)
        try {
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            while (true) {
                // AdbStream reports the peer's close as an IOException instead of EOF.
                val read = try {
                    stream.read(buffer, 0, buffer.size)
                } catch (e: IOException) {
                    if (stream.isClosed) break else throw e
                }
                watchdog.touch()
                if (read <= 0) break
                out.write(buffer, 0, read)
            }
            return out.toString("UTF-8")
        } finally {
            watchdog.stop()
            runCatching { stream.close() }
        }
    }

    /**
     * Streams a command's output line by line, so long running payloads can be shown live.
     *
     * @return the command's exit status, or -1 when it could not be determined
     */
    @Throws(Exception::class)
    fun stream(
        manager: AbsAdbConnectionManager,
        command: String,
        onLine: (String) -> Unit,
        idleTimeoutMs: Long = 120_000L,
    ): Int {
        if (ShizukuShell.isAuthorized()) return ShizukuShell.stream(command, onLine, idleTimeoutMs)
        // `pty` matters: with a pipe the payload's stdio is block buffered, so its log only arrives
        // in 4 KB chunks. A pty makes it line buffered, i.e. real time like a terminal. The v1
        // service carries no exit status, so the wrapper echoes it as a marker instead.
        val stream = openStream(manager, "$command; echo \"$EXIT_MARKER\$?\"", pty = true)
        val watchdog = StreamWatchdog(stream, idleTimeoutMs)
        val pending = StringBuilder()
        var exitCode = -1
        try {
            val buffer = ByteArray(4096)
            while (true) {
                val read = try {
                    stream.read(buffer, 0, buffer.size)
                } catch (e: IOException) {
                    if (stream.isClosed) break else throw e
                }
                watchdog.touch()
                if (read <= 0) break
                pending.append(String(buffer, 0, read, Charsets.UTF_8))
                while (true) {
                    val newline = pending.indexOf("\n")
                    if (newline < 0) break
                    val line = pending.substring(0, newline).trimEnd('\r')
                    pending.delete(0, newline + 1)
                    if (line.startsWith(EXIT_MARKER)) {
                        exitCode = line.removePrefix(EXIT_MARKER).trim().toIntOrNull() ?: -1
                    } else {
                        onLine(line)
                    }
                }
            }
            if (pending.isNotEmpty()) onLine(pending.toString().trimEnd('\r'))
        } finally {
            watchdog.stop()
            runCatching { stream.close() }
        }
        return exitCode
    }

    /** Writes [bytes] to [remotePath] through the daemon's shell. */
    @Throws(Exception::class)
    fun push(manager: AbsAdbConnectionManager, remotePath: String, bytes: ByteArray) {
        if (ShizukuShell.isAuthorized()) return ShizukuShell.push(remotePath, bytes)
        val stream = manager.openStream("shell:cat > '$remotePath'")
        try {
            var offset = 0
            while (offset < bytes.size) {
                val length = minOf(PUSH_CHUNK, bytes.size - offset)
                stream.write(bytes, offset, length)
                offset += length
            }
            stream.flush()
        } finally {
            runCatching { stream.close() }
        }
    }

    /**
     * Closes the stream when it stops producing data, so a daemon that never answers cannot leave a
     * caller waiting forever.
     */
    private class StreamWatchdog(private val stream: AdbStream, private val timeoutMs: Long) {
        @Volatile
        private var lastActivity = System.currentTimeMillis()

        private val thread = Thread({
            while (!Thread.currentThread().isInterrupted) {
                if (System.currentTimeMillis() - lastActivity > timeoutMs) {
                    runCatching { stream.close() }
                    return@Thread
                }
                try {
                    Thread.sleep(250)
                } catch (_: InterruptedException) {
                    return@Thread
                }
            }
        }, "adb-shell-watchdog").apply {
            isDaemon = true
            start()
        }

        fun touch() {
            lastActivity = System.currentTimeMillis()
        }

        fun stop() {
            thread.interrupt()
        }
    }

    /**
     * Puts [bytes] at [remotePath] and verifies the size that landed.
     *
     * When [cacheDirectory] is set the bytes are written there first and the shell copies it with
     * `cat`, which is what the engines use: piping the payload through `cat >` over stdin looks
     * fine in the log but lands as a 0-byte file on some transports, because the channel closes
     * before the child has drained its stdin. The relay file is deleted either way.
     *
     * @return the size the device reports
     * @throws IOException when the device's copy does not have the expected size
     */
    @Throws(Exception::class)
    fun stage(
        manager: AbsAdbConnectionManager,
        remotePath: String,
        bytes: ByteArray,
        cacheDirectory: File?,
        fileName: String,
        onLine: (String) -> Unit = {},
    ): Int {
        val relay = cacheDirectory?.let { dir ->
            runCatching {
                dir.mkdirs()
                File(dir, fileName).takeIf {
                    it.writeBytes(bytes)
                    it.length() == bytes.size.toLong()
                }
            }.getOrNull()
        }
        if (relay != null) {
            onLine("$ cat ${relay.absolutePath} > $remotePath")
            try {
                // `cat` is an external command: an unreadable source still creates and truncates
                // the target, so the size is checked below rather than trusting the exit status.
                exec(manager, "cat '${relay.absolutePath}' > '$remotePath'", 120_000)
            } finally {
                runCatching { relay.delete() }
            }
        } else {
            onLine("$ push $remotePath (${bytes.size} bytes)")
            push(manager, remotePath, bytes)
        }
        val actual = runCatching {
            exec(manager, "wc -c < '$remotePath' 2>/dev/null", 30_000).trim().toIntOrNull()
        }.getOrNull() ?: -1
        if (actual != bytes.size) {
            throw IOException("$remotePath is $actual bytes, expected ${bytes.size}")
        }
        return actual
    }

    /**
     * Applies [mode] and reads it back, so a file that was staged but not made executable is a log
     * line rather than a permission error several steps later.
     *
     * @return the octal mode `stat` reports, or the `ls -l` listing on a build without `stat`
     */
    fun chmod(
        manager: AbsAdbConnectionManager,
        remotePath: String,
        mode: String,
    ): String? = runCatching {
        exec(
            manager,
            "chmod $mode '$remotePath' 2>&1; stat -c '%a' '$remotePath' 2>/dev/null || " +
                "ls -l '$remotePath' 2>&1",
            30_000,
        ).trim().lineSequence()
            .map { it.trim() }
            .firstOrNull { it.isNotEmpty() }
    }.getOrNull()

    /** Opens a shell service, falling back to a plain pipe when the daemon rejects the pty flag. */
    private fun openStream(
        manager: AbsAdbConnectionManager,
        command: String,
        pty: Boolean,
    ): AdbStream {
        if (pty) {
            runCatching { return manager.openStream("shell,pty:$command") }
        }
        return manager.openStream("shell:$command")
    }

    private const val EXIT_MARKER = "__OPENROOT_EXIT:"
}
