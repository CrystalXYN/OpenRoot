package com.hexo141.liquidglass.adb

import android.content.pm.PackageManager
import rikka.shizuku.Shizuku
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.lang.reflect.Method
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Shell channel backed by Shizuku (shell uid 2000), used when the user paired through the Shizuku
 * app instead of the in-app wireless debugging flow.
 *
 * Shizuku hands us exactly the same privileges adbd's shell does, so every command and payload
 * transfer in [AdbShell] can run through here without changing the callers.
 */
object ShizukuShell {

    /** Why the last [probeUid] failed, for the status line under the button. */
    @Volatile
    var lastError: String? = null
        private set

    /**
     * Set once [probeUid] really executed a command.
     *
     * Forked managers can keep reporting the permission flag as DENIED while the shell actually
     * works, so a successful probe is the stronger evidence and must win.
     */
    @Volatile
    private var probed = false

    /** True when the Shizuku service is alive and this app has been granted access. */
    fun isAuthorized(): Boolean {
        if (probed) return true
        return runCatching {
            Shizuku.pingBinder() &&
                Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)
    }

    /**
     * End-to-end check: really runs `id -u` through the shell channel.
     *
     * [isAuthorized] trusts the permission flag, but forks rename the permission namespace, and
     * then that flag stays DENIED even after the user turns the toggle on in the manager UI.
     * Executing a command is the only answer that holds for every manager, so the pairing button
     * polls this instead of waiting for a callback that a fork may never deliver.
     *
     * @return the uid the shell runs as, or null when the channel is not usable yet.
     */
    fun probeUid(timeoutMs: Long = 4000L): Int? {
        lastError = null
        return try {
            if (!Shizuku.pingBinder()) {
                lastError = "service not running"
                return null
            }
            val out = exec("id -u", timeoutMs).trim()
            val digits = out.lineSequence()
                .map { it.trim() }
                .firstOrNull { it.isNotEmpty() && it.all(Char::isDigit) }
            if (digits == null) {
                lastError = "unexpected reply: " + out.take(48)
                null
            } else {
                probed = true
                digits.toInt()
            }
        } catch (t: Throwable) {
            lastError = t.javaClass.simpleName + ": " + (t.message ?: "no message").take(80)
            null
        }
    }

    /** Runs [command] and returns everything it wrote to stdout. */
    @Throws(IOException::class)
    fun exec(command: String, timeoutMs: Long): String {
        val process = start(command)
        val out = ByteArrayOutputStream()
        val reader = Thread({
            runCatching {
                val buffer = ByteArray(4096)
                while (true) {
                    val read = process.inputStream.read(buffer)
                    if (read <= 0) break
                    synchronized(out) { out.write(buffer, 0, read) }
                }
            }
        }, "shizuku-exec").apply {
            isDaemon = true
            start()
        }
        // Do NOT use Process.waitFor(timeout, unit): ShizukuRemoteProcess signals "still running"
        // with IllegalArgumentException("process hasn't exited"), which the stock implementation
        // only catches as IllegalThreadStateException, so it escapes as an error. EOF on stdout is
        // the same signal and cannot lie.
        reader.join(timeoutMs)
        if (reader.isAlive) {
            runCatching { process.destroy() }
            throw IOException("shizuku shell timed out")
        }
        return synchronized(out) { out.toString("UTF-8") }
    }

    /**
     * Waits for [process] to exit and returns its status, or null on timeout.
     *
     * Polls [Process.exitValue] because the remote process wrapper throws
     * `IllegalArgumentException("process hasn't exited")` instead of the documented
     * `IllegalThreadStateException`, which also breaks the blocking `waitFor() overloads.
     */
    private fun awaitExit(process: Process, timeoutMs: Long): Int? {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (true) {
            try {
                return process.exitValue()
            } catch (_: Throwable) {
                // still running
            }
            if (System.currentTimeMillis() > deadline) return null
            try {
                Thread.sleep(25)
            } catch (_: InterruptedException) {
                return null
            }
        }
    }

    /**
     * Streams [command]'s output line by line and returns its exit status, mirroring
     * [AdbShell.stream] so long running payloads can be shown live.
     */
    @Throws(IOException::class)
    fun stream(command: String, onLine: (String) -> Unit, idleTimeoutMs: Long): Int {
        val process = start(command)
        val last = AtomicLong(System.currentTimeMillis())
        val finished = AtomicBoolean(false)
        val watchdog = Thread({
            while (!finished.get()) {
                if (System.currentTimeMillis() - last.get() > idleTimeoutMs) {
                    runCatching { process.destroy() }
                    return@Thread
                }
                try {
                    Thread.sleep(250)
                } catch (_: InterruptedException) {
                    return@Thread
                }
            }
        }, "shizuku-stream-watchdog").apply {
            isDaemon = true
            start()
        }
        try {
            process.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                while (true) {
                    val line = reader.readLine() ?: break
                    last.set(System.currentTimeMillis())
                    onLine(line)
                }
            }
            return awaitExit(process, 2_000L) ?: 0
        } finally {
            finished.set(true)
            watchdog.interrupt()
        }
    }

    /** Writes [bytes] to [remotePath] through the Shizuku shell. */
    @Throws(IOException::class)
    fun push(remotePath: String, bytes: ByteArray) {
        val process = start("cat > '$remotePath'")
        process.outputStream.use { stream ->
            stream.write(bytes)
            stream.flush()
        }
        if (awaitExit(process, 60_000L) == null) {
            runCatching { process.destroy() }
            throw IOException("shizuku push timed out")
        }
    }

    private fun start(command: String): Process {
        // Shizuku 13 keeps newProcess private in the client API; reflection is the only way to
        // reach the shell without binding a user service. R8 is disabled for release here, so the
        // name survives.
        val method = newProcessMethod ?: throw IOException("Shizuku newProcess is unavailable")
        return method.invoke(null, arrayOf("sh", "-c", command), null, null) as Process
    }

    private val newProcessMethod: Method? = runCatching {
        Shizuku::class.java
            .getDeclaredMethod(
                "newProcess",
                Array<String>::class.java,
                Array<String>::class.java,
                String::class.java,
            )
            .apply { isAccessible = true }
    }.getOrNull()
}
