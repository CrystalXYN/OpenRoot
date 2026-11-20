package com.hexo141.liquidglass.adb

import android.content.Context
import android.os.Build
import java.security.PrivateKey
import java.security.cert.Certificate
import java.util.concurrent.Executors

/**
 * ADB connection manager bound to the same RSA key that was handed to adbd while pairing.
 *
 * Because adbd already stores that public key, [connectTls] authenticates without any pairing
 * code: it discovers `_adb-tls-connect._tcp` over mDNS and performs the STLS handshake.
 */
class AdbConnectionManager private constructor(context: Context) : AbsAdbConnectionManager() {

    private val keyManager = AdbKeyManager(context)

    init {
        setApi(Build.VERSION.SDK_INT)
        // Make a rejected key surface as AdbAuthenticationFailedException instead of silently
        // retrying, so the caller knows the pairing has to be redone.
        setThrowOnUnauthorised(true)
    }

    override fun getPrivateKey(): PrivateKey = keyManager.privateKey

    override fun getCertificate(): Certificate = keyManager.certificate

    override fun getDeviceName(): String = AdbPairingService.DEVICE_NAME

    companion object {
        @Volatile
        private var instance: AdbConnectionManager? = null

        /**
         * Last connection state seen by a connect attempt or a background probe.
         *
         * [isConnected] takes the manager monitor, and `connect()` holds that monitor for the whole
         * handshake — up to the six second timeout. Calling it from the UI thread froze the first
         * screen for the length of the connect, so the UI reads this cache instead and
         * [requestConnectionCheck] keeps it honest from a worker thread.
         */
        @Volatile
        private var cachedConnected = false

        /** Single-flight guard: a probe may itself sit in the monitor for the whole connect. */
        @Volatile
        private var probing = false

        private val prober = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "adb-conn-probe").apply { isDaemon = true }
        }

        /** Returns the shared manager, creating it on first use. */
        fun get(context: Context): AdbConnectionManager =
            instance ?: synchronized(this) {
                instance ?: AdbConnectionManager(context.applicationContext).also { instance = it }
            }

        /**
         * Whether the shared manager currently holds a live connection (never creates one).
         *
         * Blocking: it waits for an in-flight handshake on the manager monitor. Worker threads only.
         */
        fun isConnected(): Boolean = instance?.isConnected() == true

        /** Non-blocking read for the UI thread. */
        fun cachedConnected(): Boolean = cachedConnected

        /** Records a state that is already known, e.g. right after [connectTls] returned. */
        fun cacheConnected(value: Boolean) {
            cachedConnected = value
        }

        /**
         * Verifies the cache on a worker thread and reports the real state.
         *
         * [onResult] runs on the probe thread, so callers post to the main thread themselves.
         * Concurrent requests collapse into one: while a probe is queued or blocked in the
         * monitor, further calls are dropped instead of piling up threads.
         */
        fun requestConnectionCheck(onResult: (Boolean) -> Unit) {
            if (probing) return
            probing = true
            prober.execute {
                val real = runCatching { isConnected() }.getOrDefault(false)
                cachedConnected = real
                probing = false
                runCatching { onResult(real) }
            }
        }
    }
}
