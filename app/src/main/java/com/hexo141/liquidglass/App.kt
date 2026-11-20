package com.hexo141.liquidglass

import android.app.Application
import android.content.Context
import rikka.shizuku.ShizukuProvider

/**
 * Turns off Shizuku's automatic Sui bootstrap.
 *
 * [ShizukuProvider] is created before any Activity, and its `enableSuiInitialization` flag defaults
 * to true: every cold start therefore runs `Sui.init()`, a probe for a different root backend that
 * this app never uses. When no Sui service answers, that probe sits on the main thread for seconds
 * and the first screen is drawn but cannot be touched.
 *
 * `attachBaseContext` runs before the provider is instantiated, so the flag is in place in time.
 */
class App : Application() {

    override fun attachBaseContext(base: Context) {
        runCatching { ShizukuProvider.disableAutomaticSuiInitialization() }
        super.attachBaseContext(base)
    }
}
