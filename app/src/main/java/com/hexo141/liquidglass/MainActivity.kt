package com.hexo141.liquidglass

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.hardware.display.DisplayManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.util.DisplayMetrics
import android.util.Log
import android.view.Display
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.core.content.ContextCompat
import com.hexo141.liquidglass.adb.AdbAuthenticationFailedException
import com.hexo141.liquidglass.adb.AdbConnectionManager
import com.hexo141.liquidglass.adb.AdbKeyManager
import com.hexo141.liquidglass.adb.AdbShell
import com.hexo141.liquidglass.adb.AdbPairingService
import com.hexo141.liquidglass.adb.PairingState
import com.hexo141.liquidglass.adb.ShizukuShell
import com.hexo141.liquidglass.bootimg.BootImageParser
import com.hexo141.liquidglass.bootimg.BootProfileBuilder
import com.hexo141.liquidglass.bootimg.BundledProfiles
import com.hexo141.liquidglass.bootimg.Cve98260Profile
import com.hexo141.liquidglass.bootimg.Glk1Codec
import com.hexo141.liquidglass.bootimg.HttpRangeSource
import com.hexo141.liquidglass.bootimg.OtaPayloadReader
import com.hexo141.liquidglass.bootimg.OffsetsDocument
import com.hexo141.liquidglass.bootimg.OffsetsError
import com.hexo141.liquidglass.bootimg.MultiImageParser
import com.hexo141.liquidglass.bootimg.OtaPayloadExtractor
import com.hexo141.liquidglass.bootimg.ProfileStore
import com.hexo141.liquidglass.consent.ConsentStore
import com.hexo141.liquidglass.device.DeviceInfo
import com.hexo141.liquidglass.root.BinderBombRunner
import com.hexo141.liquidglass.root.C98260Args
import com.hexo141.liquidglass.root.DirtyFragRunner
import com.hexo141.liquidglass.root.ExploitMemory
import com.hexo141.liquidglass.root.ExploitStop
import com.hexo141.liquidglass.root.GhostLock54Runner
import com.hexo141.liquidglass.root.GpuRunner
import com.hexo141.liquidglass.root.JokerRunner
import com.hexo141.liquidglass.root.KsuManager
import com.hexo141.liquidglass.root.LSPromise
import com.hexo141.liquidglass.root.MagiskManager
import com.hexo141.liquidglass.root.MtkEasySu
import com.hexo141.liquidglass.root.Cve98260Runner
import com.hexo141.liquidglass.root.PctRunner
import com.hexo141.liquidglass.root.RootExploit
import com.hexo141.liquidglass.root.RootHandoff
import com.hexo141.liquidglass.root.RootShell
import com.hexo141.liquidglass.root.SharkRunner
import com.hexo141.liquidglass.root.Zygote31317
import com.hexo141.liquidglass.ui.C98260ProfileChoice
import com.hexo141.liquidglass.ui.ConsentScreen
import com.hexo141.liquidglass.ui.ConsentTransition
import com.hexo141.liquidglass.ui.ExploitLogScreen
import com.hexo141.liquidglass.ui.AboutScreen
import com.hexo141.liquidglass.ui.AppScaffold
import com.hexo141.liquidglass.ui.BootParseState
import com.hexo141.liquidglass.ui.PairingScreen
import com.hexo141.liquidglass.ui.ParsedBootImage
import com.hexo141.liquidglass.ui.ProfileScreen
import com.hexo141.liquidglass.ui.ExploitChoice
import com.hexo141.liquidglass.ui.ProfileOption
import com.hexo141.liquidglass.ui.ProfilePicker
import com.hexo141.liquidglass.ui.SupportState
import rikka.shizuku.Shizuku
import kotlin.math.roundToInt

class MainActivity : AppCompatActivity() {

    private companion object {
        const val TAG = "MainActivity"

        /** Shizuku and its forks: Shevery ships its own package id and permission namespace. */
        const val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
        const val SHEVERY_PACKAGE = "com.hamondev.shevery"
        val SHIZUKU_PACKAGES = listOf(SHIZUKU_PACKAGE, SHEVERY_PACKAGE)
        const val SHIZUKU_REQUEST_CODE = 4213

        /**
         * Set once the automatic connect has asked for the grant.
         *
         * Without it a user who declined would be shown the manager's dialog on every foreground
         * entry. After the first ask the status line carries the hint and the button still works.
         */
        const val SHIZUKU_PROMPTED_KEY = "shizuku_auto_prompted"

        /** Shell probe cadence: 900 ms between ticks, 25 ticks ≈ 23 s before it gives up. */
        const val SHIZUKU_POLL_INTERVAL_MS = 900L
        const val SHIZUKU_PROBE_TIMEOUT_MS = 3_000L
        const val SHIZUKU_POLL_MAX_TICKS = 25

        /** Engine ids used by the picker; one per vulnerability, never per device or payload. */
        const val ENGINE_CVE_43499 = "cve-2026-43499"
        const val ENGINE_CVE_64560 = "cve-2026-64560"
        const val ENGINE_CVE_21479 = "cve-2025-21479"
        const val ENGINE_CVE_43284 = "cve-2026-43284"
        const val ENGINE_CVE_98260 = "cve-2026-98260"
        const val ENGINE_CVE_0041 = "cve-2020-0041"

        /** The one engine that is not a kernel exploit: mtk-su plus a Magisk in /sbin. */
        const val ENGINE_MEDIATEK = "mediatek-mtk-su"

        /**
         * Zygote argument injection, offered as a *prerequisite* rather than a root: it yields a
         * `system` process, and the row says so instead of pretending otherwise.
         */
        const val ENGINE_ZYGOTE_31317 = "cve-2024-31317"

        /**
         * LSPromise: 49881 into system_server followed by 43284. One row because neither half is a
         * root on its own, and one engine because the two are only useful in this order.
         */
        const val ENGINE_LSPROMISE = "lspromise-49881-43284"

        /**
         * Same payload as [ENGINE_CVE_98260], but it stops right after clearing SELinux. Not a row
         * of its own: it is the chip on the 98260 row, because it is the same bug with an early
         * exit, not a second vulnerability.
         */
        const val ENGINE_CVE_98260_SELINUX = "cve-2026-98260-selinux"

        /**
         * arm64 puts the image at `BIT(VA_BITS_MIN-3) + (seed & mask)`, so the slide is pinned to a
         * band instead of "anywhere below the VA top". For the default 39-bit VA that band is
         * `[64 GiB, 192 GiB)` step 2 MiB; 48-bit machines use `--va-bits 48` and a far wider band.
         * These bounds only drive the card's hint text - the payload re-checks them before writing.
         */
        const val KASLR_MIN_SLIDE = 0x1000000000L
        const val KASLR_MAX_SLIDE = 0x2FFFE00000L

        /** How long to wait for `_adb-tls-connect._tcp` before giving up on a direct connect. */
        const val CONNECT_TIMEOUT_MS = 6_000L

        /** Give adbd a moment to publish the connect service after the pairing handshake. */
        const val CONNECT_AFTER_PAIR_DELAY_MS = 700L

        /**
         * Reference width of the layout in dp. Bigger number = smaller UI (more dp per screen):
         * 411 is a Pixel/OnePlus phone, 460 draws everything about 11% smaller.
         */
        const val DESIGN_WIDTH_DP = 460f

        /** Density clamps, so neither a tiny nor a huge panel produces an unusable layout. */
        const val MIN_UI_SCALE = 1.0f
        const val MAX_UI_SCALE = 3.5f
    }

    /** First start: the GPL-3.0 text and the temporary-root disclaimer must both be accepted. */
    private val consentAccepted = mutableStateOf(false)

    /** Whether the pairing service runs; Compose state so the button label follows it. */
    private val pairingRunning = mutableStateOf(false)

    /** Already paired: adbd holds our public key, so no pairing code is needed. */
    private val paired = mutableStateOf(false)

    /** A direct connect is in flight. */
    private val connecting = mutableStateOf(false)

    /** adbd is connected. */
    private val connected = mutableStateOf(false)

    /** Direct connect failed: show the pairing button again so a code can be used. */
    private val needsPairing = mutableStateOf(false)

    /** Device info: local props first, replaced by the values read over ADB once connected. */
    private val deviceInfo = mutableStateOf<DeviceInfo?>(null)

    /** Support state, used directly by the status card. */
    private val supportState = mutableStateOf(SupportState.NotConnected)

    /** CVE id of the engine in use; null when nothing can run here. */
    private val engineLabel = mutableStateOf<String?>(null)

    /** A temporary-root payload is running. */
    private val exploiting = mutableStateOf(false)

    /** A force stop is in flight: the log page shows "stopping" and ignores further taps. */
    private val forceStopping = mutableStateOf(false)

    /**
     * Set by [forceStopExploit] and read when the worker finishes, so the stream's teardown
     * exception ("stream closed") does not overwrite the honest "stopped by the user" status.
     */
    @Volatile
    private var forceStopped = false

    /** Live payload output. */
    private val exploitLog = mutableStateOf<List<String>>(emptyList())

    /** Result line after the payload ends. */
    private val exploitStatus = mutableStateOf<String?>(null)

    /** Progress bar, driven by the payload's real stages, 0..1. */
    private val exploitProgress = mutableStateOf(0f)

    /** KASLR slide resolved from the KASLR card (auto calibration or a typed-in value). */
    private val kaslrSlide = mutableStateOf<Long?>(null)

    /** An auto resolution is running; the card locks both entries meanwhile. */
    private val kaslrBusy = mutableStateOf(false)

    /** One-line feedback under the KASLR card. */
    private val kaslrNote = mutableStateOf<String?>(null)

    /** True when [kaslrNote] reports a failure, so the card tints it red. */
    private val kaslrNoteError = mutableStateOf(false)

    /** Whether the vulnerability picker is shown. */
    private val pickerVisible = mutableStateOf(false)

    /** Whether the 98260 argument sheet is shown; the row's Run opens it instead of running. */
    private val c98260OptionsVisible = mutableStateOf(false)

    /** Last arguments chosen in that sheet, reused when it reopens. */
    private val c98260Args = mutableStateOf(C98260Args())

    /** Parsed 98260 snapshots offered at the top of that sheet, rebuilt when it opens. */
    private val c98260Profiles = mutableStateOf<List<C98260ProfileChoice>>(emptyList())

    /**
     * Snapshot picked in the sheet for the run in flight.
     *
     * Kept out of [C98260Args] because the arguments are also replayed after the sheet closes;
     * this is consumed once by [runC98260Engine] so a later `--selinux-only` run goes back to the
     * automatic match instead of silently reusing the override.
     */
    private var c98260ProfileOverride: Cve98260Profile? = null

    /** Whether the profile sheet (behind "Choose a built-in profile") is shown. */
    private val profilePickerVisible = mutableStateOf(false)

    /** Rows of the profile sheet, rebuilt every time it opens. */
    private val profileChoices = mutableStateOf<List<ProfileOption>>(emptyList())

    /** Active bottom-bar tab: 0 home, 1 profile, 2 log, 3 about. */
    private val selectedTab = mutableStateOf(0)

    /** Set once Shizuku grants shell access; payloads then run through ShizukuShell. */
    private val shizukuReady = mutableStateOf(false)

    /** One-line feedback shown under the Shizuku button. */
    private val shizukuStatus = mutableStateOf<String?>(null)

    /** Probe ticks spent waiting for shell access, so the poll gives up instead of looping. */
    private var shizukuWaitTicks = 0

    /** Guards against a second tap stacking another permission request on the worker thread. */
    private var shizukuRequesting = false

    /** True once the permission callback is registered, which now happens on first use. */
    private var shizukuListenerRegistered = false

    /**
     * Polls the shell channel while the user grants access.
     *
     * [Shizuku.OnRequestPermissionResultListener] only fires when the manager shows its own dialog
     * and answers us. Forked managers (Shevery, Dhizuku-based builds) and grants made in the
     * manager's app list never deliver that callback, which left the button stuck on "Waiting…"
     * forever. Running `id -u` is the only truth every manager agrees on.
     */
    private val shizukuPoll = object : Runnable {
        override fun run() {
            shizukuWaitTicks++
            Thread({
                val uid = ShizukuShell.probeUid(SHIZUKU_PROBE_TIMEOUT_MS)
                val error = ShizukuShell.lastError
                // Granted but still unable to start a process: waiting the whole poll window would
                // only delay the fallback. Two ticks separate that from "the user has not answered
                // the dialog yet", where the permission flag is still DENIED.
                val stuck = uid == null && ShizukuShell.isAuthorized()
                runOnUiThread {
                    when {
                        uid != null -> onShizukuGranted()
                        shizukuWaitTicks >= SHIZUKU_POLL_MAX_TICKS ||
                            (stuck && shizukuWaitTicks >= 2) -> {
                            shizukuStatus.value = getString(R.string.shizuku_no_access) +
                                (error?.let { " - $it" } ?: "") + getString(R.string.shizuku_tap_retry)
                            // The grant did not turn into a working channel, so stop waiting and
                            // let the pairing route take over instead of leaving the screen idle.
                            maybeAutoConnectAdb()
                        }
                        else -> {
                            shizukuStatus.value = getString(R.string.shizuku_waiting) +
                                (error?.let { " ($it)" } ?: "")
                            refreshHandler.postDelayed(this, SHIZUKU_POLL_INTERVAL_MS)
                        }
                    }
                }
            }, "shizuku-probe").start()
        }
    }

    private val shizukuPermissionListener =
        Shizuku.OnRequestPermissionResultListener { requestCode, grantResult ->
            if (requestCode != SHIZUKU_REQUEST_CODE) return@OnRequestPermissionResultListener
            if (grantResult == PackageManager.PERMISSION_GRANTED) {
                startShizukuPolling()
            } else {
                shizukuStatus.value = getString(R.string.shizuku_denied)
                // A refusal is final for the automatic route; hand the screen back to ADB so it
                // does not sit on a grant that will not arrive.
                maybeAutoConnectAdb()
            }
        }

    /** Vulnerabilities offered for the connected device. */
    private val exploitChoices = mutableStateOf<List<ExploitChoice>>(emptyList())

    /** Resolved root manager (with its ksud path); null when none is installed. */
    private val ksudTarget = mutableStateOf<KsuManager.Target?>(null)

    /** Root command channel available (bootstrap came up). */
    private val commandMode = mutableStateOf(false)

    /** Whether the MediaTek payload has a chance here; null until the probe has run. */
    private val mtkProbe = mutableStateOf<MtkEasySu.Probe?>(null)

    /** The zygote window, read once per connection. */
    private val zygoteProbe = mutableStateOf<Zygote31317.Probe?>(null)

    /** LSPromise's own preconditions (Android 17, vermagic, KernelSU); read once per connection. */
    private val lspromiseProbe = mutableStateOf<LSPromise.Probe?>(null)

    /**
     * Whether the injected payload actually took. Separate from [zygoteProbe] on purpose: being
     * inside the vulnerable window is not the same as the write having worked.
     */
    private val zygoteReady = mutableStateOf(false)

    /** Auto-connect at most once per foreground entry, so a failure does not loop. */
    private var autoConnectTried = false

    private val refreshHandler = Handler(Looper.getMainLooper())

    /** Refuse oversized images before reading them into memory; the parse holds the whole file. */
    private val MAX_BOOT_IMAGE_BYTES = 128L * 1024 * 1024

    /** While pairing runs in the background, align the state once a second. */
    private val refreshTick = object : Runnable {
        override fun run() {
            refreshState()
            if (pairingRunning.value) refreshHandler.postDelayed(this, 1000)
        }
    }

    /** After a successful pair, connect once without asking for another code. */
    private val pairingConnect = Runnable {
        if (paired.value && !connected.value && !connecting.value) {
            connect(silent = false)
        }
    }

    private val requestNotificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) startPairing() else toast(R.string.adb_pairing_permission_needed)
        }

    /** One parse feeds two profiles: the GLK1 blob and the CVE-2026-98260 snapshot. */
    private data class ParseOutcome(
        val build: BootProfileBuilder.ProfileBuild,
        val encoded: ByteArray,
        val source: String,
        val c98260: Cve98260Profile?,
        val imageSha256: String?,
    )

    /** Profile tab: last parse, the profiles parsed on this device, and which one is active. */
    private val bootParseState = mutableStateOf<BootParseState>(BootParseState.Idle)
    private var parsedProfileBytes: ByteArray? = null

    /** CVE-2026-98260 snapshot from the same parse; saved next to the GLK1 profile. */
    private var parsedC98260: Cve98260Profile? = null

    /** Kept so an export can state where every field came from; cleared when the parse is dropped. */
    private var parsedBuild: BootProfileBuilder.ProfileBuild? = null
    private var parsedImageSha256: String? = null
    private var pendingExport: OffsetsDocument? = null
    private val parsedProfiles = mutableStateOf<List<ProfileStore.Entry>>(emptyList())
    private val selectedRelease = mutableStateOf<String?>(null)

    /** System file picker for a single boot.img; the parse itself runs on a worker thread. */
    private val pickBootImage =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) parseBootImages(listOf(uri))
        }

    /** SAF save dialog for a self-contained offsets JSON. */
    private val exportOffsetsDoc =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
            val doc = pendingExport ?: return@registerForActivityResult
            pendingExport = null
            if (uri == null) return@registerForActivityResult
            try {
                contentResolver.openOutputStream(uri)?.use { it.write(doc.toBytes()) }
                    ?: error("cannot open the output stream")
                logLine("[+] offsets exported: ${doc.release} (${doc.provenance.origin})")
                toastText(getString(R.string.offsets_exported))
            } catch (e: Exception) {
                logLine("[!] export failed: ${e.message}")
                toastText(getString(R.string.export_failed, e.message.orEmpty()))
            }
        }

    /** SAF open dialog for an offsets JSON produced by this app or the desktop CLI. */
    private val importOffsetsDoc =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) importOffsets(uri)
        }

    /** First half of an MTK pair, kept while the second picker is open. */
    private var pendingMtkBoot: Uri? = null

    /**
     * MTK layout, step 1: `boot.img`.
     *
     * Two pickers instead of one multi-select dialog: the system picker does not offer multi-select
     * on every OEM build, and when it does not, the user ends up with a single image and no hint
     * that the second one was skipped.
     */
    private val pickMtkBootImage =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri == null) return@registerForActivityResult
            pendingMtkBoot = uri
            pickMtkVendorBoot.launch(arrayOf("*/*"))
        }

    /** MTK layout, step 2: `vendor_boot.img`; cancelling here parses the `boot.img` alone. */
    private val pickMtkVendorBoot =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { vendor ->
            val boot = pendingMtkBoot ?: return@registerForActivityResult
            pendingMtkBoot = null
            if (vendor == null) {
                parseBootImages(listOf(boot), note = "vendor_boot.img not selected")
            } else {
                parseBootImages(listOf(boot, vendor))
            }
        }

    /** Pairing succeeded: refresh the screen and connect without a code. */
    private val pairingStateListener =
        SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == PairingState.KEY_PAIRED || key == PairingState.KEY_PAIRED_AT) {
                runOnUiThread {
                    refreshState(pairingSucceeded = key == PairingState.KEY_PAIRED_AT)
                }
            }
        }

    /**
     * Makes the layout measure the same on every device, ignoring "Display size" and "Font size".
     *
     * The density is derived from the shortest screen side so the layout always spans
     * [DESIGN_WIDTH_DP] dp: devices ship wildly different factory densities, and using the raw
     * physical one made the cards look bloated on some of them and correct on others. Raising the
     * design width is the single knob for the overall scale — a bigger number means more dp fit on
     * the screen, i.e. smaller text, cards and paddings. It is clamped so a tiny or a huge panel
     * does not end up unusable, and `fontScale` is pinned to 1.0 for the same reason.
     *
     * The activity has no `configChanges`, so a system change recreates it and lands here again.
     */
    override fun attachBaseContext(newBase: Context) {
        val config = Configuration(newBase.resources.configuration)
        config.fontScale = 1f

        val density = panelDensityOf(newBase)
        if (density > 0f) {
            config.densityDpi = (density * DisplayMetrics.DENSITY_DEFAULT).roundToInt()
        }

        super.attachBaseContext(newBase.createConfigurationContext(config))
    }

    /**
     * Density of the physical panel, expressed as "the layout always spans [DESIGN_WIDTH_DP]".
     *
     * Read from the display itself, never from `resources.displayMetrics`. In a freeform window
     * those describe the *window*, and the system renders a small window by scaling it - density
     * goes up, the window is shrunk to fit - so a value taken from them changes with the window
     * and, worse, could still be in effect after the window was dragged back to full screen: the
     * activity is not recreated for a configuration that ends up identical to the original, so the
     * inflated density stuck and every card came back oversized. The panel size cannot drift, so
     * the layout measures the same in a phone screen, a split screen and a floating window.
     *
     * @return 0f when the display cannot be queried, so callers keep the system value
     */
    private fun panelDensityOf(context: Context): Float {
        var shortest = 0
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching {
                val bounds = context.getSystemService(WindowManager::class.java)
                    .maximumWindowMetrics.bounds
                shortest = minOf(bounds.width(), bounds.height())
            }
        }
        if (shortest <= 0) {
            val metrics = DisplayMetrics()
            runCatching {
                val display = (context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager)
                    .getDisplay(Display.DEFAULT_DISPLAY)
                @Suppress("DEPRECATION")
                display?.getRealMetrics(metrics)
            }
            shortest = minOf(metrics.widthPixels, metrics.heightPixels)
        }
        if (shortest <= 0) return 0f
        return (shortest / DESIGN_WIDTH_DP).coerceIn(MIN_UI_SCALE, MAX_UI_SCALE)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        // The grant callback is registered up front now that every launch checks Shizuku on its
        // own: a permission result that arrives before the first tap would otherwise be dropped.
        // The wallpaper runs edge to edge; each screen pads its own content against
        // WindowInsets.safeDrawing, so nothing sits under the status or navigation bar.

        consentAccepted.value = ConsentStore.isAccepted(this)
        ensureShizukuListener()

        // Back closes the log page or the picker first, and only then leaves the app.
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                when {
                    selectedTab.value != 0 -> selectedTab.value = 0
                    // Cancelling the 98260 arguments goes back to the list it was opened from,
                    // not all the way to the home screen.
                    c98260OptionsVisible.value -> {
                        c98260OptionsVisible.value = false
                        pickerVisible.value = true
                    }
                    pickerVisible.value -> pickerVisible.value = false
                    else -> {
                        isEnabled = false
                        onBackPressedDispatcher.onBackPressed()
                    }
                }
            }
        })

        // Pin Compose to the panel density too. `attachBaseContext` already overrides it, but a
        // freeform window can hand the view a further per-window density, and that one is put back
        // to the panel value only after the window settles - leaving the tree measured at the
        // small-window scale. Providing it here makes it independent of window events.
        val panel = panelDensityOf(this)

        findViewById<ComposeView>(R.id.main).setContent {
            val system = LocalDensity.current
            CompositionLocalProvider(
                LocalDensity provides if (panel > 0f) Density(panel, 1f) else system
            ) {
                // Fade into the main screen once both documents are accepted; before that it is not
                // composed at all and no ADB work happens.
                ConsentTransition(
                    accepted = consentAccepted.value,
                    consent = { ConsentScreen(onAccept = ::acceptConsent) },
                    main = {
                        AppScaffold(
                            selectedTab = selectedTab.value,
                            onTabSelected = { selectedTab.value = it },
                            home = { backdrop ->
                                PairingScreen(
                                    running = pairingRunning.value,
                                    paired = paired.value,
                                    connecting = connecting.value,
                                    connected = connected.value || shizukuReady.value,
                                    shizukuReady = shizukuReady.value,
                                    shizukuStatus = shizukuStatus.value,
                                    onShizukuPair = ::requestShizukuPairing,
                                    needsPairing = needsPairing.value,
                                    supportState = supportState.value,
                                    engineLabel = engineLabel.value,
                                    deviceInfo = deviceInfo.value,
                                    exploiting = exploiting.value,
                                    exploitLog = exploitLog.value,
                                    exploitStatus = exploitStatus.value,
                                    exploitChoices = exploitChoices.value,
                                    pickerVisible = pickerVisible.value,
                                    backdrop = backdrop,
                                    onToggle = ::onPrimaryAction,
                                    onExploit = ::openEnginePicker,
                                    onPickEngine = ::startExploit,
                                    onDismissPicker = { pickerVisible.value = false },
                                    onOpenLog = { selectedTab.value = 2 },
                                    kaslrSlide = kaslrSlide.value,
                                    kaslrBusy = kaslrBusy.value,
                                    kaslrNote = kaslrNote.value,
                                    kaslrNoteError = kaslrNoteError.value,
                                    onKaslrAuto = ::resolveKaslrAuto,
                                    onKaslrManual = ::applyKaslrManual,
                                    c98260OptionsVisible = c98260OptionsVisible.value,
                                    c98260Args = c98260Args.value,
                                    c98260Profiles = c98260Profiles.value,
                                    onC98260Run = ::startC98260,
                                    onDismissC98260Options = {
                                        c98260OptionsVisible.value = false
                                        pickerVisible.value = true
                                    },
                                )
                            },
                            profile = { backdrop ->
                                ProfileScreen(
                                    backdrop = backdrop,
                                    info = deviceInfo.value,
                                    selectedRelease = selectedRelease.value,
                                    parsed = parsedProfiles.value,
                                    parseState = bootParseState.value,
                                    onPickImage = { pickBootImage.launch(arrayOf("*/*")) },
                                    onPickMtkImage = { pickMtkBootImage.launch(arrayOf("*/*")) },
                                    onParseUrl = ::parseBootUrl,
                                    onSaveParsed = ::saveParsedProfile,
                                    onExportOffsets = ::exportOffsets,
                                    onImportOffsets = { importOffsetsDoc.launch(arrayOf("application/json", "*/*")) },
                                    onDiscardParsed = {
                                        bootParseState.value = BootParseState.Idle
                                        parsedProfileBytes = null
                                        parsedC98260 = null
                                        parsedBuild = null
                                        parsedImageSha256 = null
                                    },
                                    onSetProfile = ::useProfile,
                                    onPickBundled = ::openProfilePicker,
                                    onDeleteProfile = ::deleteProfile,
                                )
                            },
                            log = { backdrop ->
                                ExploitLogScreen(
                                    lines = exploitLog.value,
                                    status = exploitStatus.value,
                                    progress = exploitProgress.value,
                                    commandMode = commandMode.value,
                                    running = exploiting.value,
                                    onCommand = ::runRootCommand,
                                    onForceStop = ::forceStopExploit,
                                    stopping = forceStopping.value,
                                    backdrop = backdrop,
                                )
                            },
                            about = { backdrop ->
                                AboutScreen(backdrop = backdrop)
                            },
                            // Drawn above the tab bar, so the sheet and its scrim own the whole window.
                            overlay = { backdrop ->
                                ProfilePicker(
                                    visible = profilePickerVisible.value,
                                    backdrop = backdrop,
                                    options = profileChoices.value,
                                    onPick = ::chooseProfile,
                                    onDismiss = { profilePickerVisible.value = false },
                                )
                            },
                        )
                    },
                )
            }
        }

        if (consentAccepted.value) startMain()
    }

    /** Both documents accepted: store the version and time, then start what the screen needs. */
    private fun acceptConsent() {
        ConsentStore.accept(this)
        consentAccepted.value = true
        startMain()
        beginLiveUpdates()
    }

    private fun startMain() {
        // Fill local device info first so the cards are never empty; ADB values replace it.
        deviceInfo.value = DeviceInfo.fromLocal(this)
        refreshState()
        refreshParsedProfiles()
        intent?.let { handleDebugPair(it) }
    }

    /** State sync while the main screen lives: one tick a second, instant pairing updates, one auto-connect. */
    private fun beginLiveUpdates() {
        // Reset before refreshState(): a pairing success detected there schedules the delayed
        // direct connect and marks the auto-connect as handled, so it is not attempted twice.
        autoConnectTried = false
        refreshState()
        getSharedPreferences(PairingState.PREF_NAME, MODE_PRIVATE)
            .registerOnSharedPreferenceChangeListener(pairingStateListener)
        maybeAutoConnect()
        refreshHandler.removeCallbacks(refreshTick)
        refreshHandler.postDelayed(refreshTick, 1000)
    }

    override fun onResume() {
        super.onResume()
        // No main screen and no auto-connect before the documents are accepted.
        if (!consentAccepted.value) return
        beginLiveUpdates()
        refreshParsedProfiles()
        // The Shizuku check now lives in maybeAutoConnect(), which beginLiveUpdates() runs on
        // every foreground entry. That covers the case this block used to handle by hand: a grant
        // switched on in Shevery's own app list, where no permission callback is ever delivered.
    }

    override fun onPause() {
        refreshHandler.removeCallbacks(refreshTick)
        getSharedPreferences(PairingState.PREF_NAME, MODE_PRIVATE)
            .unregisterOnSharedPreferenceChangeListener(pairingStateListener)
        super.onPause()
    }

    override fun onDestroy() {
        if (shizukuListenerRegistered) {
            runCatching { Shizuku.removeRequestPermissionResultListener(shizukuPermissionListener) }
        }
        refreshHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun refreshState(
        updatePairing: Boolean = true,
        pairingSucceeded: Boolean = false,
    ) {
        if (updatePairing) pairingRunning.value = AdbPairingService.isRunning()
        val wasPaired = paired.value
        val isPaired = PairingState(this).isPaired
        paired.value = isPaired
        // Never ask the manager here: isConnected() waits on the monitor that the connect thread
        // holds for the whole handshake, and this runs on the UI thread. Use the cache and verify
        // it from a worker; a different answer is applied as soon as it arrives.
        applyConnection(AdbConnectionManager.cachedConnected())
        AdbConnectionManager.requestConnectionCheck { real ->
            runOnUiThread { if (real != connected.value) applyConnection(real) }
        }
        // A re-pair keeps the boolean true, so the timestamp event is the reliable success edge.
        if (isPaired && (pairingSucceeded || !wasPaired)) {
            // The service stops itself after a successful pair; the button must read "Start" if a
            // later direct connect fails and brings it back.
            pairingRunning.value = false
            needsPairing.value = false
            refreshHandler.removeCallbacks(pairingConnect)
            refreshHandler.postDelayed(pairingConnect, CONNECT_AFTER_PAIR_DELAY_MS)
            autoConnectTried = true
        }
        loadDeviceInfo()
    }

    /** Applies a connection state to the UI. Main thread only. */
    private fun applyConnection(isConnected: Boolean) {
        val changed = connected.value != isConnected
        connected.value = isConnected
        if (!isConnected) {
            supportState.value = SupportState.NotConnected
            engineLabel.value = null
            // Drop the picker when the connection is gone; the button is hidden as well.
            pickerVisible.value = false
        } else if (changed) {
            // Reconnected: the cards need the values that are only reachable now.
            supportState.value = SupportState.Checking
            loadDeviceInfo()
        }
    }

    // ------------------------------------------------------------------ actions

    /**
     * Runs on every foreground entry: Shizuku first, ADB only when it cannot serve.
     *
     * A grant that is already in place therefore connects with no tap at all. The old body of this
     * method lives on as [maybeAutoConnectAdb] and keeps its exact behaviour, so a device without
     * Shizuku sees the same silent connect as before.
     */
    private fun maybeAutoConnect() {
        if (autoConnectTried) return
        if (pairingRunning.value || connected.value || shizukuReady.value || connecting.value) return
        autoConnectTried = true
        autoConnectShizuku()
    }

    /**
     * Checks the whole Shizuku chain and connects when it works.
     *
     * The order is deliberate: service alive, version, grant, then a real `id -u` through the
     * channel (the poll). A manager that reports the grant but refuses to start a process is
     * caught by the last step, and only then does the ADB route get a turn. Nothing here prompts
     * on a device where Shizuku is not installed.
     */
    private fun autoConnectShizuku() {
        if (shizukuReady.value) return
        if (shizukuManagerPackage() == null) {
            // Not installed: there is no status worth showing and no reason to wait.
            maybeAutoConnectAdb()
            return
        }
        Thread({
            val running = runCatching { Shizuku.pingBinder() }.getOrDefault(false)
            if (!running) {
                runOnUiThread {
                    shizukuStatus.value = getString(R.string.shizuku_not_running_using_adb)
                    maybeAutoConnectAdb()
                }
                return@Thread
            }
            if (runCatching { Shizuku.isPreV11() }.getOrDefault(false)) {
                runOnUiThread {
                    shizukuStatus.value = getString(R.string.shizuku_needs_v11)
                    maybeAutoConnectAdb()
                }
                return@Thread
            }
            if (ShizukuShell.isAuthorized()) {
                // Authorized is not the same as usable: the poll runs `id -u` and only a real
                // answer marks the channel ready.
                runOnUiThread { startShizukuPolling(auto = true) }
                return@Thread
            }
            val denied = runCatching {
                Shizuku.shouldShowRequestPermissionRationale()
            }.getOrDefault(false)
            val prefs = getSharedPreferences(PairingState.PREF_NAME, MODE_PRIVATE)
            val prompted = prefs.getBoolean(SHIZUKU_PROMPTED_KEY, false)
            if (!denied && !prompted) {
                // Ask once, automatically. The flag is stored before the request so a manager
                // that never answers cannot turn every launch into another dialog.
                prefs.edit().putBoolean(SHIZUKU_PROMPTED_KEY, true).apply()
                ensureShizukuListener()
                runCatching { Shizuku.requestPermission(SHIZUKU_REQUEST_CODE) }
                    .onFailure { Log.w(TAG, "automatic Shizuku permission request failed", it) }
                runOnUiThread { startShizukuPolling(auto = true) }
            } else {
                runOnUiThread {
                    shizukuStatus.value = if (denied) {
                        getString(R.string.shizuku_access_denied)
                    } else {
                        getString(R.string.shizuku_access_not_granted)
                    }
                    maybeAutoConnectAdb()
                }
            }
        }, "shizuku-auto").start()
    }

    /**
     * The ADB half: connect directly when the device is already paired, so no code is asked for
     * again; only a failure brings the pairing button back.
     *
     * A device paired before the isPaired flag existed still has our ADB key stored, so that case
     * tries one silent direct connect and fills the flag in when it works.
     */
    private fun maybeAutoConnectAdb() {
        if (pairingRunning.value || connected.value || shizukuReady.value || connecting.value) return
        val isPaired = paired.value
        if (!isPaired && !AdbKeyManager.hasStoredKey(this)) return
        connect(silent = !isPaired)
    }

    /**
     * "Shizuku pairing": reuse a running Shizuku service instead of pairing over wireless
     * debugging again. Shizuku hands the app the same shell uid adbd does, so the same payloads
     * run through [com.hexo141.liquidglass.adb.ShizukuShell] without a second pair.
     */
    private fun requestShizukuPairing() {
        if (shizukuRequesting) return
        shizukuRequesting = true
        ensureShizukuListener()
        shizukuStatus.value = getString(R.string.shizuku_checking)
        // Every Shizuku call below is a synchronous binder round trip, and requestPermission even
        // waits for the manager to bring its approval screen up. On the main thread that froze the
        // UI for a few seconds, so the whole conversation runs on a worker and only the result is
        // published back.
        Thread({
            val running = runCatching { Shizuku.pingBinder() }.getOrDefault(false)
            if (!running) {
                val manager = shizukuManagerPackage()
                runOnUiThread {
                    shizukuRequesting = false
                    if (manager == null) {
                        shizukuStatus.value = getString(R.string.shizuku_not_installed)
                    } else {
                        shizukuStatus.value = if (manager == SHEVERY_PACKAGE) {
                            getString(R.string.shizuku_start_shevery)
                        } else {
                            getString(R.string.shizuku_start_service)
                        }
                        openShizuku(manager)
                    }
                }
                return@Thread
            }
            if (runCatching { Shizuku.isPreV11() }.getOrDefault(false)) {
                runOnUiThread {
                    shizukuRequesting = false
                    shizukuStatus.value = getString(R.string.shizuku_needs_v11)
                }
                return@Thread
            }
            // A working shell or a grant flag both mean there is nothing to ask for; the probe
            // decides either way, it is the only signal forks agree on.
            val granted = shizukuReady.value ||
                runCatching { Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED }
                    .getOrDefault(false)
            var requestError: String? = null
            if (!granted) {
                runCatching { Shizuku.requestPermission(SHIZUKU_REQUEST_CODE) }
                    .onFailure { requestError = it.message ?: it.javaClass.simpleName }
            }
            runOnUiThread {
                shizukuRequesting = false
                startShizukuPolling()
                if (requestError != null) {
                    shizukuStatus.value =
                        getString(R.string.shizuku_request_failed, requestError.orEmpty())
                }
            }
        }, "shizuku-request").start()
    }

    /** Registers the permission callback on first use instead of during startup. */
    @Synchronized
    private fun ensureShizukuListener() {
        if (shizukuListenerRegistered) return
        shizukuListenerRegistered = true
        runCatching { Shizuku.addRequestPermissionResultListener(shizukuPermissionListener) }
    }

    /** Starts (or restarts) the shell probe; every tick checks the real channel. */
    private fun startShizukuPolling(auto: Boolean = false) {
        refreshHandler.removeCallbacks(shizukuPoll)
        shizukuWaitTicks = 0
        shizukuStatus.value = if (auto) getString(R.string.shizuku_checking)
        else getString(R.string.shizuku_waiting)
        refreshHandler.post(shizukuPoll)
    }

    private fun shizukuManagerPackage(): String? = SHIZUKU_PACKAGES.firstOrNull {
        runCatching { packageManager.getPackageInfo(it, 0) }.isSuccess
    }

    private fun onShizukuGranted() {
        refreshHandler.removeCallbacks(shizukuPoll)
        shizukuReady.value = true
        // The status card already reports "Connected via Shizuku"; a second line with the raw
        // shell uid read like debug noise, so a successful grant simply clears any pending note.
        shizukuStatus.value = null
        loadDeviceInfo()
    }

    private fun openShizuku(pkg: String = shizukuManagerPackage() ?: SHIZUKU_PACKAGE) {
        val intent = packageManager.getLaunchIntentForPackage(pkg)
        if (intent == null) {
            shizukuStatus.value = getString(R.string.shizuku_cannot_open)
            return
        }
        runCatching { startActivity(intent) }
    }

    private fun connect(silent: Boolean = false) {
        if (connecting.value) return
        connecting.value = true
        needsPairing.value = false
        Thread({
            val outcome = runCatching {
                AdbConnectionManager.get(this).connectTls(this, CONNECT_TIMEOUT_MS)
            }
            val ok = outcome.getOrNull() == true
            // Publish the result to the cache first: refreshState() reads it instead of touching
            // the manager monitor, which this very thread held until the handshake returned. A
            // false answer may also mean "was already connected", so let a probe settle that case.
            if (ok) AdbConnectionManager.cacheConnected(true) else AdbConnectionManager.requestConnectionCheck { }
            runOnUiThread {
                connecting.value = false
                if (ok) {
                    connected.value = true
                    supportState.value = SupportState.Checking
                    paired.value = true
                    PairingState(this).isPaired = true
                    Log.i(TAG, "connected without pairing code")
                    loadDeviceInfo()
                } else {
                    val error = outcome.exceptionOrNull()
                    Log.w(TAG, "direct connect failed (silent=$silent)", error)
                    if (silent) return@runOnUiThread
                    // adbd rejected our key: the pairing is really gone
                    if (error is AdbAuthenticationFailedException) {
                        PairingState(this).isPaired = false
                        paired.value = false
                    }
                    needsPairing.value = true
                    toast(R.string.adb_connect_failed_fallback)
                }
            }
        }, "adb-direct-connect").start()
    }

    /**
     * What can actually run on this device right now. Single source of truth for card + picker.
     *
     * The picker lists vulnerabilities (CVE ids), not devices or payload variants: the payload for
     * a given CVE is resolved from the device here, so one row covers every build of that bug.
     */
    private data class Availability(
        val profile: Boolean,
        val pageCache: String?,
        val gpuMatched: Boolean,
        val gpuPayload: GpuRunner.Payload?,
        val pctMatched: Boolean,
        val pctPayload: PctRunner.Payload?,
        /** Kernel is >= 5.7, which is when the exec() timer-free bug appeared. */
        val c98260KernelOk: Boolean,
        /** Payload packaged and a profile exists (parsed or built in). */
        val c98260: Boolean,
        /** A binder profile carries the offsets this exact `uname -r` needs, or null. */
        val binderBomb: String?,
        /**
         * CVE-2026-43499, second payload: GhostLock54's offsets are compiled in and it only runs on
         * the one kernel it was built for, so it cannot be expressed as a profile.
         */
        val ghost54: Boolean,
        /** CVE-2026-64560, JokerLock's oplus GKI build; its own `--preflight` is the real gate. */
        val joker: Boolean,
        /** CVE-2026-98260 as shipped by Shark, 6.18 family. */
        val shark98260: Boolean,
        /** CVE-2026-64560 as shipped by Shark, 6.18 family. */
        val shark64560: Boolean,
    )

    private fun availability(info: DeviceInfo?): Availability {
        // No `connected.value` read here: this runs off the main thread too, where snapshot reads
        // can be stale. A non-null DeviceInfo already means the device answered.
        if (info == null) {
            return Availability(
                profile = false,
                pageCache = null,
                gpuMatched = false,
                gpuPayload = null,
                pctMatched = false,
                pctPayload = null,
                c98260KernelOk = false,
                c98260 = false,
                binderBomb = null,
                ghost54 = false,
                joker = false,
                shark98260 = false,
                shark64560 = false,
            )
        }
        val profile = RootExploit.isPayloadPresent(this) && RootExploit.hasProfile(this, info.kernel)
        val pageCache = if (DirtyFragRunner.isPayloadPresent(this)) {
            DirtyFragRunner.describe(info.androidRelease, info.kernel)
        } else {
            null
        }
        // A Qualcomm GPU is necessary but not sufficient: whether the firmware is patched is only
        // known after a run, so the card reports Untested until ExploitMemory has an answer.
        val gpuMatched = GpuRunner.isSupported(info)
        val gpuPayload = GpuRunner.payloadFor(info)
            ?.takeIf { GpuRunner.isPayloadPresent(this, it) }
        // Same rule for CVE-2026-64560: the device family only says the port is worth trying, the
        // payload's own `--preflight` decides whether this build is the ported one.
        val pctMatched = PctRunner.isSupported(info)
        val pctPayload = PctRunner.payloadFor(info)
            ?.takeIf { PctRunner.isPayloadPresent(this, it) }
        val c98260KernelOk = Cve98260Runner.kernelSupports(info.kernel)
        val c98260 = c98260KernelOk &&
            Cve98260Runner.isPayloadPresent(this) &&
            Cve98260Runner.hasProfile(this, info.kernel)
        // CVE-2020-0041 is profile-driven too: one binary covers plain 5.4 and 5.4-qgki, and the
        // profile either carries the offsets this `uname -r` needs or it does not.
        val binderBomb = if (BinderBombRunner.isPayloadPresent(this)) {
            BinderBombRunner.describe(this, info.kernel)
        } else {
            null
        }
        // The other payloads that share a CVE with a row above. They are resolved here rather than
        // listed as rows: the picker names vulnerabilities, and which build of one runs is a
        // property of the device, not something the user should have to choose.
        val ghost54 = info.kernel == GhostLock54Runner.KERNEL &&
            GhostLock54Runner.isPayloadPresent(this)
        val joker = JokerRunner.isSupported(info.kernel) && JokerRunner.isPayloadPresent(this)
        val shark98260 = SharkRunner.Engine.CVE_98260.let {
            it.matches(info.kernel) && SharkRunner.isPayloadPresent(this, it)
        }
        val shark64560 = SharkRunner.Engine.CVE_64560.let {
            it.matches(info.kernel) && SharkRunner.isPayloadPresent(this, it)
        }
        return Availability(
            profile = profile,
            pageCache = pageCache,
            gpuMatched = gpuMatched,
            gpuPayload = gpuPayload,
            pctMatched = pctMatched,
            pctPayload = pctPayload,
            c98260KernelOk = c98260KernelOk,
            c98260 = c98260,
            binderBomb = binderBomb,
            ghost54 = ghost54,
            joker = joker,
            shark98260 = shark98260,
            shark64560 = shark64560,
        )
    }

    private fun resolveEngine(info: DeviceInfo): Pair<String?, SupportState> {
        val available = availability(info)
        // GhostLock54 covers the one kernel a profile cannot describe, so either arm makes the
        // 43499 row the one to show on the card.
        if (available.profile || available.ghost54) {
            return getString(R.string.engine_kernel_profile) to SupportState.Supported
        }
        // Same class of bug as 43499 (a kernel UAF turned into a cred write), so it sits next to it.
        if (available.c98260) {
            val state = when (ExploitMemory.result(this, info.kernel, ExploitMemory.ENGINE_C98260)) {
                true -> SupportState.Supported
                false -> SupportState.Unsupported
                null -> SupportState.Candidate
            }
            return "CVE-2026-98260" to state
        }
        // An exact binder profile for this `uname -r` is a fact, not a guess, so it outranks the
        // "worth trying" engines below; whether it takes is still only known after a run.
        available.binderBomb?.let { label ->
            val state = when (ExploitMemory.result(this, info.kernel, ExploitMemory.ENGINE_BINDER)) {
                true -> SupportState.Supported
                false -> SupportState.Unsupported
                null -> SupportState.Candidate
            }
            return label to state
        }
        // A matched device build is more specific than "this SoC has a GPU", so it comes first.
        if (available.pctPayload != null) {
            val state = when (ExploitMemory.result(this, info.kernel, ExploitMemory.ENGINE_PCT)) {
                true -> SupportState.Supported
                false -> SupportState.Unsupported
                null -> SupportState.Candidate
            }
            return PctRunner.describe(info) to state
        }
        if (available.gpuPayload != null) {
            val state = when (ExploitMemory.result(this, info.kernel, ExploitMemory.ENGINE_GPU)) {
                true -> SupportState.Supported
                false -> SupportState.Unsupported
                null -> SupportState.Candidate
            }
            return GpuRunner.describe(info) to state
        }
        val label = available.pageCache ?: return null to SupportState.Unsupported
        // Without a profile this is only "worth trying": a run is the only way to know.
        val state = when (ExploitMemory.result(this, info.kernel)) {
            true -> SupportState.Supported
            false -> SupportState.Unsupported
            null -> SupportState.Candidate
        }
        return label to state
    }

    /**
     * True when shell commands can run: adbd is connected, or Shizuku granted a shell uid.
     *
     * Every gate that used to check [connected] alone locked Shizuku users out, because that flag
     * only tracks the wireless debugging session.
     */
    private val hasShellChannel: Boolean
        get() = connected.value || shizukuReady.value

    /** Pulls the device details over ADB, replacing the locally read placeholder. */
    private fun loadDeviceInfo() {
        if (!connected.value && !shizukuReady.value) return
        Thread({
            val info = runCatching { DeviceInfo.fromAdb(AdbConnectionManager.get(this)) }
                .onFailure { Log.w(TAG, "cannot read device info over adb", it) }
                .getOrNull()
            if (info != null) {
                Log.i(TAG, "device info from adb: $info")
                // Decide on the main thread: snapshot reads on another thread can be stale.
                runOnUiThread {
                    val (engine, state) = resolveEngine(info)
                    Log.i(TAG, "availability: profile=${availability(info).profile} " +
                        "pageCache=${availability(info).pageCache}")
                    deviceInfo.value = info
                    engineLabel.value = engine
                    supportState.value = state
                }
                val ksud = KsuManager.resolve(this, AdbConnectionManager.get(this)) { line ->
                    Log.i(TAG, line)
                }
                runOnUiThread { ksudTarget.value = ksud }
                // Guarded on its own: this is a getprop plus a file check, and a throw here must not
                // stop the rest of the worker on a device that is plainly connected.
                val mtk = runCatching {
                    MtkEasySu.probe(AdbConnectionManager.get(this)) { line ->
                        Log.i(TAG, "mtk probe: $line")
                    }
                }.onFailure { Log.w(TAG, "mtk probe failed", it) }.getOrNull()
                if (mtk != null) runOnUiThread { mtkProbe.value = mtk }
                val zygote = runCatching {
                    Zygote31317.probe(AdbConnectionManager.get(this)) { line ->
                        Log.i(TAG, "31317 probe: $line")
                    }
                }.onFailure { Log.w(TAG, "31317 probe failed", it) }.getOrNull()
                if (zygote != null) runOnUiThread { zygoteProbe.value = zygote }
                // Both probes are property reads plus one file check, so they ride along with the
                // connect instead of waiting for the picker to open.
                val lspromise = runCatching {
                    LSPromise.probe(AdbConnectionManager.get(this)) { line ->
                        Log.i(TAG, "lspromise probe: $line")
                    }
                }.onFailure { Log.w(TAG, "lspromise probe failed", it) }.getOrNull()
                if (lspromise != null) runOnUiThread { lspromiseProbe.value = lspromise }
            }
        }, "adb-device-info").start()
    }

    private fun onPrimaryAction() {
        when {
            pairingRunning.value -> stopPairing()
            connecting.value -> Unit // already busy
            else -> requestStart()
        }
    }

    /**
     * Runs temporary root: the payload is pushed to /data/local/tmp over ADB and executed as the
     * `shell` user, with its output mirrored live in the log card.
     */
    /** Exploit tapped: let the user pick a vulnerability first. */
    private fun openEnginePicker() {
        if (exploiting.value) return
        // The button is hidden until adbd is connected; this is the second line of defence.
        if (!hasShellChannel) {
            toast(R.string.exploit_needs_adb)
            return
        }
        // Every CVE is always listed; each row explains whether it can run.
        exploitChoices.value = buildChoices(deviceInfo.value)
        pickerVisible.value = true
    }

    private fun buildChoices(info: DeviceInfo?): List<ExploitChoice> {
        val kernel = info?.kernel.orEmpty()
        val available = availability(info)
        val manager = ksudTarget.value
        val noConnection = info == null
        val handoff = if (manager == null) {
            getString(R.string.handoff_root_channel)
        } else {
            getString(R.string.handoff_starts, manager.packageName)
        }

        return listOf(
            /*
             * One row per CVE. CVE-2026-43499 ships two payloads: the generic one takes its
             * offsets from a GLK1 profile, GhostLock54 has one kernel's offsets compiled in. The
             * port wins when its exact kernel is running - a profile parsed for a different build
             * would be worse than useless there - and everywhere else the profile decides.
             */
            ExploitChoice(
                id = ENGINE_CVE_43499,
                title = "CVE-2026-43499",
                detail = when {
                    available.ghost54 -> getString(R.string.engine_ghost54_detail, handoff)
                    available.profile -> {
                        val picked = ProfileStore.active(this)
                        if (picked != null && picked != kernel) getString(R.string.engine_using_profile, picked)
                        else getString(R.string.engine_kernel_profile_for, kernel)
                    }
                    noConnection -> getString(R.string.engine_connect_first)
                    !RootExploit.isPayloadPresent(this) -> getString(R.string.engine_payload_missing)
                    // The fix pill points to the Profile tab; repeating the same hint here only
                    // made the row harder to read.
                    else -> ""
                },
                enabled = available.ghost54 || available.profile,
                // Picking a profile now belongs entirely to the Profile tab (Built-in offset
                // tables). A missing profile is the one blocker the user can clear inside the app,
                // so this pill takes them there instead of offering a second picker on this row.
                fixLabel = if (!available.ghost54 && !available.profile && !noConnection &&
                    RootExploit.isPayloadPresent(this)
                ) getString(R.string.engine_open_profile) else null,
                onFix = {
                    pickerVisible.value = false
                    selectedTab.value = 1
                },
            ),
            /*
             * One row for CVE-2026-98260, three ways in: Shark's own 6.18 build, the local payload
             * with a parsed profile, and the same local payload with `--selinux-only`. The last one
             * stops before the cred rewrite, so it is offered as a chip on the row rather than a
             * second vulnerability - it never was one.
             */
            ExploitChoice(
                id = ENGINE_CVE_98260,
                title = "CVE-2026-98260",
                detail = when {
                    noConnection -> getString(R.string.engine_connect_first)
                    available.shark98260 -> getString(R.string.engine_shark_driver, handoff)
                    !available.c98260KernelOk -> getString(R.string.engine_kernel_old)
                    !Cve98260Runner.isPayloadPresent(this) -> getString(R.string.engine_payload_missing)
                    !Cve98260Runner.hasProfile(this, kernel) ->
                        getString(R.string.engine_parse_first)
                    else -> getString(R.string.engine_c98260_detail, handoff)
                },
                enabled = available.shark98260 || available.c98260,
                // Only the local payload has the short path; Shark's build runs its own script.
                altLabel = if (available.c98260) getString(R.string.engine_only_selinux) else null,
                onAlt = { startExploit(ENGINE_CVE_98260_SELINUX) },
                // The local payload opens the argument sheet instead of running on the spot;
                // naming that on the capsule is cheaper than a paragraph in the row's detail.
                runLabel = if (available.c98260 && !available.shark98260) {
                    getString(R.string.picker_options)
                } else {
                    null
                },
            ),
            /*
             * One row for CVE-2026-64560, three builds of the same posix-cpu-timers bug. JokerLock
             * is the only one that pins a fingerprint, so it goes first; Shark's is next because it
             * names its kernel family; the generic port is last because `--preflight` is its only
             * gate. A run is still remembered per build inside the runner.
             */
            ExploitChoice(
                id = ENGINE_CVE_64560,
                title = "CVE-2026-64560",
                detail = when {
                    noConnection -> getString(R.string.engine_connect_first)
                    available.joker -> getString(R.string.engine_joker_detail, handoff)
                    available.shark64560 -> getString(R.string.engine_shark_driver, handoff)
                    !available.pctMatched -> getString(R.string.engine_no_port)
                    available.pctPayload == null -> getString(R.string.engine_payload_missing)
                    else -> getString(R.string.engine_pct_detail, handoff)
                },
                enabled = available.joker || available.shark64560 || available.pctPayload != null,
            ),
            ExploitChoice(
                id = ENGINE_CVE_21479,
                title = "CVE-2025-21479",
                detail = when {
                    noConnection -> getString(R.string.engine_connect_first)
                    !available.gpuMatched -> getString(R.string.engine_gpu_unsupported)
                    available.gpuPayload == null -> getString(R.string.engine_payload_missing)
                    else -> getString(R.string.engine_gpu_detail, handoff)
                },
                enabled = available.gpuPayload != null,
            ),
            ExploitChoice(
                id = ENGINE_CVE_43284,
                title = "CVE-2026-43284",
                detail = when {
                    noConnection -> getString(R.string.engine_connect_first)
                    available.pageCache == null -> getString(R.string.engine_not_covered)
                    else -> "${available.pageCache}, $handoff"
                },
                enabled = available.pageCache != null,
            ),
            /*
             * LSPromise is gated on its own prerequisites only, not on 31317: it is a complete chain
             * that starts from an ordinary app, so requiring the zygote bug first would be wrong.
             */
            ExploitChoice(
                id = ENGINE_LSPROMISE,
                title = getString(R.string.engine_lspromise_title),
                detail = when {
                    noConnection -> getString(R.string.engine_connect_first)
                    lspromiseProbe.value == null -> getString(R.string.support_checking)
                    !LSPromise.isPayloadPresent(this) ->
                        getString(R.string.engine_payload_missing)
                    else -> lspromiseProbe.value!!.detail
                },
                enabled = info != null &&
                    lspromiseProbe.value?.canRun == true &&
                    LSPromise.isPayloadPresent(this),
            ),
            /*
             * CVE-2024-31317 is the one row that does not claim root, and the text says so twice: in
             * the title (marked as a prerequisite) and in the ready detail (system only). A user who
             * picks it expecting `su` would otherwise read the result as a failure.
             */
            ExploitChoice(
                id = ENGINE_ZYGOTE_31317,
                title = getString(R.string.engine_zygote_title),
                detail = when {
                    noConnection -> getString(R.string.engine_connect_first)
                    zygoteProbe.value == null -> getString(R.string.support_checking)
                    zygoteReady.value -> getString(R.string.zygote_ran)
                    zygoteProbe.value!!.canInject ->
                        getString(R.string.zygote_ready, zygoteProbe.value!!.patchLevels.size)
                    else -> zygoteProbe.value!!.detail
                },
                enabled = info != null && zygoteProbe.value?.canInject == true,
            ),
            /*
             * CVE-2020-0041 is profile-driven: one binary covers plain 5.4 and 5.4-qgki, and the
             * profile decides which kernel it targets. No profile means no run, not a best guess.
             */
            ExploitChoice(
                id = ENGINE_CVE_0041,
                title = "CVE-2020-0041",
                detail = when {
                    noConnection -> getString(R.string.engine_connect_first)
                    available.binderBomb != null ->
                        getString(R.string.engine_0041_ready, available.binderBomb, handoff)
                    !BinderBombRunner.isPayloadPresent(this) ->
                        getString(R.string.engine_payload_missing)
                    else -> getString(R.string.engine_0041_no_profile, kernel)
                },
                enabled = available.binderBomb != null,
            ),
            /*
             * The MediaTek row is the only one that is not a kernel exploit. Its gate is the
             * `mtk-su` precondition set: an MTK SoC and a command-queue node the shell user can
             * open. A build patched after March 2020 stays enabled, because only the payload can
             * really answer that, but the row says so instead of pretending.
             */
            ExploitChoice(
                id = ENGINE_MEDIATEK,
                title = getString(R.string.engine_mtk_title),
                detail = when {
                    noConnection -> getString(R.string.engine_connect_first)
                    mtkProbe.value == null -> getString(R.string.support_checking)
                    !mtkProbe.value!!.isMediaTek ->
                        getString(R.string.engine_mtk_not_mtk, mtkProbe.value!!.soc)
                    mtkProbe.value!!.cmdqPaths.isEmpty() ->
                        getString(R.string.engine_mtk_no_cmdq)
                    mtkProbe.value!!.likelyPatched ->
                        getString(R.string.engine_mtk_patched, mtkProbe.value!!.patchLevel)
                    else -> getString(R.string.engine_mtk_detail, handoff)
                },
                enabled = info != null && (mtkProbe.value?.supported ?: false),
            ),
            // CVE-2026-61269 has no other build, so it keeps a row of its own. The other two Shark
            // ports are folded into the 64560 and 98260 rows above.
            SharkRunner.Engine.CVE_61269.toChoice(info, noConnection, handoff),
        )
    }

    /**
     * One picker row for a Shark port.
     *
     * The row is disabled unless three things hold: a device is connected, the running kernel is in
     * the family the port was built against, and the binaries made it into the APK. Every disabled
     * state names the reason, so a 5.x device sees "built for 6.18" rather than a bare grey row.
     */
    private fun SharkRunner.Engine.toChoice(
        info: DeviceInfo?,
        noConnection: Boolean,
        handoff: String,
    ): ExploitChoice {
        val kernel = info?.kernel.orEmpty()
        val family = releasePrefixes.joinToString(" / ")
        val packaged = SharkRunner.isPayloadPresent(this@MainActivity, this)
        return ExploitChoice(
            id = this.id,
            title = this.label,
            detail = when {
                noConnection -> getString(R.string.engine_connect_first)
                !matches(kernel) -> getString(R.string.engine_built_for, family, kernel)
                !packaged -> getString(R.string.engine_payload_missing)
                else -> getString(R.string.engine_shark_driver, handoff)
            },
            enabled = info != null && matches(kernel) && packaged,
        )
    }

    /**
     * "Choose a built-in profile" tapped on the Profile tab: list every profile the app can hand
     * to the engine.
     *
     * Parsed profiles live one file per release in app storage, the bundled ones come out of the
     * APK's assets. Neither list is filtered by release: the sheet exists precisely so the user can
     * override the automatic `uname -r` match. This is the only place profiles are selected.
     */
    private fun openProfilePicker() {
        val kernel = deviceInfo.value?.kernel.orEmpty()
        val active = ProfileStore.active(this)
        val parsed = ProfileStore.list(this).map { entry ->
            ProfileOption(
                release = entry.release,
                source = if (entry.sourceName.isEmpty()) {
                    "parsed on this device"
                } else {
                    "parsed from ${entry.sourceName}"
                },
                bundled = false,
                current = entry.release == kernel,
                selected = entry.release == active,
            )
        }
        val taken = parsed.mapTo(HashSet()) { it.release }
        val bundled = BundledProfiles.releases(this)
            .filterNot { it in taken }
            .map { release ->
                ProfileOption(
                    release = release,
                    source = "bundled with OpenRoot",
                    bundled = true,
                    current = release == kernel,
                    selected = release == active,
                )
            }
        // Closest to the running kernel first: exact match, then same major.minor, then same major.
        // 75+ bundled builds are listed, so the one that could plausibly work must not be buried.
        profileChoices.value = (parsed + bundled).sortedWith(
            compareBy<ProfileOption> { profileRank(it.release, kernel) }
                .thenBy { it.bundled }
                .thenByDescending { profileVersionKey(it.release) }
        )
        profilePickerVisible.value = true
    }

    /** 0 exact release, 1 same major.minor, 2 same major, 3 anything else. */
    private fun profileRank(release: String, kernel: String): Int {
        val d = kernel.split('.')
        val r = release.split('.')
        return when {
            release == kernel -> 0
            d.size >= 2 && r.size >= 2 && d[0] == r[0] && d[1] == r[1] -> 1
            d.isNotEmpty() && r.isNotEmpty() && d[0] == r[0] -> 2
            else -> 3
        }
    }

    /** Sortable `major.minor.patch`, so 6.6.102 lands above 6.6.92 instead of below it. */
    private fun profileVersionKey(release: String): String {
        val parts = release.split('.')
        fun at(i: Int) = parts.getOrNull(i)?.takeWhile { it.isDigit() }?.toIntOrNull() ?: 0
        return "%03d%03d%05d".format(at(0), at(1), at(2))
    }

    /** Sheet picked [release]: remember it, close the sheet, and re-evaluate the engine rows. */
    private fun chooseProfile(release: String) {
        ProfileStore.select(this, release)
        profilePickerVisible.value = false
        refreshParsedProfiles()
        refreshState()
        exploitChoices.value = buildChoices(deviceInfo.value)
        logLine("[+] profile $release selected for CVE-2026-43499")
    }

    private fun startExploit(engineId: String) {
        pickerVisible.value = false
        if (exploiting.value) return
        // The payload is pushed over the shell channel, which adbd or Shizuku can provide.
        if (!hasShellChannel) {
            toast(R.string.exploit_needs_adb)
            return
        }
        val info = deviceInfo.value ?: return
        // 98260's payload has more entry points than one button can express - write-zero, the two
        // leak-only modes, the address gate - so its Run asks for arguments first. Shark's 6.18
        // build runs a fixed script of its own, so that path keeps running directly.
        if (engineId == ENGINE_CVE_98260) {
            val shark = SharkRunner.Engine.CVE_98260.takeIf {
                it.matches(info.kernel) && SharkRunner.isPayloadPresent(this, it)
            }
            if (shark == null) {
                // Rebuilt on every open: a boot.img imported while the sheet was closed has to
                // show up without restarting the app.
                c98260Profiles.value = ProfileStore.listC98260(this).map {
                    C98260ProfileChoice(it.release, it.sourceName)
                }
                c98260OptionsVisible.value = true
                return
            }
        }
        startExploitNow(engineId, emptyList(), recordOutcome = true)
    }

    /** The 98260 sheet was confirmed: close it and run exactly the command line it previewed. */
    private fun startC98260(args: C98260Args) {
        c98260OptionsVisible.value = false
        pickerVisible.value = false
        if (exploiting.value) return
        if (!hasShellChannel) {
            toast(R.string.exploit_needs_adb)
            return
        }
        c98260Args.value = args
        // The sheet's picker is the only place a snapshot can be chosen, so resolve it here: the
        // runner only knows how to stage a parsed object, not a release name.
        val release = args.profileRelease.ifEmpty { deviceInfo.value?.kernel.orEmpty() }
        c98260ProfileOverride = ProfileStore.loadC98260(this, release)?.let(Cve98260Profile::parse)
        if (args.profileRelease.isNotEmpty()) {
            logLine(
                if (c98260ProfileOverride != null) "<i> profile ${args.profileRelease}"
                else "<i> profile ${args.profileRelease} is gone; the built-in table is used"
            )
        }
        // Only a full escalation says anything about this kernel; a poke or a leak run must not
        // mark the engine as "did not work" in the status card.
        startExploitNow(ENGINE_CVE_98260, args.toArgs(), args.attemptsEscalation)
    }

    private fun startExploitNow(
        engineId: String,
        extraArgs: List<String>,
        recordOutcome: Boolean,
    ) {
        val info = deviceInfo.value ?: return
        // The payload is resolved from the device, not from the row: one row per CVE.
        val gpuPayload = if (engineId == ENGINE_CVE_21479) {
            GpuRunner.payloadFor(info)?.takeIf { GpuRunner.isPayloadPresent(this, it) }
        } else {
            null
        }
        val pctPayload = if (engineId == ENGINE_CVE_64560) {
            PctRunner.payloadFor(info)?.takeIf { PctRunner.isPayloadPresent(this, it) }
        } else {
            null
        }
        // A CVE with more than one build is resolved here, once, from the device. The picker shows
        // one row per vulnerability, so the choice of build cannot be the user's - but it must not
        // be a guess either: every branch below is a fact about this kernel, not a ranking.
        val ghost54 = info.kernel == GhostLock54Runner.KERNEL &&
            GhostLock54Runner.isPayloadPresent(this)
        val joker = JokerRunner.isSupported(info.kernel) && JokerRunner.isPayloadPresent(this)
        val shark98260 = SharkRunner.Engine.CVE_98260.takeIf {
            it.matches(info.kernel) && SharkRunner.isPayloadPresent(this, it)
        }
        val shark64560 = SharkRunner.Engine.CVE_64560.takeIf {
            it.matches(info.kernel) && SharkRunner.isPayloadPresent(this, it)
        }
        // CVE-2026-43284 hands off to a manager when one is installed, otherwise it keeps a root
        // command channel; the page cache engine itself does not care which. Which one applies is
        // decided after a fresh resolve inside the worker, not from the cached value.
        when (engineId) {
            ENGINE_CVE_43499 ->
                if (!ghost54 && !RootExploit.hasProfile(this, info.kernel)) {
                    logLine("[!] no profile for ${info.kernel}; open Profile and pick one under " +
                        "Built-in offset tables")
                    return
                }
            ENGINE_CVE_98260 ->
                if (shark98260 == null && !Cve98260Runner.isSupported(this, info)) return
            ENGINE_CVE_98260_SELINUX ->
                if (!Cve98260Runner.isSupported(this, info)) return
            ENGINE_CVE_64560 ->
                if (!joker && shark64560 == null && pctPayload == null) return
            ENGINE_CVE_21479 -> if (gpuPayload == null) return
            ENGINE_CVE_0041 -> if (!BinderBombRunner.isSupported(this, info.kernel)) return
            ENGINE_MEDIATEK -> if (mtkProbe.value?.supported != true) return
            ENGINE_ZYGOTE_31317 -> if (zygoteProbe.value?.canInject != true) return
            ENGINE_LSPROMISE ->
                if (lspromiseProbe.value?.canRun != true || !LSPromise.isPayloadPresent(this)) return
            ENGINE_CVE_43284 ->
                if (!DirtyFragRunner.isSupported(info.androidRelease, info.kernel)) return
            else -> {
                // CVE-2026-61269 is the only Shark port left with a row of its own; it names its
                // kernel family and the runner refuses a mismatch before anything is pushed.
                val shark = SharkRunner.Engine.ofId(engineId) ?: return
                if (!shark.matches(info.kernel) ||
                    !SharkRunner.isPayloadPresent(this, shark)
                ) return
            }
        }

        exploiting.value = true
        forceStopping.value = false
        forceStopped = false
        ExploitStop.clearStop()
        exploitLog.value = emptyList()
        exploitStatus.value = null
        exploitProgress.value = 0f
        commandMode.value = false
        // The log is its own tab: show it while the payload runs.
        selectedTab.value = 2
        Thread({
            // Resolving ksud scans /data/app over ADB: done once on this worker and shared by all
            // engines, which also puts the scan itself in the log.
            val outcome = runCatching {
                val ksud = KsuManager.resolve(this, AdbConnectionManager.get(this), ::logLine)
                    ?.takeIf { it.packageName.isNotEmpty() }
                val shark = SharkRunner.Engine.ofId(engineId)
                when {
                    // 43499: GhostLock54 first, because a profile cannot describe its kernel.
                    engineId == ENGINE_CVE_43499 ->
                        if (ghost54) runGhostLock54Engine() else runProfileEngine(info, ksud)
                    // 98260: Shark's 6.18 build, else the local payload (which owns the short path).
                    engineId == ENGINE_CVE_98260 ->
                        if (shark98260 != null) runSharkEngine(info, shark98260, ksud)
                        else runC98260Engine(info, ksud, extraArgs, recordOutcome)
                    engineId == ENGINE_CVE_98260_SELINUX -> runC98260SelinuxEngine(info)
                    // 64560: the fingerprint-pinned build, then the family build, then the port.
                    engineId == ENGINE_CVE_64560 -> when {
                        joker -> runJokerEngine(info, ksud)
                        shark64560 != null -> runSharkEngine(info, shark64560, ksud)
                        pctPayload != null -> runPctEngine(info, pctPayload, ksud)
                        else -> getString(R.string.engine_no_port)
                    }
                    engineId == ENGINE_CVE_0041 -> runBinderEngine(info, ksud)
                    engineId == ENGINE_MEDIATEK -> runMediatekEngine()
                    engineId == ENGINE_ZYGOTE_31317 -> runZygoteEngine()
                    engineId == ENGINE_LSPROMISE -> runLSPromiseEngine()
                    pctPayload != null -> runPctEngine(info, pctPayload, ksud)
                    gpuPayload != null -> runGpuEngine(info, gpuPayload, ksud)
                    shark != null -> runSharkEngine(info, shark, ksud)
                    else -> runPageCacheEngine(
                        info = info,
                        ksud = ksud,
                        mode = if (ksud != null) {
                            DirtyFragRunner.Mode.KERNEL_SU
                        } else {
                            DirtyFragRunner.Mode.ROOT_COMMAND
                        },
                    )
                }
            }
            runOnUiThread {
                val stopped = forceStopped
                forceStopped = false
                forceStopping.value = false
                exploiting.value = false
                exploitProgress.value = 1f
                exploitStatus.value = if (stopped) {
                    // The stream ends with a closed-channel exception or exit -1; neither says
                    // anything useful once the user has already asked for the kill.
                    getString(R.string.log_force_stopped)
                } else {
                    outcome.getOrElse { error ->
                        Log.w(TAG, "exploit failed", error)
                        error.message ?: error.javaClass.simpleName
                    }
                }
            }
        }, "root-exploit").start()
    }

    private fun reportProgress(value: Float) {
        runOnUiThread { exploitProgress.value = value }
    }

    /**
     * Force stop for the log page: kills the payload processes on the device first, then cuts the
     * local stream so the worker returns without sitting through the idle timeout.
     *
     * Only running processes are killed. The 98260 payload parks a gravestone child in `SIGSTOP`
     * so the kernel never walks its poisoned timerqueue on the way out - killing that child would
     * undo the one thing keeping the device alive - which is why `T`-state processes are skipped
     * inside [ExploitStop].
     */
    private fun forceStopExploit() {
        if (!exploiting.value || forceStopping.value) return
        forceStopping.value = true
        forceStopped = true
        ExploitStop.requestStop()
        logLine("<i> 强行停止：正在结束设备上的载荷进程")
        Thread({
            val killed = runCatching { ExploitStop.killPayloads(AdbConnectionManager.get(this)) }
                .getOrElse { error ->
                    Log.w(TAG, "force stop failed", error)
                    -1
                }
            AdbShell.cancelActiveStream()
            runOnUiThread {
                logLine(
                    when {
                        killed > 0 -> "<i> 已结束 $killed 个载荷进程，日志流已断开"
                        killed == 0 -> "<i> 没有运行中的载荷进程，已断开日志流"
                        else -> "<i> 结束载荷失败，已断开日志流；设备上的进程可能仍在运行"
                    }
                )
                // A transport that ignores the local close can leave the worker blocked on read.
                // The payload is already dead, so free the page instead of showing "stopping"
                // until the idle timeout; the orphan thread exits on its own.
                refreshHandler.postDelayed({
                    if (forceStopping.value && exploiting.value) {
                        forceStopping.value = false
                        exploiting.value = false
                        exploitProgress.value = 1f
                        exploitStatus.value = getString(R.string.log_force_stopped)
                    }
                }, 5_000)
            }
        }, "exploit-force-stop").start()
    }

    /**
     * KASLR card · automatic: run calibration A only.
     *
     * The 98260 payload creates a burst of POSIX CPU timers and reads the `kmem_cache_alloc` call
     * site out of the raw ftrace buffer, then prints `C98260_SLIDE=0x…` and exits without touching
     * the kernel. Everything it prints still goes to the log page so a failure is diagnosable.
     */
    private fun resolveKaslrAuto() {
        if (kaslrBusy.value) return
        val info = deviceInfo.value ?: return
        kaslrBusy.value = true
        kaslrNoteError.value = false
        kaslrNote.value = "running calibration A…"
        // Same rule as a parse or an exploit run: one action, one fresh log - and the log tab,
        // because every long-running payload reports there and nowhere else.
        exploitLog.value = emptyList()
        selectedTab.value = 2
        logLine("--- kaslr calibration ---")
        val profile = ProfileStore.loadC98260(this, info.kernel)?.let(Cve98260Profile::parse)
        Thread({
            val outcome = runCatching {
                Cve98260Runner.resolveSlide(
                    context = this,
                    manager = AdbConnectionManager.get(this),
                    release = info.kernel,
                    profile = profile,
                    onLine = ::logLine,
                    onProgress = ::reportProgress,
                )
            }
            runOnUiThread {
                kaslrBusy.value = false
                exploitProgress.value = 0f
                val error = outcome.exceptionOrNull()
                val value = outcome.getOrNull()
                when {
                    error != null -> {
                        kaslrNoteError.value = true
                        kaslrNote.value = "auto failed: ${error.message ?: error.javaClass.simpleName}"
                        logLine("[!] kaslr auto failed: ${error.message ?: "see above"}")
                    }
                    value == null -> {
                        kaslrNoteError.value = true
                        // The runner already logged the single `[-]` line; the card repeats the
                        // verdict, not the tracefs diagnosis that made the failure noisy.
                        kaslrNote.value = getString(R.string.kaslr_no_slide)
                    }
                    else -> {
                        kaslrSlide.value = value
                        kaslrNoteError.value = false
                        kaslrNote.value = describeSlide(value)
                        logLine("[+] kaslr slide 0x" + java.lang.Long.toHexString(value))
                    }
                }
            }
        }, "kaslr-auto").start()
    }

    /** KASLR card · manual: accept `0x…` or decimal, the payload gets it back through `--slide`. */
    private fun applyKaslrManual(raw: String) {
        val text = raw.trim()
        if (text.isEmpty()) {
            kaslrNoteError.value = true
            kaslrNote.value = "enter a slide, e.g. 0x1a00000"
            return
        }
        val value = runCatching {
            if (text.startsWith("0x", ignoreCase = true)) {
                java.lang.Long.parseUnsignedLong(text.substring(2), 16)
            } else {
                text.toLong()
            }
        }.getOrNull()
        if (value == null || value < 0) {
            kaslrNoteError.value = true
            kaslrNote.value = "not a valid slide: $text"
            return
        }
        kaslrSlide.value = value
        kaslrNoteError.value = false
        kaslrNote.value = describeSlide(value)
    }

    /** One line that says whether the value looks like a real slide or like a noise candidate. */
    private fun describeSlide(value: Long): String {
        val hex = "0x" + java.lang.Long.toHexString(value)
        return when {
            value and 0x1FFFFFL != 0L -> "$hex · not 2 MiB aligned (noise candidate?)"
            value > KASLR_MAX_SLIDE ->
                "$hex · above the 39-bit VA band (custom KASLR - payload needs --max-slide)"
            value < KASLR_MIN_SLIDE ->
                "$hex · below the 39-bit VA band (old-style KASLR or noise)"
            else -> "$hex · 2 MiB aligned"
        }
    }

    private fun logLine(line: String) {
        runOnUiThread { exploitLog.value = (exploitLog.value + line).takeLast(300) }
    }

    /** CVE-2026-43499: the payload picks its profile by `uname -r` and late-loads ksud itself. */
    private fun runProfileEngine(info: DeviceInfo, ksud: KsuManager.Target?): String {
        // Run uses exactly the profile Set Profile selected (KEY_SELECTED); if nothing is selected it
        // falls back to the saved/bundled profile for this device's kernel. A freshly parsed boot
        // never sneaks in and overrides an explicit pick - that silent override was the old bug.
        val result = RootExploit.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            release = info.kernel,
            ksudPath = ksud?.ksudPath,
            ksudPackage = ksud?.packageName,
            onLine = ::logLine,
            onProgress = ::reportProgress,
        )
        ExploitMemory.record(this, info.kernel, result.kernelSuLoaded)
        return when {
            result.kernelSuLoaded -> {
                // The payload loads the module itself; the app only has to bring the manager up.
                val opened = KsuManager.launchWithRetry(
                    context = this,
                    manager = AdbConnectionManager.get(this),
                    packageName = ksud?.packageName.orEmpty(),
                    log = ::logLine,
                )
                getString(if (opened) R.string.exploit_ksu_opened else R.string.exploit_ksu_manual)
            }
            result.exitCode == 0 -> getString(R.string.exploit_finished)
            else -> getString(R.string.exploit_exit_code, result.exitCode)
        }
    }

    /**
     * CVE-2026-98260: the payload calibrates its own KASLR slide and page_offset, so the runner
     * only stages files and reads the outcome. Its profile is the 98260 snapshot parsed from the
     * same boot.img; without one the payload's built-in 6.1.134 / 6.6.118 table applies.
     */
    private fun runC98260Engine(
        info: DeviceInfo,
        ksud: KsuManager.Target?,
        extraArgs: List<String>,
        recordOutcome: Boolean,
    ): String {
        // One-shot: a snapshot chosen in the sheet applies to this run only.
        val picked = c98260ProfileOverride
        c98260ProfileOverride = null
        val profile = picked
            ?: ProfileStore.loadC98260(this, info.kernel)?.let(Cve98260Profile::parse)
        if (profile == null) {
            logLine("<i> no parsed profile for ${info.kernel}; the built-in table is used")
        } else {
            // The poke switches read these two addresses; printing them makes "where did
            // ffffffc00a01d5f8 come from" answerable from the log alone.
            logLine(
                "<i> profile ${profile.release}: kptr=${hexOrUnset(profile.kptrLink)}" +
                    " panic=${hexOrUnset(profile.panicLink)}"
            )
        }
        val result = Cve98260Runner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            release = info.kernel,
            profile = profile,
            suManager = ksud,
            onLine = ::logLine,
            onProgress = ::reportProgress,
            // A slide from the KASLR card skips calibration A; a null one lets the payload
            // measure it again, which is what it did before the card existed.
            slide = kaslrSlide.value,
            extraArgs = extraArgs,
        )
        if (recordOutcome) {
            ExploitMemory.record(
                this, info.kernel, result.handoff.rooted, ExploitMemory.ENGINE_C98260,
            )
        }
        return reportHandoff(ksud, result.handoff, result.exitCode)
    }

    /** `0x…`, or `unset` for the zero that means "this profile does not carry the symbol". */
    private fun hexOrUnset(value: Long): String =
        if (value == 0L) "unset" else "0x" + java.lang.Long.toHexString(value)

    /**
     * CVE-2026-98260, short path: same payload with `--selinux-only`. It stops as soon as
     * `selinux_enforcing` reads back 0 — before the cred rewrite — so nothing is staged as a
     * bootstrap and there is no root handoff to probe. The returned line says whether the
     * permissive state was actually confirmed or only written blind.
     */
    private fun runC98260SelinuxEngine(info: DeviceInfo): String {
        val profile = ProfileStore.loadC98260(this, info.kernel)?.let(Cve98260Profile::parse)
        if (profile == null) {
            logLine("<i> no parsed profile for ${info.kernel}; the built-in table is used")
        }
        val result = Cve98260Runner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            release = info.kernel,
            profile = profile,
            // No manager to launch, no ksud to stage: this run never reaches root.
            suManager = null,
            onLine = ::logLine,
            onProgress = ::reportProgress,
            slide = kaslrSlide.value,
            selinuxOnly = true,
        )
        return if (result.exitCode == 0) {
            result.handoff.detail
        } else {
            getString(R.string.exploit_exit_code, result.exitCode)
        }
    }

    /**
     * CVE-2025-21479: the payload runs as `shell` over the ADB channel and re-execs the staged
     * `bootstrap` as a child once root is held; bootstrap then late-loads ksud or starts the root
     * command channel according to its preferences.
     */
    private fun runGpuEngine(
        info: DeviceInfo,
        payload: GpuRunner.Payload,
        ksud: KsuManager.Target?,
    ): String {
        val result = GpuRunner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            payload = payload,
            suManager = ksud,
            onLine = ::logLine,
            onProgress = ::reportProgress,
        )
        ExploitMemory.record(this, info.kernel, result.handoff.rooted, ExploitMemory.ENGINE_GPU)
        return reportHandoff(ksud, result.handoff, result.exitCode)
    }

    /**
     * CVE-2026-64560: the payload runs `--preflight` first to confirm the fingerprint and kernel
     * really are the ported build, then the race. Once root is held it hands the root child to the
     * staged bootstrap, same as the other engines.
     */
    private fun runPctEngine(
        info: DeviceInfo,
        payload: PctRunner.Payload,
        ksud: KsuManager.Target?,
    ): String {
        val result = PctRunner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            payload = payload,
            suManager = ksud,
            onLine = ::logLine,
            onProgress = ::reportProgress,
        )
        // A refusal before the race says nothing about the vulnerability, so it is not remembered.
        if (!result.attempted) {
            return if (result.buildMismatch) {
                getString(R.string.exploit_profile_gate_failed)
            } else {
                getString(R.string.exploit_exit_code, result.exitCode)
            }
        }
        ExploitMemory.record(this, info.kernel, result.handoff.rooted, ExploitMemory.ENGINE_PCT)
        return reportHandoff(ksud, result.handoff, result.exitCode)
    }

    /**
     * JokerLock's OGKI build of CVE-2026-64560.
     *
     * The payload reports its own STAGE0..STAGE8 progress, so this runner only forwards it and then
     * checks `su -c id`. The vulnerability is the same one [runPctEngine] drives, which is why a
     * successful run is remembered under the same engine id; only the payload differs.
     */
    private fun runJokerEngine(info: DeviceInfo, ksud: KsuManager.Target?): String {
        val result = JokerRunner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            info = info,
            onLine = ::logLine,
        )
        if (result.refused) {
            return getString(R.string.exploit_exit_code, result.exitCode)
        }
        ExploitMemory.record(this, info.kernel, result.rooted, ExploitMemory.ENGINE_PCT)
        if (!result.rooted) {
            return getString(R.string.exploit_exit_code, result.exitCode)
        }
        if (ksud == null) {
            runOnUiThread { commandMode.value = true }
            return getString(R.string.exploit_root_ready)
        }
        val opened = KsuManager.launchWithRetry(
            context = this,
            manager = AdbConnectionManager.get(this),
            packageName = ksud.packageName,
            log = ::logLine,
        )
        return getString(if (opened) R.string.exploit_ksu_opened else R.string.exploit_ksu_manual)
    }

    /**
     * The OPPO Reno7 5G port of CVE-2026-43499.
     *
     * Success is a loaded `kernelsu.ko`, not a `su` that works this second: the payload swaps the
     * target's cred for `init_cred`, clears `task_struct.seccomp` and insmods a module built for
     * this exact kernel. Root afterwards is whatever that manager hands out, so the manager is
     * what gets opened — claiming "rooted" here would be true for as long as the process lives.
     */
    private fun runGhostLock54Engine(): String {
        val manager = AdbConnectionManager.get(this)
        reportProgress(0.1f)
        val result = GhostLock54Runner.run(
            context = this,
            manager = manager,
            log = ::logLine,
        )
        reportProgress(1f)
        if (!result.moduleLoaded) return result.detail
        val opened = KsuManager.launchWithRetry(
            context = this,
            manager = manager,
            packageName = GhostLock54Runner.KSUN_PACKAGE,
            log = ::logLine,
        )
        return getString(if (opened) R.string.exploit_ksu_opened else R.string.exploit_ksu_manual)
    }

    /**
     * Installs the manager that pairs with what just loaded and brings it to the front.
     *
     * Done off the main thread: the APK is fetched from a mirror over the shell channel and then
     * `pm install`ed, which takes seconds. The returned line is what the caller shows; the log
     * carries the step that failed, including where the APK was left when `pm` refuses.
     */
    private fun openMagiskManager(flavor: MagiskManager.Flavor): String {
        val manager = AdbConnectionManager.get(this)
        Thread({
            runCatching {
                val result = MagiskManager.install(manager, flavor, ::logLine)
                if (result.ok) {
                    MagiskManager.launch(manager, ::logLine)
                } else {
                    logLine("<e> ${result.message}")
                }
            }.onFailure { error -> logLine("<e> ${error.message}") }
        }, "magisk-manager").start()
        return getString(
            if (flavor == MagiskManager.Flavor.LEGACY) R.string.exploit_magisk_legacy
            else R.string.exploit_magisk
        )
    }

    /**
     * LSPromise: stage the three payloads, then run the half a shell can run.
     *
     * The result sentence is deliberately not a failure message when the syscall is unreachable.
     * Nothing broke: the chain needs Java-side objects that only exist in the app process, and this
     * shell-driven model cannot create them. The log names the missing step so the limit is
     * visible instead of looking like a failed exploit.
     */
    private fun runLSPromiseEngine(): String {
        val manager = AdbConnectionManager.get(this)
        reportProgress(0.15f)
        if (!LSPromise.pushAssets(this, manager, ::logLine)) {
            return getString(R.string.lspromise_not_staged)
        }
        reportProgress(0.4f)
        if (!LSPromise.prepare(manager, ::logLine)) {
            return getString(R.string.lspromise_not_staged)
        }
        reportProgress(0.6f)
        val result = LSPromise.run(manager, ::logLine)
        reportProgress(1f)
        return when {
            result.syscallReachable -> getString(R.string.lspromise_reached)
            result.daemonUp -> getString(R.string.lspromise_stopped, result.detail)
            else -> result.detail
        }
    }

    /**
     * CVE-2024-31317: the prerequisite row.
     *
     * It returns a sentence, never a root report, because there is no root to report. What it does
     * change is [zygoteReady], which the row reads back so a second run does not look identical to
     * a first one that failed.
     */
    private fun runZygoteEngine(): String {
        val manager = AdbConnectionManager.get(this)
        // The payload writes this file itself, so it is the one honest success signal available.
        val marker = "/data/local/tmp/openroot/31317-ok"
        val command = "mkdir -p /data/local/tmp/openroot; " +
            "printf 'uid=%s\\nseinfo=%s\\n' \"\$(id -u)\" \"\$(cat /proc/self/attr/current)\" > $marker"

        logLine("<i> ${getString(R.string.zygote_injecting)}")
        reportProgress(0.2f)
        val ok = Zygote31317.inject(
            manager = manager,
            uid = 1000,
            seinfo = "system_app",
            command = command,
            log = ::logLine,
        )
        reportProgress(1f)
        runOnUiThread { zygoteReady.value = ok }
        if (!ok) {
            logLine("<e> ${getString(R.string.zygote_failed)}")
            return getString(R.string.zygote_failed)
        }
        /* The key was restored inside `inject`, so nothing is left behind to fix. Saying so is worth
         * a line: a user who has read about 31317 expects the dangerous write, not the cleanup. */
        logLine("<i> ${getString(R.string.zygote_restored)}")
        return getString(R.string.zygote_ran)
    }

    /**
     * Bootless MediaTek root: `mtk-su`, then Magisk 20.4 into `/sbin`.
     *
     * - the arch half comes from the probe, which reads the device's own ABI list, because
     *   `mtk-su32` and `mtk-su64` are different binaries and the wrong one dies with
     *   `exec format error`;
     * - there is no KernelSU manager to open afterwards. Success means `/sbin/su` exists, and the
     *   manager to install is the legacy one, which [reportHandoff] picks from the payload tag.
     */
    private fun runMediatekEngine(): String {
        val manager = AdbConnectionManager.get(this)
        val use64 = mtkProbe.value?.use64 ?: true
        logLine("<i> MediaTek payload, ${if (use64) "64" else "32"}-bit half")
        reportProgress(0.15f)
        val ok = MtkEasySu.run(
            context = this,
            manager = manager,
            use64 = use64,
            log = ::logLine,
            timeoutMs = 180_000L,
        )
        reportProgress(1f)
        if (!ok) return getString(R.string.engine_mtk_failed)
        /* Success is a live Magisk, reported through the same handoff the kernel engines use. The
         * marker is read back rather than assumed: `magisk-boot.sh` exits 0 in some failure modes,
         * so `/dev/dfmm1` is what the app actually believes. */
        return reportHandoff(
            ksud = null,
            handoff = RootHandoff.probe(manager, ::logLine, waitMs = 8_000),
            exitCode = 0,
        )
    }

    /**
     * CVE-2020-0041: same shape as the GPU engine, but the payload is profile-driven, so the
     * runner stages an offset file next to the binary. One binary covers plain 5.4 and 5.4-qgki;
     * which kernel it targets is decided entirely by that profile.
     */
    private fun runBinderEngine(info: DeviceInfo, ksud: KsuManager.Target?): String {
        val result = BinderBombRunner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            kernelRelease = info.kernel,
            suManager = ksud,
            onLine = ::logLine,
            onProgress = ::reportProgress,
        )
        ExploitMemory.record(this, info.kernel, result.handoff.rooted, ExploitMemory.ENGINE_BINDER)
        return reportHandoff(ksud, result.handoff, result.exitCode)
    }

    /**
     * One Shark port: stage its binaries, run the shipped driver, report what it said.
     *
     * The driver owns the whole flow, including the KernelSU handoff, so this engine does not try
     * to interpret progress. Success is decided the way the driver reports it: the last step ends
     * with `id` printing `uid=0`.
     */
    private fun runSharkEngine(
        info: DeviceInfo,
        engine: SharkRunner.Engine,
        ksud: KsuManager.Target?,
    ): String {
        val result = SharkRunner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            engine = engine,
            info = info,
            ksudPath = ksud?.ksudPath,
            onLine = ::logLine,
        )
        if (result.refused) {
            return getString(R.string.exploit_exit_code, result.exitCode)
        }
        val rooted = result.output.lineSequence().any { it.contains("uid=0") }
        ExploitMemory.record(this, info.kernel, rooted, engine.id)
        if (!rooted) {
            return getString(R.string.exploit_exit_code, result.exitCode)
        }
        // The driver already tried its own late-load and manager install; all that is left is to
        // surface whichever surface the user ends up with, the same way every other engine does.
        if (ksud == null) {
            runOnUiThread { commandMode.value = true }
            return getString(R.string.exploit_root_ready)
        }
        val opened = KsuManager.launchWithRetry(
            context = this,
            manager = AdbConnectionManager.get(this),
            packageName = ksud.packageName,
            log = ::logLine,
        )
        return getString(if (opened) R.string.exploit_ksu_opened else R.string.exploit_ksu_manual)
    }

    /** CVE-2026-43284: the module is loaded by the kernel; bootstrap and ksud are staged over ADB. */
    private fun runPageCacheEngine(
        info: DeviceInfo,
        ksud: KsuManager.Target?,
        mode: DirtyFragRunner.Mode,
    ): String {
        val result = DirtyFragRunner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            androidRelease = info.androidRelease,
            kernelRelease = info.kernel,
            suManager = ksud,
            mode = mode,
            onLine = ::logLine,
            onProgress = ::reportProgress,
        )
        ExploitMemory.record(this, info.kernel, result.handoff.rooted)
        return reportHandoff(ksud, result.handoff, result.exitCode)
    }

    /**
     * Turns what `bootstrap` started into the status line and, when KernelSU is up, opens the
     * manager. A root that exists but has no manager (or whose late-load failed) is reported as
     * the command channel instead of being thrown away as "not vulnerable".
     */
    private fun reportHandoff(
        ksud: KsuManager.Target?,
        handoff: RootHandoff.Result,
        exitCode: Int,
    ): String {
        logLine("<i> ${handoff.detail}")
        return when (handoff.state) {
            RootHandoff.State.KERNEL_SU -> {
                val opened = KsuManager.launchWithRetry(
                    context = this,
                    manager = AdbConnectionManager.get(this),
                    packageName = ksud?.packageName.orEmpty(),
                    log = ::logLine,
                )
                getString(if (opened) R.string.exploit_ksu_opened else R.string.exploit_ksu_manual)
            }
            /*
             * No matching ko for this kernel, so the payload fell back to Magisk. The pairing is not
             * free: the MediaTek path leaves Magisk 20.4 in /sbin, which only the legacy manager
             * understands, and a modern manager would offer an "update" that bricks a locked device.
             */
            RootHandoff.State.MAGISK, RootHandoff.State.MAGISK_LEGACY ->
                openMagiskManager(MagiskManager.flavorFor(handoff.payload))
            RootHandoff.State.COMMAND -> {
                runOnUiThread { commandMode.value = true }
                getString(R.string.exploit_root_ready)
            }
            RootHandoff.State.NONE ->
                if (exitCode == 0) {
                    getString(R.string.exploit_finished)
                } else {
                    getString(R.string.exploit_exit_code, exitCode)
                }
        }
    }

    // ---------------------------------------------------------------- profile tab

    /** Re-reads the parsed profiles and the active selection; called on resume and after edits. */
    private fun refreshParsedProfiles() {
        parsedProfiles.value = ProfileStore.list(this)
        selectedRelease.value = ProfileStore.active(this)
    }

    /**
     * Reads the picked images and derives a profile from them.
     *
     * Both the read and the parse run on a worker: an image is tens of megabytes and the kallsyms
     * walk touches most of it, which is far too much for the main thread. Every step is written to
     * the Log tab and that tab is opened first, so a parse that takes ten seconds reads as work
     * instead of a frozen screen.
     */
    private fun parseBootImages(uris: List<Uri>, note: String? = null) {
        val names = uris.map { bootImageName(it) }
        beginProfileParse(names.joinToString(" + "), note) {
            uris.mapIndexed { index, uri ->
                val name = names[index]
                // An OTA is gigabytes, so it is never buffered: the extractor reads the zip
                // directory and the payload manifest in place and pulls out one partition.
                // A null result means "not an OTA", and the file is parsed as a plain image.
                val fromOta = OtaPayloadExtractor.extractKernel(contentResolver, uri, log = ::logLine)
                if (fromOta != null) {
                    "boot.img (from $name)" to fromOta
                } else {
                    val size = bootImageSize(uri)
                    if (size != null && size > MAX_BOOT_IMAGE_BYTES) {
                        error("$name is ${size / (1024 * 1024)} MB; the limit is " +
                            "${MAX_BOOT_IMAGE_BYTES / (1024 * 1024)} MB")
                    }
                    name to (contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: error("Cannot read $name"))
                }
            }
        }
    }

    /**
     * Parses an OTA (or a bare boot.img) straight from a URL.
     *
     * [HttpRangeSource] serves the reader's reads as HTTP Range requests, so the multi-gigabyte
     * package is never downloaded whole. A URL that is not an OTA container is downloaded as a
     * plain image, still under the in-memory limit.
     */
    private fun parseBootUrl(url: String) {
        // The signed URL itself would swamp the status line; keep just the object name.
        val label = "URL: " + url.substringBefore('?').substringAfterLast('/').take(28)
        beginProfileParse(label, "source: ${url.substringBefore('?')}") {
            HttpRangeSource(url, ::logLine).use { source ->
                val fromOta = OtaPayloadReader.extract(source, log = ::logLine)
                val image = if (fromOta != null) {
                    fromOta
                } else {
                    if (source.size > MAX_BOOT_IMAGE_BYTES) {
                        error("URL is ${source.size / (1024 * 1024)} MB; the limit is " +
                            "${MAX_BOOT_IMAGE_BYTES / (1024 * 1024)} MB")
                    }
                    logLine("[~] URL is not an OTA; downloading it as a plain image")
                    source.read(0, source.size.toInt())
                }
                listOf("boot.img (from URL)" to image)
            }
        }
    }

    /**
     * Shared parse session: log tab first, work on a background thread, then publish the outcome.
     * [supply] produces the images to parse; both the document picker and the URL path use it.
     */
    private fun beginProfileParse(
        label: String,
        note: String?,
        supply: () -> List<Pair<String, ByteArray>>,
    ) {
        if (bootParseState.value is BootParseState.Running) return
        bootParseState.value = BootParseState.Running(label)
        parsedProfileBytes = null
        parsedC98260 = null
        parsedBuild = null
        parsedImageSha256 = null
        selectedTab.value = 2
        // Each parse is its own session: keeping the previous image's lines made it impossible to
        // tell which offsets came from the file just picked.
        exploitLog.value = emptyList()
        logLine("--- profile parse ---")
        note?.let { logLine("[~] $it") }
        Thread({
            val outcome = runCatching {
                val files = supply()
                val candidate = MultiImageParser.select(files, ::logLine)
                val build = BootProfileBuilder.build(
                    candidate.info,
                    candidate.sourceName,
                    BundledProfiles.templates(this),
                ) ?: error("No kernel release found in this image")
                logLine("template ${build.templateRelease}: ${build.derived.size} fields from " +
                    "the image, ${build.inherited.size} inherited")
                if (build.missing.isNotEmpty()) {
                    logLine("[~] missing offsets: " + build.missing.joinToString())
                }
                if (build.blocked.isNotEmpty()) {
                    // A required `offset.*` is absent: saving this profile would either carry the
                    // template's foreign address or make the native side fall back to its own
                    // hard-coded one. Refuse the whole parse instead of quietly aiming the payload
                    // at the wrong kernel address.
                    build.notes.forEach { logLine(it) }
                    error("43499 profile refused: required symbol offsets cannot be proven " +
                        "from this image (" + build.blocked.joinToString() + "); the template's " +
                        "absolute addresses were discarded, not inherited")
                }
                build.notes.forEach { logLine(it) }
                // Green line: the offsets exist and the profile is complete enough to save.
                logLine("[+] offsets parsed: ${build.profile.release} - " +
                    "${build.derived.size} from the image, ${build.inherited.size} inherited")
                // The 98260 payload needs link-time addresses, which the same kallsyms walk has;
                // a missing one is fatal for that engine but must not block the 43499 profile.
                val c98260 = BootProfileBuilder.buildC98260(candidate.info)
                // Only the failure is worth a line: "N fields from the image" repeated the count
                // already printed above and read like a second, competing result.
                if (c98260.profile == null) {
                    logLine("[~] CVE-2026-98260 not available: " +
                        c98260.missing.joinToString())
                }
                ParseOutcome(
                    build = build,
                    encoded = Glk1Codec.encode(build.profile),
                    source = candidate.sourceName,
                    c98260 = c98260.profile,
                    imageSha256 = candidate.info.imageSha256,
                )
            }
            runOnUiThread {
                outcome.onSuccess { result ->
                    parsedProfileBytes = result.encoded
                    parsedC98260 = result.c98260
                    parsedBuild = result.build
                    parsedImageSha256 = result.imageSha256
                    bootParseState.value =
                        BootParseState.Ready(result.build.toParsedImage(result.source))
                }.onFailure { error ->
                    val message = error.message ?: error.javaClass.simpleName
                    bootParseState.value = BootParseState.Failed(message)
                    logLine("[!] parse failed: $message")
                }
            }
        }, "boot-image-parse").start()
    }

    // ---------------------------------------------------------------- offsets export / import

    /**
     * Exports the freshest offsets available. A live parse is preferred because it carries the
     * per-field provenance; a saved/bundled profile can still be exported but is labelled
     * `imported`, since a binary blob cannot say where each value came from.
     */
    private fun exportOffsets() {
        val doc = runCatching { buildExportDocument() }.getOrElse { e ->
            logLine("[!] export failed: ${e.message}")
            toastText(getString(R.string.export_failed, e.message.orEmpty()))
            null
        } ?: return
        pendingExport = doc
        exportOffsetsDoc.launch(doc.suggestedName())
    }

    private fun buildExportDocument(): OffsetsDocument {
        val build = parsedBuild
        val ready = bootParseState.value as? BootParseState.Ready
        if (build != null && ready != null && parsedProfileBytes != null) {
            val hocon = parsedC98260?.toHocon(ready.image.fileName)
            return OffsetsDocument.fromBuild(
                build, ready.image.fileName, parsedImageSha256, hocon,
            )
        }
        // No live parse: export the active profile, or the bundled one for the running kernel.
        val release = ProfileStore.active(this)
            ?: deviceInfo.value?.kernel
            ?: error("nothing to export: parse a boot.img first, or select a profile")
        val bytes = ProfileStore.load(this, release)
            ?: BundledProfiles.bytes(this, release)
            ?: error("no stored offsets for $release")
        val profile = Glk1Codec.decode(bytes)
        val hocon = ProfileStore.loadC98260(this, release)
        return OffsetsDocument.fromSavedProfile(profile, release, hocon)
    }

    /**
     * Imports an offsets JSON. The checks are deliberately strict: a file carrying addresses
     * inherited from a bundled template (pre-fix exports) or with unresolved required offsets is
     * refused instead of being written into the active profile slot.
     */
    private fun importOffsets(uri: Uri) {
        try {
            val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: error("cannot read the selected file")
            val doc = OffsetsDocument.decode(bytes)
            doc.validateForImport()

            // An attached 98260 snapshot must round-trip, otherwise half the pair would be stale.
            val c98260 = doc.c98260Hocon?.let { text ->
                Cve98260Profile.parse(text)
                    ?: error("the attached CVE-2026-98260 snapshot does not parse")
            }

            val encoded = Glk1Codec.encode(doc.toProfile())
            val running = deviceInfo.value?.kernel
            val matches = running != null && running == doc.release
            // A validated import is the user's deliberate choice of kernel profile, so it becomes
            // the active selection immediately - otherwise Run would silently fall back to the
            // previously parsed boot profile and ignore what was just imported. validateForImport()
            // already refused files carrying borrowed cross-build addresses or unresolved offsets.
            ProfileStore.save(this, doc.release, encoded, "imported: ${doc.source}", activate = true)
            c98260?.let { ProfileStore.saveC98260(this, doc.release, it.toHocon(doc.source)) }

            // An import is not a parse: drop any stale parse state so the screen cannot show two
            // competing results, then refresh the stored list and the support state.
            parsedBuild = null
            parsedImageSha256 = null
            parsedProfileBytes = null
            parsedC98260 = null
            bootParseState.value = BootParseState.Idle
            refreshParsedProfiles()
            refreshState()

            logLine("[+] offsets imported: ${doc.release} (${doc.offsets["offset"]?.size} symbol offsets, " +
                "origin ${doc.provenance.origin})")
            logLine("[+] profile activated for CVE-2026-43499")
            if (!matches) {
                logLine("[~] imported release differs from this device's $running; verify it is " +
                    "the right profile before running - pick another under Built-in offset tables")
            }
            toastText(getString(R.string.offsets_imported))
        } catch (e: OffsetsError) {
            logLine("[!] import refused: ${e.message}")
            toastText(getString(R.string.import_refused, e.message.orEmpty()))
        } catch (e: Exception) {
            logLine("[!] import failed: ${e.message}")
            toastText(getString(R.string.import_failed, e.message.orEmpty()))
        }
    }

    /** Stores the parsed profile under its release and makes it the active one. */
    private fun saveParsedProfile() {
        val image = (bootParseState.value as? BootParseState.Ready)?.image ?: return
        val bytes = parsedProfileBytes ?: return
        ProfileStore.save(this, image.release, bytes, image.fileName, activate = false)
        parsedC98260?.let {
            ProfileStore.saveC98260(this, image.release, it.toHocon(image.fileName))
        }
        bootParseState.value = BootParseState.Idle
        parsedProfileBytes = null
        parsedC98260 = null
        parsedBuild = null
        parsedImageSha256 = null
        refreshParsedProfiles()
        // The support state depends on which profiles exist, so the home screen has to see it.
        refreshState()
        Toast.makeText(this, R.string.profile_saved, Toast.LENGTH_SHORT).show()
    }

    /** Selected by tapping a parsed row in the Profile tab; becomes the profile Run uses. */
    private fun useProfile(release: String) {
        ProfileStore.select(this, release)
        refreshParsedProfiles()
        refreshState()
    }

    private fun deleteProfile(release: String) {
        ProfileStore.delete(this, release)
        refreshParsedProfiles()
        refreshState()
    }

    /** Size of the picked document, when the provider reports one. */
    private fun bootImageSize(uri: Uri): Long? =
        runCatching {
            contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)
                ?.use { cursor -> if (cursor.moveToFirst()) cursor.getLong(0) else null }
        }.getOrNull()?.takeIf { it > 0 }

    /** Display name of the picked document, used as the profile's source label. */
    private fun bootImageName(uri: Uri): String =
        runCatching {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
        }.getOrNull()?.takeIf { it.isNotBlank() } ?: "boot.img"

    /** Flattens the builder result into the shape the screen draws. */
    private fun BootProfileBuilder.ProfileBuild.toParsedImage(fileName: String) =
        ParsedBootImage(
            release = profile.release,
            fileName = fileName,
            templateRelease = templateRelease,
            derivedCount = derived.size,
            inheritedCount = inherited.size,
            missing = missing,
            notes = notes,
            sections = profile.sections.map { (section, entries) ->
                ParsedBootImage.Section(section, entries.toList())
            },
        )

    /** Runs one command through the root channel and mirrors its output while it runs. */
    private fun runRootCommand(command: String) {
        logLine("$ $command")
        Thread({
            runCatching {
                RootShell.run(AdbConnectionManager.get(this), command) { line -> logLine(line) }
            }.onFailure { error -> logLine("<e> ${error.message}") }
        }, "root-shell").start()
    }

    /** Debug-only hook so an ADB-driven smoke test can run a pairing attempt with a known code. */
    private fun handleDebugPair(intent: Intent) {
        val code = intent.getStringExtra(AdbPairingService.EXTRA_DEBUG_CODE) ?: return
        val port = intent.getIntExtra(AdbPairingService.EXTRA_DEBUG_PORT, -1)
        val host = intent.getStringExtra(AdbPairingService.EXTRA_DEBUG_HOST)
        AdbPairingService.debugPair(this, code, port, host)
    }

    private fun requestStart() {
        if (hasNotificationPermission()) {
            startPairing()
        } else {
            requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun startPairing() {
        AdbPairingService.start(this)
        pairingRunning.value = true
        refreshHandler.removeCallbacks(refreshTick)
        refreshHandler.postDelayed(refreshTick, 1000)
    }

    private fun stopPairing() {
        AdbPairingService.stop(this)
        refreshHandler.removeCallbacks(refreshTick)
        // Set the UI state directly. Re-reading isRunning() here races the asynchronous
        // stopService(): the old value would flip the button back to "Stop".
        pairingRunning.value = false
        refreshState(updatePairing = false)
    }

    private fun hasNotificationPermission(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    private fun toast(resId: Int) = Toast.makeText(this, resId, Toast.LENGTH_SHORT).show()

    private fun toastText(text: String) = Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
}
