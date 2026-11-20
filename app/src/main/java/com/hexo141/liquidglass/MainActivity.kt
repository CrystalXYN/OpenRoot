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
import com.hexo141.liquidglass.root.DirtyFragRunner
import com.hexo141.liquidglass.root.ExploitMemory
import com.hexo141.liquidglass.root.GpuRunner
import com.hexo141.liquidglass.root.KsuManager
import com.hexo141.liquidglass.root.Cve98260Runner
import com.hexo141.liquidglass.root.PctRunner
import com.hexo141.liquidglass.root.RootExploit
import com.hexo141.liquidglass.root.RootHandoff
import com.hexo141.liquidglass.root.RootShell
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

        /** Same payload as [ENGINE_CVE_98260], but it stops right after clearing SELinux. */
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
                runOnUiThread {
                    when {
                        uid != null -> onShizukuGranted()
                        shizukuWaitTicks >= SHIZUKU_POLL_MAX_TICKS -> {
                            shizukuStatus.value = "No shell access yet" +
                                (error?.let { " - $it" } ?: "") + " · tap to retry"
                        }
                        else -> {
                            shizukuStatus.value = "Waiting for Shizuku permission…" +
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
                shizukuStatus.value = "Shizuku permission denied"
            }
        }

    /** Vulnerabilities offered for the connected device. */
    private val exploitChoices = mutableStateOf<List<ExploitChoice>>(emptyList())

    /** Resolved root manager (with its ksud path); null when none is installed. */
    private val ksudTarget = mutableStateOf<KsuManager.Target?>(null)

    /** Root command channel available (bootstrap came up). */
    private val commandMode = mutableStateOf(false)

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
                toastText("Offsets exported")
            } catch (e: Exception) {
                logLine("[!] export failed: ${e.message}")
                toastText("Export failed: ${e.message}")
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
        // Shizuku is only touched once the user asks for it: loading the API and registering the
        // callback during startup adds work to the first frame for a feature most launches skip.
        // The wallpaper runs edge to edge; each screen pads its own content against
        // WindowInsets.safeDrawing, so nothing sits under the status or navigation bar.

        consentAccepted.value = ConsentStore.isAccepted(this)

        // Back closes the log page or the picker first, and only then leaves the app.
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                when {
                    selectedTab.value != 0 -> selectedTab.value = 0
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
        // The grant may have been switched on in Shevery's own app list, where no callback exists:
        // re-probe as soon as we are back in front.
        if (!shizukuReady.value && shizukuStatus.value != null &&
            runCatching { Shizuku.pingBinder() }.getOrDefault(false)
        ) {
            startShizukuPolling()
        }
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
     * Connect directly when the device is already paired instead of asking for a code again; only a
     * failure brings the pairing button back.
     *
     * A device paired before the isPaired flag existed still has our ADB key stored, so that case
     * tries one silent direct connect and fills the flag in when it works.
     */
    private fun maybeAutoConnect() {
        if (autoConnectTried) return
        // A granted Shizuku shell already runs payloads, so there is nothing to reconnect.
        if (pairingRunning.value || connected.value || shizukuReady.value || connecting.value) return
        val isPaired = paired.value
        if (!isPaired && !AdbKeyManager.hasStoredKey(this)) return
        autoConnectTried = true
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
        shizukuStatus.value = "Checking Shizuku…"
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
                        shizukuStatus.value = "Shizuku / Shevery is not installed"
                    } else {
                        shizukuStatus.value = if (manager == SHEVERY_PACKAGE) {
                            "Start Shevery's service, then tap again"
                        } else {
                            "Start the Shizuku service, then tap again"
                        }
                        openShizuku(manager)
                    }
                }
                return@Thread
            }
            if (runCatching { Shizuku.isPreV11() }.getOrDefault(false)) {
                runOnUiThread {
                    shizukuRequesting = false
                    shizukuStatus.value = "Shizuku 11 or newer is required"
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
                        "Waiting for Shizuku permission… (request failed: $requestError)"
                }
            }
        }, "shizuku-request").start()
    }

    /** Registers the permission callback on first use instead of during startup. */
    private fun ensureShizukuListener() {
        if (shizukuListenerRegistered) return
        shizukuListenerRegistered = true
        runCatching { Shizuku.addRequestPermissionResultListener(shizukuPermissionListener) }
    }

    /** Starts (or restarts) the shell probe; every tick checks the real channel. */
    private fun startShizukuPolling() {
        refreshHandler.removeCallbacks(shizukuPoll)
        shizukuWaitTicks = 0
        shizukuStatus.value = "Waiting for Shizuku permission…"
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
            shizukuStatus.value = "Cannot open Shizuku"
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
    )

    private fun availability(info: DeviceInfo?): Availability {
        // No `connected.value` read here: this runs off the main thread too, where snapshot reads
        // can be stale. A non-null DeviceInfo already means the device answered.
        if (info == null) return Availability(false, null, false, null, false, null, false, false)
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
        return Availability(
            profile, pageCache, gpuMatched, gpuPayload, pctMatched, pctPayload,
            c98260KernelOk, c98260,
        )
    }

    private fun resolveEngine(info: DeviceInfo): Pair<String?, SupportState> {
        val available = availability(info)
        if (available.profile) {
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
            "root command channel"
        } else {
            "starts ${manager.packageName}"
        }

        return listOf(
            ExploitChoice(
                id = ENGINE_CVE_43499,
                title = "CVE-2026-43499",
                detail = when {
                    available.profile -> {
                        val picked = ProfileStore.active(this)
                        if (picked != null && picked != kernel) "Using profile for $picked"
                        else "Kernel profile for $kernel"
                    }
                    noConnection -> "Connect to adb first"
                    !RootExploit.isPayloadPresent(this) -> "Payload not packaged for this ABI"
                    // The fix pill points to the Profile tab; repeating the same hint here only
                    // made the row harder to read.
                    else -> ""
                },
                enabled = available.profile,
                // Picking a profile now belongs entirely to the Profile tab (Built-in offset
                // tables). A missing profile is the one blocker the user can clear inside the app,
                // so this pill takes them there instead of offering a second picker on this row.
                fixLabel = if (!available.profile && !noConnection &&
                    RootExploit.isPayloadPresent(this)
                ) "Open Profile" else null,
                onFix = {
                    pickerVisible.value = false
                    selectedTab.value = 1
                },
            ),
            ExploitChoice(
                id = ENGINE_CVE_98260,
                title = "CVE-2026-98260",
                detail = when {
                    noConnection -> "Connect to adb first"
                    !available.c98260KernelOk -> "Kernel older than 5.7"
                    !Cve98260Runner.isPayloadPresent(this) -> "Payload not packaged for this ABI"
                    !Cve98260Runner.hasProfile(this, kernel) ->
                        "Parse this kernel's boot.img in Profile first"
                    else -> "POSIX timer race, up to 24 rounds, $handoff"
                },
                enabled = available.c98260,
            ),
            ExploitChoice(
                id = ENGINE_CVE_98260_SELINUX,
                title = "CVE-2026-98260 - Only selinux",
                detail = when {
                    noConnection -> "Connect to adb first"
                    !available.c98260KernelOk -> "Kernel older than 5.7"
                    !Cve98260Runner.isPayloadPresent(this) -> "Payload not packaged for this ABI"
                    !Cve98260Runner.hasProfile(this, kernel) ->
                        "Parse this kernel's boot.img in Profile first"
                    else -> "Sets SELinux permissive, stops before cred"
                },
                enabled = available.c98260,
            ),
            ExploitChoice(
                id = ENGINE_CVE_64560,
                title = "CVE-2026-64560",
                detail = when {
                    noConnection -> "Connect to adb first"
                    !available.pctMatched -> "No ported build for this device"
                    available.pctPayload == null -> "Payload not packaged for this ABI"
                    else -> "Race, up to 32 attempts, SELinux stays off, $handoff"
                },
                enabled = available.pctPayload != null,
            ),
            ExploitChoice(
                id = ENGINE_CVE_21479,
                title = "CVE-2025-21479",
                detail = when {
                    noConnection -> "Connect to adb first"
                    !available.gpuMatched -> "GPU not supported"
                    available.gpuPayload == null -> "Payload not packaged for this ABI"
                    else -> "SELinux stays off, $handoff"
                },
                enabled = available.gpuPayload != null,
            ),
            ExploitChoice(
                id = ENGINE_CVE_43284,
                title = "CVE-2026-43284",
                detail = when {
                    noConnection -> "Connect to adb first"
                    available.pageCache == null -> "Kernel not covered by the module images"
                    else -> "${available.pageCache}, $handoff"
                },
                enabled = available.pageCache != null,
            ),
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
        // CVE-2026-43284 hands off to a manager when one is installed, otherwise it keeps a root
        // command channel; the page cache engine itself does not care which. Which one applies is
        // decided after a fresh resolve inside the worker, not from the cached value.
        when (engineId) {
            ENGINE_CVE_43499 ->
                if (!RootExploit.hasProfile(this, info.kernel)) {
                    logLine("[!] no profile for ${info.kernel}; open Profile and pick one under " +
                        "Built-in offset tables")
                    return
                }
            ENGINE_CVE_98260 ->
                if (!Cve98260Runner.isSupported(this, info)) return
            ENGINE_CVE_98260_SELINUX ->
                if (!Cve98260Runner.isSupported(this, info)) return
            ENGINE_CVE_64560 -> if (pctPayload == null) return
            ENGINE_CVE_21479 -> if (gpuPayload == null) return
            else -> if (!DirtyFragRunner.isSupported(info.androidRelease, info.kernel)) return
        }

        exploiting.value = true
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
                when {
                    engineId == ENGINE_CVE_43499 -> runProfileEngine(info, ksud)
                    engineId == ENGINE_CVE_98260 -> runC98260Engine(info, ksud)
                    engineId == ENGINE_CVE_98260_SELINUX -> runC98260SelinuxEngine(info)
                    pctPayload != null -> runPctEngine(info, pctPayload, ksud)
                    gpuPayload != null -> runGpuEngine(info, gpuPayload, ksud)
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
                exploiting.value = false
                exploitProgress.value = 1f
                exploitStatus.value = outcome.getOrElse { error ->
                    Log.w(TAG, "exploit failed", error)
                    error.message ?: error.javaClass.simpleName
                }
            }
        }, "root-exploit").start()
    }

    private fun reportProgress(value: Float) {
        runOnUiThread { exploitProgress.value = value }
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
                        kaslrNote.value =
                            "no slide reported - tracefs locked, or the profile does not match this kernel"
                        logLine("[!] kaslr: the payload printed no slide")
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
    private fun runC98260Engine(info: DeviceInfo, ksud: KsuManager.Target?): String {
        val profile = ProfileStore.loadC98260(this, info.kernel)?.let(Cve98260Profile::parse)
        if (profile == null) {
            logLine("<i> no parsed profile for ${info.kernel}; the built-in table is used")
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
        )
        ExploitMemory.record(this, info.kernel, result.handoff.rooted, ExploitMemory.ENGINE_C98260)
        return reportHandoff(ksud, result.handoff, result.exitCode)
    }

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
            toastText("Export failed: ${e.message}")
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
            toastText("Offsets imported and activated")
        } catch (e: OffsetsError) {
            logLine("[!] import refused: ${e.message}")
            toastText("Import refused: ${e.message}")
        } catch (e: Exception) {
            logLine("[!] import failed: ${e.message}")
            toastText("Import failed: ${e.message}")
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
        Toast.makeText(this, "Profile saved", Toast.LENGTH_SHORT).show()
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
