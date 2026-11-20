package com.hexo141.liquidglass.ui

import com.kyant.backdrop.BackdropEffectScope

/**
 * Whether glass surfaces blur, saturate and refract what sits behind them.
 *
 * The wallpaper is one flat colour. Blurring, saturating or refracting a uniform colour gives that
 * same colour back, so the whole effect chain cannot change a pixel here — while every surface
 * still pays for a render pass and a shader compile on the render thread. That work is what made
 * the first draw wait up to 1.4 s (`HardwareRenderer.nSetStopped`) on this device.
 *
 * Turn it back on together with an image wallpaper.
 */
const val GlassesRefract = false

/** The effect chain of a glass surface, switched off as a whole while [GlassesRefract] is false. */
fun glassBlock(block: BackdropEffectScope.() -> Unit): BackdropEffectScope.() -> Unit =
    if (GlassesRefract) block else NoGlassEffects

private val NoGlassEffects: BackdropEffectScope.() -> Unit = {}
