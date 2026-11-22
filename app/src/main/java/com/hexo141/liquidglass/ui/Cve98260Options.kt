package com.hexo141.liquidglass.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.isSpecified
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hexo141.liquidglass.R
import com.hexo141.liquidglass.root.C98260Args
import com.hexo141.liquidglass.root.C98260Mode
import com.kyant.backdrop.Backdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import com.kyant.shapes.RoundedRectangle

/**
 * One parsed snapshot the sheet can stage as `--profile`.
 *
 * [source] is the `boot.img` it came from, shown under the chips so two releases with the same
 * number can be told apart.
 */
data class C98260ProfileChoice(val release: String, val source: String)

/**
 * Argument sheet for CVE-2026-98260.
 *
 * The row used to launch one fixed command line. The payload grew entry points that are not part
 * of a normal escalation run - the write-zero endpoint, the two leak-only modes, the address gate -
 * and putting each one on the row would have turned a vulnerability list into a switchboard. So
 * Run opens this form instead: one mode chip, the fields that mode actually consumes, and a
 * preview of the exact arguments.
 *
 * Duplicated entries are deliberate non-entries: `--slide` and `--kaslr-only` stay on the KASLR
 * card, `--selinux-only` stays the chip on the row, `--color` / `--no-ksu` are fixed by the
 * runner. `--profile` is the one thing that moved *into* the sheet: the parsed snapshots are
 * per-release, so pointing a run at a different build is a run-time choice, not a global setting.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun Cve98260Options(
    visible: Boolean,
    backdrop: Backdrop,
    initial: C98260Args,
    hasSlide: Boolean,
    profiles: List<C98260ProfileChoice>,
    onRun: (C98260Args) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    surfaceColor: Color = Color.Unspecified,
) {
    val progress by animateFloatAsState(
        targetValue = if (visible) 1f else 0f,
        animationSpec = tween(durationMillis = if (visible) 220 else 160),
        label = "c98260-options"
    )
    if (!visible && progress <= 0.01f) return

    // Keyed on visibility so a dismissed sheet reopens with the last run's arguments but not with
    // half-typed text from a cancelled edit.
    var state by remember(visible) { mutableStateOf(initial) }

    Box(
        modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.5f * progress))
            .clickable(enabled = visible, indication = null, interactionSource = null) { onDismiss() },
        contentAlignment = Alignment.Center
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp)
                .graphicsLayer {
                    val scale = 0.92f + 0.08f * progress
                    scaleX = scale
                    scaleY = scale
                    translationY = (1f - progress) * 28.dp.toPx()
                }
                .drawBackdrop(
                    backdrop = backdrop,
                    shape = { RoundedRectangle(24.dp) },
                    effects = glassBlock {
                        vibrancy()
                        blur(4f.dp.toPx())
                        lens(10f.dp.toPx(), 22f.dp.toPx())
                    },
                    onDrawSurface = {
                        if (surfaceColor.isSpecified) drawRect(surfaceColor)
                        drawRect(Color.Black.copy(alpha = 0.84f))
                        drawRect(Color.White.copy(alpha = 0.05f))
                    }
                )
                .padding(vertical = 16.dp, horizontal = 16.dp)
        ) {
            BasicText(
                text = stringResource(R.string.c98260_options_title),
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.95f),
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold,
                    shadow = optionsShadow
                )
            )
            Spacer(Modifier.height(4.dp))
            BasicText(
                text = stringResource(R.string.c98260_options_note),
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.55f),
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    shadow = optionsShadow
                )
            )
            Spacer(Modifier.height(12.dp))

            // Only this part scrolls: the mode title and the footer stay reachable on a short
            // screen, and a form with nine fields is taller than any phone.
            Column(
                Modifier
                    .heightIn(max = 430.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                SectionLabel(stringResource(R.string.c98260_profile_title))
                // A release deleted from the Profile tab can still be the remembered choice; it is
                // shown as Auto here so the row is not left with no selection, and the runner says
                // "profile … is gone" when the run starts.
                val picked = state.profileRelease.takeIf { release ->
                    profiles.any { it.release == release }
                }
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    ModeChip(
                        text = stringResource(R.string.c98260_profile_auto),
                        selected = picked == null
                    ) { state = state.copy(profileRelease = "") }
                    profiles.forEach { choice ->
                        ModeChip(
                            text = choice.release.take(28),
                            selected = picked == choice.release
                        ) { state = state.copy(profileRelease = choice.release) }
                    }
                }
                Spacer(Modifier.height(4.dp))
                BasicText(
                    text = if (profiles.isEmpty()) {
                        stringResource(R.string.c98260_profile_none)
                    } else {
                        stringResource(R.string.c98260_profile_note)
                    },
                    style = TextStyle(
                        color = Color.White.copy(alpha = 0.45f),
                        fontSize = 10.sp,
                        lineHeight = 14.sp,
                        shadow = optionsShadow
                    )
                )

                Spacer(Modifier.height(12.dp))
                SectionLabel(stringResource(R.string.c98260_mode_title))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    ModeChip(stringResource(R.string.c98260_mode_full), state.mode == C98260Mode.FULL) {
                        state = state.copy(mode = C98260Mode.FULL)
                    }
                    ModeChip(stringResource(R.string.c98260_mode_poke), state.mode == C98260Mode.POKE) {
                        state = state.copy(mode = C98260Mode.POKE)
                    }
                    ModeChip(stringResource(R.string.c98260_mode_lmap), state.mode == C98260Mode.LMAP) {
                        state = state.copy(mode = C98260Mode.LMAP)
                    }
                    ModeChip(stringResource(R.string.c98260_mode_cred), state.mode == C98260Mode.CRED) {
                        state = state.copy(mode = C98260Mode.CRED)
                    }
                    ModeChip(stringResource(R.string.c98260_mode_check), state.mode == C98260Mode.CHECK) {
                        state = state.copy(mode = C98260Mode.CHECK)
                    }
                    ModeChip(stringResource(R.string.c98260_mode_dump), state.mode == C98260Mode.DUMP) {
                        state = state.copy(mode = C98260Mode.DUMP)
                    }
                }

                when (state.mode) {
                    C98260Mode.POKE -> {
                        Spacer(Modifier.height(12.dp))
                        SectionLabel(stringResource(R.string.c98260_poke_title))
                        CheckRow(
                            checked = state.pokePanic,
                            title = stringResource(R.string.c98260_poke_panic),
                            detail = stringResource(R.string.c98260_poke_panic_note)
                        ) { state = state.copy(pokePanic = !state.pokePanic) }
                        CheckRow(
                            checked = state.pokeKptr,
                            title = stringResource(R.string.c98260_poke_kptr),
                            detail = stringResource(R.string.c98260_poke_kptr_note)
                        ) { state = state.copy(pokeKptr = !state.pokeKptr) }
                        Spacer(Modifier.height(4.dp))
                        BasicText(
                            text = stringResource(R.string.c98260_poke_builtin_note),
                            style = TextStyle(
                                color = Color.White.copy(alpha = 0.45f),
                                fontSize = 10.sp,
                                lineHeight = 14.sp,
                                shadow = optionsShadow
                            )
                        )
                        Spacer(Modifier.height(6.dp))
                        FieldLabel(stringResource(R.string.c98260_poke_abs))
                        ArgField(
                            value = state.pokeAbsolute,
                            hint = stringResource(R.string.c98260_poke_abs_hint)
                        ) { state = state.copy(pokeAbsolute = it) }
                        Spacer(Modifier.height(8.dp))
                        FieldLabel(stringResource(R.string.c98260_poke_link))
                        ArgField(
                            value = state.pokeLink,
                            hint = stringResource(R.string.c98260_poke_link_hint)
                        ) { state = state.copy(pokeLink = it) }
                        if (!hasSlide) {
                            Spacer(Modifier.height(6.dp))
                            BasicText(
                                text = stringResource(R.string.c98260_no_slide),
                                style = TextStyle(
                                    color = Color(0xFFFFD479),
                                    fontSize = 11.sp,
                                    lineHeight = 15.sp,
                                    shadow = optionsShadow
                                )
                            )
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            FieldLabel(stringResource(R.string.c98260_poke_retry))
                            Spacer(Modifier.width(12.dp))
                            StepButton("-") {
                                state = state.copy(pokeRetry = (state.pokeRetry - 1).coerceAtLeast(1))
                            }
                            BasicText(
                                text = state.pokeRetry.toString(),
                                modifier = Modifier.padding(horizontal = 12.dp),
                                style = TextStyle(
                                    color = Color.White,
                                    fontSize = 13.sp,
                                    fontFamily = FontFamily.Monospace
                                )
                            )
                            StepButton("+") {
                                state = state.copy(pokeRetry = (state.pokeRetry + 1).coerceAtMost(20))
                            }
                        }
                        Spacer(Modifier.height(4.dp))
                        BasicText(
                            text = stringResource(R.string.c98260_poke_retry_note),
                            style = TextStyle(
                                color = Color.White.copy(alpha = 0.45f),
                                fontSize = 10.sp,
                                lineHeight = 14.sp,
                                shadow = optionsShadow
                            )
                        )
                    }

                    C98260Mode.FULL -> {
                        Spacer(Modifier.height(12.dp))
                        SectionLabel(stringResource(R.string.c98260_extra_title))
                        CheckRow(
                            checked = state.skipSelinuxCheck,
                            title = stringResource(R.string.c98260_skip_check),
                            detail = stringResource(R.string.c98260_skip_check_note)
                        ) { state = state.copy(skipSelinuxCheck = !state.skipSelinuxCheck) }
                        Spacer(Modifier.height(8.dp))
                        FieldLabel(stringResource(R.string.c98260_netshell))
                        ArgField(
                            value = state.netshellPort,
                            hint = stringResource(R.string.c98260_netshell_hint)
                        ) { state = state.copy(netshellPort = it) }
                    }

                    else -> Unit
                }

                if (state.mode == C98260Mode.FULL || state.mode == C98260Mode.POKE ||
                    state.mode == C98260Mode.CHECK
                ) {
                    Spacer(Modifier.height(10.dp))
                    FieldLabel(stringResource(R.string.c98260_page_offset))
                    ArgField(
                        value = state.pageOffset,
                        hint = stringResource(R.string.c98260_page_offset_hint)
                    ) { state = state.copy(pageOffset = it) }
                }

                // Calibration knobs. They matter when the parsed profile or the formula window is
                // wrong for this build; leaving them empty is the common case.
                if (state.mode != C98260Mode.DUMP) {
                    Spacer(Modifier.height(12.dp))
                    SectionLabel(stringResource(R.string.c98260_calib_title))
                    FieldLabel(stringResource(R.string.c98260_va_bits))
                    ArgField(
                        value = state.vaBits,
                        hint = stringResource(R.string.c98260_va_bits_hint)
                    ) { state = state.copy(vaBits = it) }
                    Spacer(Modifier.height(8.dp))
                    FieldLabel(stringResource(R.string.c98260_max_slide))
                    ArgField(
                        value = state.maxSlide,
                        hint = stringResource(R.string.c98260_max_slide_hint)
                    ) { state = state.copy(maxSlide = it) }
                    Spacer(Modifier.height(8.dp))
                    FieldLabel(stringResource(R.string.c98260_set))
                    ArgField(
                        value = state.setOverrides,
                        hint = stringResource(R.string.c98260_set_hint)
                    ) { state = state.copy(setOverrides = it) }
                }

                // The form is the command line: showing it here is how a typo gets caught before
                // it costs a UAF instead of after.
                val preview = state.preview()
                if (preview.isNotEmpty()) {
                    Spacer(Modifier.height(10.dp))
                    BasicText(
                        text = stringResource(R.string.c98260_preview, preview),
                        style = TextStyle(
                            color = Color.White.copy(alpha = 0.55f),
                            fontSize = 10.sp,
                            lineHeight = 14.sp,
                            fontFamily = FontFamily.Monospace,
                            shadow = optionsShadow
                        )
                    )
                }
            }

            Spacer(Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically
            ) {
                FlatButton(stringResource(R.string.common_cancel), onClick = onDismiss)
                Spacer(Modifier.width(10.dp))
                AccentButton(stringResource(R.string.c98260_run)) {
                    onRun(state)
                }
            }
        }
    }
}

@Composable
private fun SectionLabel(text: String) {
    BasicText(
        text = text,
        style = TextStyle(
            color = Color.White.copy(alpha = 0.75f),
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            shadow = optionsShadow
        )
    )
    Spacer(Modifier.height(6.dp))
}

@Composable
private fun FieldLabel(text: String) {
    BasicText(
        text = text,
        style = TextStyle(
            color = Color.White.copy(alpha = 0.68f),
            fontSize = 11.sp,
            shadow = optionsShadow
        )
    )
    Spacer(Modifier.height(4.dp))
}

@Composable
private fun ModeChip(text: String, selected: Boolean, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(percent = 50))
            .background(if (selected) OptionsAccent else Color.White.copy(alpha = 0.12f))
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 7.dp)
    ) {
        BasicText(
            text = text,
            style = TextStyle(
                color = Color.White.copy(alpha = if (selected) 1f else 0.78f),
                fontSize = 12.sp,
                fontWeight = if (selected) FontWeight.Medium else FontWeight.Normal
            )
        )
    }
}

/**
 * Checkbox without Material: the rest of this screen is foundation-only, and pulling in a whole
 * widget set for one 18 dp square is not worth the dependency.
 */
@Composable
private fun CheckRow(
    checked: Boolean,
    title: String,
    detail: String?,
    onToggle: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle)
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(18.dp)
                .clip(RoundedCornerShape(5.dp))
                .background(if (checked) OptionsAccent else Color.White.copy(alpha = 0.10f))
                .border(
                    width = 1.dp,
                    color = Color.White.copy(alpha = if (checked) 0f else 0.22f),
                    shape = RoundedCornerShape(5.dp)
                ),
            contentAlignment = Alignment.Center
        ) {
            if (checked) {
                BasicText(
                    text = "✓",
                    style = TextStyle(color = Color.White, fontSize = 11.sp)
                )
            }
        }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            BasicText(
                text = title,
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.92f),
                    fontSize = 12.sp,
                    shadow = optionsShadow
                )
            )
            if (detail != null) {
                Spacer(Modifier.height(2.dp))
                BasicText(
                    text = detail,
                    style = TextStyle(
                        color = Color.White.copy(alpha = 0.48f),
                        fontSize = 10.sp,
                        lineHeight = 14.sp,
                        shadow = optionsShadow
                    )
                )
            }
        }
    }
}

@Composable
private fun ArgField(
    value: String,
    hint: String,
    mono: Boolean = true,
    onChange: (String) -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(36.dp)
            .background(Color.White.copy(alpha = 0.10f), RoundedCornerShape(10.dp))
            .padding(horizontal = 10.dp),
        contentAlignment = Alignment.CenterStart
    ) {
        BasicTextField(
            value = value,
            onValueChange = onChange,
            singleLine = true,
            textStyle = TextStyle(
                color = Color.White,
                fontSize = 12.sp,
                fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default
            ),
            // Without a fill the field is only as wide as its text, and taps miss the empty part.
            modifier = Modifier.fillMaxWidth(),
            cursorBrush = SolidColor(OptionsAccent),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Ascii,
                imeAction = ImeAction.Done
            ),
            keyboardActions = KeyboardActions(onDone = {}),
            decorationBox = { inner ->
                Box(Modifier.fillMaxWidth()) {
                    if (value.isEmpty()) {
                        BasicText(
                            text = hint,
                            style = TextStyle(
                                color = Color.White.copy(alpha = 0.32f),
                                fontSize = 11.sp,
                                fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default
                            )
                        )
                    }
                    inner()
                }
            }
        )
    }
}

@Composable
private fun StepButton(label: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .size(26.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(Color.White.copy(alpha = 0.12f))
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        BasicText(
            text = label,
            style = TextStyle(color = Color.White.copy(alpha = 0.9f), fontSize = 14.sp)
        )
    }
}

@Composable
private fun AccentButton(text: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(percent = 50))
            .background(OptionsAccent)
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 9.dp)
    ) {
        BasicText(
            text = text,
            style = TextStyle(color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.Medium)
        )
    }
}

@Composable
private fun FlatButton(text: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(percent = 50))
            .background(Color.White.copy(alpha = 0.10f))
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 9.dp)
    ) {
        BasicText(
            text = text,
            style = TextStyle(color = Color.White.copy(alpha = 0.85f), fontSize = 13.sp)
        )
    }
}

private val optionsShadow = Shadow(
    color = Color.Black.copy(alpha = 0.45f),
    offset = Offset(0f, 1f),
    blurRadius = 6f
)

private val OptionsAccent = Color(0xFF0A84FF)
