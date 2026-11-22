package com.hexo141.liquidglass.ui

import com.hexo141.liquidglass.R
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.draw.clip
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.isSpecified
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kyant.backdrop.Backdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import com.kyant.shapes.RoundedRectangle

/** One row of the engine picker. Disabled rows stay visible and explain why they cannot run. */
data class ExploitChoice(
    val id: String,
    val title: String,
    val detail: String,
    val enabled: Boolean = true,
    /**
     * A disabled row is normally labelled "Unavailable". When the blocker is something the user can
     * fix themselves - a missing kernel profile, for instance - setting this makes the label a pill
     * instead, so the row points at the fix rather than just refusing.
     */
    val fixLabel: String? = null,
    val onFix: (() -> Unit)? = null,
    /**
     * A second action on an enabled row, for the one payload that shares its CVE with another but
     * deliberately stops short - CVE-2026-98260's `--selinux-only` run. It sits above Run as a
     * quiet chip so the two entry points stay a single row instead of two.
     */
    val altLabel: String? = null,
    val onAlt: (() -> Unit)? = null,
    /**
     * Overrides the Run capsule's text for a row whose Run opens a form instead of starting the
     * payload directly (CVE-2026-98260 asks for arguments first). Null keeps "Run".
     */
    val runLabel: String? = null,
)

/**
 * Engine picker shown above the main screen when the exploit button is tapped.
 *
 * It lives inside the same composition instead of a Dialog so the rows keep refracting the
 * wallpaper like every other surface. Opening fades the scrim in and scales the card up from 92%;
 * closing runs the same animation backwards before the node leaves the tree.
 */
@Composable
fun EnginePicker(
    visible: Boolean,
    backdrop: Backdrop,
    choices: List<ExploitChoice>,
    onPick: (String) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    surfaceColor: Color = Color.Unspecified,
) {
    val progress by animateFloatAsState(
        targetValue = if (visible) 1f else 0f,
        animationSpec = tween(durationMillis = if (visible) 220 else 160),
        label = "engine-picker"
    )
    if (!visible && progress <= 0.01f) return

    Box(
        modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.5f * progress))
            .clickable(
                enabled = visible,
                indication = null,
                interactionSource = null,
                onClick = onDismiss
            ),
        contentAlignment = Alignment.Center
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
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
                        drawRect(Color.Black.copy(alpha = 0.82f))
                        drawRect(Color.White.copy(alpha = 0.05f))
                    }
                )
                .padding(vertical = 18.dp, horizontal = 18.dp)
        ) {
            BasicText(
                text = stringResource(R.string.picker_select_vulnerability),
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.95f),
                    fontSize = 19.sp,
                    fontWeight = FontWeight.SemiBold,
                    shadow = pickerShadow
                )
            )
            Spacer(Modifier.height(12.dp))
            // Five rows can overflow a short screen; only the list scrolls, so the title and
            // the Cancel button stay put.
            Column(
                Modifier
                    .heightIn(max = 400.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                choices.forEach { choice ->
                    // A row with a fix pill is not "dead", only unarmed: it is one tap away from
                    // running, so its title stays full white. Dimming it read as "this exploit does
                    // not support your device", which is the opposite of what the pill says.
                    val lit = choice.enabled || (choice.fixLabel != null && choice.onFix != null)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable(enabled = choice.enabled) { onPick(choice.id) }
                            .padding(vertical = 11.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            BasicText(
                                text = choice.title,
                                style = TextStyle(
                                    color = Color.White.copy(alpha = if (lit) 1f else 0.45f),
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Medium,
                                    shadow = pickerShadow
                                )
                            )
                            // A row whose blocker is spelled out by the pill on the right does not
                            // repeat it here; skipping the line keeps the card from growing.
                            if (choice.detail.isNotEmpty()) {
                                Spacer(Modifier.height(3.dp))
                                BasicText(
                                    text = choice.detail,
                                    style = TextStyle(
                                        color = Color.White.copy(alpha = if (lit) 0.62f else 0.35f),
                                        fontSize = 11.sp,
                                        lineHeight = 15.sp,
                                        shadow = pickerShadow
                                    )
                                )
                            }
                        }
                        Spacer(Modifier.width(12.dp))
                        when {
                            // The alternate action stacks above Run rather than beside it: two
                            // capsules side by side would eat the space the title needs.
                            choice.enabled && choice.altLabel != null && choice.onAlt != null ->
                                Column(horizontalAlignment = Alignment.End) {
                                    PickerChip(text = choice.altLabel, onClick = choice.onAlt)
                                    Spacer(Modifier.height(6.dp))
                                    PickerButton(text = choice.runLabel ?: stringResource(R.string.picker_run)) {
                                        onPick(choice.id)
                                    }
                                }
                            choice.enabled -> PickerButton(text = choice.runLabel ?: stringResource(R.string.picker_run)) {
                                onPick(choice.id)
                            }
                            choice.fixLabel != null && choice.onFix != null ->
                                PickerChip(text = choice.fixLabel, onClick = choice.onFix)
                            else -> BasicText(
                                text = stringResource(R.string.picker_unavailable),
                                style = TextStyle(
                                    color = Color.White.copy(alpha = 0.3f),
                                    fontSize = 13.sp,
                                    shadow = pickerShadow
                                )
                            )
                        }
                    }
                }
            }
            Spacer(Modifier.height(4.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                PickerButton(text = stringResource(R.string.common_cancel), onClick = onDismiss)
            }
        }
    }
}

/** Blue capsule, same accent as the exploit button, sized to its label. */
@Composable
private fun PickerButton(text: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(percent = 50))
            .background(ExploitAccent)
            .clickable(onClick = onClick)
            .padding(horizontal = 18.dp, vertical = 9.dp)
    ) {
        BasicText(
            text = text,
            style = TextStyle(
                color = Color.White,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium
            )
        )
    }
}

/**
 * Secondary capsule for a fixable blocker ("Open Profile"). Deliberately not the accent blue: it
 * opens a page, it does not run anything.
 */
@Composable
private fun PickerChip(text: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(percent = 50))
            .background(Color.White.copy(alpha = 0.14f))
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 7.dp)
    ) {
        BasicText(
            text = text,
            style = TextStyle(
                color = Color.White.copy(alpha = 0.92f),
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium
            )
        )
    }
}

private val pickerShadow = Shadow(
    color = Color.Black.copy(alpha = 0.45f),
    offset = Offset(0f, 1f),
    blurRadius = 6f
)

private val ExploitAccent = Color(0xFF0A84FF)
