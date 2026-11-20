package com.hexo141.liquidglass.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.isSpecified
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kyant.backdrop.Backdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import com.kyant.shapes.RoundedRectangle

/**
 * One selectable profile.
 *
 * Two sources feed the sheet: profiles parsed on this device (stored per release, `boot.img` as the
 * subtitle) and the ones shipped inside the APK. They are not interchangeable - a profile carries
 * the offsets of the kernel build it was taken from - so the row says which one it is and whether
 * it matches the running kernel.
 */
data class ProfileOption(
    val release: String,
    val source: String,
    val bundled: Boolean,
    /** Release equals the device's `uname -r`, i.e. the profile was built for this very kernel. */
    val current: Boolean,
    /** This is the release picked in the Profile tab; Run hands exactly this one to the engine. */
    val selected: Boolean,
)

/**
 * Bottom sheet behind "Choose a built-in profile" on the Profile tab.
 *
 * Slides up from the bottom edge instead of switching tabs: picking a profile is a decision about
 * one engine, and leaving the home screen for it lost the picker that asked the question.
 */
@Composable
fun ProfilePicker(
    visible: Boolean,
    backdrop: Backdrop,
    options: List<ProfileOption>,
    onPick: (String) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    surfaceColor: Color = Color.Unspecified,
) {
    val progress by animateFloatAsState(
        targetValue = if (visible) 1f else 0f,
        animationSpec = tween(durationMillis = if (visible) 240 else 180),
        label = "profile-picker"
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
        contentAlignment = Alignment.BottomCenter
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .graphicsLayer {
                    translationY = (1f - progress) * 440.dp.toPx()
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
                        drawRect(Color.Black.copy(alpha = 0.9f))
                        drawRect(Color.White.copy(alpha = 0.05f))
                    }
                )
                // Swallows taps on the sheet itself so only the scrim dismisses it.
                .clickable(indication = null, interactionSource = null) {}
                .padding(horizontal = 18.dp, vertical = 14.dp)
                // The sheet sits on the bottom edge, right above the gesture bar.
                .windowInsetsPadding(WindowInsets.navigationBars)
        ) {
            Box(
                Modifier
                    .align(Alignment.CenterHorizontally)
                    .width(36.dp)
                    .height(4.dp)
                    .background(Color.White.copy(alpha = 0.22f), RoundedCornerShape(2.dp))
            )
            Spacer(Modifier.height(12.dp))
            BasicText(
                text = "Select profile",
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.95f),
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold,
                    shadow = sheetShadow
                )
            )
            Spacer(Modifier.height(3.dp))
            BasicText(
                text = "Parsed on this device or one of the offset tables bundled with OpenRoot. " +
                    "Handed to CVE-2026-43499 as-is: a profile from another build carries the " +
                    "wrong offsets and may fault the kernel.",
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.55f),
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    shadow = sheetShadow
                )
            )
            Spacer(Modifier.height(10.dp))

            if (options.isEmpty()) {
                BasicText(
                    text = "No profiles are available in this APK; parse a boot.img first.",
                    style = TextStyle(
                        color = Color.White.copy(alpha = 0.5f),
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                        shadow = sheetShadow
                    )
                )
            } else {
                Column(
                    Modifier
                        .heightIn(max = 320.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    options.forEach { option ->
                        ProfileRow(option) { onPick(option.release) }
                    }
                }
            }

            Spacer(Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                Box(
                    Modifier
                        .clip(RoundedCornerShape(percent = 50))
                        .background(Color.White.copy(alpha = 0.14f))
                        .clickable(onClick = onDismiss)
                        .padding(horizontal = 18.dp, vertical = 9.dp)
                ) {
                    BasicText(
                        text = "Cancel",
                        style = TextStyle(
                            color = Color.White.copy(alpha = 0.9f),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Medium
                        )
                    )
                }
            }
            Spacer(Modifier.height(6.dp))
        }
    }
}

@Composable
private fun ProfileRow(option: ProfileOption, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            BasicText(
                text = option.release,
                style = TextStyle(
                    color = Color.White.copy(alpha = if (option.selected) 1f else 0.88f),
                    fontSize = 13.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = if (option.selected) FontWeight.SemiBold else FontWeight.Normal,
                    shadow = sheetShadow
                )
            )
            Spacer(Modifier.height(2.dp))
            BasicText(
                text = option.source,
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.45f),
                    fontSize = 10.sp,
                    shadow = sheetShadow
                )
            )
        }
        Spacer(Modifier.width(10.dp))
        when {
            option.selected -> Badge("Selected", Color(0xFF56D364))
            option.current -> Badge("This kernel", Color(0xFFFBBF24))
            option.bundled -> Badge("bundled", Color.White.copy(alpha = 0.45f))
        }
    }
}

@Composable
private fun Badge(text: String, color: Color) {
    BasicText(
        text = text,
        style = TextStyle(
            color = color,
            fontSize = 10.sp,
            fontWeight = FontWeight.Medium,
            shadow = sheetShadow
        )
    )
}

private val sheetShadow = Shadow(
    color = Color.Black.copy(alpha = 0.45f),
    offset = Offset(0f, 1f),
    blurRadius = 6f
)
