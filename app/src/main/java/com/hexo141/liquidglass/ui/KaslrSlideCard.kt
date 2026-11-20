package com.hexo141.liquidglass.ui

import com.hexo141.liquidglass.R
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.isSpecified
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kyant.backdrop.Backdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import com.kyant.shapes.RoundedRectangle

/**
 * KASLR slide workbench, sitting directly under the Exploit bar.
 *
 * Two ways in, because the two have very different preconditions:
 *
 * - **auto**: the 98260 payload runs calibration A only (`--kaslr-only`). It creates a burst of
 *   POSIX CPU timers and reads the `kmem_cache_alloc` call site out of the raw ftrace buffer, so it
 *   needs a working tracefs and the payload's per-kernel table. Deterministic when those hold.
 * - **manual**: the value is typed in, for devices where tracefs is locked down or the slide was
 *   obtained elsewhere. It is passed straight back to the payload as `--slide`, skipping A.
 *
 * @param slide resolved slide, or {@code null} while nothing is known yet
 * @param busy an auto resolution is running; both entries are locked to avoid a double run
 * @param note one-line feedback (why the auto run failed, what the manual value looks like)
 * @param noteError true when [note] describes a failure, so it is tinted red
 */
@Composable
fun KaslrSlideCard(
    slide: Long?,
    busy: Boolean,
    note: String?,
    noteError: Boolean,
    backdrop: Backdrop,
    surfaceColor: Color,
    onAuto: () -> Unit,
    onManual: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var manualOpen by remember { mutableStateOf(false) }
    var text by remember { mutableStateOf("") }

    val stateLabel = when {
        busy -> "resolving"
        slide != null -> "resolved"
        else -> "unresolved"
    }
    val stateColor = when {
        busy -> Color(0xFFFBBF24)
        slide != null -> Color(0xFF56D364)
        else -> Color.White.copy(alpha = 0.55f)
    }

    Column(
        modifier
            .drawBackdrop(
                backdrop = backdrop,
                shape = { RoundedRectangle(22.dp) },
                effects = glassBlock {
                    vibrancy()
                    blur(4f.dp.toPx())
                    lens(10f.dp.toPx(), 22f.dp.toPx())
                },
                onDrawSurface = {
                    if (surfaceColor.isSpecified) {
                        drawRect(surfaceColor)
                    }
                    drawRect(Color.Black.copy(alpha = 0.22f))
                    drawRect(Color.White.copy(alpha = 0.08f))
                }
            )
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            BasicText(
                text = stringResource(R.string.kaslr_title),
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.95f),
                    fontSize = 19.sp,
                    fontWeight = FontWeight.SemiBold,
                    shadow = cardShadow
                )
            )
            Spacer(Modifier.weight(1f))
            BasicText(
                text = stateLabel,
                style = TextStyle(
                    color = stateColor,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Medium,
                    shadow = cardShadow
                )
            )
        }
        Spacer(Modifier.height(3.dp))
        BasicText(
            text = slide?.let { "0x" + java.lang.Long.toHexString(it) } ?: "not resolved",
            style = TextStyle(
                color = if (slide != null) Color.White.copy(alpha = 0.92f)
                else Color.White.copy(alpha = 0.45f),
                fontSize = 13.sp,
                fontFamily = FontFamily.Monospace,
                shadow = cardShadow
            )
        )
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            LiquidGlassButton(
                onClick = { if (!busy) onAuto() },
                backdrop = backdrop,
                surfaceColor = surfaceColor,
                tint = if (busy) Color.Unspecified else KaslrBlue,
                height = 34.dp,
                horizontalPadding = 14.dp,
                isInteractive = !busy,
            ) {
                BasicText(
                    text = if (busy) stringResource(R.string.kaslr_resolving)
                    else stringResource(R.string.kaslr_get),
                    style = TextStyle(color = Color.White, fontSize = 12.sp, shadow = cardShadow)
                )
            }
            LiquidGlassButton(
                onClick = { manualOpen = !manualOpen },
                backdrop = backdrop,
                surfaceColor = surfaceColor,
                height = 34.dp,
                horizontalPadding = 14.dp,
            ) {
                BasicText(
                    text = if (manualOpen) stringResource(R.string.kaslr_manual_close)
                    else stringResource(R.string.kaslr_manual),
                    style = TextStyle(color = Color.White, fontSize = 12.sp, shadow = cardShadow)
                )
            }
        }
        if (manualOpen) {
            Spacer(Modifier.height(8.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Box(
                    Modifier
                        .weight(1f)
                        .height(34.dp)
                        .background(Color.White.copy(alpha = 0.10f), RoundedCornerShape(10.dp))
                        .padding(horizontal = 10.dp),
                    contentAlignment = Alignment.CenterStart
                ) {
                    BasicTextField(
                        value = text,
                        onValueChange = { text = it },
                        singleLine = true,
                        textStyle = TextStyle(
                            color = Color.White,
                            fontSize = 13.sp,
                            fontFamily = FontFamily.Monospace
                        ),
                        // Without this the field is only as wide as its own text - a few dp while
                        // empty - so almost the whole pill was dead space and a tap never landed
                        // on the field, which is why typing did nothing.
                        modifier = Modifier.fillMaxWidth(),
                        // BasicTextField's default cursor is black: invisible on this card, so even
                        // a focused field looked dead.
                        cursorBrush = SolidColor(KaslrBlue),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Ascii,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(onDone = { onManual(text) }),
                        decorationBox = { inner ->
                            Box(Modifier.fillMaxWidth()) {
                                if (text.isEmpty()) {
                                    BasicText(
                                        text = stringResource(R.string.kaslr_hex_hint),
                                        style = TextStyle(
                                            color = Color.White.copy(alpha = 0.35f),
                                            fontSize = 13.sp,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    )
                                }
                                inner()
                            }
                        }
                    )
                }
                LiquidGlassButton(
                    onClick = { onManual(text) },
                    backdrop = backdrop,
                    surfaceColor = surfaceColor,
                    height = 34.dp,
                    horizontalPadding = 14.dp,
                    isInteractive = !busy,
                ) {
                    BasicText(
                        text = stringResource(R.string.kaslr_set),
                        style = TextStyle(color = Color.White, fontSize = 12.sp, shadow = cardShadow)
                    )
                }
            }
        }
        if (note != null) {
            Spacer(Modifier.height(6.dp))
            BasicText(
                text = note,
                style = TextStyle(
                    color = if (noteError) Color(0xFFFF7B72) else Color.White.copy(alpha = 0.62f),
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    shadow = cardShadow
                )
            )
        }
    }
}

private val KaslrBlue = Color(0xFF0A84FF)

private val cardShadow = Shadow(
    color = Color.Black.copy(alpha = 0.45f),
    offset = Offset(0f, 1f),
    blurRadius = 6f
)
