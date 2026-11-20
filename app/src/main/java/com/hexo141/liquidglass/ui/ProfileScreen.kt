package com.hexo141.liquidglass.ui

import com.hexo141.liquidglass.R
import androidx.compose.ui.res.stringResource
import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.BasicTextField
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
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.isSpecified
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hexo141.liquidglass.bootimg.ProfileStore
import com.hexo141.liquidglass.device.DeviceInfo
import com.kyant.backdrop.Backdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import com.kyant.shapes.RoundedRectangle
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Profile tab: where a profile comes from.
 *
 * The payload needs struct and symbol offsets that belong to one exact kernel build. Bundled
 * profiles cover the builds the project verified; this screen produces the missing ones from the
 * device's own `boot.img` — the struct layouts come from BTF, the symbol addresses from kallsyms,
 * and the run tuning is borrowed from the closest bundled profile.
 *
 * @param selectedRelease release currently chosen as the profile Run uses, null when none
 * @param parsed profiles already parsed on this device, newest first
 */
@Composable
fun ProfileScreen(
    backdrop: Backdrop,
    /** `uname -r` of the connected device, used to warn when a parsed profile targets another build. */
    info: DeviceInfo?,
    /** Release currently chosen in the profile sheet, null when none is selected. */
    selectedRelease: String?,
    parsed: List<ProfileStore.Entry>,
    parseState: BootParseState,
    onPickImage: () -> Unit,
    /** MTK devices: `boot.img` first; `vendor_boot.img` is optional. */
    onPickMtkImage: () -> Unit,
    /** Parse an OTA / boot.img URL directly, downloading only the needed HTTP ranges. */
    onParseUrl: (String) -> Unit,
    onSaveParsed: () -> Unit,
    /** Write the current offsets to a portable JSON (SAF create-document). */
    onExportOffsets: () -> Unit,
    /** Read back an offsets JSON (SAF open-document) without re-parsing the boot image. */
    onImportOffsets: () -> Unit,
    onDiscardParsed: () -> Unit,
    /** Tap a parsed row: make [release] the profile Run uses. */
    onSetProfile: (String) -> Unit,
    /** Open the sheet that lists every profile, bundled and parsed, for the engine to use. */
    onPickBundled: () -> Unit,
    onDeleteProfile: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val surfaceColor =
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) Color.Black.copy(alpha = 0.3f)
        else Color.Unspecified

    Column(
        modifier = modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .verticalScroll(rememberScrollState())
            .padding(start = 20.dp, end = 20.dp, top = 12.dp, bottom = BottomBarSpace + 16.dp)
    ) {
        BasicText(
            text = stringResource(R.string.tab_profile),
            style = TextStyle(
                color = Color.White,
                fontSize = 30.sp,
                fontWeight = FontWeight.SemiBold,
                shadow = profileShadow
            )
        )
        Spacer(Modifier.height(14.dp))

        // ---------------------------------------------------------------- built-in offset tables
        GlassCard(backdrop, surfaceColor) {
            SectionLabel(stringResource(R.string.profile_section_tables))
            Spacer(Modifier.height(6.dp))
            BasicText(
                text = stringResource(R.string.profile_tables_note),
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.7f),
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    shadow = profileShadow
                )
            )
            Spacer(Modifier.height(12.dp))
            LiquidGlassButton(
                onClick = onPickBundled,
                backdrop = backdrop,
                surfaceColor = surfaceColor,
                height = 44.dp,
                horizontalPadding = 20.dp,
                modifier = Modifier.fillMaxWidth()
            ) {
                BasicText(
                    text = stringResource(R.string.profile_choose_builtin),
                    style = TextStyle(color = Color.White, fontSize = 14.sp, shadow = profileShadow)
                )
            }
            if (!selectedRelease.isNullOrEmpty()) {
                Spacer(Modifier.height(10.dp))
                BasicText(
                    text = stringResource(R.string.profile_selected, selectedRelease),
                    style = TextStyle(
                        color = profileAccent,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        shadow = profileShadow
                    ),
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }

        Spacer(Modifier.height(12.dp))

        // ---------------------------------------------------------------- parse a boot.img
        GlassCard(backdrop, surfaceColor) {
            SectionLabel(stringResource(R.string.profile_section_boot))
            Spacer(Modifier.height(8.dp))
            BasicText(
                text = stringResource(R.string.profile_parse_note),
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.7f),
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    shadow = profileShadow
                )
            )
            Spacer(Modifier.height(12.dp))
            LiquidGlassButton(
                onClick = onPickImage,
                backdrop = backdrop,
                surfaceColor = surfaceColor,
                height = 44.dp,
                horizontalPadding = 20.dp,
                modifier = Modifier.fillMaxWidth()
            ) {
                BasicText(
                    text = when (parseState) {
                        is BootParseState.Running -> stringResource(R.string.profile_parsing)
                        else -> stringResource(R.string.profile_select_boot)
                    },
                    style = TextStyle(color = Color.White, fontSize = 14.sp, shadow = profileShadow)
                )
            }
            Spacer(Modifier.height(8.dp))
            LiquidGlassButton(
                onClick = onPickMtkImage,
                backdrop = backdrop,
                surfaceColor = surfaceColor,
                height = 44.dp,
                horizontalPadding = 18.dp,
                modifier = Modifier.fillMaxWidth()
            ) {
                BasicText(
                    text = stringResource(R.string.profile_select_mtk),
                    style = TextStyle(color = Color.White, fontSize = 12.sp, shadow = profileShadow),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.height(12.dp))
            BasicText(
                text = stringResource(R.string.profile_ota_note),
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.7f),
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    shadow = profileShadow
                )
            )
            Spacer(Modifier.height(8.dp))
            OtaUrlRow(
                onParseUrl = onParseUrl,
                enabled = parseState !is BootParseState.Running,
            )
            Spacer(Modifier.height(8.dp))
            BasicText(
                text = stringResource(R.string.profile_portable_note),
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.7f),
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    shadow = profileShadow
                )
            )
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                LiquidGlassButton(
                    onClick = onExportOffsets,
                    backdrop = backdrop,
                    surfaceColor = surfaceColor,
                    height = 44.dp,
                    horizontalPadding = 14.dp,
                    modifier = Modifier.weight(1f)
                ) {
                    BasicText(
                        text = stringResource(R.string.profile_export),
                        style = TextStyle(color = Color.White, fontSize = 13.sp, shadow = profileShadow)
                    )
                }
                LiquidGlassButton(
                    onClick = onImportOffsets,
                    backdrop = backdrop,
                    surfaceColor = surfaceColor,
                    height = 44.dp,
                    horizontalPadding = 14.dp,
                    modifier = Modifier.weight(1f)
                ) {
                    BasicText(
                        text = stringResource(R.string.profile_import),
                        style = TextStyle(color = Color.White, fontSize = 13.sp, shadow = profileShadow)
                    )
                }
            }
            when (parseState) {
                BootParseState.Idle -> Unit
                is BootParseState.Running -> {
                    Spacer(Modifier.height(10.dp))
                    StatusLine(stringResource(R.string.profile_reading, parseState.fileName), warn = false)
                }
                is BootParseState.Failed -> {
                    Spacer(Modifier.height(10.dp))
                    StatusLine(parseState.message, warn = true)
                }
                is BootParseState.Ready -> {
                    Spacer(Modifier.height(12.dp))
                    ParsedSummary(parseState.image, info?.kernel)
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        LiquidGlassButton(
                            onClick = onSaveParsed,
                            backdrop = backdrop,
                            surfaceColor = surfaceColor,
                            height = 42.dp,
                            horizontalPadding = 18.dp,
                            modifier = Modifier.weight(1f)
                        ) {
                            BasicText(
                                text = stringResource(R.string.common_save),
                                style = TextStyle(color = Color.White, fontSize = 13.sp, shadow = profileShadow)
                            )
                        }
                        TextAction(stringResource(R.string.common_discard), subdued = false, onClick = onDiscardParsed)
                    }
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        // ---------------------------------------------------------------- parsed profiles
        GlassCard(backdrop, surfaceColor) {
            SectionLabel(stringResource(R.string.profile_section_parsed))
            Spacer(Modifier.height(8.dp))
            if (parsed.isEmpty()) {
                BasicText(
                    text = stringResource(R.string.profile_parsed_empty),
                    style = TextStyle(
                        color = Color.White.copy(alpha = 0.6f),
                        fontSize = 11.sp,
                        shadow = profileShadow
                    )
                )
            } else {
                parsed.forEachIndexed { index, entry ->
                    if (index > 0) Spacer(Modifier.height(10.dp))
                    ParsedRow(
                        entry = entry,
                        selected = entry.release == selectedRelease,
                        onSetProfile = { onSetProfile(entry.release) },
                        onDelete = { onDeleteProfile(entry.release) }
                    )
                }
            }
        }

        Spacer(Modifier.height(12.dp))
        BasicText(
            text = stringResource(R.string.profile_verify_note),
            style = TextStyle(
                color = Color.White.copy(alpha = 0.55f),
                fontSize = 11.sp,
                lineHeight = 15.sp,
                shadow = profileShadow
            )
        )
    }
}

@Composable
private fun ParsedSummary(image: ParsedBootImage, deviceKernel: String?) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            StatusDot(ok = image.missing.isEmpty())
            Spacer(Modifier.width(8.dp))
            BasicText(
                text = image.release,
                style = TextStyle(
                    color = Color.White,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    fontFamily = FontFamily.Monospace,
                    shadow = profileShadow
                ),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
        if (!deviceKernel.isNullOrEmpty() && deviceKernel != image.release) {
            Spacer(Modifier.height(6.dp))
            StatusLine(
                stringResource(R.string.profile_kernel_mismatch, deviceKernel),
                warn = true
            )
        }
        Spacer(Modifier.height(6.dp))
        BasicText(
            text = stringResource(
                R.string.profile_fields,
                image.derivedCount,
                image.inheritedCount,
                image.templateRelease
            ),
            style = TextStyle(
                color = Color.White.copy(alpha = 0.62f),
                fontSize = 11.sp,
                lineHeight = 15.sp,
                shadow = profileShadow
            )
        )
        if (image.missing.isNotEmpty()) {
            Spacer(Modifier.height(6.dp))
            StatusLine(
                stringResource(R.string.profile_missing, image.missing.joinToString()),
                warn = true
            )
        }
        if (image.notes.isNotEmpty()) {
            Spacer(Modifier.height(6.dp))
            StatusLine(image.notes.joinToString("; "), warn = false)
        }
        if (image.sections.isNotEmpty()) {
            var expanded by remember(image.release) { mutableStateOf(false) }
            Spacer(Modifier.height(8.dp))
            TextAction(
                if (expanded) stringResource(R.string.profile_hide_offsets)
                else stringResource(R.string.profile_show_offsets)
            ) { expanded = !expanded }
            if (expanded) {
                Spacer(Modifier.height(8.dp))
                Column {
                    image.sections.forEach { section ->
                        BasicText(
                            text = "[${section.name}]",
                            style = TextStyle(
                                color = Color.White.copy(alpha = 0.6f),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Medium,
                                shadow = profileShadow
                            )
                        )
                        section.entries.forEach { (key, value) ->
                            BasicText(
                                text = "  $key = $value",
                                style = TextStyle(
                                    color = Color.White.copy(alpha = 0.85f),
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    shadow = profileShadow
                                )
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun ParsedRow(
    entry: ProfileStore.Entry,
    selected: Boolean,
    onSetProfile: () -> Unit,
    onDelete: () -> Unit
) {
    Row(
        Modifier
            .fillMaxWidth()
            .then(if (selected) Modifier else Modifier.clickable(onClick = onSetProfile)),
        verticalAlignment = Alignment.CenterVertically
    ) {
        StatusDot(ok = selected)
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            BasicText(
                text = entry.release,
                style = TextStyle(
                    color = Color.White,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium,
                    fontFamily = FontFamily.Monospace,
                    shadow = profileShadow
                ),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(Modifier.height(3.dp))
            BasicText(
                text = buildString {
                    append(if (selected) stringResource(R.string.profile_selected_badge)
                        else stringResource(R.string.profile_tap_select))
                    if (entry.sourceName.isNotEmpty()) {
                        append(" ").append(
                            stringResource(R.string.profile_from, entry.sourceName)
                        )
                    }
                    append(" - ").append(formatDate(entry.savedAt))
                },
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.55f),
                    fontSize = 10.sp,
                    shadow = profileShadow
                ),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
        if (selected) {
            Spacer(Modifier.width(8.dp))
            BasicText(
                text = stringResource(R.string.profile_selected_badge),
                style = TextStyle(
                    color = profileAccent,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    shadow = profileShadow
                ),
                modifier = Modifier
                    .clip(RoundedCornerShape(16.dp))
                    .background(profileAccent.copy(alpha = 0.16f))
                    .padding(horizontal = 12.dp, vertical = 7.dp)
            )
        }
        Spacer(Modifier.width(8.dp))
        TextAction(stringResource(R.string.common_delete), subdued = true, onClick = onDelete)
    }
}

@Composable
private fun GlassCard(
    backdrop: Backdrop,
    surfaceColor: Color,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        Modifier
            .fillMaxWidth()
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
                    drawRect(Color.Black.copy(alpha = 0.14f))
                    drawRect(Color.White.copy(alpha = 0.06f))
                }
            )
            .padding(horizontal = 18.dp, vertical = 16.dp),
        content = content
    )
}

@Composable
private fun SectionLabel(text: String) {
    BasicText(
        text = text,
        style = TextStyle(
            color = Color.White.copy(alpha = 0.62f),
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium
        )
    )
}

@Composable
private fun StatusLine(text: String, warn: Boolean) {
    BasicText(
        text = text,
        style = TextStyle(
            color = if (warn) Color(0xFFFFB4AB) else Color.White.copy(alpha = 0.72f),
            fontSize = 10.sp,
            lineHeight = 14.sp,
            shadow = profileShadow
        )
    )
}

@Composable
private fun StatusDot(ok: Boolean) {
    Box(
        Modifier
            .size(7.dp)
            .clip(CircleShape)
            .background(if (ok) profileAccent else Color.White.copy(alpha = 0.28f))
    )
}

/** Small text button used where a full glass capsule would take too much room. */
@Composable
private fun TextAction(text: String, subdued: Boolean = false, onClick: () -> Unit) {
    BasicText(
        text = text,
        style = TextStyle(
            color = Color.White.copy(alpha = if (subdued) 0.55f else 0.85f),
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium,
            shadow = profileShadow
        ),
        modifier = Modifier
            .clip(RoundedRectangle(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 6.dp)
    )
}

/** URL entry for the OTA path; mirrors the command row's look on the Log tab. */
@Composable
private fun OtaUrlRow(onParseUrl: (String) -> Unit, enabled: Boolean) {
    var text by remember { mutableStateOf("") }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .weight(1f)
                .background(Color.White.copy(alpha = 0.08f), RoundedCornerShape(10.dp))
                .padding(horizontal = 10.dp, vertical = 8.dp)
        ) {
            if (text.isEmpty()) {
                BasicText(
                    text = "https://…/ota.zip",
                    style = TextStyle(
                        color = Color.White.copy(alpha = 0.4f),
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace
                    )
                )
            }
            BasicTextField(
                value = text,
                onValueChange = { text = it },
                singleLine = true,
                enabled = enabled,
                textStyle = TextStyle(
                    color = Color.White,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace
                ),
                cursorBrush = SolidColor(profileAccent),
                modifier = Modifier.fillMaxWidth()
            )
        }
        Spacer(Modifier.width(8.dp))
        BasicText(
            text = stringResource(R.string.profile_parse),
            modifier = Modifier
                .clickable(enabled = enabled) {
                    val link = text.trim()
                    if (link.isNotEmpty()) onParseUrl(link)
                }
                .padding(horizontal = 8.dp, vertical = 6.dp),
            style = TextStyle(
                color = profileAccent,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                shadow = profileShadow
            )
        )
    }
}

private fun formatDate(millis: Long): String =
    SimpleDateFormat("MM-dd HH:mm", Locale.US).format(Date(millis))

private val profileAccent = Color(0xFF0A84FF)

private val profileShadow = Shadow(
    color = Color.Black.copy(alpha = 0.45f),
    offset = Offset(0f, 1f),
    blurRadius = 6f
)
