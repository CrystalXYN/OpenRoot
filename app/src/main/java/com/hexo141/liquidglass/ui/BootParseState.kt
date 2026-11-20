package com.hexo141.liquidglass.ui

/**
 * What the Profile tab knows about the last `boot.img` it read.
 *
 * Parsing is a few seconds of CPU work on a 64 MB file, so the screen renders these states instead
 * of blocking; [Ready] carries everything needed to show the offsets before they are saved.
 */
sealed interface BootParseState {

    data object Idle : BootParseState

    data class Running(val fileName: String) : BootParseState

    data class Failed(val message: String) : BootParseState

    data class Ready(val image: ParsedBootImage) : BootParseState
}

/** Result of one parse, flattened for the screen; the encoded profile stays in [MainActivity]. */
data class ParsedBootImage(
    val release: String,
    val fileName: String,
    val templateRelease: String,
    val derivedCount: Int,
    val inheritedCount: Int,
    /** Geometry the payload needs that the image could not prove. */
    val missing: List<String>,
    val notes: List<String>,
    val sections: List<Section>,
) {
    data class Section(val name: String, val entries: List<Pair<String, Long>>)
}
