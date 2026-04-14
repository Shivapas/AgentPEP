"""6-Pass ResponseNormalizer — Unicode normalization for response body analysis.

Sprint 46 — APEP-365: Implements a 6-pass Unicode normalization pipeline that
prepares response text for injection detection by stripping evasion characters
and normalizing confusable glyphs.

The 6 passes are:
  1. NFC — Canonical Composition (compose precomposed chars)
  2. NFKC — Compatibility Composition (normalise ligatures, width variants)
  3. Confusable Map — Map Unicode confusables to ASCII equivalents
  4. Zero-Width Strip — Remove zero-width joiners, non-joiners, spaces
  5. BiDi Strip — Remove bidirectional override / embedding characters
  6. Homoglyph Normalize — Map visually similar characters to ASCII base forms

Thread-safe: all operations are pure functions on immutable lookup tables.
"""

from __future__ import annotations

import logging
import time
import unicodedata

from app.models.fetch_proxy import (
    NormalizationPass,
    NormalizationPassResult,
    NormalizationResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pass 3: Confusable character mapping (subset of Unicode confusables)
# Maps visually similar Unicode chars to their ASCII equivalents.
# ---------------------------------------------------------------------------

_CONFUSABLE_MAP: dict[str, str] = {
    "\u0410": "A",  # Cyrillic А -> Latin A
    "\u0412": "B",  # Cyrillic В -> Latin B
    "\u0421": "C",  # Cyrillic С -> Latin C
    "\u0415": "E",  # Cyrillic Е -> Latin E
    "\u041d": "H",  # Cyrillic Н -> Latin H
    "\u041a": "K",  # Cyrillic К -> Latin K
    "\u041c": "M",  # Cyrillic М -> Latin M
    "\u041e": "O",  # Cyrillic О -> Latin O
    "\u0420": "P",  # Cyrillic Р -> Latin P
    "\u0422": "T",  # Cyrillic Т -> Latin T
    "\u0425": "X",  # Cyrillic Х -> Latin X
    "\u0430": "a",  # Cyrillic а -> Latin a
    "\u0435": "e",  # Cyrillic е -> Latin e
    "\u043e": "o",  # Cyrillic о -> Latin o
    "\u0440": "p",  # Cyrillic р -> Latin p
    "\u0441": "c",  # Cyrillic с -> Latin c
    "\u0443": "y",  # Cyrillic у -> Latin y
    "\u0445": "x",  # Cyrillic х -> Latin x
    "\u0456": "i",  # Cyrillic і -> Latin i
    "\u0458": "j",  # Cyrillic ј -> Latin j
    "\u0455": "s",  # Cyrillic ѕ -> Latin s
    "\u04bb": "h",  # Cyrillic һ -> Latin h
    "\u0501": "d",  # Cyrillic ԁ -> Latin d
    "\u051b": "q",  # Cyrillic ԛ -> Latin q
    "\u051d": "w",  # Cyrillic ԝ -> Latin w
    # Greek confusables
    "\u0391": "A",  # Greek Α -> Latin A
    "\u0392": "B",  # Greek Β -> Latin B
    "\u0395": "E",  # Greek Ε -> Latin E
    "\u0396": "Z",  # Greek Ζ -> Latin Z
    "\u0397": "H",  # Greek Η -> Latin H
    "\u0399": "I",  # Greek Ι -> Latin I
    "\u039a": "K",  # Greek Κ -> Latin K
    "\u039c": "M",  # Greek Μ -> Latin M
    "\u039d": "N",  # Greek Ν -> Latin N
    "\u039f": "O",  # Greek Ο -> Latin O
    "\u03a1": "P",  # Greek Ρ -> Latin P
    "\u03a4": "T",  # Greek Τ -> Latin T
    "\u03a5": "Y",  # Greek Υ -> Latin Y
    "\u03a7": "X",  # Greek Χ -> Latin X
    "\u03bf": "o",  # Greek ο -> Latin o
    "\u03b1": "a",  # Greek α -> Latin a (visual)
    # Fullwidth Latin
    "\uff21": "A",
    "\uff22": "B",
    "\uff23": "C",
    "\uff24": "D",
    "\uff25": "E",
    "\uff26": "F",
    "\uff27": "G",
    "\uff28": "H",
    "\uff29": "I",
    "\uff2a": "J",
    "\uff2b": "K",
    "\uff2c": "L",
    "\uff2d": "M",
    "\uff2e": "N",
    "\uff2f": "O",
    "\uff30": "P",
    "\uff31": "Q",
    "\uff32": "R",
    "\uff33": "S",
    "\uff34": "T",
    "\uff35": "U",
    "\uff36": "V",
    "\uff37": "W",
    "\uff38": "X",
    "\uff39": "Y",
    "\uff3a": "Z",
    "\uff41": "a",
    "\uff42": "b",
    "\uff43": "c",
    "\uff44": "d",
    "\uff45": "e",
    "\uff46": "f",
    "\uff47": "g",
    "\uff48": "h",
    "\uff49": "i",
    "\uff4a": "j",
    "\uff4b": "k",
    "\uff4c": "l",
    "\uff4d": "m",
    "\uff4e": "n",
    "\uff4f": "o",
    "\uff50": "p",
    "\uff51": "q",
    "\uff52": "r",
    "\uff53": "s",
    "\uff54": "t",
    "\uff55": "u",
    "\uff56": "v",
    "\uff57": "w",
    "\uff58": "x",
    "\uff59": "y",
    "\uff5a": "z",
    # Mathematical/styled letters (common evasion)
    "\U0001d400": "A",  # Mathematical Bold Capital A
    "\U0001d401": "B",
    "\U0001d402": "C",
    "\U0001d41a": "a",  # Mathematical Bold Small A
    "\U0001d41b": "b",
    "\U0001d41c": "c",
    # Special characters
    "\u00a0": " ",  # Non-breaking space -> regular space
    "\u2000": " ",  # En quad
    "\u2001": " ",  # Em quad
    "\u2002": " ",  # En space
    "\u2003": " ",  # Em space
    "\u2004": " ",  # Three-per-em space
    "\u2005": " ",  # Four-per-em space
    "\u2006": " ",  # Six-per-em space
    "\u2007": " ",  # Figure space
    "\u2008": " ",  # Punctuation space
    "\u2009": " ",  # Thin space
    "\u200a": " ",  # Hair space
    "\u3000": " ",  # Ideographic space
}

# Build a translation table for fast confusable mapping
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLE_MAP)

# ---------------------------------------------------------------------------
# Pass 4: Zero-width characters to strip
# ---------------------------------------------------------------------------

_ZERO_WIDTH_CHARS: set[str] = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\u2060",  # Word joiner
    "\ufeff",  # Zero-width no-break space (BOM)
    "\u00ad",  # Soft hyphen
    "\u034f",  # Combining grapheme joiner
    "\u180e",  # Mongolian vowel separator
}

# ---------------------------------------------------------------------------
# Pass 5: Bidirectional override/embedding characters to strip
# ---------------------------------------------------------------------------

_BIDI_CHARS: set[str] = {
    "\u200e",  # Left-to-right mark
    "\u200f",  # Right-to-left mark
    "\u202a",  # Left-to-right embedding
    "\u202b",  # Right-to-left embedding
    "\u202c",  # Pop directional formatting
    "\u202d",  # Left-to-right override
    "\u202e",  # Right-to-left override
    "\u2066",  # Left-to-right isolate
    "\u2067",  # Right-to-left isolate
    "\u2068",  # First strong isolate
    "\u2069",  # Pop directional isolate
}

# ---------------------------------------------------------------------------
# Pass 6: Homoglyph normalization (visual similarity mapping)
# ---------------------------------------------------------------------------

_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0131": "i",  # Dotless i
    "\u0130": "I",  # Dotted I
    "\u017f": "s",  # Long s
    "\u1e9b": "s",  # Latin small letter long s with dot above
    "\u00df": "ss",  # German sharp s
    "\u0111": "d",  # Latin small letter d with stroke
    "\u0110": "D",  # Latin capital letter D with stroke
    "\u0142": "l",  # Latin small letter l with stroke
    "\u0141": "L",  # Latin capital letter L with stroke
    "\u00f8": "o",  # Latin small letter o with stroke
    "\u00d8": "O",  # Latin capital letter O with stroke
    "\u0127": "h",  # Latin small letter h with stroke
    "\u0126": "H",  # Latin capital letter H with stroke
    "\u0167": "t",  # Latin small letter t with stroke
    "\u0166": "T",  # Latin capital letter T with stroke
    "\u2013": "-",  # En dash
    "\u2014": "-",  # Em dash
    "\u2015": "-",  # Horizontal bar
    "\u2018": "'",  # Left single quotation mark
    "\u2019": "'",  # Right single quotation mark
    "\u201c": '"',  # Left double quotation mark
    "\u201d": '"',  # Right double quotation mark
    "\u2026": "...",  # Horizontal ellipsis
    "\u00b7": ".",  # Middle dot
    "\u2022": "*",  # Bullet
    "\u2024": ".",  # One dot leader
}


# ---------------------------------------------------------------------------
# ResponseNormalizer
# ---------------------------------------------------------------------------


class ResponseNormalizer:
    """6-pass Unicode normalization pipeline for response body text.

    Each pass strips or maps a class of Unicode evasion characters,
    producing a canonicalized ASCII-like string suitable for injection
    detection.  Thread-safe and stateless.
    """

    def normalize(self, text: str) -> NormalizationResult:
        """Run all 6 normalization passes and return aggregate results."""
        if not text:
            return NormalizationResult(
                original_length=0,
                normalized_length=0,
                total_changes=0,
                passes=[],
                normalized_text="",
            )

        original_length = len(text)
        pass_results: list[NormalizationPassResult] = []
        current = text

        # Pass 1: NFC — Canonical Composition
        current, p1 = self._pass_nfc(current)
        pass_results.append(p1)

        # Pass 2: NFKC — Compatibility Composition
        current, p2 = self._pass_nfkc(current)
        pass_results.append(p2)

        # Pass 3: Confusable character mapping
        current, p3 = self._pass_confusable_map(current)
        pass_results.append(p3)

        # Pass 4: Zero-width character stripping
        current, p4 = self._pass_zero_width_strip(current)
        pass_results.append(p4)

        # Pass 5: BiDi character stripping
        current, p5 = self._pass_bidi_strip(current)
        pass_results.append(p5)

        # Pass 6: Homoglyph normalization
        current, p6 = self._pass_homoglyph_normalize(current)
        pass_results.append(p6)

        total_changes = sum(p.changes_made + p.characters_stripped for p in pass_results)

        return NormalizationResult(
            original_length=original_length,
            normalized_length=len(current),
            total_changes=total_changes,
            passes=pass_results,
            normalized_text=current,
        )

    # --- Individual passes ---

    def _pass_nfc(self, text: str) -> tuple[str, NormalizationPassResult]:
        """Pass 1: NFC canonical composition."""
        result = unicodedata.normalize("NFC", text)
        changes = sum(1 for a, b in zip(text, result) if a != b) + abs(len(text) - len(result))
        return result, NormalizationPassResult(
            pass_name=NormalizationPass.NFC,
            applied=True,
            changes_made=changes,
            description="Canonical Composition (NFC)",
        )

    def _pass_nfkc(self, text: str) -> tuple[str, NormalizationPassResult]:
        """Pass 2: NFKC compatibility composition."""
        result = unicodedata.normalize("NFKC", text)
        changes = sum(1 for a, b in zip(text, result) if a != b) + abs(len(text) - len(result))
        return result, NormalizationPassResult(
            pass_name=NormalizationPass.NFKC,
            applied=True,
            changes_made=changes,
            description="Compatibility Composition (NFKC)",
        )

    def _pass_confusable_map(self, text: str) -> tuple[str, NormalizationPassResult]:
        """Pass 3: Map Unicode confusables to ASCII equivalents."""
        result = text.translate(_CONFUSABLE_TABLE)
        changes = sum(1 for a, b in zip(text, result) if a != b)
        return result, NormalizationPassResult(
            pass_name=NormalizationPass.CONFUSABLE_MAP,
            applied=True,
            changes_made=changes,
            description="Confusable character mapping to ASCII",
        )

    def _pass_zero_width_strip(self, text: str) -> tuple[str, NormalizationPassResult]:
        """Pass 4: Strip zero-width characters."""
        stripped = 0
        chars: list[str] = []
        for ch in text:
            if ch in _ZERO_WIDTH_CHARS:
                stripped += 1
            else:
                chars.append(ch)
        result = "".join(chars)
        return result, NormalizationPassResult(
            pass_name=NormalizationPass.ZERO_WIDTH_STRIP,
            applied=True,
            characters_stripped=stripped,
            description="Zero-width character removal",
        )

    def _pass_bidi_strip(self, text: str) -> tuple[str, NormalizationPassResult]:
        """Pass 5: Strip bidirectional override/embedding characters."""
        stripped = 0
        chars: list[str] = []
        for ch in text:
            if ch in _BIDI_CHARS:
                stripped += 1
            else:
                chars.append(ch)
        result = "".join(chars)
        return result, NormalizationPassResult(
            pass_name=NormalizationPass.BIDI_STRIP,
            applied=True,
            characters_stripped=stripped,
            description="Bidirectional control character removal",
        )

    def _pass_homoglyph_normalize(self, text: str) -> tuple[str, NormalizationPassResult]:
        """Pass 6: Normalize homoglyphs to ASCII base forms."""
        changes = 0
        chars: list[str] = []
        for ch in text:
            replacement = _HOMOGLYPH_MAP.get(ch)
            if replacement is not None:
                chars.append(replacement)
                changes += 1
            else:
                chars.append(ch)
        result = "".join(chars)
        return result, NormalizationPassResult(
            pass_name=NormalizationPass.HOMOGLYPH_NORMALIZE,
            applied=True,
            changes_made=changes,
            description="Homoglyph normalization to ASCII base forms",
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

response_normalizer = ResponseNormalizer()
