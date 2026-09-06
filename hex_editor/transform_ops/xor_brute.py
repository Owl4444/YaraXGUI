# -*- coding: utf-8 -*-
"""Single-byte XOR brute-force: decrypt or report top candidates."""

from __future__ import annotations

from ..transforms import (TransformError, TransformParam, parse_bytes_input,
                          register_transform)


# ── scoring helpers ────────────────────────────────────────────────

# Relative frequencies of letters in English text, a-z. Sum ≈ 1.0.
_ENGLISH_FREQ = {
    'a': .0817, 'b': .0149, 'c': .0278, 'd': .0425, 'e': .1270, 'f': .0223,
    'g': .0202, 'h': .0609, 'i': .0697, 'j': .0015, 'k': .0077, 'l': .0403,
    'm': .0241, 'n': .0675, 'o': .0751, 'p': .0193, 'q': .0010, 'r': .0599,
    's': .0633, 't': .0906, 'u': .0276, 'v': .0098, 'w': .0236, 'x': .0015,
    'y': .0197, 'z': .0007,
}

# Known magic bytes for quick file-type detection.
_MAGIC_PRESETS = {
    "(auto)": None,  # try all of the below
    "MZ (PE/DOS)": b"MZ",
    "PE\\0\\0": b"PE\x00\x00",
    "PK (ZIP/JAR/Office)": b"PK\x03\x04",
    "%PDF": b"%PDF-",
    "\\x7fELF": b"\x7fELF",
    "GIF8": b"GIF8",
    "\\x89PNG": b"\x89PNG\r\n\x1a\n",
    "\\xff\\xd8\\xff (JPEG)": b"\xff\xd8\xff",
    "RIFF": b"RIFF",
    "{ (JSON)": b"{",
    "<?xml": b"<?xml",
    "<html": b"<html",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "Rar!": b"Rar!\x1a\x07",
}

_AUTO_MAGICS = [v for k, v in _MAGIC_PRESETS.items()
                if k != "(auto)" and v is not None]


def _xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _printable_score(buf: bytes) -> float:
    """Fraction of bytes that are printable ASCII or common whitespace."""
    if not buf:
        return 0.0
    good = 0
    for b in buf:
        if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D):
            good += 1
    return good / len(buf)


def _english_score(buf: bytes) -> float:
    """Higher is better. Uses simple letter-frequency correlation.

    Not quite chi-squared — we return a score in [0, 1]-ish where English
    text clusters near 1 and random garbage near 0.
    """
    if not buf:
        return 0.0
    counts = [0] * 26
    letters = 0
    for b in buf:
        if 0x41 <= b <= 0x5A:
            counts[b - 0x41] += 1
            letters += 1
        elif 0x61 <= b <= 0x7A:
            counts[b - 0x61] += 1
            letters += 1
    if letters == 0:
        return 0.0
    # Correlate observed frequency with expected English frequency.
    score = 0.0
    for i in range(26):
        observed = counts[i] / letters
        expected = _ENGLISH_FREQ[chr(ord('a') + i)]
        score += min(observed, expected)  # overlap coefficient
    # Weight by how much of the buffer was actually letters.
    letter_ratio = letters / len(buf)
    return score * (0.5 + 0.5 * letter_ratio)


def _find_key_for_magic(data: bytes, magic: bytes) -> int | None:
    """Return the single-byte key that makes *data* start with *magic*,
    or ``None`` if no such key exists."""
    if not data or not magic or len(data) < len(magic):
        return None
    # For a single-byte XOR, key is simply data[0] ^ magic[0]; verify rest.
    candidate = data[0] ^ magic[0]
    for i in range(1, len(magic)):
        if data[i] ^ candidate != magic[i]:
            return None
    return candidate


def _resolve_mode(data: bytes, mode: str,
                  magic_choice: str, known_text: str) -> int:
    """Pick the winning key. Raises TransformError on failure."""
    if not data:
        raise TransformError("Selection is empty.")

    if mode == "auto (printable)":
        best_k, best_score = 0, -1.0
        for k in range(256):
            s = _printable_score(_xor_bytes(data[:4096], k))
            if s > best_score:
                best_k, best_score = k, s
        return best_k

    if mode == "auto (english)":
        best_k, best_score = 0, -1.0
        for k in range(256):
            s = _english_score(_xor_bytes(data[:4096], k))
            if s > best_score:
                best_k, best_score = k, s
        return best_k

    if mode == "magic header":
        if magic_choice == "(auto)":
            for magic in _AUTO_MAGICS:
                k = _find_key_for_magic(data, magic)
                if k is not None:
                    return k
            raise TransformError("No single-byte key produces any known magic header.")
        magic = _MAGIC_PRESETS.get(magic_choice)
        if magic is None:
            raise TransformError(f"Unknown magic preset: {magic_choice}")
        k = _find_key_for_magic(data, magic)
        if k is None:
            raise TransformError(f"No single-byte key produces {magic_choice!r}.")
        return k

    if mode == "known plaintext":
        needle = parse_bytes_input(known_text)
        if not needle:
            raise TransformError("Known plaintext is empty.")
        # Try every key, look for the needle in the output.
        for k in range(256):
            if needle in _xor_bytes(data, k):
                return k
        raise TransformError(
            f"No single-byte key produces the given plaintext in the selection."
        )

    raise TransformError(f"Unknown mode: {mode}")


# ── decrypt op (length-preserving) ────────────────────────────────

@register_transform(
    name="XOR brute-force (decrypt)",
    category="Bitwise",
    params=[
        TransformParam("mode", "Mode", "choice",
                       choices=["auto (printable)", "auto (english)",
                                "magic header", "known plaintext"],
                       default="auto (printable)"),
        TransformParam("magic", "Magic header", "choice",
                       choices=list(_MAGIC_PRESETS.keys()),
                       default="(auto)",
                       help="Used when Mode = 'magic header'."),
        TransformParam("plaintext", "Known plaintext", "text",
                       placeholder='"http" or 68747470',
                       help="Used when Mode = 'known plaintext'."),
    ],
    length_preserving=True,
    help="Try all 256 single-byte XOR keys, pick the best by the chosen criterion, "
         "and apply it.",
)
def xor_brute_decrypt(data: bytes, params: dict) -> bytes:
    mode = params.get("mode", "auto (printable)")
    magic_choice = params.get("magic", "(auto)")
    known = params.get("plaintext", "")
    key = _resolve_mode(data, mode, magic_choice, known)
    return _xor_bytes(data, key)


# ── report op (text output, top-N candidates) ─────────────────────

@register_transform(
    name="XOR brute-force (report)",
    category="Bitwise",
    params=[
        TransformParam("score", "Score by", "choice",
                       choices=["printable", "english"],
                       default="printable"),
        TransformParam("top", "Top N", "int", default="10"),
        TransformParam("preview", "Preview bytes", "int", default="48"),
    ],
    help="Try all 256 single-byte XOR keys; output the top-N candidates as text.",
)
def xor_brute_report(data: bytes, params: dict) -> bytes:
    if not data:
        raise TransformError("Selection is empty.")
    score_mode = params.get("score", "printable")
    try:
        top = max(1, min(256, int(params.get("top", 10) or 10)))
        preview = max(1, min(4096, int(params.get("preview", 48) or 48)))
    except (TypeError, ValueError) as e:
        raise TransformError(f"Invalid integer parameter: {e}") from e

    scorer = _printable_score if score_mode == "printable" else _english_score
    sample = data[:4096]

    scored: list[tuple[int, float]] = []
    for k in range(256):
        scored.append((k, scorer(_xor_bytes(sample, k))))
    scored.sort(key=lambda t: t[1], reverse=True)

    def _preview(b: bytes) -> str:
        out = []
        for x in b:
            if 0x20 <= x <= 0x7E:
                out.append(chr(x))
            elif x in (0x09, 0x0A, 0x0D):
                out.append(" ")
            else:
                out.append(".")
        return "".join(out)

    lines = [f"XOR brute-force report  (scored by {score_mode}, "
             f"sample {len(sample)} bytes)",
             "-" * 72,
             f"{'key':>5}  {'score':>7}  preview"]
    for k, s in scored[:top]:
        dec = _xor_bytes(data[:preview], k)
        lines.append(f"  0x{k:02X}  {s:7.4f}  {_preview(dec)}")
    return "\n".join(lines).encode("ascii")
