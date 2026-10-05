"""Canonicalise text so obfuscated attacks look like plain ones before detection."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
# Cyrillic / Greek letters that render like Latin ones
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u",
})
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def strip_invisible(text: str) -> str:
    return text.translate(ZERO_WIDTH)


def decode_hidden(text: str) -> list[str]:
    """Decode base64 blobs that contain readable text (a common way to smuggle instructions)."""
    out = []
    for blob in B64_BLOB.findall(text):
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(c.isalpha() or c.isspace() for c in decoded) / max(len(decoded), 1) > 0.8:
            out.append(decoded)
    return out


def normalize(text: str) -> str:
    t = unicodedata.normalize("NFKC", strip_invisible(text))
    t = re.sub(r"(?<=\b\w) {2,}(?=\w\b)", " | ", t)                   # keep word breaks of spaced-out text
    t = t.translate(HOMOGLYPHS).lower()
    t = re.sub(r"(?<=\w)[\.\-_*](?=\w\b|\w[\.\-_*])", "", t)        # i.g.n.o.r.e -> ignore
    t = t.translate(LEET)
    t = re.sub(r"\s+", " ", t).strip()
    # i g n o r e  p r e v i o u s -> ignore previous (runs of single letters; double spaces mark word breaks)
    t = re.sub(r"\b(?:\w ){3,}\w\b", lambda m: m.group(0).replace(" ", ""), t)
    return t


def views(text: str) -> list[str]:
    """All representations worth scanning: normalised text plus decoded hidden payloads."""
    return [normalize(text)] + [normalize(h) for h in decode_hidden(text)]
