"""Magic-byte sniffing, safe filenames and thumbnails (ClassDrop upload rules)."""

from __future__ import annotations

import io
import zipfile

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
PPTX_MIME = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

_MAX_UNCOMPRESSED = 200 * 1024 * 1024
_MAX_ENTRIES = 2000

_HEIC_BRANDS = (b"heic", b"heix", b"hevc", b"hevx")
_HEIF_BRANDS = (b"mif1", b"msf1", b"heif", b"heis", b"hems", b"hevm", b"hevs")


def _sniff_heic_heif(data: bytes) -> str | None:
    if len(data) < 12 or data[4:8] != b"ftyp":
        return None
    try:
        box_size = int.from_bytes(data[0:4], "big")
    except Exception:
        return None
    if box_size < 8 and box_size != 0:
        return None
    end = 4 + box_size if 8 <= box_size <= len(data) else min(len(data), 32)
    payload = data[8:end].lower()
    for brand in _HEIC_BRANDS:
        if brand in payload:
            return "image/heic"
    for brand in _HEIF_BRANDS:
        if brand in payload:
            return "image/heif"
    # Unknown ftyp brand: treat bare mif/heic family conservatively.
    major = data[8:12].lower()
    if major.startswith(b"hei"):
        return "image/heic"
    if major.startswith(b"mif") or major.startswith(b"msf"):
        return "image/heif"
    return None


def _sniff_ooxml(data: bytes) -> str | None:
    if len(data) < 4 or data[0:2] != b"PK":
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            names = zf.namelist()
    except Exception:
        return None
    if "[Content_Types].xml" not in names:
        return None
    lowered = [n.lower() for n in names]
    if any(n == "vbaproject.bin" or n.endswith("/vbaproject.bin") for n in lowered):
        return None
    if len(infos) > _MAX_ENTRIES:
        return None
    try:
        total = sum(i.file_size for i in infos)
    except Exception:
        return None
    if total > _MAX_UNCOMPRESSED:
        return None
    has_word = any(n.startswith("word/") for n in names)
    has_ppt = any(n.startswith("ppt/") for n in names)
    has_xl = any(n.startswith("xl/") for n in names)
    if has_word:
        return DOCX_MIME
    if has_ppt:
        return PPTX_MIME
    if has_xl:
        return XLSX_MIME
    return None


def sniff(data: bytes) -> str | None:
    """Return MIME for supported types by magic bytes, else None."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    if len(data) < 3:
        return None
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if len(data) >= 6 and data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if len(data) >= 5 and data[:5] == b"%PDF-":
        return "application/pdf"
    if len(data) >= 12 and data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    heic = _sniff_heic_heif(data)
    if heic is not None:
        return heic
    ooxml = _sniff_ooxml(data)
    if ooxml is not None:
        return ooxml
    return None


_ALLOWED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._ -")


def safe_filename(name: str) -> str:
    """Basename-only sanitizer; fallback 'datei'."""
    if not isinstance(name, str):
        return "datei"
    base = name.replace("\\", "/").split("/")[-1].strip()
    cleaned = "".join(c for c in base if c in _ALLOWED).strip()
    if cleaned in ("", ".", "..") or cleaned.strip(" .") == "":
        return "datei"
    if len(cleaned) > 100:
        cleaned = cleaned[:100]
        if cleaned in ("", ".", ".."):
            return "datei"
    return cleaned


def thumbnail(data: bytes, mime: str) -> bytes | None:
    """400px JPEG thumbnail via Pillow; None when unavailable/failing."""
    try:
        if not isinstance(mime, str) or not mime.startswith("image/"):
            return None
        if not isinstance(data, (bytes, bytearray)) or not data:
            return None
        from PIL import Image
    except Exception:
        return None
    try:
        import warnings
        Image.MAX_IMAGE_PIXELS = int(25e6)
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            img = Image.open(io.BytesIO(bytes(data)))
        with img:
            if img.width * img.height > 25e6:
                return None
            img.draft("RGB", (800, 800))
            img.load()
            rgb = img.convert("RGB")
            rgb.thumbnail((400, 400), Image.LANCZOS)
            out = io.BytesIO()
            rgb.save(out, format="JPEG", quality=80)
            return out.getvalue()
    except Exception:
        return None


def selftest() -> None:
    assert sniff(b"\xff\xd8\xff\xe0junk") == "image/jpeg"
    assert sniff(b"\x89PNG\r\n\x1a\nrest") == "image/png"
    assert sniff(b"GIF89arest") == "image/gif"
    assert sniff(b"%PDF-1.4 rest") == "application/pdf"
    assert sniff(b"RIFF\x00\x00\x00\x00WEBPxx") == "image/webp"
    assert sniff(b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00") == "image/heic"
    assert sniff(b"\x00\x00\x00\x18ftypmif1\x00\x00\x00\x00") == "image/heif"
    assert sniff(b"MZ\x90\x00exe-body") is None
    assert sniff(b"hello world") is None
    assert safe_filename("../../etc/passwd") == "passwd"
    assert safe_filename("a/b\\c.txt") == "c.txt"
    assert safe_filename("") == "datei"
    assert len(safe_filename("a" * 200)) == 100
    assert thumbnail(b"not-an-image", "image/png") is None
    assert thumbnail(b"%PDF-1.4 x", "application/pdf") is None
    try:
        from PIL import Image
    except Exception:
        return
    img = Image.new("RGB", (800, 100), (255, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    thumb = thumbnail(buf.getvalue(), "image/png")
    assert thumb is not None and thumb[:3] == b"\xff\xd8\xff"
    with Image.open(io.BytesIO(thumb)) as t:
        assert max(t.size) <= 400


if __name__ == "__main__":
    selftest()
    print("sniff selftest ok")
