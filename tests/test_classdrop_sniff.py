import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from onetime_drop.classdrop.sniff import sniff, safe_filename, thumbnail
from onetime_drop.classdrop.multipart import parse


def _ooxml(kind: str, with_vba: bool = False, n_extra: int = 0) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        if kind == "docx":
            zf.writestr("word/document.xml", "<w:doc/>")
        elif kind == "pptx":
            zf.writestr("ppt/presentation.xml", "<p:pres/>")
        elif kind == "xlsx":
            zf.writestr("xl/workbook.xml", "<x:wb/>")
        if with_vba:
            zf.writestr("word/vbaProject.bin", "macro")
        for i in range(n_extra):
            zf.writestr(f"word/extra{i}.xml", "x")
    return buf.getvalue()


def test_jpeg_png_gif_pdf_webp():
    assert sniff(b"\xff\xd8\xff\xe0" + b"J" * 100) == "image/jpeg"
    assert sniff(b"\x89PNG\r\n\x1a\n" + b"P" * 10) == "image/png"
    assert sniff(b"GIF89a" + b"G" * 10) == "image/gif"
    assert sniff(b"GIF87a" + b"G" * 10) == "image/gif"
    assert sniff(b"%PDF-1.7\n" + b"P" * 10) == "application/pdf"
    assert sniff(b"RIFF\x12\x34\x56\x78WEBP" + b"W" * 10) == "image/webp"


def test_heic_heif():
    heic = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1"
    heif = b"\x00\x00\x00\x18ftypmif1\x00\x00\x00\x00"
    assert sniff(heic) == "image/heic"
    assert sniff(heif) == "image/heif"


def test_ooxml_ok():
    assert sniff(_ooxml("docx")) == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert sniff(_ooxml("pptx")) == "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    assert sniff(_ooxml("xlsx")) == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def test_renamed_exe_as_jpg_rejected():
    exe = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100
    assert sniff(exe) is None


def test_docm_with_vba_rejected():
    assert sniff(_ooxml("docx", with_vba=True)) is None


def test_zip_bomb_rejected():
    assert sniff(_ooxml("docx", n_extra=2001)) is None
    assert sniff(b"PK\x03\x04not-a-zip") is None


def test_plain_zip_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.txt", "hi")
    assert sniff(buf.getvalue()) is None


def test_unknown_none():
    assert sniff(b"") is None
    assert sniff(b"hi") is None
    assert sniff(b"\x00\x01\x02\x03\x04") is None


def test_safe_filename():
    assert safe_filename("../../etc/passwd") == "passwd"
    assert safe_filename("a/b\\c.txt") == "c.txt"
    assert safe_filename("my file (1).jpg") == "my file 1.jpg"
    assert safe_filename("") == "datei"
    assert safe_filename("...") == "datei"
    long = safe_filename("a" * 200)
    assert len(long) == 100


def test_thumbnail_png():
    from PIL import Image

    img = Image.new("RGB", (800, 200), (10, 20, 30))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    out = thumbnail(buf.getvalue(), "image/png")
    assert out is not None and out[:2] == b"\xff\xd8"
    with Image.open(io.BytesIO(out)) as t:
        assert max(t.size) <= 400


def test_thumbnail_rejects_nonimage():
    assert thumbnail(b"%PDF-1.4 xx", "application/pdf") is None
    assert thumbnail(b"zzz", "image/png") is None


def _encode(parts, boundary):
    body = b""
    for headers, payload in parts:
        body += f"--{boundary}\r\n".encode()
        for h in headers:
            body += h.encode() + b"\r\n"
        body += b"\r\n" + payload + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return body


def test_multipart_roundtrip():
    boundary = "BOUND12345"
    ctype = f"multipart/form-data; boundary={boundary}"
    file_bytes = b"\xff\xd8\xff fake-jpeg-bytes \x00\x01\x02"
    body = _encode(
        [
            (['Content-Disposition: form-data; name="title"'], "hello".encode()),
            (
                [
                    'Content-Disposition: form-data; name="upload"; filename="pic.jpg"',
                    "Content-Type: image/jpeg",
                ],
                file_bytes,
            ),
        ],
        boundary,
    )
    fields, files = parse(ctype, body, max_files=5, max_file_bytes=1000)
    assert fields == {"title": "hello"}
    assert len(files) == 1
    assert files[0][0] == "pic.jpg"
    assert files[0][1] == file_bytes


def test_multipart_limits():
    import pytest

    boundary = "B2"
    ctype = f"multipart/form-data; boundary={boundary}"
    one = _encode(
        [(['Content-Disposition: form-data; name="f"; filename="a.bin"'], b"X" * 10)],
        boundary,
    )
    with pytest.raises(ValueError):
        parse(ctype, one, max_files=5, max_file_bytes=5)
    two = _encode(
        [
            (['Content-Disposition: form-data; name="f1"; filename="a.bin"'], b"a"),
            (['Content-Disposition: form-data; name="f2"; filename="b.bin"'], b"b"),
        ],
        boundary,
    )
    with pytest.raises(ValueError):
        parse(ctype, two, max_files=1, max_file_bytes=100)
    big_text = _encode(
        [(['Content-Disposition: form-data; name="t"'], b"y" * 1001)], boundary
    )
    with pytest.raises(ValueError):
        parse(ctype, big_text, max_files=5, max_file_bytes=100)
    with pytest.raises(ValueError):
        parse("text/plain", b"junk", 5, 100)
    with pytest.raises(ValueError):
        parse(ctype, b"not a multipart body --", 5, 100)
