"""Bounded multipart/form-data parser (stdlib, bytes.find based, no email/cgi module).

Linear in the body size: parts are located by boundary search, never line by line.
Limits: part count, header bytes per part, file count, bytes per file and per text field.
"""
from __future__ import annotations

import re

_TEXT_FIELD_MAX = 1000
_HEADER_MAX = 2048
_EXTRA_PARTS = 8  # text fields allowed besides files
_BOUNDARY_RE = re.compile(r'boundary="?([0-9A-Za-z\'()+_,./:=? -]{1,70})"?(?:;|$)', re.I)
_DISP_RE = re.compile(r'^content-disposition:\s*form-data\s*;(.*)$', re.I | re.M)
_PARAM_RE = re.compile(r'(name|filename)="([^"\r\n]*)"', re.I)


def _boundary(content_type: str) -> bytes:
    if not isinstance(content_type, str) or not content_type.lower().startswith("multipart/form-data"):
        raise ValueError("malformed content-type")
    m = _BOUNDARY_RE.search(content_type)
    if not m:
        raise ValueError("missing boundary")
    return m.group(1).rstrip(" ").encode("ascii")


def parse(content_type: str, body: bytes, max_files: int, max_file_bytes: int
          ) -> tuple[dict[str, str], list[tuple[str, bytes]]]:
    """Return (text fields, [(filename, data)]); ValueError on anything malformed or over limit."""
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise ValueError("malformed body")
    raw = body if isinstance(body, bytes) else bytes(body)
    delim = b"--" + _boundary(content_type)
    sep = b"\r\n" + delim
    if not raw.startswith(delim):
        raise ValueError("body does not start with boundary")
    pos = len(delim)
    fields: dict[str, str] = {}
    files: list[tuple[str, bytes]] = []
    parts = 0
    while True:
        if raw[pos:pos + 2] == b"--":
            return fields, files  # closing delimiter
        if raw[pos:pos + 2] != b"\r\n":
            raise ValueError("malformed delimiter")
        pos += 2
        hend = raw.find(b"\r\n\r\n", pos, pos + _HEADER_MAX + 4)
        if hend < 0:
            raise ValueError("part header missing or too long")
        nxt = raw.find(sep, hend + 4)
        if nxt < 0:
            raise ValueError("unterminated part")
        parts += 1
        if parts > max_files + _EXTRA_PARTS:
            raise ValueError("too many parts")
        try:
            headers = raw[pos:hend].decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("bad part header") from None
        disp = _DISP_RE.search(headers)
        if not disp:
            raise ValueError("missing content-disposition")
        params = {k.lower(): v for k, v in _PARAM_RE.findall(disp.group(1))}
        name = params.get("name")
        if not name:
            raise ValueError("part without name")
        size = nxt - (hend + 4)
        if "filename" in params:
            if size > max_file_bytes:
                raise ValueError("file too big")
            files.append((params["filename"], raw[hend + 4:nxt]))
            if len(files) > max_files:
                raise ValueError("too many files")
        else:
            if size > _TEXT_FIELD_MAX:
                raise ValueError("text field too big")
            try:
                fields[name] = raw[hend + 4:nxt].decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("bad text field") from None
        pos = nxt + len(sep)
