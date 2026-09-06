from __future__ import annotations

import base64
import binascii
import re
import struct
import urllib.parse

from pydantic import BaseModel, ConfigDict, Field

MAX_DECODE_ROUNDS = 3
MAX_DECODE_OUTPUT = 1024 * 1024
MAX_PCAP_RECORDS = 10000
MAX_ROUTE_HINTS = 500


class CtfAdapterOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    adapter_id: str
    rendered: str
    observations: tuple[str, ...] = Field(default_factory=tuple)


def expanded_adapters(kind: object, category: object | None = None) -> tuple[str, ...]:
    value = getattr(kind, "value", str(kind))
    category_value = getattr(category, "value", str(category)) if category is not None else ""
    mapping = {
        "javascript": ("web-route-hints",),
        "html": ("web-route-hints",),
        "executable_pe": ("executable-metadata",),
        "executable_elf": ("executable-metadata",),
        "image": ("image-metadata",),
        "pcap": ("pcap-inventory",),
    }
    adapters = list(mapping.get(value, ()))
    if category_value == "crypto" and value in {"text", "json", "binary"}:
        adapters.append("encoding-layers")
    return tuple(adapters)


def _decode_layers(data: bytes) -> CtfAdapterOutput:
    seed = data.decode("utf-8", errors="ignore")[:MAX_DECODE_OUTPUT]
    rendered: list[str] = [seed]
    seen = {seed}
    frontier = [seed]
    observations: list[str] = []
    for _ in range(MAX_DECODE_ROUNDS):
        next_frontier: list[str] = []
        for text in frontier:
            compact = "".join(text.split())
            candidates: list[tuple[str, bytes]] = []
            if compact and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
                try:
                    candidates.append(("hex", bytes.fromhex(compact)))
                except ValueError:
                    pass
            if compact and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
                try:
                    padded = compact + "=" * (-len(compact) % 4)
                    candidates.append(("base64", base64.urlsafe_b64decode(padded)))
                except (binascii.Error, ValueError):
                    pass
            if "%" in text or "+" in text:
                decoded_url = urllib.parse.unquote_plus(text)
                if decoded_url != text:
                    candidates.append(("url", decoded_url.encode("utf-8")))
            for label, raw in candidates:
                if len(raw) > MAX_DECODE_OUTPUT:
                    continue
                decoded = raw.decode("utf-8", errors="ignore")
                if decoded and decoded not in seen:
                    seen.add(decoded)
                    rendered.append(decoded)
                    next_frontier.append(decoded)
                    observations.append(f"decoded {label} layer")
        frontier = next_frontier
        if not frontier:
            break
    return CtfAdapterOutput(
        adapter_id="encoding-layers",
        rendered="\n".join(rendered),
        observations=tuple(observations),
    )


def _web_route_hints(data: bytes) -> CtfAdapterOutput:
    text = data.decode("utf-8", errors="replace")
    values: list[str] = []
    pattern = re.compile(r"(?P<q>['\"])(?P<value>/(?:api/)?[A-Za-z0-9_./?=&%{}:-]{1,240})(?P=q)")
    for match in pattern.finditer(text):
        value = match.group("value")
        if value not in values:
            values.append(value)
        if len(values) >= MAX_ROUTE_HINTS:
            break
    return CtfAdapterOutput(
        adapter_id="web-route-hints",
        rendered="\n".join(values),
        observations=(f"route hints: {len(values)}",),
    )


def _image_metadata(data: bytes) -> CtfAdapterOutput:
    observations: list[str] = []
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        width, height = struct.unpack(">II", data[16:24])
        observations.extend(("format=PNG", f"width={width}", f"height={height}"))
    elif data.startswith(b"\xff\xd8\xff"):
        observations.append("format=JPEG")
    elif data.startswith((b"GIF87a", b"GIF89a")) and len(data) >= 10:
        width, height = struct.unpack("<HH", data[6:10])
        observations.extend(("format=GIF", f"width={width}", f"height={height}"))
    else:
        observations.append("format=unknown")
    return CtfAdapterOutput(
        adapter_id="image-metadata",
        rendered="\n".join(observations),
        observations=tuple(observations),
    )


def _pcap_inventory(data: bytes) -> CtfAdapterOutput:
    observations: list[str] = []
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        offset = 0
        blocks = 0
        while offset + 12 <= len(data) and blocks < MAX_PCAP_RECORDS:
            block_len = int.from_bytes(data[offset + 4 : offset + 8], "little")
            if block_len < 12 or offset + block_len > len(data):
                break
            blocks += 1
            offset += block_len
        observations.extend(("format=pcapng", f"blocks={blocks}"))
    elif data[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"} and len(data) >= 24:
        little = data[:4] == b"\xd4\xc3\xb2\xa1"
        byteorder = "little" if little else "big"
        offset = 24
        packets = 0
        while offset + 16 <= len(data) and packets < MAX_PCAP_RECORDS:
            incl_len = int.from_bytes(data[offset + 8 : offset + 12], byteorder)
            if incl_len < 0 or offset + 16 + incl_len > len(data):
                break
            packets += 1
            offset += 16 + incl_len
        observations.extend(("format=pcap", f"packets={packets}"))
    else:
        observations.append("format=unknown")
    return CtfAdapterOutput(
        adapter_id="pcap-inventory",
        rendered="\n".join(observations),
        observations=tuple(observations),
    )


def _executable_metadata(data: bytes) -> CtfAdapterOutput:
    observations: list[str] = []
    if data.startswith(b"MZ"):
        observations.append("format=PE")
        if len(data) >= 0x40:
            pe_offset = int.from_bytes(data[0x3C:0x40], "little")
            if pe_offset + 6 <= len(data) and data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                machine = int.from_bytes(data[pe_offset + 4 : pe_offset + 6], "little")
                observations.append(f"machine=0x{machine:04x}")
    elif data.startswith(b"\x7fELF") and len(data) >= 20:
        observations.extend(("format=ELF", f"class={data[4]}", f"endianness={data[5]}"))
        endian = "little" if data[5] == 1 else "big"
        machine = int.from_bytes(data[18:20], endian)
        observations.append(f"machine=0x{machine:04x}")
    else:
        observations.append("format=unknown")
    return CtfAdapterOutput(
        adapter_id="executable-metadata",
        rendered="\n".join(observations),
        observations=tuple(observations),
    )


def run_category_adapter(adapter_id: str, data: bytes) -> CtfAdapterOutput:
    if adapter_id == "encoding-layers":
        return _decode_layers(data)
    if adapter_id == "web-route-hints":
        return _web_route_hints(data)
    if adapter_id == "image-metadata":
        return _image_metadata(data)
    if adapter_id == "pcap-inventory":
        return _pcap_inventory(data)
    if adapter_id == "executable-metadata":
        return _executable_metadata(data)
    raise ValueError(f"unsupported category adapter: {adapter_id}")
