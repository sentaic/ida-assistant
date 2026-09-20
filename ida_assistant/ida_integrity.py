"""Read-only IDA checks; imports are confined to the private worker."""

from __future__ import annotations

import struct
from pathlib import Path


def _pe_ranges(source: Path, base: int) -> list[tuple[int, int]]:
    """File-backed executable PE extents; loaders may omit data padding/BSS."""
    with source.open("rb") as stream:
        header = stream.read(64)
        if len(header) < 64 or header[:2] != b"MZ":
            return []
        stream.seek(struct.unpack_from("<I", header, 60)[0])
        coff = stream.read(24)
        if len(coff) != 24 or coff[:4] != b"PE\0\0":
            return []
        count = struct.unpack_from("<H", coff, 6)[0]
        optional_size = struct.unpack_from("<H", coff, 20)[0]
        if count > 96:
            return []
        stream.seek(optional_size, 1)
        ranges = []
        for _ in range(count):
            section = stream.read(40)
            if len(section) != 40:
                break
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", section, 8)
            characteristics = struct.unpack_from("<I", section, 36)[0]
            if not characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                continue
            size = min(raw_size, virtual_size or raw_size)
            if size and raw_offset and raw_offset + size <= source.stat().st_size:
                ranges.append((base + rva, base + rva + size))
        return ranges


def probe(source: Path | None) -> dict:
    import ida_bytes
    import ida_ida
    import ida_loader
    import ida_segment
    import idaapi

    minimum, maximum = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
    count = ida_segment.get_segm_qty()
    issues = []
    if not count or minimum >= maximum or minimum == idaapi.BADADDR:
        issues.append("empty or invalid address space")
    ranges = []
    if source and source.suffix.lower() not in {".i64", ".idb"}:
        ranges = _pe_ranges(source, idaapi.get_imagebase())
    samples = 0
    for start, end in ranges:
        # At most 257 probes per section, including both boundaries. This is a
        # corruption tripwire, not a proof that every byte of a large IDB is valid.
        step = max(1, (end - start + 254) // 255)
        for ea in sorted({start, end - 1, *range(start, end, step)}):
            samples += 1
            if (
                ida_segment.getseg(ea) is None
                or not ida_bytes.is_loaded(ea)
                or ida_loader.get_fileregion_offset(ea) < 0
            ):
                issues.append(f"file-backed address is missing: {ea:#x}")
                if len(issues) >= 16:
                    break
        if len(issues) >= 16:
            break
    return {
        "ok": not issues,
        "min_ea": hex(minimum),
        "max_ea": hex(maximum),
        "segments": count,
        "samples": samples,
        "issues": issues,
    }


def read_loaded_bytes(ea: int, size: int) -> str:
    import ida_bytes

    if not 0 < size <= 1024 * 1024:
        raise ValueError("size must be between 1 and 1048576")
    for address in range(ea, ea + size):
        if not ida_bytes.is_loaded(address):
            raise ValueError(f"UNLOADED_RANGE: {address:#x} within [{ea:#x}, {ea + size:#x})")
    data = ida_bytes.get_bytes(ea, size)
    if data is None or len(data) != size:
        raise ValueError(f"UNLOADED_RANGE: cannot read [{ea:#x}, {ea + size:#x})")
    return " ".join(f"{byte:#02x}" for byte in data)
