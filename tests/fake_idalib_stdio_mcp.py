from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

parser = argparse.ArgumentParser(description="Deterministic fake idalib worker")
parser.add_argument("--session-id", required=True)
parser.add_argument("--session-dir", required=True)
parser.add_argument("--database-dir", required=True)
parser.add_argument("--ida-user-dir")
parser.add_argument("--pid-file", required=True)
parser.add_argument("--open-delay", type=float, default=0.15)
parser.add_argument("--output-database")
parser.add_argument("--source-path")
parser.add_argument("--bootstrap-only", action="store_true")
parser.add_argument("--bootstrap-wait", action="store_true")
args, _ = parser.parse_known_args()
Path(args.pid_file).write_text(str(os.getpid()), encoding="ascii")

# Regression sentinel: the old scheduler passed this before MCP initialization,
# so a slow analysis consumed the short startup timeout.
if args.bootstrap_only:
    source = Path(args.source_path).resolve(strict=True)
    content = source.read_bytes()
    session_dir = Path(args.session_dir)
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / "bootstrap-args.json").write_text(
        json.dumps({"bootstrap_wait": args.bootstrap_wait, "pid": os.getpid()}),
        encoding="utf-8",
    )
    if content == b"WAIT_FOR_RELEASE":
        Path(args.output_database).resolve().write_bytes(b"partial-idb")
        (session_dir / "analysis-started").write_text(str(os.getpid()), encoding="ascii")
        deadline = time.monotonic() + 30
        while not (session_dir / "analysis.release").exists():
            if time.monotonic() >= deadline:
                raise SystemExit(31)
            time.sleep(0.05)
    if content == b"SLOW_OPEN":
        time.sleep(2.5)
    if content == b"CANCEL_ONCE":
        marker = Path(args.session_dir) / "cancel-once.marker"
        if not marker.exists():
            marker.write_text("1", encoding="ascii")
            Path(args.output_database).resolve().write_bytes(b"partial-idb")
            time.sleep(10)
    database = Path(args.output_database).resolve()
    database.parent.mkdir(parents=True, exist_ok=True)
    database.write_bytes(b"fake-idb")
    raise SystemExit(0)
if args.output_database:
    time.sleep(2.5)

from mcp.server.fastmcp import FastMCP

SESSION_ID = args.session_id
SESSION_DIR = Path(args.session_dir).resolve()
SESSION_DIR.mkdir(parents=True, exist_ok=True)
mcp = FastMCP(f"fake-worker-{SESSION_ID}")
current_path: Path | None = None
current_database: Path | None = None


def metadata() -> dict[str, object]:
    return {
        "path": str(current_path) if current_path else None,
        "module": current_path.name if current_path else None,
        "base": "0x140000000" if current_path else None,
        "pid": os.getpid(),
    }


@mcp.tool()
def ida_open_file(
    path: str,
    database_path: str | None = None,
    create_database: bool = False,
    wait_for_analysis: bool = False,
    save_previous: bool | None = None,
) -> dict[str, object]:
    del save_previous
    global current_path, current_database
    started_at = time.perf_counter()
    time.sleep(args.open_delay)
    current_path = Path(path).resolve(strict=True)
    database = Path(database_path).resolve() if database_path else current_path
    if database_path and (create_database or not database.exists()):
        database.parent.mkdir(parents=True, exist_ok=True)
        database.write_bytes(b"fake-idb")
    current_database = database
    return {
        "source": str(current_path),
        "opened": str(current_path),
        "wait_for_analysis": wait_for_analysis,
        "database": str(database),
        "pid": os.getpid(),
        "started_at": started_at,
        "finished_at": time.perf_counter(),
    }


@mcp.tool()
def ida_close_file(save: bool | None = None) -> dict[str, object]:
    global current_path, current_database
    (SESSION_DIR / "close-started").touch()
    delay = SESSION_DIR / "close-delay"
    if delay.exists():
        time.sleep(float(delay.read_text()))
    previous = metadata()
    current_path = None
    current_database = None
    (SESSION_DIR / "close-finished").touch()
    return {"closed": previous["path"] is not None, "save": bool(save), "previous": previous}


@mcp.tool()
def ida_status() -> dict[str, object]:
    return {
        "session_id": args.session_id,
        "pid": os.getpid(),
        "source_path": str(current_path) if current_path else None,
        "opened_path": str(current_database) if current_database else None,
        "database_path": str(current_database) if current_database else None,
        "has_database": current_database is not None,
        "metadata": metadata(),
    }


@mcp.tool()
def ida_integrity_probe() -> dict[str, object]:
    if (SESSION_DIR / "bad-integrity").exists():
        return {"ok": False, "issues": ["missing executable mapping"]}
    return {"ok": True}


@mcp.tool()
def ida_analysis_status() -> dict[str, object]:
    return {"done": True, "state": 0, "state_name": "AU_NONE", "metadata": metadata()}


@mcp.tool()
def ida_action_catalog(plane: str = "read", filter: str = "") -> list[dict[str, str]]:
    rows = [
        {
            "action": "list_globals",
            "plane": "read",
            "signature": "(offset: int, count: int)",
            "description": "List globals.",
        }
    ]
    return [row for row in rows if plane in {"all", row["plane"]} and filter in row["action"]]


@mcp.tool()
def get_metadata() -> dict[str, object]:
    if current_path is None:
        raise RuntimeError("no database open")
    return metadata()


@mcp.tool()
def list_functions(offset: int, count: int) -> list[dict[str, object]]:
    return [
        {"address": hex(0x140001000 + i * 0x10), "name": f"fn_{i}"}
        for i in range(offset, offset + count)
    ]


@mcp.tool()
def ida_functions_filter(filter: str, offset: int, count: int) -> dict[str, object]:
    rows = [
        {"address": hex(0x140001000 + i * 0x10), "name": f"{filter}_fn_{i}"}
        for i in range(offset, offset + count)
    ]
    return {"data": rows, "next_offset": None, "total_matches": len(rows)}


@mcp.tool()
def list_strings_filter(filter: str, offset: int, count: int) -> list[dict[str, object]]:
    if current_path is None:
        raise RuntimeError("no database open")
    rows = [
        line
        for line in current_path.read_text(encoding="utf-8").splitlines()
        if filter.casefold() in line.casefold()
    ]
    return [{"value": value} for value in rows[offset : offset + count]]


@mcp.tool()
def ida_basic_blocks(address: str) -> dict[str, object]:
    return {
        "function": address,
        "name": "fake_function",
        "blocks": [
            {
                "id": 0,
                "start": address,
                "end": hex(int(address, 0) + 4),
                "size": 4,
                "type": 0,
                "successors": [],
                "predecessors": [],
            }
        ],
    }


@mcp.tool()
def ida_xrefs_from(address: str) -> list[dict[str, object]]:
    return [{"from": address, "to": hex(int(address, 0) + 4), "type": 0, "is_code": True}]


@mcp.tool()
def ida_exports() -> list[dict[str, object]]:
    return [{"ordinal": 1, "address": "0x140001000", "name": "Exported"}]


@mcp.tool()
def ida_entry_points() -> list[dict[str, object]]:
    return [{"address": "0x140001000", "name": "entry"}]


@mcp.tool()
def ida_segments() -> list[dict[str, object]]:
    return [{"name": ".text", "start": "0x140001000", "permissions": "rx"}]


@mcp.tool()
def ida_search(
    query: str,
    kind: str = "bytes",
    encoding: str = "UTF-8",
    start: str | None = None,
    end: str | None = None,
    max_results: int = 100,
) -> list[dict[str, object]]:
    del query, kind, encoding, end, max_results
    return [{"address": start or "0x140000000"}]


@mcp.tool()
def ida_python_exec(
    code: str,
    arguments: dict[str, object] | None = None,
    filename: str | None = None,
) -> dict[str, object]:
    del filename
    namespace: dict[str, object] = {"arguments": arguments or {}}
    exec(code, namespace)  # noqa: S102 - deterministic fake for the explicit execution tool.
    return {"result": namespace.get("result"), "stdout": "", "stderr": ""}


@mcp.tool()
def test_hang(seconds: float) -> None:
    (SESSION_DIR / "call-started").touch()
    time.sleep(seconds)
    (SESSION_DIR / "call-finished").touch()


@mcp.tool()
def test_crash() -> None:
    os._exit(23)


@mcp.tool()
def test_error() -> None:
    raise ValueError("deliberate tool error")


if __name__ == "__main__":
    mcp.run(transport="stdio")
