from __future__ import annotations

import argparse
import ctypes
import functools
import importlib
import inspect
import io
import json
import os
import re
import subprocess
import sys
import time
import traceback
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

try:
    from .actions import DEBUG_ACTIONS, EDIT_ACTIONS, SUPPORTED_ACTIONS
    from .database_safety import atomic_save
    from .ida_integrity import probe, read_loaded_bytes
except ImportError:  # Executed directly as the private worker script.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from ida_assistant.actions import DEBUG_ACTIONS, EDIT_ACTIONS, SUPPORTED_ACTIONS
    from ida_assistant.database_safety import atomic_save
    from ida_assistant.ida_integrity import probe, read_loaded_bytes

WINDOWS_CREATION_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _parse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Private idalib worker (stdio MCP)")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--database-dir", required=True)
    parser.add_argument("--ida-user-dir", required=True)
    parser.add_argument("--pid-file", required=True)
    parser.add_argument("--ida-dir", required=True)
    parser.add_argument("--idalib-python", required=True)
    parser.add_argument("--pythonpath", action="append", default=[])
    parser.add_argument("--plugin-module", default="ida_pro_mcp.mcp-plugin")
    parser.add_argument("--unsafe", action="store_true")
    parser.add_argument("--bootstrap-only", action="store_true")
    parser.add_argument("--output-database")
    parser.add_argument("--source-path")
    parser.add_argument("--bootstrap-wait", action="store_true")
    return parser.parse_args()


ARGS = _parse()
SESSION_DIR = Path(ARGS.session_dir).resolve()
SESSION_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_DIR = Path(ARGS.database_dir).resolve()
DATABASE_DIR.mkdir(parents=True, exist_ok=True)
Path(ARGS.pid_file).write_text(str(os.getpid()), encoding="ascii")
Path(ARGS.ida_user_dir).mkdir(parents=True, exist_ok=True)
os.environ["IDAUSR"] = str(Path(ARGS.ida_user_dir).resolve())

for value in reversed(ARGS.pythonpath):
    sys.path.insert(0, str(Path(value).resolve()))
sys.path.insert(0, str(Path(ARGS.idalib_python).resolve()))


def _bootstrap_database() -> None:
    if not ARGS.output_database or not ARGS.source_path:
        raise RuntimeError("bootstrap requires --output-database and --source-path")
    source = Path(ARGS.source_path).resolve(strict=True)
    database = Path(ARGS.output_database).resolve()
    database.parent.mkdir(parents=True, exist_ok=True)
    for suffix in (database.suffix, ".id0", ".id1", ".id2", ".nam", ".til"):
        database.with_suffix(suffix).unlink(missing_ok=True)
    batch_script = Path(__file__).with_name("ida_batch_exit.py").resolve()
    executable = Path(ARGS.ida_dir).resolve() / ("idat.exe" if os.name == "nt" else "idat")
    bootstrap_log = SESSION_DIR / "bootstrap.log"
    child_environment = dict(os.environ)
    child_environment["IDA_ASSISTANT_BATCH_WAIT"] = "1" if ARGS.bootstrap_wait else "0"
    with bootstrap_log.open("a", encoding="utf-8") as log:
        started = time.time()
        log.write(
            json.dumps(
                {
                    "time": started,
                    "event": "idat_starting",
                    "wrapper_pid": os.getpid(),
                    "source": str(source),
                    "database": str(database),
                    "wait_for_analysis": ARGS.bootstrap_wait,
                },
                ensure_ascii=False,
            )
            + "\n"
        )
        log.flush()
        completed = subprocess.run(
            [
                str(executable),
                "-A",
                "-c",
                f"-o{database}",
                f"-S{batch_script}",
                str(source),
            ],
            cwd=str(SESSION_DIR),
            stdout=log,
            stderr=subprocess.STDOUT,
            env=child_environment,
            check=False,
            creationflags=WINDOWS_CREATION_FLAGS,
        )
        log.write(
            json.dumps(
                {
                    "time": time.time(),
                    "event": "idat_exited",
                    "returncode": completed.returncode,
                    "elapsed_seconds": round(time.time() - started, 3),
                    "database_exists": database.is_file(),
                    "database_size": database.stat().st_size if database.is_file() else None,
                },
                ensure_ascii=False,
            )
            + "\n"
        )
        log.flush()
    if completed.returncode or not database.is_file():
        raise RuntimeError(
            f"IDA batch database creation failed (rc={completed.returncode}); see {bootstrap_log}"
        )


if ARGS.bootstrap_only:
    _bootstrap_database()
    raise SystemExit(0)

# IDA imports occur only in this child process, never in the scheduler.
_saved_stdout = os.dup(1)
_null_stdout = os.open(os.devnull, os.O_WRONLY)
try:
    os.dup2(_null_stdout, 1)
    try:
        # idapro must initialize idalib before any ida_* module is imported.
        idapro = importlib.import_module("idapro")
        libida = idapro.libida
        ida_auto = importlib.import_module("ida_auto")
        ida_bytes = importlib.import_module("ida_bytes")
        ida_entry = importlib.import_module("ida_entry")
        ida_hexrays = importlib.import_module("ida_hexrays")
        ida_funcs = importlib.import_module("ida_funcs")
        ida_gdl = importlib.import_module("ida_gdl")
        ida_ida = importlib.import_module("ida_ida")
        ida_loader = importlib.import_module("ida_loader")
        ida_name = importlib.import_module("ida_name")
        ida_segment = importlib.import_module("ida_segment")
        idaapi = importlib.import_module("idaapi")
        idautils = importlib.import_module("idautils")
        from ida_pro_mcp import idalib_server
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            f"cannot load IDA 9.1 idalib from {ARGS.idalib_python}; "
            "pass all Windows paths with scheduler CLI arguments"
        ) from exc
    finally:
        if os.name == "nt":
            ctypes.CDLL("msvcrt").fflush(None)
        else:
            ctypes.CDLL(None).fflush(None)
finally:
    os.dup2(_saved_stdout, 1)
    os.close(_saved_stdout)
    os.close(_null_stdout)

libida.enable_console_messages(False)


mcp = idalib_server.mcp
_source_path: Path | None = None
_opened_path: Path | None = None
_managed_database: Path | None = None
_dirty = False
_python_namespace: dict[str, Any] = {
    "__name__": "__ida_assistant__",
    "idaapi": idaapi,
    "idapro": idapro,
    "ida_auto": ida_auto,
    "ida_bytes": ida_bytes,
    "ida_entry": ida_entry,
    "ida_funcs": ida_funcs,
    "ida_gdl": ida_gdl,
    "ida_hexrays": ida_hexrays,
    "ida_ida": ida_ida,
    "ida_loader": ida_loader,
    "ida_name": ida_name,
    "ida_segment": ida_segment,
    "idautils": idautils,
    "SESSION_DIR": SESSION_DIR,
    "DATABASE_DIR": DATABASE_DIR,
}


def _has_database() -> bool:
    try:
        return bool(idaapi.get_input_file_path())
    except Exception:  # noqa: BLE001 - IDA extension exceptions are not stable Python types.
        return False


def _metadata() -> dict[str, Any]:
    if not _has_database():
        return {"path": None, "module": None, "base": None}
    return {
        "path": idaapi.get_input_file_path(),
        "module": idaapi.get_root_filename(),
        "base": hex(idaapi.get_imagebase()),
    }


def _database_path() -> str | None:
    try:
        database = Path(idaapi.get_path(idaapi.PATH_TYPE_IDB)).resolve()
    except Exception:  # noqa: BLE001 - IDA extension exceptions are not stable Python types.
        return None
    return str(database)


def _status() -> dict[str, Any]:
    return {
        "session_id": ARGS.session_id,
        "pid": os.getpid(),
        "source_path": str(_source_path) if _source_path else None,
        "opened_path": str(_opened_path) if _opened_path else None,
        "database_dir": str(DATABASE_DIR),
        "session_dir": str(SESSION_DIR),
        "ida_user_dir": os.environ["IDAUSR"],
        "has_database": _has_database(),
        "dirty": _dirty,
        "database_path": _database_path() if _has_database() else None,
        "metadata": _metadata(),
    }


def _analysis_status() -> dict[str, Any]:
    if not _has_database():
        raise RuntimeError("no database is open")
    state = int(ida_auto.get_auto_state())
    state_names = {
        int(getattr(ida_auto, name)): name
        for name in (
            "AU_NONE",
            "AU_UNK",
            "AU_CODE",
            "AU_WEAK",
            "AU_PROC",
            "AU_TAIL",
            "AU_FCHUNK",
            "AU_USED",
            "AU_USD2",
            "AU_TYPE",
            "AU_LIBF",
            "AU_LBF2",
            "AU_LBF3",
            "AU_CHLB",
            "AU_FINAL",
        )
        if hasattr(ida_auto, name)
    }
    return {
        "done": bool(ida_auto.auto_is_ok()),
        "state": state,
        "state_name": state_names.get(state, "UNKNOWN"),
        "metadata": _metadata(),
    }


@mcp.tool()
async def ida_status() -> dict[str, Any]:
    return _status()


@mcp.tool()
async def ida_analysis_status() -> dict[str, Any]:
    """Return autoanalysis state without blocking for completion."""
    return _analysis_status()


@mcp.tool()
async def ida_open_file(
    path: str,
    database_path: str | None = None,
    create_database: bool = False,
    wait_for_analysis: bool = False,
    save_previous: bool | None = None,
) -> dict[str, Any]:
    """Read the source directly, optionally directing a new IDB into the project."""
    global _source_path, _opened_path, _managed_database, _dirty
    source = Path(path).expanduser().resolve(strict=True)
    database = Path(database_path).resolve() if database_path else None
    if database is not None and database.is_file():
        opened, ida_args = database, None
    elif database is not None:
        if not create_database:
            raise RuntimeError(f"project database does not exist: {database}")
        raise RuntimeError("project database bootstrap was not completed by the scheduler")
    else:
        opened, ida_args = source, None
    if _has_database():
        await ida_close_file(save_previous)
    rc = libida.open_database(
        str(opened).encode(), wait_for_analysis, ida_args.encode() if ida_args else None
    )
    if rc:
        raise RuntimeError(f"idalib open_database failed for {opened} (rc={rc})")
    if wait_for_analysis:
        ida_auto.auto_wait()
    # Unsupported processors may have no decompiler; ordinary reads still work.
    decompiler_available = bool(ida_hexrays.init_hexrays_plugin())
    _source_path, _opened_path = source, opened
    _managed_database = database
    _dirty = wait_for_analysis
    actual_database = _database_path()
    return {
        "source": str(source),
        "opened": str(opened),
        "database": actual_database,
        "wait_for_analysis": wait_for_analysis,
        "metadata": _metadata(),
        "decompiler_available": decompiler_available,
    }


@mcp.tool()
async def ida_wait_for_analysis() -> dict[str, Any]:
    global _dirty
    if not _has_database():
        raise RuntimeError("no database is open")
    _dirty = True
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler initialization failed")
    return {"done": True, "metadata": _metadata()}


@mcp.tool()
async def ida_integrity_probe() -> dict[str, Any]:
    return probe(_source_path)


@mcp.tool()
async def read_memory_bytes(memory_address: str, size: int) -> str:
    return read_loaded_bytes(_resolve_ea(memory_address), size)


@mcp.tool()
async def ida_close_file(save: bool | None = None) -> dict[str, Any]:
    global _source_path, _opened_path, _managed_database, _dirty
    if not _has_database():
        return {"closed": False, "reason": "no database is open"}
    previous = _status()
    should_save = _dirty if save is None else save
    if should_save:
        target = _managed_database or _opened_path
        if target is None:
            raise RuntimeError("no database publication path")
        atomic_save(
            target,
            lambda path: ida_loader.save_database(path, ida_loader.DBFL_COMP),
            lambda: libida.close_database(False),
        )
    else:
        libida.close_database(False)
    _source_path = _opened_path = None
    _managed_database = None
    _dirty = False
    return {"closed": True, "save": should_save, "previous": previous}


def _resolve_ea(value: str) -> int:
    try:
        ea = int(value, 0)
    except ValueError:
        ea = ida_name.get_name_ea(idaapi.BADADDR, value)
    if ea == idaapi.BADADDR:
        raise ValueError(f"cannot resolve address or name: {value!r}")
    return ea


@mcp.tool()
async def ida_basic_blocks(address: str) -> dict[str, Any]:
    """Enumerate one function's basic blocks and control-flow edges."""
    ea = _resolve_ea(address)
    function = ida_funcs.get_func(ea)
    if function is None:
        raise ValueError(f"no function contains {address!r}")
    blocks = []
    for block in ida_gdl.FlowChart(function):
        blocks.append(
            {
                "id": int(block.id),
                "start": hex(block.start_ea),
                "end": hex(block.end_ea),
                "size": block.end_ea - block.start_ea,
                "type": int(block.type),
                "successors": [int(item.id) for item in block.succs()],
                "predecessors": [int(item.id) for item in block.preds()],
            }
        )
    return {
        "function": hex(function.start_ea),
        "name": ida_funcs.get_func_name(function.start_ea),
        "blocks": blocks,
    }


@mcp.tool()
async def ida_xrefs_from(address: str) -> list[dict[str, Any]]:
    """Enumerate outgoing code and data cross-references from one address."""
    ea = _resolve_ea(address)
    result = []
    for xref in idautils.XrefsFrom(ea, 0):
        target_name = ida_name.get_ea_name(xref.to) or ida_funcs.get_func_name(xref.to)
        result.append(
            {
                "from": hex(xref.frm),
                "to": hex(xref.to),
                "type": int(xref.type),
                "is_code": bool(xref.iscode),
                "target_name": target_name or None,
            }
        )
    return result


def _matches_filter(value: str, pattern: str) -> bool:
    if not pattern:
        return True
    if len(pattern) >= 2 and pattern.startswith("/") and pattern.endswith("/"):
        return re.search(pattern[1:-1], value, re.IGNORECASE) is not None
    return pattern.casefold() in value.casefold()


@mcp.tool()
async def ida_functions_filter(filter: str, offset: int, count: int) -> dict[str, Any]:
    """Filter functions by a case-insensitive substring or /regular expression/."""
    rows = []
    matches = 0
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        if _matches_filter(name, filter):
            if matches >= offset and len(rows) < count:
                rows.append({"address": hex(ea), "name": name})
            matches += 1
    next_offset = offset + len(rows) if offset + len(rows) < matches else None
    return {
        "data": rows,
        "next_offset": next_offset,
        "total_matches": matches,
    }


def _entries() -> list[dict[str, Any]]:
    rows = []
    for index in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(index)
        ea = ida_entry.get_entry(ordinal)
        forwarder = ida_entry.get_entry_forwarder(ordinal)
        rows.append(
            {
                "index": index,
                "ordinal": ordinal,
                "address": None if ea == idaapi.BADADDR else hex(ea),
                "name": ida_entry.get_entry_name(ordinal) or None,
                "forwarder": forwarder or None,
            }
        )
    return rows


@mcp.tool()
async def ida_exports() -> list[dict[str, Any]]:
    """List IDA's export/entry table with ordinals and forwarders."""
    return _entries()


@mcp.tool()
async def ida_entry_points() -> list[dict[str, Any]]:
    """List all loader-defined entry points, including named DLL exports."""
    return _entries()


@mcp.tool()
async def ida_segments() -> list[dict[str, Any]]:
    """List loaded segments/sections, permissions, address ranges, and file offsets."""
    rows = []
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        if segment is None:
            continue
        permissions = "".join(
            letter
            for flag, letter in (
                (ida_segment.SEGPERM_READ, "r"),
                (ida_segment.SEGPERM_WRITE, "w"),
                (ida_segment.SEGPERM_EXEC, "x"),
            )
            if segment.perm & flag
        )
        file_offset = ida_loader.get_fileregion_offset(segment.start_ea)
        rows.append(
            {
                "index": index,
                "name": ida_segment.get_segm_name(segment),
                "class": ida_segment.get_segm_class(segment),
                "start": hex(segment.start_ea),
                "end": hex(segment.end_ea),
                "size": segment.end_ea - segment.start_ea,
                "permissions": permissions,
                "bitness": 16 << int(segment.bitness),
                "type": int(segment.type),
                "file_offset": None if file_offset < 0 else file_offset,
            }
        )
    return rows


@mcp.tool()
async def ida_search(
    query: str,
    kind: str = "bytes",
    encoding: str = "UTF-8",
    start: str | None = None,
    end: str | None = None,
    max_results: int = 100,
) -> list[dict[str, Any]]:
    """Search raw loaded bytes using IDA patterns or text in a specified encoding."""
    if kind not in {"bytes", "text"}:
        raise ValueError("kind must be 'bytes' or 'text'")
    if not 1 <= max_results <= 10000:
        raise ValueError("max_results must be between 1 and 10000")
    cursor = _resolve_ea(start) if start else ida_ida.inf_get_min_ea()
    range_end = _resolve_ea(end) if end else ida_ida.inf_get_max_ea()
    rows = []
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
    encoded_query = query.encode(encoding) if kind == "text" else None
    while cursor < range_end and len(rows) < max_results:
        if kind == "bytes":
            found = ida_bytes.find_bytes(query, cursor, range_end=range_end, flags=flags)
        else:
            found = ida_bytes.find_bytes(
                encoded_query,
                cursor,
                range_end=range_end,
                flags=flags,
            )
        if found == idaapi.BADADDR:
            break
        rows.append({"address": hex(found)})
        cursor = found + 1
    return rows


def _json_safe(value: Any, depth: int = 0) -> Any:
    if depth > 10:
        return repr(value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item, depth + 1) for item in value]
    return repr(value)


@mcp.tool()
async def ida_python_exec(
    code: str,
    arguments: dict[str, Any] | None = None,
    filename: str | None = None,
) -> dict[str, Any]:
    """Execute unrestricted Python on IDA's main thread; assign the return value to result."""
    if not ARGS.unsafe:
        raise RuntimeError("custom Python is disabled in this worker")
    global _dirty
    _dirty = True
    stdout, stderr = io.StringIO(), io.StringIO()
    _python_namespace.pop("result", None)
    _python_namespace["arguments"] = arguments or {}
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exec(  # noqa: S102 - this tool deliberately exposes unrestricted IDAPython.
                compile(code, filename or f"<ida-python:{ARGS.session_id}>", "exec"),
                _python_namespace,
            )
    except BaseException as exc:
        detail = traceback.format_exc()
        raise RuntimeError(
            f"custom IDAPython failed: {exc}\nstdout:\n{stdout.getvalue()}\n"
            f"stderr:\n{stderr.getvalue()}\n{detail}"
        ) from exc
    return {
        "result": _json_safe(_python_namespace.get("result")),
        "stdout": stdout.getvalue(),
        "stderr": stderr.getvalue(),
    }


UPSTREAM_PLUGIN = importlib.import_module(ARGS.plugin_module)


@mcp.tool()
async def ida_action_catalog(plane: str = "read", filter: str = "") -> list[dict[str, Any]]:
    """Describe long-tail upstream actions available through query or edit."""
    if plane not in {"read", "edit", "debug", "all"}:
        raise ValueError("plane must be read, edit, debug, or all")
    needle = filter.casefold()
    rows: list[dict[str, Any]] = []
    for name, function in sorted(UPSTREAM_PLUGIN.rpc_registry.methods.items()):
        if name not in SUPPORTED_ACTIONS:
            continue
        action_plane = (
            "debug" if name in DEBUG_ACTIONS else "edit" if name in EDIT_ACTIONS else "read"
        )
        if plane != "all" and action_plane != plane:
            continue
        description = inspect.getdoc(function) or ""
        signature = str(inspect.signature(function))
        if needle and needle not in name.casefold() and needle not in description.casefold():
            continue
        rows.append(
            {
                "action": name,
                "plane": action_plane,
                "signature": signature,
                "arguments_schema": mcp._tool_manager.get_tool(name).parameters,
                "required_capability": action_plane if action_plane != "read" else None,
                "description": description.splitlines()[0] if description else "",
            }
        )
    return rows


@mcp.tool()
async def disassemble_function(start_address: str) -> dict[str, Any]:
    """Run upstream disassembly without its overly strict nested output schema."""
    function = UPSTREAM_PLUGIN.rpc_registry.methods["disassemble_function"]
    result = _json_safe(function(start_address))
    if not isinstance(result, dict):
        raise TypeError("upstream disassemble_function returned a non-object result")
    return result


def _register_upstream() -> None:
    reserved = {
        "ida_status",
        "ida_analysis_status",
        "ida_action_catalog",
        "ida_open_file",
        "ida_wait_for_analysis",
        "ida_close_file",
        "disassemble_function",
        "read_memory_bytes",
    }
    for name, function in UPSTREAM_PLUGIN.rpc_registry.methods.items():
        if name in reserved:
            continue
        if ARGS.unsafe or name not in UPSTREAM_PLUGIN.rpc_registry.unsafe:
            # FastMCP executes synchronous functions in a thread pool. idalib 9.1
            # requires every API call on the thread that initialized the library,
            # so an async wrapper deliberately executes the function inline on the
            # worker's event-loop/main thread. functools.wraps preserves its schema.
            @functools.wraps(function)
            async def on_ida_thread(
                *args: Any, __function: Any = function, __name: str = name, **kwargs: Any
            ) -> Any:
                global _dirty
                if __name in EDIT_ACTIONS or __name in DEBUG_ACTIONS:
                    _dirty = True
                return __function(*args, **kwargs)

            mcp.add_tool(on_ida_thread, name)
    idalib_server.fixup_tool_argument_descriptions(mcp)


_register_upstream()

if __name__ == "__main__":
    mcp.run(transport="stdio")
