from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from anyio import CancelScope
from mcp.server.fastmcp import Context, FastMCP

from .actions import DEBUG_ACTIONS, EDIT_ACTIONS, READ_ACTIONS
from .capabilities import CapabilityRegistry
from .config import Settings
from .errors import UnsafeOperation
from .pool import SessionPool

UNSAFE_TOOLS = EDIT_ACTIONS | DEBUG_ACTIONS
RESERVED_TOOLS = {
    "ida_open_file",
    "ida_close_file",
    "ida_status",
    "ida_wait_for_analysis",
    "ida_python_exec",
}


def _client_identity(settings: Settings, ctx: Context) -> str:
    params = ctx.request_context.session.client_params
    protocol = (
        "unknown-client"
        if params is None
        else f"{params.clientInfo.name}@{params.clientInfo.version}"
    )
    return f"{settings.agent}/{protocol}"


def _binding_key(ctx: Context) -> str:
    """The MCP protocol session is the isolation boundary for the active analysis."""
    return str(id(ctx.request_context.session))


def _load_python_source(settings: Settings, value: str) -> tuple[str, str]:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = settings.project_root / path
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"script is not a file: {path}")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("script must not exceed 1 MiB")
    return path.read_text(encoding="utf-8-sig"), str(path)


def create_server(settings: Settings) -> tuple[FastMCP, SessionPool]:
    pool = SessionPool(settings)
    capabilities = CapabilityRegistry(settings.unsafe)

    @asynccontextmanager
    async def lifespan(_: FastMCP) -> AsyncIterator[None]:
        async def reaper() -> None:
            while True:
                await asyncio.sleep(min(30.0, settings.worker_idle_seconds / 2))
                await pool.reap()

        task = asyncio.create_task(reaper(), name="ida-session-reaper")
        try:
            yield
        finally:
            with CancelScope(shield=True):
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                await pool.shutdown()

    mcp = FastMCP(
        "ida",
        instructions=(
            "Call open(path) once, or use(session) for an existing project analysis. "
            "Then call analysis tools without a path or session: the active analysis is isolated "
            "per MCP connection. Inputs are read directly and project state lives under .ida. "
            "Use targeted query only for exceptional one-off access. Connections start safe; "
            "set_capabilities can enable edit, unrestricted Python, or debugging per caller."
        ),
        lifespan=lifespan,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )

    @mcp.tool(name="health")
    async def ida_health(ctx: Context) -> dict[str, Any]:
        """Scheduler health and caller identity; never starts an idalib worker."""
        return {
            "ok": True,
            "identity": _client_identity(settings, ctx),
            "default_unsafe": settings.unsafe,
            "capabilities": capabilities.get(_binding_key(ctx)).as_dict(),
            **pool.status(),
        }

    @mcp.tool(name="set_capabilities")
    async def ida_set_capabilities(
        ctx: Context,
        edit: bool | None = None,
        python: bool | None = None,
        debug: bool | None = None,
    ) -> dict[str, Any]:
        """Change edit, unrestricted Python, or debugger access for this MCP connection."""
        value = capabilities.set(_binding_key(ctx), edit=edit, python=python, debug=debug)
        return {
            "capabilities": value.as_dict(),
            "scope": "this MCP connection",
            "python_is_unrestricted": True,
        }

    @mcp.tool(name="sessions")
    async def ida_sessions(ctx: Context, session: str | None = None) -> dict[str, Any]:
        """List persistent project analyses, runtime ownership, workers, errors, and quotas."""
        del ctx
        return pool.status(session)

    @mcp.tool(name="logs")
    async def ida_logs(ctx: Context, session: str, lines: int = 100) -> dict[str, Any]:
        """Return bounded event and worker stderr tails without starting a worker."""
        del ctx
        return pool.log_tail(session, max(1, min(lines, 1000)))

    @mcp.tool(name="open")
    async def ida_open(
        ctx: Context,
        path: str,
        session: str | None = None,
        wait_for_analysis: bool | None = None,
        reset_if_changed: bool = False,
    ) -> dict[str, Any]:
        """Submit or reuse a detached analysis job and return after its persistence handshake."""
        return await pool.open(
            path,
            _client_identity(settings, ctx),
            _binding_key(ctx),
            session,
            wait_for_analysis,
            reset_if_changed,
        )

    @mcp.tool(name="use")
    async def ida_use(
        ctx: Context, session: str | None = None, path: str | None = None
    ) -> dict[str, Any]:
        """Make one existing analysis active; this never creates a new analysis."""
        return await pool.use(_client_identity(settings, ctx), _binding_key(ctx), session, path)

    @mcp.tool(name="current")
    async def ida_current(ctx: Context) -> dict[str, Any]:
        """Show the active analysis for this MCP connection without starting a worker."""
        return pool.current(_binding_key(ctx))

    @mcp.tool(name="rename_session")
    async def ida_rename_session(ctx: Context, session: str, new_name: str) -> dict[str, Any]:
        """Rename a persistent project session without copying or reanalyzing its IDB."""
        return await pool.rename(session, new_name, _client_identity(settings, ctx))

    @mcp.tool(name="close")
    async def ida_close(
        ctx: Context, session: str | None = None, save: bool | None = None
    ) -> dict[str, Any]:
        """Stop a session worker and deactivate it for this connection; analysis stays on disk."""
        return await pool.close(_binding_key(ctx), _client_identity(settings, ctx), session, save)

    @mcp.tool(name="abort")
    async def ida_abort(
        ctx: Context,
        session: str | None = None,
        job_id: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Abort one persistent analysis job or a local stuck query worker."""
        if not confirm:
            raise UnsafeOperation("aborting a worker requires confirm=true")
        return await pool.abort(_binding_key(ctx), session, job_id)

    async def read(ctx: Context, tool: str, arguments: dict[str, Any]) -> Any:
        return await pool.call_active(
            _binding_key(ctx),
            _client_identity(settings, ctx),
            tool,
            arguments,
            retry_read=True,
        )

    @mcp.tool(name="metadata")
    async def ida_metadata(ctx: Context) -> Any:
        """Return metadata for the active analysis."""
        return await read(ctx, "get_metadata", {})

    @mcp.tool(name="wait_for_analysis")
    async def ida_wait_for_analysis(ctx: Context) -> Any:
        """Wait asynchronously for the detached job; cancellation never cancels the job."""
        selected = pool.current(_binding_key(ctx)).get("session")
        if selected is None:
            raise ValueError("NO_ACTIVE_SESSION: call ida/open(path) or ida/use(session) first")
        while True:
            state = pool.analysis_status(selected)
            if state["phase"] not in {"launching", "queued", "analyzing", "publishing"}:
                return {"session": selected, **state}
            await asyncio.sleep(0.2)

    @mcp.tool(name="analysis_status")
    async def ida_analysis_status(ctx: Context, session: str | None = None) -> dict[str, Any]:
        """Read persistent background-job state without starting or calling idalib."""
        binding = _binding_key(ctx)
        selected = session or pool.current(binding).get("session")
        if selected is None:
            raise ValueError("NO_ACTIVE_SESSION: call ida/open(path), ida/use(), or pass session")
        scheduler = pool.status(selected)["sessions"][selected]
        return {
            "session": selected,
            "scheduler": scheduler,
            "analysis": pool.analysis_status(selected),
        }

    @mcp.tool(name="actions")
    async def ida_actions(
        ctx: Context,
        plane: Literal["read", "edit", "debug", "all"] = "read",
        filter: str = "",
    ) -> Any:
        """Discover long-tail query/edit action names, signatures, and short descriptions."""
        return await read(ctx, "ida_action_catalog", {"plane": plane, "filter": filter})

    @mcp.tool(name="functions")
    async def ida_functions(
        ctx: Context, filter: str = "", offset: int = 0, count: int = 100
    ) -> Any:
        """Page through functions, optionally filtering names by substring or /regex/."""
        tool = "ida_functions_filter" if filter else "list_functions"
        arguments: dict[str, Any] = {"offset": max(0, offset), "count": max(1, min(count, 1000))}
        if filter:
            arguments["filter"] = filter
        return await read(ctx, tool, arguments)

    @mcp.tool(name="function")
    async def ida_function(
        ctx: Context, value: str, by: Literal["address", "name"] = "address"
    ) -> Any:
        """Resolve one function in the active analysis by address or name."""
        tool = "get_function_by_address" if by == "address" else "get_function_by_name"
        return await read(ctx, tool, {by: value})

    @mcp.tool(name="imports")
    async def ida_imports(ctx: Context, offset: int = 0, count: int = 100) -> Any:
        """Page through imports in the active analysis."""
        return await read(
            ctx,
            "list_imports",
            {"offset": max(0, offset), "count": max(1, min(count, 1000))},
        )

    @mcp.tool(name="strings")
    async def ida_strings(ctx: Context, filter: str = "", offset: int = 0, count: int = 100) -> Any:
        """Page through strings in the active analysis, optionally filtering them."""
        tool = "list_strings_filter" if filter else "list_strings"
        arguments: dict[str, Any] = {
            "offset": max(0, offset),
            "count": max(1, min(count, 1000)),
        }
        if filter:
            arguments["filter"] = filter
        return await read(ctx, tool, arguments)

    @mcp.tool(name="decompile")
    async def ida_decompile(ctx: Context, address: str) -> Any:
        """Decompile one function in the active analysis."""
        return await read(ctx, "decompile_function", {"address": address})

    @mcp.tool(name="disassemble")
    async def ida_disassemble(ctx: Context, address: str) -> Any:
        """Disassemble one function in the active analysis."""
        return await read(ctx, "disassemble_function", {"start_address": address})

    @mcp.tool(name="xrefs")
    async def ida_xrefs(
        ctx: Context,
        address: str,
        kind: Literal["to", "callers", "callees"] = "to",
    ) -> Any:
        """Get incoming xrefs or callers/callees in the active analysis."""
        mapping = {
            "to": ("get_xrefs_to", "address"),
            "callers": ("get_callers", "function_address"),
            "callees": ("get_callees", "function_address"),
        }
        tool, key = mapping[kind]
        return await read(ctx, tool, {key: address})

    @mcp.tool(name="basic_blocks")
    async def ida_basic_blocks(ctx: Context, address: str) -> Any:
        """Enumerate a function's basic blocks and control-flow edges."""
        return await read(ctx, "ida_basic_blocks", {"address": address})

    @mcp.tool(name="xrefs_from")
    async def ida_xrefs_from(ctx: Context, address: str) -> Any:
        """Enumerate outgoing code and data references from one address."""
        return await read(ctx, "ida_xrefs_from", {"address": address})

    @mcp.tool(name="inspect")
    async def ida_inspect(
        ctx: Context,
        kind: Literal["exports", "entry_points", "segments"],
    ) -> Any:
        """Inspect exports, entry points, or segments/sections."""
        tools = {
            "exports": "ida_exports",
            "entry_points": "ida_entry_points",
            "segments": "ida_segments",
        }
        return await read(ctx, tools[kind], {})

    @mcp.tool(name="search")
    async def ida_search(
        ctx: Context,
        query: str,
        kind: Literal["bytes", "text"] = "bytes",
        encoding: str = "UTF-8",
        start: str | None = None,
        end: str | None = None,
        max_results: int = 100,
    ) -> Any:
        """Search loaded bytes using IDA patterns or text in a specified encoding."""
        if not 1 <= max_results <= 1000:
            raise ValueError("max_results must be between 1 and 1000")
        return await read(
            ctx,
            "ida_search",
            {
                "query": query,
                "kind": kind,
                "encoding": encoding,
                "start": start,
                "end": end,
                "max_results": max_results,
            },
        )

    @mcp.tool(name="bytes")
    async def ida_bytes(ctx: Context, address: str, size: int) -> Any:
        """Read up to 1 MiB from the active database address space."""
        if not 1 <= size <= 1024 * 1024:
            raise ValueError("size must be between 1 and 1048576")
        return await read(ctx, "read_memory_bytes", {"memory_address": address, "size": size})

    @mcp.tool(name="query")
    async def ida_query(
        ctx: Context,
        action: str,
        arguments: dict[str, Any],
        session: str | None = None,
        path: str | None = None,
    ) -> Any:
        """Low-frequency read execution plane; optional target is an exceptional one-off."""
        if action not in READ_ACTIONS or action in RESERVED_TOOLS:
            raise UnsafeOperation(
                f"{action!r} is not an approved read action; call actions(plane='read')"
            )
        if session is None and path is None:
            return await read(ctx, action, arguments)
        return await pool.call_targeted(
            _client_identity(settings, ctx), action, arguments, session, path, retry_read=True
        )

    @mcp.tool(name="edit")
    async def ida_edit(
        ctx: Context,
        action: str,
        arguments: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Gated edit/debug plane for the active analysis; requires a connection capability."""
        enabled = capabilities.get(_binding_key(ctx))
        required = "debug" if action in DEBUG_ACTIONS else "edit"
        if not getattr(enabled, required):
            raise UnsafeOperation(
                f"{required} capability is disabled; call set_capabilities({required}=true)"
            )
        if not confirm:
            raise UnsafeOperation("editing requires confirm=true on every call")
        allowed = DEBUG_ACTIONS if required == "debug" else EDIT_ACTIONS
        if action not in allowed:
            raise UnsafeOperation(
                f"{action!r} is not an approved {required} action; call actions(plane='{required}')"
            )
        return await pool.call_active(
            _binding_key(ctx),
            _client_identity(settings, ctx),
            action,
            arguments,
            retry_read=False,
        )

    @mcp.tool(name="python")
    async def ida_python(
        ctx: Context,
        code: str | None = None,
        script: str | None = None,
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        """Execute IDAPython after this connection explicitly enables Python capability."""
        if not capabilities.get(_binding_key(ctx)).python:
            raise UnsafeOperation(
                "python capability is disabled; call set_capabilities(python=true)"
            )
        if (code is None) == (script is None):
            raise ValueError("specify exactly one of code or script")
        filename = None
        if script is not None:
            code, filename = _load_python_source(settings, script)
        assert code is not None
        return await pool.call_active(
            _binding_key(ctx),
            _client_identity(settings, ctx),
            "ida_python_exec",
            {"code": code, "arguments": arguments or {}, "filename": filename},
            retry_read=False,
        )

    return mcp, pool
