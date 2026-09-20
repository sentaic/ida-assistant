from __future__ import annotations

import asyncio
import json
import os
import subprocess
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from .config import Settings
from .errors import ToolFailed, WorkerFailed, WorkerTimedOut

WINDOWS_CREATION_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _hidden_python(command: str) -> str:
    """Prefer windowless Python while keeping redirected stdio available."""
    path = Path(command)
    if os.name == "nt" and path.name.casefold() == "python.exe":
        candidate = path.with_name("pythonw.exe")
        if candidate.is_file():
            return str(candidate)
    return command


def _result_payload(result: types.CallToolResult) -> Any:
    if result.isError:
        message = "\n".join(getattr(block, "text", "") for block in result.content)
        raise ToolFailed(message or "worker tool returned an error")
    if result.structuredContent is not None:
        value = result.structuredContent
        return value.get("result") if set(value) == {"result"} else value
    if len(result.content) == 1 and getattr(result.content[0], "type", None) == "text":
        value = getattr(result.content[0], "text", "")
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return [block.model_dump(mode="json", exclude_none=True) for block in result.content]


@dataclass(slots=True)
class _Request:
    tool: str
    arguments: dict[str, Any]
    future: asyncio.Future[Any]


class WorkerActor:
    """Owns a child MCP connection in one asyncio task.

    MCP stdio context managers must be entered and exited in the same task.  The
    actor also gives the scheduler a cancellation point for forcibly killing a
    wedged idalib process.
    """

    def __init__(
        self,
        settings: Settings,
        session_id: str,
        session_dir: Path,
        database_dir: Path,
        slots: asyncio.Semaphore,
    ):
        self.settings = settings
        self.session_id = session_id
        self.session_dir = session_dir
        self.database_dir = database_dir
        self.slots = slots
        self.pid_file = session_dir / "worker.pid"
        self.stderr_path = session_dir / "worker.stderr.log"
        self._queue: asyncio.Queue[_Request | None] = asyncio.Queue()
        self._ready: asyncio.Future[None] | None = None
        self._task: asyncio.Task[None] | None = None
        self._pid: int | None = None
        self.tainted = False
        self._flushing = False
        self._inflight: asyncio.Future[Any] | None = None
        self._close_future: asyncio.Future[Any] | None = None
        self._stop_task: asyncio.Task[Any] | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def pid(self) -> int | None:
        self._read_pid()
        return self._pid

    async def start(self) -> None:
        if self.running:
            return
        loop = asyncio.get_running_loop()
        self._ready = loop.create_future()
        self._task = asyncio.create_task(self._run(), name=f"ida-worker:{self.session_id}")
        try:
            await asyncio.wait_for(asyncio.shield(self._ready), self.settings.startup_timeout)
        except asyncio.CancelledError:
            await asyncio.shield(self.force_stop("startup cancelled"))
            raise
        except TimeoutError as exc:
            await self.force_stop("startup timeout")
            raise WorkerTimedOut(
                f"worker {self.session_id!r} did not initialize within "
                f"{self.settings.startup_timeout:g}s"
            ) from exc

    def _args(self) -> list[str]:
        args = [
            str(self.settings.worker_script),
            "--session-id",
            self.session_id,
            "--session-dir",
            str(self.session_dir),
            "--database-dir",
            str(self.database_dir),
            "--ida-user-dir",
            str(self.session_dir / "ida-user"),
            "--pid-file",
            str(self.pid_file),
            "--ida-dir",
            str(self.settings.ida_dir),
            "--idalib-python",
            str(self.settings.idalib_python),
        ]
        for path in self.settings.pythonpaths:
            args.extend(("--pythonpath", str(path)))
        # Workers expose the complete IDAPython/upstream surface privately. The
        # scheduler enforces safe/edit/python/debug capabilities per MCP connection.
        args.append("--unsafe")
        return args

    async def bootstrap_database(
        self, source: Path, database: Path, wait_for_analysis: bool
    ) -> None:
        """Create and atomically publish an IDB in a separate process."""
        staging = database.with_name(f"{database.stem}.bootstrap{database.suffix}")
        self._remove_database_family(staging)
        args = self._args()
        args.extend(("--bootstrap-only", "--source-path", str(source)))
        args.extend(("--output-database", str(staging)))
        if wait_for_analysis:
            args.append("--bootstrap-wait")
        process: subprocess.Popen[bytes] | None = None
        acquired = False
        try:
            await asyncio.wait_for(self.slots.acquire(), self.settings.call_timeout)
            acquired = True
            self.session_dir.mkdir(parents=True, exist_ok=True)
            # Popen itself is deliberately synchronous here.  If the surrounding
            # task is cancelled while Popen runs in a thread, asyncio cannot stop
            # that thread and the local process variable can remain unset while a
            # late bootstrap process is still created.  Taking the handle before
            # the next cancellation point makes process-tree cleanup reliable.
            process = subprocess.Popen(  # noqa: ASYNC220 - avoids an orphan-on-cancel race
                [
                    # This subprocess already uses CREATE_NO_WINDOW. Replacing uv's
                    # python.exe shim with pythonw.exe here can stall before the
                    # bootstrap module runs, leaving no idat process or log output.
                    self.settings.worker_command,
                    *args,
                ],
                cwd=str(self.session_dir),
                env=dict(os.environ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=WINDOWS_CREATION_FLAGS,
            )
            try:
                returncode = await asyncio.wait_for(
                    asyncio.to_thread(process.wait), self.settings.call_timeout
                )
            except TimeoutError as exc:
                await asyncio.to_thread(_kill_process_tree, process.pid)
                await asyncio.to_thread(process.wait)
                raise WorkerTimedOut(
                    "IDA database creation exceeded "
                    f"{self.settings.call_timeout:g}s; process tree was terminated"
                ) from exc
            if returncode or not staging.is_file():
                raise ToolFailed(
                    f"IDA database creation failed (rc={returncode}); "
                    f"see {self.session_dir / 'bootstrap.log'}"
                )
            database.parent.mkdir(parents=True, exist_ok=True)
            staging.replace(database)
        except asyncio.CancelledError:
            if process is not None and process.poll() is None:
                await asyncio.shield(asyncio.to_thread(_kill_process_tree, process.pid))
                await asyncio.shield(asyncio.to_thread(process.wait))
            raise
        finally:
            self._remove_database_family(staging)
            if acquired:
                self.slots.release()

    @staticmethod
    def _remove_database_family(database: Path) -> None:
        for suffix in (database.suffix, ".id0", ".id1", ".id2", ".nam", ".til"):
            database.with_suffix(suffix).unlink(missing_ok=True)

    async def _run(self) -> None:
        acquired = False
        try:
            await asyncio.wait_for(self.slots.acquire(), self.settings.startup_timeout)
            acquired = True
            self.session_dir.mkdir(parents=True, exist_ok=True)
            self.pid_file.unlink(missing_ok=True)
            params = StdioServerParameters(
                command=_hidden_python(self.settings.worker_command),
                args=self._args(),
                cwd=str(self.session_dir),
                env=dict(os.environ),
            )
            with self.stderr_path.open("a", encoding="utf-8") as stderr:
                async with AsyncExitStack() as stack:
                    read, write = await stack.enter_async_context(
                        stdio_client(params, errlog=stderr)
                    )
                    client = await stack.enter_async_context(ClientSession(read, write))
                    await client.initialize()
                    self._read_pid()
                    if self._ready is not None and not self._ready.done():
                        self._ready.set_result(None)
                    while True:
                        request = await self._queue.get()
                        if request is None:
                            return
                        if request.future.cancelled():
                            continue
                        try:
                            result = await client.call_tool(
                                request.tool,
                                request.arguments,
                            )
                            payload = _result_payload(result)
                            if not request.future.done():
                                request.future.set_result(payload)
                        except ToolFailed as exc:
                            if not request.future.done():
                                request.future.set_exception(exc)
                        except BaseException as exc:
                            if not request.future.done():
                                request.future.set_exception(
                                    WorkerFailed(f"worker call {request.tool!r} failed: {exc}")
                                )
                            if isinstance(exc, asyncio.CancelledError):
                                raise
                        finally:
                            if request.tool == "ida_close_file":
                                self._flushing = False
        except BaseException as exc:
            if self._ready is not None and not self._ready.done():
                self._ready.set_exception(WorkerFailed(f"worker failed to start: {exc}"))
            self._fail_queued(exc)
            if isinstance(exc, asyncio.CancelledError):
                raise
        finally:
            if acquired:
                self.slots.release()

    def _fail_queued(self, cause: BaseException) -> None:
        while True:
            try:
                request = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if request is not None and not request.future.done():
                request.future.set_exception(WorkerFailed(f"worker exited: {cause}"))

    async def call(self, tool: str, arguments: dict[str, Any], timeout: float | None = None) -> Any:
        if self.tainted and tool != "ida_close_file":
            raise WorkerFailed("WORKER_DRAINING: abandoned call is still being retired")
        await self.start()
        assert self._task is not None
        if self._task.done():
            raise WorkerFailed(f"worker {self.session_id!r} exited")
        future = asyncio.get_running_loop().create_future()
        # Retrieving abandoned exceptions prevents unhandled-future warnings; it does
        # not change the result observed by a caller still awaiting this future.
        future.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        self._inflight = future
        if tool == "ida_open_file":
            self._close_future = None
        if tool == "ida_close_file":
            self._close_future = future
            self._flushing = True
        await self._queue.put(_Request(tool, arguments, future))
        limit = (
            timeout
            if timeout is not None
            else (
                self.settings.flush_timeout
                if tool == "ida_close_file"
                else self.settings.call_timeout
            )
        )
        try:
            return await asyncio.wait_for(asyncio.shield(future), limit or None)
        except asyncio.CancelledError:
            self.tainted = True
            raise
        except TimeoutError as exc:
            self.tainted = True
            raise WorkerTimedOut(
                f"worker call {tool!r} exceeded {limit:g}s; call continues under the IDB lock; "
                "cancellation is not rollback"
            ) from exc

    async def stop(self, graceful: bool = True, save: bool | None = None) -> Any:
        if (
            self._stop_task is not None
            and self._stop_task.done()
            and not self._stop_task.cancelled()
            and self._stop_task.exception() is not None
            and self.running
        ):
            # A failed OS termination attempt does not mean the child exited.
            self._stop_task = None
        if self._stop_task is None:
            self._stop_task = asyncio.create_task(self._finish_stop(graceful, save))
        return await asyncio.shield(self._stop_task)

    async def _finish_stop(self, graceful: bool, save: bool | None) -> Any:
        if self._task is None:
            return
        result = None
        if self._inflight is not None and not self._inflight.done():
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._inflight),
                    None if self._flushing else self.settings.drain_timeout,
                )
            except TimeoutError:
                await self.force_stop("abandoned call exceeded drain deadline")
                return
            except (ToolFailed, WorkerFailed):
                pass
        if graceful and self.running:
            try:
                if self._close_future is not None:
                    result = await asyncio.shield(self._close_future)
                else:
                    result = await self.call("ida_close_file", {"save": save}, timeout=0)
            except (ToolFailed, WorkerFailed):
                # Saving failed after returning from IDA. The atomic save retains
                # the original database and any recovery candidate on disk.
                await self.force_stop("close failed")
                raise
        if self.running:
            await self._queue.put(None)
            try:
                await asyncio.wait_for(asyncio.shield(self._task), self.settings.shutdown_timeout)
            except TimeoutError:
                await self.force_stop("shutdown timeout")
        self._task = None
        return result

    async def force_stop(self, reason: str) -> None:
        if self._flushing:
            raise WorkerFailed("FLUSH_IN_PROGRESS: refusing to terminate a database save/close")
        del reason
        self._read_pid()
        if self._pid:
            await asyncio.to_thread(_kill_process_tree, self._pid)
        if self._task is not None and not self._task.done():
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self._task = None

    def _read_pid(self) -> None:
        try:
            self._pid = int(self.pid_file.read_text(encoding="ascii").strip())
        except (FileNotFoundError, ValueError, OSError):
            pass


def _kill_process_tree(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            creationflags=WINDOWS_CREATION_FLAGS,
        )
        return
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass
