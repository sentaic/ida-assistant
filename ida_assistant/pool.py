from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .analysis_job import (
    ACTIVE_PHASES,
    TERMINAL_PHASES,
    abort_path,
    persistent_creation_flags,
    process_alive,
    read_job,
    remove_database_family,
    terminate_named_job,
    write_job,
)
from .asset_lock import AssetLock
from .config import Settings
from .database_safety import quarantine_sidecars, verify_fingerprint
from .errors import (
    AnalysisFailed,
    AnalysisPending,
    QuotaExceeded,
    SampleBusy,
    SessionConflict,
    SessionNotFound,
    SourceChanged,
    SourceOpenError,
    ToolFailed,
    WorkerFailed,
)
from .fingerprint import canonical_path, quick_fingerprint, same_content
from .recovery_cleanup import CHECK_INTERVAL_SECONDS, prune_inactive_recovery, prune_recovery
from .state_paths import load_state_path, store_state_path
from .worker_client import WorkerActor

SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
DATABASE_SUFFIXES = {".i64", ".idb"}


def _release_detached_process_handle(process: subprocess.Popen[bytes]) -> None:
    """Drop the scheduler's Windows handle without waiting for or terminating the job."""
    if os.name != "nt":
        return
    handle = getattr(process, "_handle", None)
    if handle is not None:
        handle.Close()
        process._handle = None  # type: ignore[attr-defined]
    process.returncode = 0


@dataclass(slots=True)
class Analysis:
    session: str
    source: Path
    fingerprint: dict[str, Any]
    database: Path
    external_database: bool
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    renamed_from: list[str] = field(default_factory=list)

    @property
    def source_key(self) -> str:
        return canonical_path(self.source)


@dataclass(slots=True)
class RuntimeSession:
    analysis: Analysis
    owners: set[str]
    session_dir: Path
    database_dir: Path
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    active_calls: int = 0
    worker_lock: AssetLock | None = None
    worker: WorkerActor | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    restarts: int = 0
    last_error: str | None = None
    force_create: bool = False


class SessionPool:
    """Project-scoped registry plus a bounded set of lazy idalib runtimes."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._analyses: dict[str, Analysis] = self._load_analyses()
        self._renames = self._load_renames()
        self._sessions: dict[str, RuntimeSession] = {}
        self._bindings: dict[str, str] = {}
        self._pool_lock = asyncio.Lock()
        self._registry_lock = asyncio.Lock()
        self._worker_start_lock = asyncio.Lock()
        self._worker_slots = asyncio.Semaphore(settings.max_workers)
        self._closed = False
        self._retiring: dict[str, asyncio.Task[Any]] = {}
        self._next_recovery_cleanup = time.monotonic() + CHECK_INTERVAL_SECONDS

    @property
    def databases_dir(self) -> Path:
        return self.settings.state_dir / "databases"

    @property
    def sessions_dir(self) -> Path:
        return self.settings.state_dir / "sessions"

    async def open(
        self,
        path: str,
        owner: str,
        binding: str,
        session: str | None = None,
        wait_for_analysis: bool | None = None,
        reset_if_changed: bool = False,
    ) -> dict[str, Any]:
        source = self._resolve_source(path)
        fingerprint = quick_fingerprint(source)
        changed = False
        async with self._registry_lock:
            registry_file_lock = AssetLock.acquire(
                self.settings.state_dir,
                {"operation": "open", "source": str(source)},
                filename="registry.lock",
                purpose="project registry",
            )
            try:
                self._refresh_analyses()
                existing = self._analysis_by_source(source)
                reused = existing is not None
                requested_ignored = False
                if existing is not None:
                    if session is not None and session != existing.session:
                        requested_ignored = True
                    changed = not same_content(existing.fingerprint, fingerprint)
                    if changed and not reset_if_changed:
                        raise SourceChanged(
                            f"SOURCE_CHANGED: {source} belongs to session "
                            f"{existing.session!r}; inspect it and call "
                            "ida/open(..., reset_if_changed=true) only if replacement is intended"
                        )
                    analysis = existing
                    if changed:
                        analysis.fingerprint = fingerprint
                        analysis.updated_at = time.time()
                else:
                    name = self._choose_session(session, source)
                    database_dir = self.databases_dir / name
                    external = source.suffix.casefold() in DATABASE_SUFFIXES
                    database = source if external else database_dir / f"{name}.i64"
                    analysis = Analysis(name, source, fingerprint, database, external)
                    self._analyses[analysis.session] = analysis
                # Reserve source/session before starting the expensive worker so a second
                # scheduler observes and reuses the same project analysis.
                self._write_manifest(analysis)
            finally:
                registry_file_lock.release()

        self._bindings[binding] = analysis.session
        if analysis.external_database:
            result: dict[str, Any] = {
                "phase": "ready",
                "database_ready": True,
                "legacy_ready": True,
                "deferred": True,
                "reason": "external IDB will be opened by the first analysis call",
            }
        else:
            if reset_if_changed:
                record = self._sessions.get(analysis.session)
                if record is not None:
                    async with self._serialized(record):
                        if record.worker is not None:
                            await asyncio.shield(self._retire_worker(record, graceful=False))
                            self._release_worker_lock(record)
            # Compatibility parameter: open is now always non-blocking, while the
            # detached runner always waits for complete autoanalysis before publish.
            complete_analysis = True
            result = await asyncio.to_thread(
                self._start_analysis_job,
                analysis,
                complete_analysis,
                bool(reset_if_changed and (changed or analysis.database.is_file())),
            )
        return {
            "session": analysis.session,
            "source": str(analysis.source),
            "database": str(analysis.database),
            "reused": reused,
            "requested_session_ignored": requested_ignored,
            "active": True,
            "result": result,
        }

    async def use(
        self,
        owner: str,
        binding: str,
        session: str | None = None,
        path: str | None = None,
    ) -> dict[str, Any]:
        self._refresh_analyses()
        analysis = self._select_analysis(session, path)
        self._check_source(analysis)
        await self._runtime(analysis, owner)
        self._bindings[binding] = analysis.session
        return self._analysis_row(analysis, active=True)

    def current(self, binding: str) -> dict[str, Any]:
        session = self._bindings.get(binding)
        if session is None:
            return {"active": False, "session": None}
        analysis = self._analyses.get(session)
        if analysis is None:
            self._bindings.pop(binding, None)
            return {"active": False, "session": None}
        return self._analysis_row(analysis, active=True)

    async def call_active(
        self,
        binding: str,
        owner: str,
        tool: str,
        arguments: dict[str, Any],
        retry_read: bool = True,
    ) -> Any:
        session = self._bindings.get(binding)
        if session is None:
            raise SessionNotFound(
                "NO_ACTIVE_SESSION: call ida/open(path) or ida/use(session) first"
            )
        return await self.call(session, owner, tool, arguments, retry_read)

    async def call_targeted(
        self,
        owner: str,
        tool: str,
        arguments: dict[str, Any],
        session: str | None = None,
        path: str | None = None,
        retry_read: bool = True,
    ) -> Any:
        analysis = self._select_analysis(session, path)
        return await self.call(analysis.session, owner, tool, arguments, retry_read)

    async def call(
        self,
        session: str,
        owner: str,
        tool: str,
        arguments: dict[str, Any],
        retry_read: bool = True,
    ) -> Any:
        analysis = self._analysis_named(session)
        self._require_ready(analysis)
        record = await self._runtime(analysis, owner)
        async with self._serialized(record):
            return await self._call_worker(record, tool, arguments, restore=True, retry=retry_read)

    async def rename(self, session: str, new_name: str, owner: str) -> dict[str, Any]:
        self._validate_session(new_name)
        self._refresh_analyses()
        analysis = self._analysis_named(session)
        if self._job_snapshot(analysis)["phase"] in ACTIVE_PHASES:
            raise SampleBusy(
                f"analysis job for session {session!r} is active; wait for ready or abort it"
            )
        if new_name == session:
            return self._analysis_row(analysis)
        if new_name in self._analyses or (self.databases_dir / new_name).exists():
            raise SessionConflict(f"SESSION_CONFLICT: session {new_name!r} already exists")
        record = await self._runtime(analysis, owner)
        async with self._serialized(record):
            if record.worker is not None:
                await asyncio.shield(self._retire_worker(record))
            self._release_worker_lock(record)
            registry_guard = AssetLock.acquire(
                self.settings.state_dir,
                {"operation": "rename", "session": session},
                filename="registry.lock",
                purpose="project registry",
            )
            try:
                rename_guard = AssetLock.acquire(
                    record.database_dir,
                    {"operation": "rename", "session": session},
                    purpose="session IDB",
                )
                rename_guard.release()
                old_database_dir = record.database_dir
                old_session_dir = record.session_dir
                new_database_dir = self.databases_dir / new_name
                new_session_dir = self.sessions_dir / new_name
                if old_database_dir.exists():
                    old_database_dir.rename(new_database_dir)
                if old_session_dir.exists():
                    old_session_dir.rename(new_session_dir)
                if not analysis.external_database:
                    analysis.database = new_database_dir / analysis.database.name
                analysis.renamed_from.append(session)
                analysis.session = new_name
                analysis.updated_at = time.time()
                record.database_dir = new_database_dir
                record.session_dir = new_session_dir
                self._analyses.pop(session)
                self._analyses[new_name] = analysis
                self._sessions.pop(session, None)
                self._sessions[new_name] = record
                self._renames[session] = new_name
                for key, value in list(self._bindings.items()):
                    if value == session:
                        self._bindings[key] = new_name
                self._write_manifest(analysis)
                self._write_renames()
                self._event(record, "session_renamed", old_session=session)
            finally:
                registry_guard.release()
        return {"old_session": session, **self._analysis_row(analysis, active=True)}

    async def close(
        self,
        binding: str,
        owner: str,
        session: str | None = None,
        save: bool | None = None,
    ) -> dict[str, Any]:
        name = session or self._bindings.get(binding)
        if name is None:
            raise SessionNotFound("NO_ACTIVE_SESSION: nothing to close")
        analysis = self._analysis_named(name)
        record = self._sessions.get(name)
        worker_result: Any = {"closed": False, "reason": "worker is not running"}
        if record is not None:
            record.owners.add(owner)
            async with self._serialized(record):
                if record.worker is not None and record.worker.running:
                    try:
                        worker_result = await record.worker.call("ida_close_file", {"save": save})
                    finally:
                        abandoned = record.worker.tainted
                        retirement = self._retire_worker(record)
                        if not abandoned:
                            await asyncio.shield(retirement)
                if worker_result.get("save") and analysis.external_database:
                    analysis.fingerprint = quick_fingerprint(analysis.source)
                    analysis.updated_at = time.time()
                    self._write_manifest(analysis)
            async with self._pool_lock:
                self._sessions.pop(name, None)
        if self._bindings.get(binding) == name:
            self._bindings.pop(binding, None)
        return {"session": name, "active": False, "worker": worker_result}

    async def abort(
        self, binding: str, session: str | None = None, job_id: str | None = None
    ) -> dict[str, Any]:
        """Abort a persistent analysis job, or force-stop a local interactive worker."""
        name = session or self._bindings.get(binding)
        if name is None:
            raise SessionNotFound(
                "NO_ACTIVE_SESSION: call ida/open(path), ida/use(session), or pass session"
            )
        analysis = self._analysis_named(name)
        snapshot = self._job_snapshot(analysis)
        job = snapshot.get("job") or {}
        if snapshot["phase"] in ACTIVE_PHASES:
            actual_job_id = str(job.get("job_id") or "")
            if job_id is not None and job_id != actual_job_id:
                return {
                    "session": analysis.session,
                    "aborted": False,
                    "reason": "job_id_mismatch",
                    "expected_job_id": job_id,
                    "current_job_id": actual_job_id,
                }
            return await asyncio.to_thread(self._abort_analysis_job, analysis, actual_job_id)
        if analysis.session in self._retiring:
            raise WorkerFailed("WORKER_DRAINING: cleanup still owns the IDB; save cannot be aborted")
        record = self._sessions.get(analysis.session)
        if record is None or (record.worker is None and not record.lock.locked()):
            return {"session": analysis.session, "aborted": False, "reason": "not running"}

        worker = record.worker
        if worker is not None:
            await worker.force_stop("explicit abort")

        # The interrupted call owns the normal session lock.  Wait only for its
        # finally blocks to remove staging files and release the cross-process
        # IDB lock; abort must never queue behind the original call indefinitely.
        acquired = False
        try:
            await asyncio.wait_for(record.lock.acquire(), self.settings.shutdown_timeout)
            acquired = True
        except TimeoutError as exc:
            raise WorkerFailed(
                f"abort stopped session {analysis.session!r}, but cleanup did not finish within "
                f"{self.settings.shutdown_timeout:g}s"
            ) from exc
        finally:
            if acquired:
                record.lock.release()

        if record.worker is worker:
            record.worker = None
        self._release_worker_lock(record)
        record.last_error = "explicitly aborted"
        record.last_used = time.time()
        self._event(record, "session_aborted")
        return {"session": analysis.session, "aborted": True}

    async def reap(self) -> dict[str, list[str]]:
        now = time.time()
        workers: list[str] = []
        sessions: list[str] = []
        async with self._pool_lock:
            records = list(self._sessions.values())
        for record in records:
            if record.active_calls or record.lock.locked():
                continue
            idle = now - record.last_used
            name = record.analysis.session
            if (
                record.worker is not None
                and record.worker.running
                and idle >= self.settings.worker_idle_seconds
            ):
                async with record.lock:
                    if time.time() - record.last_used < self.settings.worker_idle_seconds:
                        continue
                    if record.worker is None:
                        continue
                    await asyncio.shield(self._retire_worker(record))
                if record.analysis.external_database:
                    record.analysis.fingerprint = quick_fingerprint(record.analysis.source)
                    self._write_manifest(record.analysis)
                workers.append(name)
                self._event(record, "worker_reaped", idle_seconds=idle)
            if idle >= self.settings.session_idle_seconds:
                async with self._pool_lock:
                    if self._sessions.get(name) is record:
                        self._sessions.pop(name)
                sessions.append(name)
                self._event(record, "runtime_reaped", idle_seconds=idle)
        # Reuse the existing async reaper; between deadlines this is one clock
        # comparison, with no directory scans, extra tasks or sleeping threads.
        if time.monotonic() >= self._next_recovery_cleanup:
            for analysis in list(self._analyses.values()):
                if not analysis.external_database:
                    prune_inactive_recovery(analysis.database, self.settings.state_dir)
            self._next_recovery_cleanup = time.monotonic() + CHECK_INTERVAL_SECONDS
        return {"workers": workers, "sessions": sessions}

    async def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        async with self._pool_lock:
            records = list(self._sessions.values())
            self._sessions.clear()
        await asyncio.shield(
            asyncio.gather(*(self._dispose(row) for row in records), return_exceptions=True)
        )
        await asyncio.shield(asyncio.gather(*list(self._retiring.values()), return_exceptions=True))

    def status(self, session: str | None = None) -> dict[str, Any]:
        self._refresh_analyses()
        analyses = self._analyses.values()
        if session is not None:
            analysis = self._analysis_named(session)
            analyses = [analysis]
        rows = {row.session: self._status_row(row) for row in analyses}
        return {
            "agent": self.settings.agent,
            "transport": self.settings.transport,
            "project_root": str(self.settings.project_root),
            "state_dir": str(self.settings.state_dir),
            "limits": {
                "sessions": self.settings.max_sessions,
                "workers": self.settings.max_workers,
                "worker_idle_seconds": self.settings.worker_idle_seconds,
                "session_idle_seconds": self.settings.session_idle_seconds,
                "analysis_timeout": self.settings.analysis_timeout,
            },
            "runtime_sessions": len(self._sessions),
            "workers": sum(bool(row["worker_running"]) for row in rows.values()),
            "sessions": rows,
        }

    def log_tail(self, session: str, lines: int = 100) -> dict[str, Any]:
        self._refresh_analyses()
        analysis = self._analysis_named(session)
        session_dir = self.sessions_dir / analysis.session
        result: dict[str, Any] = {}
        for name, path in (
            ("events", session_dir / "events.jsonl"),
            ("bootstrap", session_dir / "bootstrap.log"),
            ("worker_stderr", session_dir / "worker.stderr.log"),
        ):
            try:
                result[name] = path.read_text(encoding="utf-8", errors="replace").splitlines()[
                    -lines:
                ]
            except FileNotFoundError:
                result[name] = []
        return {"session": analysis.session, **result}

    def analysis_status(self, session: str) -> dict[str, Any]:
        """Read persistent analysis state without starting or calling idalib."""
        analysis = self._analysis_named(session)
        return self._job_snapshot(analysis)

    def _job_snapshot(self, analysis: Analysis) -> dict[str, Any]:
        if analysis.external_database:
            return {
                "phase": "ready",
                "database_ready": analysis.database.is_file(),
                "legacy_ready": True,
                "completeness": "external_unknown",
                "job": None,
            }
        session_dir = self.sessions_dir / analysis.session
        job = read_job(session_dir)
        if job is None:
            ready = analysis.database.is_file()
            return {
                "phase": "ready" if ready else "registered",
                "database_ready": ready,
                "legacy_ready": ready,
                "completeness": "legacy_unknown" if ready else None,
                "job": None,
            }
        phase = str(job.get("phase") or "failed")
        fingerprint_matches = same_content(job.get("fingerprint") or {}, analysis.fingerprint)
        lifecycle = AssetLock.inspect(session_dir, filename="analysis-job.lock")
        owner = lifecycle.get("owner") if lifecycle.get("locked") else None
        owns_lifecycle = bool(
            isinstance(owner, dict)
            and owner.get("kind") == "analysis_job"
            and owner.get("job_id") == job.get("job_id")
        )
        if phase == "publishing" and not owns_lifecycle:
            staging = Path(str(job.get("staging") or ""))
            if analysis.database.is_file() and not staging.is_file() and fingerprint_matches:
                phase = "ready"
        if phase in ACTIVE_PHASES and not owns_lifecycle:
            age = time.time() - float(job.get("updated_at") or job.get("created_at") or 0)
            launching = phase == "launching" and age < min(self.settings.startup_timeout, 5)
            if not launching:
                phase = "interrupted"
        ready = phase == "ready" and analysis.database.is_file() and fingerprint_matches
        if phase == "ready" and not ready:
            phase = "failed"
        completeness = (
            "complete"
            if ready and job.get("complete_analysis")
            else "partial"
            if ready
            else "pending_complete"
            if job.get("complete_analysis")
            else "pending_partial"
        )
        return {
            "phase": phase,
            "database_ready": ready,
            "legacy_ready": False,
            "completeness": completeness,
            "job_active": owns_lifecycle,
            "job_process_alive": process_alive(job.get("job_pid")),
            "job": {**job, "phase": phase},
        }

    def _require_ready(self, analysis: Analysis) -> None:
        snapshot = self._job_snapshot(analysis)
        if snapshot["database_ready"]:
            return
        phase = snapshot["phase"]
        job = snapshot.get("job") or {}
        if phase in {"failed", "interrupted", "aborted"}:
            code = "ANALYSIS_ABORTED" if phase == "aborted" else "ANALYSIS_FAILED"
            raise AnalysisFailed(
                f"{code}: session {analysis.session!r} is {phase}; "
                f"job_id={job.get('job_id')}; error={job.get('error') or 'none'}; "
                "call ida/open(path) to submit a new persistent analysis job"
            )
        raise AnalysisPending(
            f"ANALYSIS_PENDING: session {analysis.session!r} is {phase}; "
            f"job_id={job.get('job_id')}; poll ida/analysis_status()"
        )

    def _start_analysis_job(
        self, analysis: Analysis, complete_analysis: bool, force: bool
    ) -> dict[str, Any]:
        session_dir = self.sessions_dir / analysis.session
        database_dir = self.databases_dir / analysis.session
        guard = AssetLock.acquire(
            session_dir,
            {"operation": "submit_analysis", "session": analysis.session},
            filename="job-launch.lock",
            purpose="analysis job launch",
        )
        try:
            snapshot = self._job_snapshot(analysis)
            if not force and snapshot["database_ready"]:
                return {
                    **snapshot,
                    "submitted": False,
                    "reused": True,
                    "non_blocking": True,
                }
            if snapshot["phase"] in ACTIVE_PHASES:
                return {
                    **snapshot,
                    "submitted": False,
                    "reused": True,
                    "non_blocking": True,
                }
            previous = snapshot.get("job") or {}
            generation = int(previous.get("generation") or 0) + 1
            job_id = uuid.uuid4().hex
            staging = analysis.database.with_name(
                f"{analysis.database.stem}.{job_id}.staging{analysis.database.suffix}"
            )
            state: dict[str, Any] = {
                "version": 2,
                "job_id": job_id,
                "generation": generation,
                "session": analysis.session,
                "source": str(analysis.source),
                "database": str(analysis.database),
                "staging": str(staging),
                "fingerprint": analysis.fingerprint,
                "complete_analysis": complete_analysis,
                "phase": "launching",
                "launcher_pid": os.getpid(),
                "job_pid": None,
                "worker_pid": None,
                "windows_job_name": None,
                "created_at": time.time(),
                "updated_at": time.time(),
                "started_at": None,
                "finished_at": None,
                "error": None,
            }
            write_job(session_dir, state)
            abort_path(session_dir, job_id).unlink(missing_ok=True)
            script = Path(__file__).with_name("analysis_job.py")
            command = [
                self.settings.worker_command,
                str(script),
                "--job-id",
                job_id,
                "--generation",
                str(generation),
                "--session-id",
                analysis.session,
                "--source",
                str(analysis.source),
                "--database",
                str(analysis.database),
                "--staging",
                str(staging),
                "--session-dir",
                str(session_dir),
                "--database-dir",
                str(database_dir),
                "--state-dir",
                str(self.settings.state_dir),
                "--worker-command",
                self.settings.worker_command,
                "--worker-script",
                str(self.settings.worker_script),
                "--ida-dir",
                str(self.settings.ida_dir),
                "--idalib-python",
                str(self.settings.idalib_python),
                "--fingerprint-json",
                json.dumps(analysis.fingerprint),
                "--max-workers",
                str(self.settings.max_workers),
                "--analysis-timeout",
                str(self.settings.analysis_timeout),
            ]
            for value in self.settings.pythonpaths:
                command.extend(("--pythonpath", str(value)))
            if complete_analysis:
                command.append("--complete-analysis")
            try:
                process = subprocess.Popen(
                    command,
                    cwd=str(session_dir),
                    env=dict(os.environ),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    creationflags=persistent_creation_flags(),
                    start_new_session=os.name != "nt",
                )
            except BaseException as exc:
                state["phase"] = "failed"
                state["error"] = f"PERSISTENCE_START_FAILED: {type(exc).__name__}: {exc}"
                state["finished_at"] = state["updated_at"] = time.time()
                write_job(session_dir, state)
                raise
            deadline = time.monotonic() + min(self.settings.startup_timeout, 5)
            while time.monotonic() < deadline:
                current = read_job(session_dir)
                lifecycle = AssetLock.inspect(session_dir, filename="analysis-job.lock")
                owner = lifecycle.get("owner") if lifecycle.get("locked") else None
                if (
                    current
                    and current.get("job_id") == job_id
                    and (
                        current.get("phase") in TERMINAL_PHASES
                        or current.get("phase") in {"queued", "analyzing", "publishing"}
                        or (isinstance(owner, dict) and owner.get("job_id") == job_id)
                    )
                ):
                    _release_detached_process_handle(process)
                    return {
                        **self._job_snapshot(analysis),
                        "submitted": True,
                        "reused": False,
                        "non_blocking": True,
                    }
                if process.poll() is not None:
                    break
                time.sleep(0.02)
            current = read_job(session_dir) or state
            if current.get("job_id") == job_id and current.get("phase") in TERMINAL_PHASES:
                _release_detached_process_handle(process)
                return {
                    **self._job_snapshot(analysis),
                    "submitted": True,
                    "reused": False,
                    "non_blocking": True,
                }
            if process.poll() is None:
                terminate_named_job(str(current.get("windows_job_name") or ""))
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                else:
                    os.killpg(process.pid, 9)
            current["phase"] = "failed"
            current["error"] = "PERSISTENCE_START_FAILED: analysis job handshake failed"
            current["finished_at"] = current["updated_at"] = time.time()
            write_job(session_dir, current)
            raise WorkerFailed(current["error"])
        finally:
            guard.release()

    def _abort_analysis_job(self, analysis: Analysis, expected_job_id: str) -> dict[str, Any]:
        session_dir = self.sessions_dir / analysis.session
        guard = AssetLock.acquire(
            session_dir,
            {"operation": "abort_analysis", "session": analysis.session},
            filename="job-launch.lock",
            purpose="analysis job launch",
        )
        try:
            current = read_job(session_dir) or {}
            actual_job_id = str(current.get("job_id") or "")
            if actual_job_id != expected_job_id:
                return {
                    "session": analysis.session,
                    "aborted": False,
                    "reason": "job_id_mismatch",
                    "expected_job_id": expected_job_id,
                    "current_job_id": actual_job_id,
                }
            if current.get("phase") not in ACTIVE_PHASES:
                return {
                    "session": analysis.session,
                    "aborted": False,
                    "reason": f"job is already {current.get('phase')}",
                    "job_id": actual_job_id,
                }
            marker = abort_path(session_dir, actual_job_id)
            marker.write_text(actual_job_id, encoding="ascii")
            deadline = time.monotonic() + self.settings.shutdown_timeout
            matched_owner = False
            while time.monotonic() < deadline:
                lifecycle = AssetLock.inspect(session_dir, filename="analysis-job.lock")
                owner = lifecycle.get("owner") if lifecycle.get("locked") else None
                matched_owner = bool(
                    isinstance(owner, dict)
                    and owner.get("kind") == "analysis_job"
                    and owner.get("job_id") == actual_job_id
                )
                if matched_owner or not lifecycle.get("locked"):
                    break
                time.sleep(0.05)
            if matched_owner:
                job_name = str(current.get("windows_job_name") or "")
                if os.name == "nt":
                    if not job_name or not terminate_named_job(job_name):
                        raise WorkerFailed(
                            "analysis job identity matched, but its Windows Job Object "
                            "could not be terminated"
                        )
                else:
                    os.killpg(int(current["job_pid"]), 9)
            elif AssetLock.inspect(session_dir, filename="analysis-job.lock")["locked"]:
                raise WorkerFailed(
                    "analysis lifecycle lock owner does not match the requested job; "
                    "refusing to terminate by PID"
                )
            while time.monotonic() < deadline:
                if not AssetLock.inspect(session_dir, filename="analysis-job.lock")["locked"]:
                    break
                time.sleep(0.05)
            else:
                raise WorkerFailed("analysis job did not release its lifecycle lock after abort")
            final = read_job(session_dir) or current
            staging_value = str(final.get("staging") or "")
            staging = Path(staging_value) if staging_value else None
            if (
                final.get("phase") in {"ready", "publishing"}
                and analysis.database.is_file()
                and (staging is None or not staging.is_file())
            ):
                return {
                    "session": analysis.session,
                    "aborted": False,
                    "reason": "analysis completed before abort won",
                    "job_id": actual_job_id,
                    "phase": "ready",
                }
            if staging is not None:
                try:
                    staging.resolve().relative_to((self.databases_dir / analysis.session).resolve())
                except ValueError:
                    pass
                else:
                    if actual_job_id in staging.name:
                        remove_database_family(staging)
            final["phase"] = "aborted"
            final["error"] = "explicitly aborted"
            final["finished_at"] = final["updated_at"] = time.time()
            write_job(session_dir, final)
            marker.unlink(missing_ok=True)
            return {
                "session": analysis.session,
                "aborted": True,
                "job_id": actual_job_id,
            }
        finally:
            guard.release()

    async def _runtime(self, analysis: Analysis, owner: str) -> RuntimeSession:
        async with self._pool_lock:
            record = self._sessions.get(analysis.session)
            if record is not None:
                record.owners.add(owner)
                record.last_used = time.time()
                return record
            if len(self._sessions) >= self.settings.max_sessions:
                raise QuotaExceeded(
                    f"session quota reached ({self.settings.max_sessions}); close an idle session"
                )
            record = RuntimeSession(
                analysis,
                {owner},
                self.sessions_dir / analysis.session,
                self.databases_dir / analysis.session,
            )
            self._sessions[analysis.session] = record
            self._event(record, "runtime_created")
            return record

    async def _call_worker(
        self,
        record: RuntimeSession,
        tool: str,
        arguments: dict[str, Any],
        restore: bool,
        retry: bool = False,
    ) -> Any:
        attempts = 2 if retry else 1
        for attempt in range(attempts):
            try:
                worker, started = await self._ensure_worker(record)
            except BaseException as exc:
                record.last_error = str(exc)
                self._event(record, "worker_start_failed", error=str(exc))
                raise
            try:
                restoring = restore and started
                if restoring:
                    await worker.call(
                        "ida_open_file", self._open_arguments(record.analysis, False, False)
                    )
                    status = await worker.call("ida_status", {})
                    if not self._worker_has_analysis(record.analysis, status):
                        raise WorkerFailed("DATABASE_INTEGRITY_FAILED: worker opened the wrong IDB")
                    integrity = await worker.call("ida_integrity_probe", {})
                    if not isinstance(integrity, dict) or not integrity.get("ok"):
                        raise WorkerFailed(f"DATABASE_INTEGRITY_FAILED: {integrity}")
                restoring = False
                return await worker.call(tool, arguments)
            except ToolFailed:
                if restoring:
                    # Failed open/probe must never leave a worker eligible for
                    # subsequent queries that would bypass validation.
                    await asyncio.shield(self._retire_worker(record, graceful=False))
                raise
            except WorkerFailed as exc:
                record.last_error = str(exc)
                self._event(record, "worker_failed", tool=tool, error=str(exc))
                if worker.tainted:
                    self._retire_worker(record)
                    raise
                await worker.force_stop("worker failure")
                record.worker = None
                self._release_worker_lock(record)
                if attempt + 1 >= attempts:
                    raise
                record.restarts += 1
            except asyncio.CancelledError:
                record.last_error = f"cancelled during {tool}"
                self._event(record, "worker_cancelled", tool=tool)
                self._retire_worker(record)
                raise
        raise AssertionError("unreachable")

    async def _ensure_worker(self, record: RuntimeSession) -> tuple[WorkerActor, bool]:
        self._require_ready(record.analysis)
        if record.analysis.session in self._retiring:
            raise SampleBusy("WORKER_DRAINING: previous call/close still owns this IDB")
        if record.worker is not None and record.worker.running:
            return record.worker, False
        if record.worker is not None:
            await record.worker.stop(graceful=False)
            record.worker = None
            self._release_worker_lock(record)
        registry_guard = AssetLock.acquire(
            self.settings.state_dir,
            {"operation": "start_worker", "session": record.analysis.session},
            filename="registry.lock",
            purpose="project registry",
        )
        try:
            record.worker_lock = AssetLock.acquire(
                record.database_dir,
                {"session": record.analysis.session, "owners": sorted(record.owners)},
            )
        finally:
            registry_guard.release()
        record.worker = WorkerActor(
            self.settings,
            record.analysis.session,
            record.session_dir,
            record.database_dir,
            self._worker_slots,
        )
        startup_guard: AssetLock | None = None
        try:
            if not record.analysis.external_database:
                job = read_job(record.session_dir) or {}
                verify_fingerprint(record.analysis.database, job.get("database_fingerprint"))
                quarantine_sidecars(record.analysis.database)
                prune_recovery(record.analysis.database)
            async with self._worker_start_lock:
                startup_guard = await self._acquire_startup_guard(record)
                self._event(record, "worker_starting")
                await record.worker.start()
        except BaseException as exc:
            record.last_error = str(exc)
            record.worker = None
            self._release_worker_lock(record)
            raise
        finally:
            if startup_guard is not None:
                startup_guard.release()
        record.force_create = False
        self._event(record, "worker_started", pid=record.worker.pid)
        return record.worker, True

    @staticmethod
    def _remove_database_files(database: Path) -> None:
        for suffix in (database.suffix, ".id0", ".id1", ".id2", ".nam", ".til"):
            database.with_suffix(suffix).unlink(missing_ok=True)

    async def _acquire_startup_guard(self, record: RuntimeSession) -> AssetLock:
        deadline = time.monotonic() + self.settings.startup_timeout
        while True:
            try:
                return AssetLock.acquire(
                    self.settings.state_dir,
                    {"operation": "initialize_idalib", "session": record.analysis.session},
                    filename="worker-startup.lock",
                    purpose="idalib initialization",
                )
            except SampleBusy:
                if time.monotonic() >= deadline:
                    raise WorkerFailed(
                        "timed out waiting for another idalib worker to finish initializing"
                    )
                await asyncio.sleep(0.1)

    def _open_arguments(
        self, analysis: Analysis, wait_for_analysis: bool, reset: bool
    ) -> dict[str, Any]:
        return {
            "path": str(analysis.source),
            "database_path": None if analysis.external_database else str(analysis.database),
            "create_database": reset
            or (not analysis.external_database and not analysis.database.is_file()),
            "wait_for_analysis": wait_for_analysis,
            "save_previous": None,
        }

    @staticmethod
    def _worker_has_analysis(analysis: Analysis, status: Any) -> bool:
        if not isinstance(status, dict) or not status.get("has_database"):
            return False
        expected = analysis.source if analysis.external_database else analysis.database
        if not expected.is_file():
            return False
        opened = status.get("database_path") or status.get("opened_path")
        if not opened:
            return False
        return canonical_path(Path(str(opened))) == canonical_path(expected)

    class _CallContext:
        def __init__(self, pool: SessionPool, record: RuntimeSession):
            self.pool = pool
            self.record = record

        async def __aenter__(self) -> None:
            try:
                await asyncio.wait_for(self.record.lock.acquire(), self.pool.settings.call_timeout)
            except TimeoutError as exc:
                raise WorkerFailed(
                    f"session {self.record.analysis.session!r} queue wait exceeded "
                    f"{self.pool.settings.call_timeout:g}s"
                ) from exc
            self.record.active_calls += 1
            self.record.last_used = time.time()

        async def __aexit__(self, *_: object) -> None:
            self.record.active_calls -= 1
            self.record.last_used = time.time()
            self.record.lock.release()

    def _serialized(self, record: RuntimeSession) -> _CallContext:
        return self._CallContext(self, record)

    async def _dispose(self, record: RuntimeSession) -> None:
        if record.worker is not None:
            await asyncio.shield(self._retire_worker(record))
        self._release_worker_lock(record)
        self._event(record, "runtime_disposed")

    def _retire_worker(self, record: RuntimeSession, graceful: bool = True) -> asyncio.Task[Any]:
        """Transfer ownership to cleanup, so client cancellation cannot release the IDB."""
        name = record.analysis.session
        if name in self._retiring:
            return self._retiring[name]
        worker, guard = record.worker, record.worker_lock
        record.worker = record.worker_lock = None

        async def finish() -> None:
            try:
                result = None
                while worker is not None:
                    try:
                        result = await worker.stop(graceful=graceful)
                        break
                    except Exception as exc:
                        if not worker.running:
                            raise
                        record.last_error = str(exc)
                        self._event(record, "worker_retirement_retry", error=str(exc))
                        await asyncio.sleep(1)
                if result and result.get("save"):
                    analysis = record.analysis
                    if analysis.external_database:
                        analysis.fingerprint = quick_fingerprint(analysis.source)
                        self._write_manifest(analysis)
                    else:
                        job = read_job(record.session_dir)
                        if job and job.get("phase") == "ready":
                            job["database_fingerprint"] = quick_fingerprint(analysis.database)
                            write_job(record.session_dir, job)
            except Exception as exc:  # noqa: BLE001 - retain asynchronous cleanup diagnostics.
                record.last_error = str(exc)
                self._event(record, "worker_retirement_failed", error=str(exc))
            finally:
                if (
                    guard is not None
                    and worker is not None
                    and not worker.running
                    and not record.analysis.external_database
                ):
                    prune_recovery(
                        record.analysis.database,
                        successful_save=bool(result and result.get("save")),
                    )
                if guard is not None:
                    guard.release()
                self._retiring.pop(name, None)

        task = asyncio.create_task(finish(), name=f"ida-retire:{name}")
        self._retiring[name] = task
        return task

    def _resolve_source(self, value: str) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self.settings.project_root / path
        try:
            path = path.resolve(strict=True)
        except OSError as exc:
            code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
            raise SourceOpenError(
                f"SOURCE_READ_FAILED: cannot resolve {path}; os_error={code}; "
                "the agent must decide how to handle the source"
            ) from exc
        for reserved in (self.databases_dir, self.sessions_dir):
            try:
                path.relative_to(reserved)
            except ValueError:
                continue
            raise ValueError(
                f"managed path {reserved} cannot be opened as an input; select its session instead"
            )
        if not path.is_file():
            raise ValueError(f"input is not a file: {path}")
        return path

    def _analysis_by_source(self, source: Path) -> Analysis | None:
        key = canonical_path(source)
        return next((row for row in self._analyses.values() if row.source_key == key), None)

    def _analysis_named(self, session: str) -> Analysis:
        analysis = self._analyses.get(session)
        if analysis is not None:
            return analysis
        self._renames.update(self._load_renames())
        renamed = self._renames.get(session)
        if renamed:
            raise SessionNotFound(f"SESSION_RENAMED: {session!r} is now {renamed!r}")
        raise SessionNotFound(f"SESSION_NOT_FOUND: {session!r}; use ida/sessions()")

    def _select_analysis(self, session: str | None, path: str | None) -> Analysis:
        if (session is None) == (path is None):
            raise ValueError("specify exactly one of session or path")
        if session is not None:
            return self._analysis_named(session)
        assert path is not None
        source = self._resolve_source(path)
        analysis = self._analysis_by_source(source)
        if analysis is None:
            raise SessionNotFound(
                f"PATH_NOT_ANALYZED: {source}; call ida/open(path) to create an analysis"
            )
        return analysis

    def _check_source(self, analysis: Analysis) -> None:
        current = quick_fingerprint(analysis.source)
        if not same_content(analysis.fingerprint, current):
            raise SourceChanged(
                f"SOURCE_CHANGED: {analysis.source} belongs to session {analysis.session!r}; "
                "call ida/open(path, reset_if_changed=true) only if replacement is intended"
            )

    def _choose_session(self, requested: str | None, source: Path) -> str:
        if requested is not None:
            self._validate_session(requested)
            if requested in self._analyses:
                raise SessionConflict(
                    f"SESSION_CONFLICT: {requested!r} already refers to "
                    f"{self._analyses[requested].source}"
                )
            return requested
        base = re.sub(r"[^a-z0-9_.-]+", "-", source.stem.casefold()).strip("-._") or "analysis"
        base = base[:64]
        if base not in self._analyses:
            return base
        suffix = 2
        while True:
            tail = f"-{suffix}"
            candidate = f"{base[: 64 - len(tail)]}{tail}"
            if candidate not in self._analyses:
                return candidate
            suffix += 1

    @staticmethod
    def _validate_session(session: str) -> None:
        if not SESSION_RE.fullmatch(session):
            raise ValueError("session must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")

    def _manifest_path(self, session: str) -> Path:
        return self.databases_dir / session / "database.json"

    def _write_manifest(self, analysis: Analysis) -> None:
        path = self._manifest_path(analysis.session)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 2,
            "session": analysis.session,
            "source": str(analysis.source),
            "fingerprint": analysis.fingerprint,
            "database": (
                str(analysis.database)
                if analysis.external_database
                else store_state_path(analysis.database, self.settings.state_dir)
            ),
            "external_database": analysis.external_database,
            "created_at": analysis.created_at,
            "updated_at": analysis.updated_at,
            "renamed_from": analysis.renamed_from,
        }
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)

    def _load_analyses(self) -> dict[str, Analysis]:
        result: dict[str, Analysis] = {}
        if not self.databases_dir.is_dir():
            return result
        for path in self.databases_dir.glob("*/database.json"):
            try:
                row = json.loads(path.read_text(encoding="utf-8"))
                external_database = bool(row["external_database"])
                stored_database = str(row["database"])
                database = (
                    Path(stored_database).expanduser().resolve()
                    if external_database
                    else load_state_path(
                        stored_database,
                        self.settings.state_dir,
                        legacy_directory=path.parent,
                    )
                )
                analysis = Analysis(
                    session=str(row["session"]),
                    source=Path(str(row["source"])).resolve(),
                    fingerprint=dict(row["fingerprint"]),
                    database=database,
                    external_database=external_database,
                    created_at=float(row.get("created_at", path.stat().st_ctime)),
                    updated_at=float(row.get("updated_at", path.stat().st_mtime)),
                    renamed_from=list(row.get("renamed_from", [])),
                )
                self._validate_session(analysis.session)
                result[analysis.session] = analysis
            except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
                continue
        return result

    def _refresh_analyses(self) -> None:
        for name, analysis in self._load_analyses().items():
            if name not in self._sessions:
                self._analyses[name] = analysis

    @property
    def _renames_path(self) -> Path:
        return self.settings.state_dir / "renames.json"

    def _load_renames(self) -> dict[str, str]:
        try:
            return dict(json.loads(self._renames_path.read_text(encoding="utf-8")))
        except (FileNotFoundError, OSError, TypeError, json.JSONDecodeError):
            return {}

    def _write_renames(self) -> None:
        self.settings.state_dir.mkdir(parents=True, exist_ok=True)
        self._renames_path.write_text(
            json.dumps(self._renames, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def _status_row(self, analysis: Analysis) -> dict[str, Any]:
        record = self._sessions.get(analysis.session)
        local_running = bool(record and record.worker and record.worker.running)
        local_owned = bool(record and record.worker_lock is not None)
        lock = (
            {"locked": False, "owner": None}
            if local_owned
            else AssetLock.inspect(self.databases_dir / analysis.session)
        )
        cross_scheduler = bool(lock["locked"] and not local_owned)
        initializing = bool(local_owned and not local_running and record and record.active_calls)
        active_calls = record.active_calls if record else 0
        analysis_state = self._job_snapshot(analysis)
        database_ready = analysis_state["database_ready"]
        phase = analysis_state["phase"]
        if database_ready and cross_scheduler:
            phase = "cross_scheduler"
        elif database_ready and initializing:
            phase = "initializing"
        elif database_ready and active_calls:
            phase = "busy"
        job = analysis_state.get("job") or {}
        staging = Path(str(job.get("staging"))) if job.get("staging") else None
        return {
            **self._analysis_row(analysis),
            "phase": phase,
            "database_ready": database_ready,
            "completeness": analysis_state.get("completeness"),
            "legacy_ready": analysis_state.get("legacy_ready", False),
            "analysis_job": job or None,
            "analysis_job_active": analysis_state.get("job_active", False),
            "bootstrap_staging": bool(staging and staging.is_file()),
            "owners": sorted(record.owners) if record else [],
            "worker_running": local_running
            or (cross_scheduler and (lock.get("owner") or {}).get("kind") != "analysis_job"),
            "worker_pid": record.worker.pid if record and record.worker else None,
            "worker_draining": analysis.session in self._retiring,
            "initializing": initializing,
            "cross_scheduler_active": cross_scheduler,
            "lock_owner": lock["owner"] if cross_scheduler else None,
            "active_calls": active_calls,
            "last_used": record.last_used if record else None,
            "restarts": record.restarts if record else 0,
            "last_error": record.last_error if record else None,
        }

    @staticmethod
    def _analysis_row(analysis: Analysis, active: bool | None = None) -> dict[str, Any]:
        row = {
            "session": analysis.session,
            "source": str(analysis.source),
            "database": str(analysis.database),
            "external_database": analysis.external_database,
            "fingerprint": analysis.fingerprint,
            "renamed_from": analysis.renamed_from,
        }
        if active is not None:
            row["active"] = active
        return row

    @staticmethod
    def _release_worker_lock(record: RuntimeSession) -> None:
        if record.worker_lock is not None:
            record.worker_lock.release()
            record.worker_lock = None

    @staticmethod
    def _event(record: RuntimeSession, event: str, **fields: object) -> None:
        record.session_dir.mkdir(parents=True, exist_ok=True)
        row = {
            "time": time.time(),
            "event": event,
            "session": record.analysis.session,
            **fields,
        }
        with (record.session_dir / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
