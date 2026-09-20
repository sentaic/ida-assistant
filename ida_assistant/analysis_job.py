from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from .asset_lock import AssetLock
    from .fingerprint import quick_fingerprint, same_content
    from .state_paths import load_state_path, store_state_path
except ImportError:  # Executed directly as the persistent analysis runner.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from ida_assistant.asset_lock import AssetLock
    from ida_assistant.fingerprint import quick_fingerprint, same_content
    from ida_assistant.state_paths import load_state_path, store_state_path


TERMINAL_PHASES = {"ready", "failed", "aborted"}
ACTIVE_PHASES = {"launching", "queued", "analyzing", "publishing"}
WINDOWS_CREATION_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def job_path(session_dir: Path) -> Path:
    return session_dir / "analysis-job.json"


def abort_path(session_dir: Path, job_id: str) -> Path:
    return session_dir / f"analysis-abort.{job_id}"


def read_job(session_dir: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(job_path(session_dir).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    state_dir = session_dir.resolve().parent.parent
    legacy_directory = state_dir / "databases" / session_dir.name
    for name in ("database", "staging"):
        stored = value.get(name)
        if stored:
            value[name] = str(
                load_state_path(
                    str(stored),
                    state_dir,
                    legacy_directory=legacy_directory,
                )
            )
    return value


def write_job(session_dir: Path, value: dict[str, Any]) -> None:
    session_dir.mkdir(parents=True, exist_ok=True)
    target = job_path(session_dir)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    stored = dict(value)
    stored["version"] = 2
    state_dir = session_dir.resolve().parent.parent
    for name in ("database", "staging"):
        current = stored.get(name)
        if current:
            stored[name] = store_state_path(Path(str(current)), state_dir)
    temporary.write_text(json.dumps(stored, ensure_ascii=False, indent=2), encoding="utf-8")
    deadline = time.monotonic() + 2
    while True:
        try:
            os.replace(temporary, target)
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                temporary.unlink(missing_ok=True)
                raise
            time.sleep(0.01)


def remove_database_family(database: Path) -> None:
    for suffix in (database.suffix, ".id0", ".id1", ".id2", ".nam", ".til"):
        database.with_suffix(suffix).unlink(missing_ok=True)


def process_alive(pid: object) -> bool:
    try:
        value = int(pid)
        if value <= 0:
            return False
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.restype = ctypes.c_void_p
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            handle = kernel32.OpenProcess(0x00100000, False, value)  # SYNCHRONIZE
            if not handle:
                return False
            try:
                return kernel32.WaitForSingleObject(handle, 0) == 0x00000102
            finally:
                kernel32.CloseHandle(handle)
        os.kill(value, 0)
        return True
    except (OSError, TypeError, ValueError):
        return False


def persistent_creation_flags() -> int:
    """Return Windows flags that escape a kill-on-close parent job when permitted."""
    if os.name != "nt":
        return 0
    flags = WINDOWS_CREATION_FLAGS | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    kernel32.QueryInformationJobObject.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    in_job = ctypes.c_int()
    if not kernel32.IsProcessInJob(kernel32.GetCurrentProcess(), None, ctypes.byref(in_job)):
        raise OSError(ctypes.get_last_error(), "IsProcessInJob failed")
    if not in_job.value:
        return flags

    class IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_ulonglong)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", ctypes.c_ulong),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_ulong),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_ulong),
            ("SchedulingClass", ctypes.c_ulong),
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimits),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    limits = ExtendedLimits()
    if not kernel32.QueryInformationJobObject(
        None, 9, ctypes.byref(limits), ctypes.sizeof(limits), None
    ):
        raise OSError(ctypes.get_last_error(), "QueryInformationJobObject failed")
    limit_flags = int(limits.BasicLimitInformation.LimitFlags)
    kill_on_close = 0x2000
    breakaway_ok = 0x0800
    silent_breakaway_ok = 0x1000
    if limit_flags & kill_on_close and not limit_flags & (breakaway_ok | silent_breakaway_ok):
        raise RuntimeError(
            "PERSISTENCE_UNAVAILABLE: the parent Windows Job kills descendants on close "
            "and forbids breakaway"
        )
    if limit_flags & breakaway_ok and not limit_flags & silent_breakaway_ok:
        flags |= getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0)
    return flags


def terminate_named_job(name: str, exit_code: int = 20) -> bool:
    if os.name != "nt":
        return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenJobObjectW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    handle = kernel32.OpenJobObjectW(0x0008, False, name)  # JOB_OBJECT_TERMINATE
    if not handle:
        return False
    try:
        return bool(kernel32.TerminateJobObject(handle, exit_code))
    finally:
        kernel32.CloseHandle(handle)


def _own_windows_job(name: str) -> object | None:
    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.SetInformationJobObject.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", ctypes.c_ulong),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_ulong),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_ulong),
            ("SchedulingClass", ctypes.c_ulong),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            (field, ctypes.c_ulonglong)
            for field in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimits),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    handle = kernel32.CreateJobObjectW(None, name)
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateJobObject failed")
    if ctypes.get_last_error() == 183:
        kernel32.CloseHandle(handle)
        raise RuntimeError(f"analysis Job Object already exists: {name}")
    limits = ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(handle)
        raise OSError(error, "SetInformationJobObject failed")
    if not kernel32.AssignProcessToJobObject(handle, kernel32.GetCurrentProcess()):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(handle)
        raise OSError(error, "AssignProcessToJobObject failed")
    return handle


def _release_windows_job(handle: object | None) -> None:
    if handle is not None and os.name == "nt":
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)


def _acquire_slot(state_dir: Path, count: int, owner: dict[str, object], marker: Path) -> AssetLock:
    slots = state_dir / "analysis-slots"
    while True:
        if marker.exists():
            raise InterruptedError("analysis was aborted while queued")
        for index in range(count):
            try:
                return AssetLock.acquire(
                    slots, owner, filename=f"slot-{index}.lock", purpose="analysis slot"
                )
            except (
                Exception
            ) as exc:  # Only SampleBusy is expected; keep direct-script imports small.
                if exc.__class__.__name__ != "SampleBusy":
                    raise
        time.sleep(0.1)


def _parse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Persistent IDA analysis job")
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--staging", required=True)
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--database-dir", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--worker-command", required=True)
    parser.add_argument("--worker-script", required=True)
    parser.add_argument("--ida-dir", required=True)
    parser.add_argument("--idalib-python", required=True)
    parser.add_argument("--pythonpath", action="append", default=[])
    parser.add_argument("--fingerprint-json", required=True)
    parser.add_argument("--max-workers", type=int, required=True)
    parser.add_argument("--analysis-timeout", type=float, default=0)
    parser.add_argument("--complete-analysis", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = _parse()
    source = Path(args.source).resolve()
    database = Path(args.database).resolve()
    staging = Path(args.staging).resolve()
    session_dir = Path(args.session_dir).resolve()
    database_dir = Path(args.database_dir).resolve()
    state_dir = Path(args.state_dir).resolve()
    expected_fingerprint = json.loads(args.fingerprint_json)
    marker = abort_path(session_dir, args.job_id)
    job_name = f"Local\\IDA-Assistant-{args.job_id}"
    now = time.time()
    state: dict[str, Any] = {
        "version": 2,
        "job_id": args.job_id,
        "generation": args.generation,
        "session": args.session_id,
        "source": str(source),
        "database": str(database),
        "staging": str(staging),
        "fingerprint": expected_fingerprint,
        "complete_analysis": bool(args.complete_analysis),
        "phase": "launching",
        "launcher_pid": None,
        "job_pid": os.getpid(),
        "worker_pid": None,
        "windows_job_name": job_name if os.name == "nt" else None,
        "created_at": now,
        "updated_at": now,
        "started_at": now,
        "finished_at": None,
        "error": None,
    }
    lifecycle: AssetLock | None = None
    slot: AssetLock | None = None
    worker_lock: AssetLock | None = None
    windows_job: object | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        windows_job = _own_windows_job(job_name)
        owner = {"kind": "analysis_job", "job_id": args.job_id, "session": args.session_id}
        lifecycle = AssetLock.acquire(
            session_dir, owner, filename="analysis-job.lock", purpose="analysis job"
        )
        state["phase"] = "queued"
        state["updated_at"] = time.time()
        write_job(session_dir, state)
        slot = _acquire_slot(state_dir, args.max_workers, owner, marker)
        worker_lock = AssetLock.acquire(database_dir, owner, purpose="session IDB")
        if marker.exists():
            raise InterruptedError("analysis was aborted before startup")
        if not same_content(quick_fingerprint(source), expected_fingerprint):
            raise RuntimeError("SOURCE_CHANGED_DURING_ANALYSIS: refusing to publish a stale IDB")
        remove_database_family(staging)
        pid_file = session_dir / f"analysis-worker.{args.job_id}.pid"
        pid_file.unlink(missing_ok=True)
        command = [
            args.worker_command,
            args.worker_script,
            "--session-id",
            args.session_id,
            "--session-dir",
            str(session_dir),
            "--database-dir",
            str(database_dir),
            "--ida-user-dir",
            str(session_dir / "ida-user"),
            "--pid-file",
            str(pid_file),
            "--ida-dir",
            args.ida_dir,
            "--idalib-python",
            args.idalib_python,
        ]
        for value in args.pythonpath:
            command.extend(("--pythonpath", value))
        command.extend(
            (
                "--unsafe",
                "--bootstrap-only",
                "--source-path",
                str(source),
                "--output-database",
                str(staging),
            )
        )
        if args.complete_analysis:
            command.append("--bootstrap-wait")
        process = subprocess.Popen(
            command,
            cwd=str(session_dir),
            env=dict(os.environ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=WINDOWS_CREATION_FLAGS,
            start_new_session=os.name != "nt",
        )
        state["phase"] = "analyzing"
        state["worker_pid"] = process.pid
        state["updated_at"] = time.time()
        write_job(session_dir, state)
        deadline = time.monotonic() + args.analysis_timeout if args.analysis_timeout > 0 else None
        while process.poll() is None:
            if marker.exists():
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=WINDOWS_CREATION_FLAGS,
                    )
                else:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise InterruptedError("analysis was aborted")
            if deadline is not None and time.monotonic() >= deadline:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=WINDOWS_CREATION_FLAGS,
                    )
                else:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise TimeoutError(f"analysis exceeded {args.analysis_timeout:g}s")
            time.sleep(0.1)
        if process.returncode or not staging.is_file():
            raise RuntimeError(
                f"IDA database creation failed (rc={process.returncode}); "
                f"see {session_dir / 'bootstrap.log'}"
            )
        if marker.exists():
            raise InterruptedError("analysis was aborted before publication")
        if not same_content(quick_fingerprint(source), expected_fingerprint):
            raise RuntimeError("SOURCE_CHANGED_DURING_ANALYSIS: refusing to publish a stale IDB")
        state["phase"] = "publishing"
        state["updated_at"] = time.time()
        write_job(session_dir, state)
        database.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, database)
        state["phase"] = "ready"
        state["database_size"] = database.stat().st_size
        state["database_fingerprint"] = quick_fingerprint(database)
        state["finished_at"] = state["updated_at"] = time.time()
        write_job(session_dir, state)
        worker_lock.release()
        worker_lock = None
        return 0
    except InterruptedError as exc:
        state["phase"] = "aborted"
        state["error"] = str(exc)
        state["finished_at"] = state["updated_at"] = time.time()
        write_job(session_dir, state)
        return 20
    except Exception as exc:  # noqa: BLE001 - persist every runner failure in job state.
        state["phase"] = "failed"
        state["error"] = f"{type(exc).__name__}: {exc}"
        state["finished_at"] = state["updated_at"] = time.time()
        write_job(session_dir, state)
        return 1
    finally:
        remove_database_family(staging)
        if worker_lock is not None:
            worker_lock.release()
        if slot is not None:
            slot.release()
        if lifecycle is not None:
            lifecycle.release()
        marker.unlink(missing_ok=True)
        _release_windows_job(windows_job)


if __name__ == "__main__":
    raise SystemExit(main())
