from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path


def _path(value: str | Path) -> Path:
    return Path(os.path.expandvars(str(value))).expanduser().resolve()


def _is_wsl_linux_filesystem(path: Path) -> bool:
    normalized = str(path).replace("/", "\\").casefold()
    return normalized.startswith(("\\\\wsl.localhost\\", "\\\\wsl$\\"))


@dataclass(frozen=True, slots=True)
class Settings:
    transport: str
    host: str
    port: int
    agent: str
    project_root: Path
    worker_command: str
    worker_script: Path
    ida_dir: Path
    idalib_python: Path
    pythonpaths: tuple[Path, ...]
    max_sessions: int
    max_workers: int
    worker_idle_seconds: float
    session_idle_seconds: float
    startup_timeout: float
    call_timeout: float
    analysis_timeout: float
    shutdown_timeout: float
    unsafe: bool
    log_level: str
    flush_timeout: float = 0
    drain_timeout: float = 900

    @classmethod
    def from_args(cls, argv: list[str] | None = None) -> Settings:
        parser = argparse.ArgumentParser(description="IDA Assistant MCP scheduler")
        parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=8741)
        parser.add_argument(
            "--agent", default="unspecified", help="Deployment identity (Codex/pi/etc.)"
        )
        parser.add_argument(
            "--project-root",
            default=str(Path.cwd()),
            help="Project containing the managed .ida directory (default: current directory)",
        )
        parser.add_argument("--worker-command", default=sys.executable)
        parser.add_argument(
            "--worker-script",
            default=str(Path(__file__).with_name("idalib_worker.py")),
        )
        parser.add_argument("--ida-dir", default=r"C:\Program Files\IDA Professional 9.1")
        parser.add_argument("--idalib-python")
        parser.add_argument("--pythonpath", action="append", default=[])
        parser.add_argument("--max-sessions", type=int, default=8)
        parser.add_argument("--max-workers", type=int, default=3)
        parser.add_argument("--worker-idle-seconds", type=float, default=60)
        parser.add_argument("--session-idle-seconds", type=float, default=900)
        parser.add_argument("--startup-timeout", type=float, default=120)
        parser.add_argument("--call-timeout", type=float, default=300)
        parser.add_argument(
            "--analysis-timeout",
            type=float,
            default=0,
            help="Detached full-analysis deadline in seconds; 0 means unlimited",
        )
        parser.add_argument("--shutdown-timeout", type=float, default=10)
        parser.add_argument(
            "--flush-timeout",
            type=float,
            default=0,
            help="Close/save response deadline; 0 waits indefinitely; never kills a save",
        )
        parser.add_argument(
            "--drain-timeout",
            type=float,
            default=900,
            help="Grace period for abandoned non-save calls before termination",
        )
        parser.add_argument("--unsafe", action="store_true")
        parser.add_argument(
            "--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO"
        )
        args = parser.parse_args(argv)

        ida_dir = _path(args.ida_dir)
        idalib_python = _path(args.idalib_python or ida_dir / "idalib" / "python")
        settings = cls(
            transport=args.transport,
            host=args.host,
            port=args.port,
            agent=args.agent,
            project_root=_path(args.project_root),
            worker_command=args.worker_command,
            worker_script=_path(args.worker_script),
            ida_dir=ida_dir,
            idalib_python=idalib_python,
            pythonpaths=tuple(_path(item) for item in args.pythonpath),
            max_sessions=args.max_sessions,
            max_workers=args.max_workers,
            worker_idle_seconds=args.worker_idle_seconds,
            session_idle_seconds=args.session_idle_seconds,
            startup_timeout=args.startup_timeout,
            call_timeout=args.call_timeout,
            analysis_timeout=args.analysis_timeout,
            shutdown_timeout=args.shutdown_timeout,
            unsafe=args.unsafe,
            log_level=args.log_level,
            flush_timeout=args.flush_timeout,
            drain_timeout=args.drain_timeout,
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if _is_wsl_linux_filesystem(self.project_root):
            raise ValueError(
                "WSL_LINUX_FILESYSTEM_UNSUPPORTED: --project-root resolves to the WSL "
                f"Linux filesystem ({self.project_root}). IDA Assistant runs as a Windows "
                "process and its project .ida state requires Windows byte-range locking, "
                "which WSL Linux filesystem UNC paths do not provide. Open or move the "
                "project to a Windows-backed path such as /mnt/c/... or /mnt/d/... and retry."
            )
        if not self.project_root.is_dir():
            raise ValueError(f"--project-root is not a directory: {self.project_root}")
        if self.max_sessions < 1 or self.max_workers < 1:
            raise ValueError("--max-sessions and --max-workers must be positive")
        if self.max_workers > self.max_sessions:
            raise ValueError("--max-workers cannot exceed --max-sessions")
        for name, value in (
            ("worker idle", self.worker_idle_seconds),
            ("session idle", self.session_idle_seconds),
            ("startup timeout", self.startup_timeout),
            ("call timeout", self.call_timeout),
            ("shutdown timeout", self.shutdown_timeout),
            ("drain timeout", self.drain_timeout),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if self.analysis_timeout < 0:
            raise ValueError("analysis timeout must be zero (unlimited) or positive")
        if self.flush_timeout < 0:
            raise ValueError("flush timeout must be zero (unlimited) or positive")
        if self.session_idle_seconds < self.worker_idle_seconds:
            raise ValueError("session idle timeout must be >= worker idle timeout")

    @property
    def state_dir(self) -> Path:
        return self.project_root / ".ida"
