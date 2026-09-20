from __future__ import annotations

from pathlib import Path


def store_state_path(path: Path, state_dir: Path) -> str:
    """Store paths owned by the project state relative to its movable root."""
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(state_dir.resolve())
    except ValueError:
        return str(resolved)
    return relative.as_posix()


def load_state_path(
    value: str,
    state_dir: Path,
    *,
    legacy_directory: Path | None = None,
) -> Path:
    """Resolve new relative paths and relocate legacy absolute managed paths."""
    stored = Path(value).expanduser()
    if not stored.is_absolute():
        return (state_dir / stored).resolve()

    resolved = stored.resolve()
    if legacy_directory is None:
        return resolved

    relocated = (legacy_directory / stored.name).resolve()
    if relocated.is_file() or not resolved.exists():
        return relocated
    return resolved
