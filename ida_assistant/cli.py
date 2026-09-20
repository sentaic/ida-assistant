from __future__ import annotations

from .config import Settings
from .server import create_server


def main(argv: list[str] | None = None) -> None:
    try:
        settings = Settings.from_args(argv)
    except ValueError as exc:
        raise SystemExit(f"IDA Assistant startup error: {exc}") from None
    mcp, _ = create_server(settings)
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
