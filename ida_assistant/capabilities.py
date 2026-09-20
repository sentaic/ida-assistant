from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict, dataclass, replace


@dataclass(frozen=True, slots=True)
class Capabilities:
    edit: bool = False
    python: bool = False
    debug: bool = False

    def as_dict(self) -> dict[str, bool]:
        return asdict(self)


class CapabilityRegistry:
    """Bounded, connection-local operation capabilities."""

    def __init__(self, default_unsafe: bool, max_entries: int = 1024):
        enabled = Capabilities(True, True, True)
        self.default = enabled if default_unsafe else Capabilities()
        self.max_entries = max_entries
        self._entries: OrderedDict[str, Capabilities] = OrderedDict()

    def get(self, binding: str) -> Capabilities:
        value = self._entries.get(binding)
        if value is None:
            return self.default
        self._entries.move_to_end(binding)
        return value

    def set(
        self,
        binding: str,
        *,
        edit: bool | None = None,
        python: bool | None = None,
        debug: bool | None = None,
    ) -> Capabilities:
        current = self.get(binding)
        value = replace(
            current,
            edit=current.edit if edit is None else edit,
            python=current.python if python is None else python,
            debug=current.debug if debug is None else debug,
        )
        if value == self.default:
            self._entries.pop(binding, None)
            return value
        self._entries[binding] = value
        self._entries.move_to_end(binding)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        return value
