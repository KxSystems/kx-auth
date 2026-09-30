"""The two things every command that talks to q needs: a quiet PyKX import, and readable q values.

Both exist only because of how PyKX presents itself and how q presents its values, so they live
together rather than being restated by each command that connects.
"""

from __future__ import annotations

import contextlib
import io
from typing import Any


def import_pykx() -> Any:
    """Import PyKX without letting its banner reach stdout.

    Community PyKX prints an embedded-q welcome banner while importing. Every command here has a
    one-envelope stdout contract, so a library banner would corrupt `--json` output for a caller that
    is parsing it — and it is irrelevant to a remote qIPC client in any case.

    Raises whatever the import raised, so each caller can map it to its own error surface.
    """
    with contextlib.redirect_stdout(io.StringIO()):
        import pykx as kx
    return kx


def readable(obj: Any) -> Any:
    """Convert a q readback into something JSON can render honestly.

    Three q-to-Python artifacts have to be undone, or they leak into an interface contract:

    * a PyKX wrapper that has not been converted yet (`.py()`),
    * q char vectors, which arrive as `bytes` and would print as `b'...'`,
    * numpy scalars and arrays, which `json.dumps` cannot serialise.

    Containers are walked so a nested claims blob comes back clean.
    """
    if hasattr(obj, "py"):
        obj = obj.py()
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    if isinstance(obj, dict):
        return {readable(k): readable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [readable(v) for v in obj]
    if hasattr(obj, "item"):
        try:
            return readable(obj.item())
        except (TypeError, ValueError):
            pass
    if hasattr(obj, "tolist"):
        return readable(obj.tolist())
    return obj
