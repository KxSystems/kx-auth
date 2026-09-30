"""Client-side token cache for ``kx auth`` — a single JSON file, keyed by endpoint.

``login`` writes the acquired credential here; ``exchange`` reads it as a subject-token fallback.
The cache is a *client-side* concern (the agent/operator's own credentials), so it lives in the CLI
rather than the shared core. Templates include product CLIs' endpoint-keyed caches and ``gh``'s
``~/.config/gh/hosts.yml`` — a single JSON file under a dotdir, path overridable, keyed by endpoint
so multiple deployments coexist. OS-keyring storage is a later hardening, not the v1 bar.

The keys are the ``--server`` (MCP-server / resource) URLs the agent connects to. ``introspect`` is
stateless and never touches this file.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Optional

from . import atomic


def cache_path() -> Path:
    """The credential file path: ``$KX_AUTH_CACHE`` if set, else ``~/.kx/credentials.json``."""
    override = os.environ.get("KX_AUTH_CACHE")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".kx" / "credentials.json"


def load() -> dict[str, Any]:
    """The whole cache as ``{server: credential}``; ``{}`` if absent or unreadable (never raises)."""
    path = cache_path()
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        # Missing or corrupt cache is "no cached credentials", not a hard error.
        return {}


def get(server: str) -> Optional[dict[str, Any]]:
    """The cached credential for ``server``, or ``None`` if not present."""
    entry = load().get(server)
    return entry if isinstance(entry, dict) else None


def save(server: str, credential: dict[str, Any]) -> Path:
    """Merge ``credential`` under ``server`` and persist. Dir ``0700``, file ``0600``."""
    path = cache_path()
    # The directory mode is this function's own concern; atomic.write_json owns the file's. mkdir's
    # mode is create-only, so a directory that already existed keeps whatever mode it had — narrow it
    # explicitly, except a sticky directory (e.g. $KX_AUTH_CACHE pointed into /tmp), which is shared by
    # design and never ours to re-mode; there the 0600 file mode carries the guarantee alone.
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        if not parent.stat().st_mode & stat.S_ISVTX:
            parent.chmod(0o700)
    data = load()
    data[server] = credential
    # PRIVATE, not the umask: this file holds bearer tokens.
    return atomic.write_json(path, data, mode=atomic.PRIVATE)
