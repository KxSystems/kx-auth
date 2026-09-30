"""Temp-then-rename file writes, with the file mode stated rather than inherited.

Three commands write files a later step reads back — the login cache, `assert --promoted-out`, and
`rbac export`. All three need the same two properties, so they share one implementation:

* **Atomic replacement.** A crash mid-write must not leave a truncated file where a complete one was.
  `os.replace` is atomic within a filesystem, and the temp file is created alongside the target so
  the rename never crosses one.
* **An explicit mode.** The mode is passed at `open` rather than `chmod`'d afterwards, so the file is
  never briefly readable at the process umask before being narrowed.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from typing import Any

#: Owner-only. For anything carrying a credential or an identity's claims.
PRIVATE = 0o600

#: Whatever the process umask allows. For files whose contents are not sensitive.
UMASK = 0o666


def write_text(path: Path, text: str, *, mode: int = UMASK) -> Path:
    """Write ``text`` to ``path`` atomically, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    # os.open's mode applies only when it CREATES the file, so a temp left by an earlier run (or
    # planted) would survive an O_TRUNC with its own wider mode and then be renamed onto the target —
    # observed as a 0644 credentials.json holding a bearer. Remove it, then O_EXCL, so the mode below
    # is always one we set on a file we created (O_EXCL also refuses a planted symlink).
    with contextlib.suppress(FileNotFoundError):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        # Leave no half-written temp file behind for the next run to trip over.
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return path


def write_json(path: Path, obj: Any, *, mode: int = UMASK, newline: bool = False) -> Path:
    """Write ``obj`` as indented JSON, atomically. ``default=str`` matches the CLI's output contract."""
    text = json.dumps(obj, indent=2, default=str)
    return write_text(path, text + ("\n" if newline else ""), mode=mode)
