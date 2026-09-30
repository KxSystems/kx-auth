"""The client-side token cache: endpoint-keyed round-trip, path override, file mode."""

from __future__ import annotations

import json
import os
import stat

import pytest

from kx_auth_cli import atomic, cache


@pytest.fixture
def cache_file(tmp_path, monkeypatch):
    path = tmp_path / "creds.json"
    monkeypatch.setenv("KX_AUTH_CACHE", str(path))
    return path


def test_path_honours_env_override(cache_file):
    assert cache.cache_path() == cache_file


def test_load_missing_is_empty(cache_file):
    assert cache.load() == {}
    assert cache.get("https://mcp.example") is None


def test_save_then_get_round_trips(cache_file):
    cred = {"access_token": "tok-1", "token_type": "Bearer"}
    cache.save("https://mcp.example", cred)
    assert cache.get("https://mcp.example") == cred
    # persisted as JSON keyed by endpoint
    on_disk = json.loads(cache_file.read_text())
    assert on_disk["https://mcp.example"]["access_token"] == "tok-1"


def test_save_is_keyed_by_endpoint(cache_file):
    cache.save("https://a.example", {"access_token": "a"})
    cache.save("https://b.example", {"access_token": "b"})
    assert cache.get("https://a.example")["access_token"] == "a"
    assert cache.get("https://b.example")["access_token"] == "b"  # the first is not clobbered


def test_file_mode_is_0600(cache_file):
    cache.save("https://mcp.example", {"access_token": "x"})
    mode = stat.S_IMODE(os.stat(cache_file).st_mode)
    assert mode == 0o600


def test_corrupt_cache_reads_as_empty(cache_file):
    cache_file.write_text("not json{")
    assert cache.load() == {}


# Regression for finding kx-auth-cli #9 — os.open/mkdir modes are create-only, so pre-existing
# temporary files and cache directories are never narrowed.
def test_the_atomic_writer_narrows_what_it_finds_already_there(monkeypatch, tmp_path):
    target = tmp_path / "creds.json"
    leftover = target.with_suffix(target.suffix + ".tmp")
    leftover.write_text("{}")
    os.chmod(leftover, 0o666)
    atomic.write_json(target, {"a": 1}, mode=atomic.PRIVATE)
    got = stat.S_IMODE(target.stat().st_mode)
    assert got == atomic.PRIVATE, (
        f"a leftover temp file kept mode {got:o}; the credential file must be {atomic.PRIVATE:o}"
    )

    wide = tmp_path / "cachedir"
    wide.mkdir(mode=0o755)
    monkeypatch.setenv("KX_AUTH_CACHE", str(wide / "creds.json"))
    cache.save("https://mcp.test", {"access_token": "at"})
    got = stat.S_IMODE(wide.stat().st_mode)
    assert got == 0o700, f"an existing cache directory kept mode {got:o}; cache.save documents 0700"
