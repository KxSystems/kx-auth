"""`_scopes()` — byte-identical in `login.py` and `exchange.py`, asserted against both copies so a
future edit to one that isn't mirrored in the other fails loudly instead of silently drifting.
"""

from __future__ import annotations

import argparse

import pytest

from kx_auth_cli import exchange, login

_IMPLEMENTATIONS = [login._scopes, exchange._scopes]


@pytest.mark.parametrize("scopes_fn", _IMPLEMENTATIONS, ids=["login", "exchange"])
@pytest.mark.parametrize(
    "scope_flag, expected",
    [
        (None, None),
        ([], None),
        (["a b c"], ["a", "b", "c"]),
        (["a,b"], ["a", "b"]),
        (["a, b  c", "d"], ["a", "b", "c", "d"]),  # comma AND space within one value, plus a repeat
        ([""], None),
        ([" , "], None),
        (["a", "a"], ["a", "a"]),  # duplicates are NOT deduped — the values are space-joined onto
                                   # a wire request downstream, so this is the actual contract
    ],
)
def test_scopes(scopes_fn, scope_flag, expected):
    args = argparse.Namespace(scope=scope_flag)
    assert scopes_fn(args) == expected
