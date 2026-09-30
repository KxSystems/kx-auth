"""``kx auth`` — the client-side auth CLI for kdb+ identity assertion.

A thin ``kx`` umbrella (stdlib argparse) whose ``auth`` group exposes the auth flows as a headless
surface for an operator, a CI step or an autonomous agent: structured ``--json`` output and a stable
exit-code contract so the caller branches on codes, not prose. Subcommands: ``introspect``, ``login``,
``exchange``, ``assert``. Verification reuses the lean :mod:`kx_auth_core` (no fastmcp).

It is the OAuth-aware half of the ``kx.auth`` story: the q module deliberately does no token parsing
and no crypto, so acquiring a bearer, exchanging it and projecting it into a principal all happen
here, client-side, and ``assert`` binds the result onto a kdb+ process over qIPC.
"""
