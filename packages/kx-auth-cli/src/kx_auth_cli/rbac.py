"""``kx rbac`` — inspect and administer the kx.rbac policy engine.

The command has two transports: direct qIPC (``--connect``) and an OAuth-aware HTTP gateway
(``--server``). Policy visibility and pure decisions are public inside either transport. Mutations
authorize the connection/request principal in q and persist atomically through the module's batch
API; ``--principal`` is decision input only and can never authenticate a mutation.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import io
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from . import atomic, cache, qbridge
from .envelope import AuthRequired, CliError, Denied, UsageError, guarded, json_parent

HELP_DESCRIPTION = (
    "Inspect, test and atomically administer a kx.rbac policy over direct qIPC or an "
    "OAuth-aware HTTP gateway. Grants are visible; only changes require admin:kx.rbac."
)
HELP_EPILOG = """\
exit codes (branch on the code, not the text):
  0  ok             the call succeeded, or the decision was allow
  1  error          transport failure, a malformed server response or import file, or --fail-on tripped
  2  usage          bad ACTION/RESOURCE, a bad --ctx value, an import file that fails validation
  3  auth-required  no bearer (or an expired cached login) for --server, or the gateway answered 401
  4  denied         check/explain decided deny, the gateway answered 403, or q signalled "denied: ..."

transport (exactly one):  --connect HOST:PORT (qIPC, needs the [qipc] extra)  |  --server URL (gateway)
  --principal JSON|@FILE|-  models the subject for check/explain/show only; it never authenticates
"""


def add_transport_arguments(parser: argparse.ArgumentParser) -> None:
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--connect", metavar="HOST:PORT", help="Direct qIPC target (needs the [qipc] extra).")
    transport.add_argument("--server", metavar="URL", help="OAuth-aware gateway exposing /kx/rbac/v1.")
    parser.add_argument("--user", default=os.environ.get("KX_AUTH_KDB_USER", ""), help="qIPC login user.")
    parser.add_argument("--password", default=os.environ.get("KX_AUTH_KDB_PASSWORD"), help="qIPC login password.")
    parser.add_argument("--tls", action="store_true", help="Use TLS for qIPC.")
    parser.add_argument("--token", help="Gateway bearer (then $KX_AUTH_TOKEN, then cached login for --server).")
    parser.add_argument("--no-verify", action="store_true", help="Disable gateway TLS verification (development only).")
    parser.add_argument("--timeout", type=float, default=5.0, help="Transport timeout, seconds.")


def add_commands(commands: argparse._SubParsersAction) -> None:
    parent = argparse.ArgumentParser(add_help=False, parents=[json_parent()])
    add_transport_arguments(parent)

    show = commands.add_parser("show", parents=[parent], help="Show public grants.")
    show.add_argument("--group", help="Restrict rows to one group.")
    show.add_argument("--principal", help="Show only what this principal holds: JSON, '-' for stdin, or @FILE.")
    show.set_defaults(func=run_show)

    verify = commands.add_parser("verify", parents=[parent], help="Lint the live policy.")
    verify.add_argument(
        "--fail-on", choices=("error", "warning"), dest="fail_on",
        help="Exit 1 when a finding at this severity or worse is present.",
    )
    verify.set_defaults(func=run_verify)

    for name, func in (("check", run_check), ("explain", run_explain)):
        p = commands.add_parser(name, parents=[parent], help=f"{name.title()} an action/resource for a principal.")
        p.add_argument("action", help="Action, or ACTION:RESOURCE.")
        p.add_argument("resource", nargs="?", help="Resource (omit with ACTION:RESOURCE).")
        p.add_argument("--principal", help="Canonical principal JSON, '-' for stdin, or @FILE.")
        p.add_argument(
            "--resource", dest="resources", action="append", metavar="RESOURCE",
            help="Additional resource; repeat for many. Asks the seam, which answers with the permitted subset.",
        )
        p.add_argument(
            "--ctx", metavar="JSON",
            help="Declared request context as a JSON object, '-' for stdin, or @FILE. "
                 "Asks the seam, which may answer with narrowings of the axes you declare.",
        )
        p.set_defaults(func=func)

    for name, func in (("grant", run_grant), ("revoke", run_revoke)):
        p = commands.add_parser(name, parents=[parent], help=f"Atomically persist one {name} operation.")
        p.add_argument("group")
        p.add_argument("action", help="Action, or ACTION:RESOURCE.")
        p.add_argument("resource", nargs="?", help="Resource (omit with ACTION:RESOURCE).")
        p.set_defaults(func=func)

    imp = commands.add_parser("import", parents=[parent], help="Validate and atomically import JSON or CSV.")
    imp.add_argument("file", type=Path)
    imp.add_argument("--replace", action="store_true", help="Replace from a full grants snapshot.")
    imp.add_argument("--dry-run", action="store_true", help="Return the q-computed diff and findings without mutation.")
    imp.set_defaults(func=run_import)

    exp = commands.add_parser("export", parents=[parent], help="Export a portable grants snapshot.")
    exp.add_argument("file", type=Path)
    exp.add_argument("--format", choices=("json", "csv"), help="Defaults from FILE suffix, then JSON.")
    exp.set_defaults(func=run_export)

    save = commands.add_parser("save", parents=[parent], help="Atomically save the live policy to its configured store.")
    save.set_defaults(func=run_save)
    load = commands.add_parser("load", parents=[parent], help="Load the configured store into the live policy.")
    load.set_defaults(func=run_load)


def _records(value: Any, columns: tuple[str, ...] = ("grp", "act", "res")) -> list[dict[str, Any]]:
    value = qbridge.readable(value)
    if value is None:
        return []
    if isinstance(value, list):
        if not value:
            return []
        if all(isinstance(row, dict) for row in value):
            return [{str(k): v for k, v in row.items()} for row in value]
    if isinstance(value, dict) and all(c in value for c in columns):
        # Every list column must agree: the loop below indexes all of them by position, so a ragged
        # table (a real possibility from a hand-rolled gateway) would IndexError mid-render rather than
        # being refused as the malformed response it is.
        widths = {len(value[c]) for c in columns if isinstance(value[c], list)}
        if len(widths) > 1:
            raise CliError(f"server returned a ragged table: column lengths {sorted(widths)} differ")
        n = widths.pop() if widths else 1
        rows = []
        for i in range(n):
            rows.append({c: value[c][i] if isinstance(value[c], list) else value[c] for c in columns})
        return rows
    raise CliError(f"server returned an unexpected table shape: {value!r}")


def _as_allowed(value: Any) -> bool:
    """Read a decision as a boolean, refusing anything that is not one.

    `bool(value)` fails OPEN. The string "false", the string "denied", `{"allowed": False}` and even
    the nested `{"result": {"allowed": False}}` — the last two being the shapes this CLI's own
    explain/scope responses use — are all truthy in Python, so a gateway or q build answering `check`
    in any of those richer forms would turn every denial into an allow. A decision is a boolean or it
    is not an answer.
    """
    value = qbridge.readable(value)
    if isinstance(value, bool):
        return value
    raise CliError(f"the policy engine returned a non-boolean decision: {value!r}")


def _wild(value: Any) -> Any:
    return "*" if value in (None, "") else value


def _public_rows(value: Any) -> list[dict[str, Any]]:
    return [
        {"group": _wild(r.get("grp")), "action": _wild(r.get("act")), "resource": _wild(r.get("res"))}
        for r in _records(value)
    ]


def _parse_pair(action: str, resource: str | None) -> tuple[str | None, str | None]:
    if resource is None:
        if ":" not in action:
            raise UsageError("supply ACTION RESOURCE or ACTION:RESOURCE")
        action, resource = action.split(":", 1)
    elif ":" in action:
        raise UsageError("do not combine ACTION:RESOURCE with a separate RESOURCE")
    if not action or resource == "":
        raise UsageError("action and resource must not be empty; use '*' for a wildcard")
    return (None if action == "*" else action, None if resource == "*" else resource)


def _read_arg(raw: str, what: str) -> str:
    """Literal, '-' for stdin, or @FILE — the one convention every JSON-bearing argument here uses."""
    if raw == "-":
        # A tty would block forever, and a broken stdin raises OSError, which the boundary would file
        # as an operational error — but a stdin that yields nothing is the caller's usage mistake, so
        # `--principal -`/`--ctx -` classify it here.
        try:
            text = "" if sys.stdin.isatty() else sys.stdin.read()
        except (OSError, ValueError) as exc:
            raise UsageError(f"cannot read {what} from stdin: {exc}") from exc
        if not text.strip():
            raise UsageError(f"no {what} supplied: nothing readable on stdin")
        return text
    if raw.startswith("@"):
        try:
            return Path(raw[1:]).read_text(encoding="utf-8")
        except OSError as exc:
            raise UsageError(f"cannot read {what} file: {exc}") from exc
    return raw


def _principal(raw: str | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    text = _read_arg(raw, "principal")
    # A principal is DATA — usually a file written by `assert --promoted-out` — so malformed contents
    # are an error (exit 1), matching `assert --principal`, not a usage mistake (exit 2). `--ctx` is
    # the opposite: those are values the caller typed, and `_to_q` keeps them at exit 2 via UsageError.
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CliError(f"principal is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CliError("principal JSON must be an object")
    return value


@dataclass
class DirectTransport:
    conn: Any

    @classmethod
    def open(cls, args: argparse.Namespace) -> "DirectTransport":
        try:
            kx = qbridge.import_pykx()
        except Exception as exc:
            raise CliError("PyKX is required for --connect; install 'kx-auth-cli[qipc]'") from exc
        host, sep, port = args.connect.rpartition(":")
        if not sep or not port.isdigit():
            raise UsageError("--connect must be HOST:PORT")
        try:
            conn = kx.SyncQConnection(
                host=host or "localhost", port=int(port), username=args.user,
                password=args.password or "", timeout=args.timeout, tls=args.tls,
            )
        except Exception as exc:
            raise CliError(f"connect failed: {exc}") from exc
        return cls(conn)

    def call(self, name: str, payload: dict[str, Any] | None = None) -> Any:
        payload = payload or {}
        try:
            if name == "grants":
                return qbridge.readable(self.conn(".kx.rbac.grants[]"))
            if name == "current":
                return json.loads(qbridge.readable(self.conn(".j.j .kx.auth.current[]")))
            if name in ("check", "explain"):
                principal = payload.get("principal")
                if principal is None:
                    principal = self.call("current")
                expression = f"{{[p;a;r] .j.j .kx.rbac.{name}[p;`$string a;`$string r]}}" if name == "explain" else (
                    "{[p;a;r] .kx.rbac.check[p;`$string a;`$string r]}"
                )
                result = qbridge.readable(self.conn(
                    expression, principal,
                    "" if payload["action"] is None else payload["action"],
                    "" if payload["resource"] is None else payload["resource"],
                ))
                return json.loads(result) if name == "explain" else result
            if name == "scope":
                # The seam, not the engine: only .kx.auth sees narrowing, and only it knows the installed
                # policy's rank. Keys and values go over as parallel lists and are dict-ed in q, the same
                # shape `apply` uses, so nothing depends on how PyKX renders a dictionary.
                principal = payload.get("principal")
                if principal is None:
                    principal = self.call("current")
                axes = payload.get("context") or {}
                kx = qbridge.import_pykx()
                expression = (
                    "{[p;a;rs;k;v] .j.j .kx.auth.explain["
                    "p; `$string a; `$string rs; $[count k; (`$string k)!v; (::)]]}"
                )
                result = qbridge.readable(self.conn(
                    expression, principal,
                    "" if payload["action"] is None else payload["action"],
                    payload["resources"],
                    list(axes.keys()),
                    [_to_q(kx, k, v) for k, v in axes.items()],
                ))
                return json.loads(result)
            if name == "apply":
                ops = payload["operations"]
                expression = (
                    "{[op;g;a;r;d] .j.j .kx.rbac.apply["
                    "([] op:`$string op;grp:`$string g;act:`$string a;res:`$string r);d]}"
                )
                result = qbridge.readable(self.conn(
                    expression,
                    [o["op"] for o in ops], [o["group"] for o in ops],
                    ["" if o["action"] is None else o["action"] for o in ops],
                    ["" if o["resource"] is None else o["resource"] for o in ops],
                    payload.get("dry_run", False),
                ))
                return json.loads(result)
            if name == "replace":
                grants = payload["grants"]
                expression = (
                    "{[g;a;r;d] .j.j .kx.rbac.replace["
                    "([] grp:`$string g;act:`$string a;res:`$string r);d]}"
                )
                result = qbridge.readable(self.conn(
                    expression,
                    [o["group"] for o in grants],
                    ["" if o["action"] is None else o["action"] for o in grants],
                    ["" if o["resource"] is None else o["resource"] for o in grants],
                    payload.get("dry_run", False),
                ))
                return json.loads(result)
            if name == "effective":
                principal = payload.get("principal")
                if principal is None:
                    principal = self.call("current")
                return qbridge.readable(self.conn("{[p] .kx.rbac.effective[p]}", principal))
            if name == "verify":
                return json.loads(qbridge.readable(self.conn(".j.j .kx.rbac.verify[]")))
            if name in ("save", "load"):
                return qbridge.readable(self.conn(f".kx.rbac.{name}[]"))
        except CliError:
            # Already classified — `_to_q` refusing a context value the CALLER typed is a usage error,
            # not a q/transport failure — so the blanket wrap below must not re-file it as exit 1.
            raise
        except Exception as exc:
            message = str(exc)
            if message.lower().startswith("denied"):
                raise Denied(message) from exc
            raise CliError(message) from exc
        raise CliError(f"unsupported direct operation: {name}")


@dataclass
class HttpTransport:
    base: str
    token: str
    verify: bool
    timeout: float

    @classmethod
    def open(cls, args: argparse.Namespace) -> "HttpTransport":
        credential = cache.get(args.server) or {}
        token = args.token or os.environ.get("KX_AUTH_TOKEN")
        if not token:
            expires_at = credential.get("expires_at")
            if expires_at is not None:
                try:
                    expired = float(expires_at) <= time.time()
                except (TypeError, ValueError) as exc:
                    # An expiry that will not read is not a usable credential — same answer as an
                    # expired one: demand a re-login rather than let a TypeError escape `_guarded`'s
                    # type-scoped allow-list as a traceback.
                    raise AuthRequired(
                        f"cached login for {args.server} has an unreadable expiry; "
                        f"run `kx auth login --server {args.server}`"
                    ) from exc
                if expired:
                    raise AuthRequired(f"cached login for {args.server} has expired; run `kx auth login --server {args.server}`")
            token = credential.get("access_token")
        if not token:
            raise AuthRequired(f"no bearer for {args.server}; run `kx auth login --server {args.server}`")
        return cls(args.server.rstrip("/") + "/kx/rbac/v1", token, not args.no_verify, args.timeout)

    def call(self, name: str, payload: dict[str, Any] | None = None) -> Any:
        method, path = {
            "grants": ("GET", "/grants"), "verify": ("GET", "/verify"),
            "effective": ("POST", "/effective"),
            "check": ("POST", "/check"), "explain": ("POST", "/explain"),
            "scope": ("POST", "/scope"),
            "apply": ("POST", "/transactions"), "replace": ("POST", "/replace"),
            "save": ("POST", "/save"), "load": ("POST", "/load"),
        }[name]
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = httpx.request(
                method, self.base + path, headers=headers, json=payload if method == "POST" else None,
                verify=self.verify, timeout=self.timeout,
            )
        # httpx.InvalidURL does NOT subclass httpx.HTTPError, so a malformed --server would
        # otherwise escape as a traceback instead of this command's exit-code contract.
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise CliError(f"gateway request failed: {exc}") from exc
        if response.status_code == 401:
            raise AuthRequired(response.text or "gateway authentication required")
        if response.status_code == 403:
            raise Denied(response.text or "gateway denied the caller")
        try:
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise CliError(f"gateway returned {response.status_code}: {response.text}") from exc
        return body.get("result", body) if isinstance(body, dict) else body


def _transport(args: argparse.Namespace):
    return DirectTransport.open(args) if args.connect else HttpTransport.open(args)


def _guarded(args: argparse.Namespace, operation) -> int:
    # The transport is opened INSIDE the boundary: an unreachable host or a missing bearer is a
    # classified failure, not a traceback.
    return guarded(args, lambda: operation(_transport(args)))


def run_show(args: argparse.Namespace) -> int:
    def op(transport):
        principal = _principal(getattr(args, "principal", None))
        if principal is None and getattr(args, "principal", None) is None:
            rows = _public_rows(transport.call("grants"))
        else:
            rows = _public_rows(transport.call("effective", {"principal": principal}))
        if args.group:
            rows = [row for row in rows if row["group"] == args.group]
        return {"grants": rows}
    return _guarded(args, op)


_SEVERITY = {"note": 0, "warning": 1, "error": 2}


def run_verify(args: argparse.Namespace) -> int:
    def op(transport):
        findings = _findings(transport.call("verify"))
        result = {"findings": findings, "counts": _counts(findings)}
        if args.fail_on:
            floor = _SEVERITY[args.fail_on]
            result["failed"] = any(_SEVERITY.get(f.get("severity"), 0) >= floor for f in findings)
            if result["failed"]:
                # The command worked, so this is not a denial — the policy is simply not in a state
                # the caller was willing to accept. The findings ride along so a pipeline can print them.
                counts = result["counts"]
                at_or_above = [s for s in ("error", "warning") if _SEVERITY[s] >= floor and counts[s]]
                reason = "policy lint reported " + ", ".join(
                    f"{counts[s]} {s}" + ("s" if counts[s] != 1 else "") for s in at_or_above
                )
                raise CliError(reason, result=result)
        return result
    return _guarded(args, op)


def _findings(value: Any) -> list[dict[str, Any]]:
    """Normalise q's (severity;issue;detail) findings table into a list of records."""
    return [
        {"severity": _text(r.get("severity")), "issue": _text(r.get("issue")), "detail": _text(r.get("detail"))}
        for r in _records(value, ("severity", "issue", "detail"))
    ]


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"error": 0, "warning": 0, "note": 0}
    for finding in findings:
        if finding.get("severity") in counts:
            counts[finding["severity"]] += 1
    return counts


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode()
    if isinstance(value, list):
        return "".join(v.decode() if isinstance(v, bytes) else str(v) for v in value)
    return "" if value is None else str(value)


_ISO = (
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
)


def _as_datetime(text: str) -> Any:
    for fmt in _ISO:
        try:
            return datetime.datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _ctx(raw: str | None) -> dict[str, Any] | None:
    """Read a declared context from JSON, '-' or @FILE. Returns None when none was declared."""
    if raw is None:
        return None
    text = _read_arg(raw, "context")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UsageError(f"context is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise UsageError("context must be a JSON object of axis names to values")
    return value


def _to_q(kx: Any, key: str, value: Any) -> Any:
    """Map one JSON context value onto a q type.

    JSON has no timestamp and no symbol, and the seam requires an obligation to carry the SAME q type the
    caller declared — so this mapping is part of the CLI's contract, not an implementation detail:

    * a string that parses as ISO-8601 becomes a q timestamp, any other string becomes a symbol
    * an integer becomes a long, a real becomes a float, a boolean becomes a boolean
    * an array becomes a vector of whatever its elements map to, and must be homogeneous
    * null and nested objects are refused: an axis carries a value or a list of them, not a structure
    """
    if isinstance(value, bool):
        return kx.BooleanAtom(value)
    if isinstance(value, int):
        return kx.LongAtom(value)
    if isinstance(value, float):
        return kx.FloatAtom(value)
    if isinstance(value, str):
        stamp = _as_datetime(value)
        return kx.TimestampAtom(stamp) if stamp is not None else kx.SymbolAtom(value)
    if isinstance(value, list):
        if not value:
            raise UsageError(f"context axis '{key}' is an empty list; omit the axis instead")
        kinds = {type(v) is bool or isinstance(v, (int, float, str)) for v in value}
        if kinds != {True}:
            raise UsageError(f"context axis '{key}' may only list strings, numbers or booleans")
        if len({type(v) for v in value}) > 1:
            raise UsageError(f"context axis '{key}' mixes value types; a declared axis is homogeneous")
        first = value[0]
        if isinstance(first, str):
            if _as_datetime(first) is not None:
                return kx.TimestampVector([_as_datetime(v) for v in value])
            return kx.SymbolVector(value)
        if isinstance(first, bool):
            return kx.BooleanVector(value)
        if isinstance(first, int):
            return kx.LongVector(value)
        return kx.FloatVector(value)
    raise UsageError(f"context axis '{key}' must be a value or a list of values, not {type(value).__name__}")


def _decision(args: argparse.Namespace, explain: bool) -> int:
    def op(transport):
        action, resource = _parse_pair(args.action, args.resource)
        principal = _principal(args.principal)
        context = _ctx(getattr(args, "ctx", None))
        extra = list(getattr(args, "resources", None) or [])

        # Extra resources or a declared context make this a question only the SEAM can answer, because
        # only the seam sees narrowing. Without them it stays the grant-table question it has always been,
        # answered by the engine on exactly today's route — so the dominant case is untouched, and
        # `kx rbac check` still works against a host running kx.rbac on its own.
        if context is not None or extra:
            resources = ([] if resource is None else [resource]) + extra
            if not resources:
                raise UsageError("a wildcard resource cannot be combined with --resource or --ctx")
            decision = transport.call("scope", {
                "action": action, "resources": resources,
                "principal": principal, "context": context or {},
            })
            decision = qbridge.readable(decision)
            if not isinstance(decision, dict):
                raise CliError(f"the seam returned an unexpected decision shape: {decision!r}")
            allowed = _as_allowed(decision.get("allowed"))
            public = {
                "allowed": allowed,
                "action": _wild(action),
                "resources": resources,
                "obligations": decision.get("obligations") or {},
                "declared": sorted(context or {}),
            }
            for key in ("reason", "denial"):
                if _text(decision.get(key)):
                    public[key] = _text(decision[key])
            if not allowed:
                raise Denied(result=public)
            return public

        result = transport.call(
            "explain" if explain else "check",
            {"action": action, "resource": resource, "principal": principal},
        )
        if explain:
            result = qbridge.readable(result)
            if not isinstance(result, dict):
                raise CliError(f"the seam returned an unexpected explain shape: {result!r}")
            if not _as_allowed(result.get("allowed")):
                raise Denied(result=result)
            return result
        allowed = _as_allowed(result)
        public = {"allowed": allowed, "action": _wild(action), "resource": _wild(resource)}
        if not allowed:
            raise Denied(result=public)
        return public
    return _guarded(args, op)


def run_check(args: argparse.Namespace) -> int:
    return _decision(args, False)


def run_explain(args: argparse.Namespace) -> int:
    return _decision(args, True)


def _single_mutation(args: argparse.Namespace, verb: str) -> int:
    def op(transport):
        action, resource = _parse_pair(args.action, args.resource)
        result = transport.call("apply", {
            "operations": [{"op": verb, "group": args.group, "action": action, "resource": resource}],
            "dry_run": False,
        })
        public = _transaction_public(result)
        if isinstance(public, dict):
            changed = bool(public.get("changed"))
            public["acknowledgement"] = (
                ("grant removed" if changed else "grant did not exist")
                if verb == "revoke"
                else ("grant added" if changed else "grant already existed")
            )
        return public
    return _guarded(args, op)


def run_grant(args: argparse.Namespace) -> int:
    return _single_mutation(args, "grant")


def run_revoke(args: argparse.Namespace) -> int:
    return _single_mutation(args, "revoke")


def _normal_row(row: dict[Any, Any], *, operation: bool, csv_mode: bool = False) -> dict[str, Any]:
    accepted = {"group", "grp", "action", "act", "resource", "res"}
    if operation:
        accepted.add("op")
    if None in row:
        raise UsageError("CSV row has more fields than its header")
    extra = set(row) - accepted
    if extra:
        raise UsageError(f"unexpected import field(s): {', '.join(sorted(str(key) for key in extra))}")
    for public, q_name in (("group", "grp"), ("action", "act"), ("resource", "res")):
        if public not in row and q_name not in row:
            raise UsageError(f"each row requires a {public} field")
    group = row.get("group", row.get("grp"))
    action = row.get("action", row.get("act"))
    resource = row.get("resource", row.get("res"))
    if not isinstance(group, str) or not group or group == "*":
        raise UsageError("each row requires a non-wildcard string group")
    if csv_mode and any(value is None or value == "" for value in (action, resource)):
        raise UsageError("CSV action and resource cells must be non-empty; use literal '*' for a wildcard")
    result = {
        "group": group,
        "action": None if action in (None, "", "*") else action,
        "resource": None if resource in (None, "", "*") else resource,
    }
    if not all(value is None or isinstance(value, str) for value in (result["action"], result["resource"])):
        raise UsageError("action and resource must be strings, '*' or JSON null")
    if operation:
        verb = row.get("op")
        if verb not in ("grant", "revoke"):
            raise UsageError("each operation row requires op 'grant' or 'revoke'")
        result["op"] = verb
    return result


def _load_import(path: Path) -> tuple[str, list[dict[str, Any]]]:
    try:
        if path.suffix.lower() == ".csv":
            with path.open(newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                rows = list(reader)
                operation = "op" in (reader.fieldnames or ())
            kind = "operations" if operation else "grants"
            return kind, [_normal_row(row, operation=operation, csv_mode=True) for row in rows]
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, csv.Error, json.JSONDecodeError) as exc:
        raise UsageError(f"cannot read import file: {exc}") from exc
    if not isinstance(value, dict):
        raise UsageError("JSON import must be an object containing 'operations' or 'grants'")
    keys = [key for key in ("operations", "grants") if key in value]
    if len(keys) != 1 or not isinstance(value[keys[0]], list):
        raise UsageError("JSON import must contain exactly one array: 'operations' or 'grants'")
    extra = set(value) - {keys[0]}
    if extra:
        raise UsageError(f"unexpected import field(s): {', '.join(sorted(extra))}")
    kind = keys[0]
    rows = [_normal_row(row, operation=kind == "operations") for row in value[kind] if isinstance(row, dict)]
    if len(rows) != len(value[kind]):
        raise UsageError(f"every {kind} entry must be an object")
    return kind, rows


def _transaction_public(result: Any) -> Any:
    result = qbridge.readable(result)
    if not isinstance(result, dict):
        return result
    names = {
        "dryRun": "dry_run", "beforeCount": "before_count",
        "afterCount": "after_count", "wouldPersist": "would_persist",
    }
    out = {names.get(key, key): value for key, value in result.items()}
    for key in ("added", "removed"):
        if key in out:
            out[key] = _public_rows(out[key])
    if "findings" in out:
        try:
            out["findings"] = _records(out["findings"], ("severity", "issue", "detail"))
        except CliError:
            pass
    return out


def run_import(args: argparse.Namespace) -> int:
    def op(transport):
        kind, rows = _load_import(args.file)
        if args.replace != (kind == "grants"):
            if kind == "grants":
                raise UsageError("a grants snapshot requires --replace")
            raise UsageError("--replace accepts a grants snapshot, not operations")
        result = transport.call("replace" if args.replace else "apply", {
            kind: rows, "dry_run": args.dry_run,
        })
        return _transaction_public(result)
    return _guarded(args, op)


def _atomic_text(path: Path, text: str) -> None:
    # An export is a portable snapshot of the PUBLIC grant set, so it takes the process umask rather
    # than the private mode the login cache and a promoted principal use.
    try:
        atomic.write_text(path, text)
    except OSError as exc:
        raise CliError(f"cannot write export: {exc}") from exc


def run_export(args: argparse.Namespace) -> int:
    def op(transport):
        rows = _public_rows(transport.call("grants"))
        fmt = args.format or ("csv" if args.file.suffix.lower() == ".csv" else "json")
        if fmt == "json":
            text = json.dumps({"grants": rows}, indent=2) + "\n"
        else:
            stream = io.StringIO(newline="")
            writer = csv.DictWriter(stream, fieldnames=("group", "action", "resource"))
            writer.writeheader()
            writer.writerows(rows)
            text = stream.getvalue()
        _atomic_text(args.file, text)
        return {"file": str(args.file), "format": fmt, "count": len(rows)}
    return _guarded(args, op)


def _persistence(args: argparse.Namespace, verb: str) -> int:
    """Run `save` or `load` and name what each one actually returns.

    q hands back a store path from `save` and an installed grant count from `load`, so the envelope
    names each rather than nesting a second "result" under the envelope's own.
    """
    def op(transport):
        value = qbridge.readable(transport.call(verb))
        if verb == "save":
            # A q filehandle symbol carries a leading colon. Report the filesystem path, as `export` does.
            return {"path": str(value).lstrip(":")}
        return {"grants": int(value)}

    return _guarded(args, op)


def run_save(args: argparse.Namespace) -> int:
    return _persistence(args, "save")


def run_load(args: argparse.Namespace) -> int:
    return _persistence(args, "load")
