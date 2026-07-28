"""Internal API for SSH/HTTP/Telegram executor plugins.

This module must not be registered as an LLM tool. It resolves an executor
policy from Memory Wiki, creates a one-time capability inside the process,
consumes it immediately, and passes plaintext only to the supplied callback.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Callable, TypeVar
from urllib.parse import unquote, urlsplit
import posixpath

T = TypeVar("T")


def _import_core():
    home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))).expanduser()
    lib = Path(os.environ.get("HERMES_SECRET_CORE_PATH", str(home / "lib"))).expanduser()
    if str(lib) not in sys.path:
        sys.path.insert(0, str(lib))
    from hermes_secret_core import MemorySecretIndex, VaultStore
    return home, MemorySecretIndex, VaultStore


def _global_allowed() -> set[str]:
    configured = os.environ.get("HERMES_VAULT_ALLOWED_EXECUTORS", "ssh,http,telegram")
    return {item.strip() for item in configured.split(",") if item.strip()}


def _parsed_locator(value: str):
    raw = str(value or "").strip()
    parsed = urlsplit(raw)
    if not parsed.scheme or not parsed.hostname:
        raise PermissionError("valid_target_locator_required")
    scheme = parsed.scheme.casefold()
    host = (parsed.hostname or "").casefold()
    try:
        host = host.encode("idna").decode("ascii")
    except Exception as exc:
        raise PermissionError("invalid_target_host") from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise PermissionError("invalid_target_port") from exc
    if parsed.password:
        raise PermissionError("target_locator_must_not_contain_password")
    user = unquote(parsed.username or "")
    raw_path = unquote(parsed.path or "/")
    if "\\" in raw_path or "\x00" in raw_path:
        raise PermissionError("invalid_target_path")
    path = posixpath.normpath("/" + raw_path.lstrip("/"))
    if raw_path.endswith("/") and path != "/":
        path += "/"
    return scheme, user, host, port, path


def _locator_matches(expected: str, target: str, executor_id: str) -> bool:
    try:
        es, eu, eh, ep, epath = _parsed_locator(expected)
        ts, tu, th, tp, tpath = _parsed_locator(target)
    except PermissionError:
        return False
    if executor_id == "ssh":
        if es not in {"ssh", "sftp", "scp"} or ts not in {"ssh", "sftp", "scp"}:
            return False
        return (eu, eh, ep or 22) == (tu, th, tp or 22)
    if executor_id == "http":
        if eu or tu:
            return False
        if es not in {"http", "https"} or ts not in {"http", "https"}:
            return False
        eport = ep or (443 if es == "https" else 80)
        tport = tp or (443 if ts == "https" else 80)
        if (es, eh, eport) != (ts, th, tport):
            return False
        prefix = epath.rstrip("/")
        return not prefix or prefix == "" or tpath == prefix or tpath.startswith(prefix + "/")
    if executor_id == "telegram":
        if eu or tu or es != "telegram" or ts != "telegram":
            return False
        return (eh, ep, epath.rstrip("/")) == (th, tp, tpath.rstrip("/"))
    return False


def _authorize(secret_id: str, executor_id: str, target_locator: str, approved: bool) -> None:
    home, MemorySecretIndex, _ = _import_core()
    if executor_id not in _global_allowed():
        raise PermissionError("executor_not_globally_allowed")
    record = MemorySecretIndex(home=home).authorization_record(secret_id)
    if not record:
        raise PermissionError("secret_metadata_not_found")
    allowed = set(record.get("allowed_executors") or [])
    if not allowed:
        raise PermissionError("secret_has_no_executor_policy")
    if executor_id not in allowed:
        raise PermissionError("executor_not_allowed_for_secret")
    expected_locator = str(record.get("locator") or "")
    if not expected_locator:
        raise PermissionError("secret_has_no_bound_locator")
    if not _locator_matches(expected_locator, target_locator, executor_id):
        raise PermissionError("target_locator_mismatch")
    if bool(record.get("require_user_approval")) and not approved:
        raise PermissionError("user_approval_required")


def authorize_target(secret_id: str, executor_id: str, target_locator: str, *, approved: bool = False) -> None:
    """Internal re-authorization hook for redirects, reconnects and retries."""
    _authorize(secret_id, executor_id, target_locator, approved)

def _contains_secret(value, secret: str, depth: int = 0) -> bool:
    if depth > 6 or len(secret) < 8:
        return False
    if isinstance(value, str):
        return secret in value
    if isinstance(value, (bytes, bytearray)):
        return secret.encode("utf-8", "ignore") in bytes(value)
    if isinstance(value, dict):
        return any(_contains_secret(k, secret, depth+1) or _contains_secret(v, secret, depth+1) for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_secret(item, secret, depth+1) for item in value)
    return False

def execute(
    secret_id: str,
    executor_id: str,
    purpose: str,
    target_locator: str,
    callback: Callable[[str], T],
    *,
    approved: bool = False,
    ttl_seconds: int = 30,
) -> T:
    """Run an executor callback with a secret without returning plaintext/token.

    ``approved=True`` must only be supplied by executor code after a real UI or
    policy approval, never copied blindly from model arguments.
    """
    _authorize(secret_id, executor_id, target_locator, approved)
    home, _, VaultStore = _import_core()
    store = VaultStore(home=home)
    issued = store.issue_capability(
        secret_id,
        executor_id,
        purpose,
        max(5, min(int(ttl_seconds or 30), 60)),
        single_use=True,
    )
    token = issued["capability"]
    secret = store.consume_for_executor(token, executor_id, purpose)
    try:
        try:
            result = callback(secret)
        except Exception as exc:
            if len(secret) >= 8 and secret in str(exc):
                raise RuntimeError("executor_failed; secret removed from exception") from None
            raise
        if _contains_secret(result, secret):
            raise RuntimeError("executor_result_would_expose_secret")
        return result
    finally:
        secret = ""
        token = ""
