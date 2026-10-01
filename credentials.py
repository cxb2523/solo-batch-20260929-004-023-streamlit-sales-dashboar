"""Credential service for the sales dashboard.

Single place that knows *where* credentials live on disk, *how* they are
encoded, and *when* an in-memory copy is stale. The page layer (``app.py``)
and the offline generator (``generate_keys.py``) must both go through this
module instead of touching the pickle file themselves.

Public surface (intentionally small):

* :data:`CURRENT`, :data:`CACHED`, :data:`EXPIRED`, :data:`LEGACY`,
  :data:`UNKNOWN` -- the load state machine.
* :class:`Credentials` -- parsed credentials plus the state they were loaded
  in.
* :class:`MigrationError` -- raised when the on-disk file is neither the
  new nested format nor the old flat list.
* :func:`load` -- read (and cache) credentials.
* :func:`save` -- atomically persist a new-format credentials mapping.
* :func:`verify_password` -- service-level username/password check.

State machine for :func:`load`::

    first successful load, new format       -> CURRENT
    later load, file untouched (mtime+size) -> CACHED
    later load, file changed on disk        -> EXPIRED (cache refreshed)
    successful load from the old flat list  -> LEGACY
    file missing / unparseable / malformed  -> MigrationError
                                              (UNKNOWN documents the failure)

Hashing note: passwords are hashed with ``stauth.Hasher`` (bcrypt). bcrypt
stores a freshly generated per-hash random salt *inside* the hash string
itself (``$2b$12$<22-char salt><31-char digest>``), so no separate salt
file exists and verification only needs the stored hash. The hashes in the
legacy ``hashed_pw.pkl`` are plain bcrypt hashes and still verify.
"""

from __future__ import annotations

import copy
import os
import pickle
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import streamlit_authenticator as stauth

# --- states -----------------------------------------------------------------

CURRENT = "current"
CACHED = "cached"
EXPIRED = "expired"
LEGACY = "legacy"
UNKNOWN = "unknown"

STATES = (CURRENT, CACHED, EXPIRED, LEGACY, UNKNOWN)

# --- locations / shape ------------------------------------------------------

# Anchor at the project root (this file's directory), never at the process
# working directory, so `python app.py` works from anywhere.
PROJECT_ROOT = Path(__file__).resolve().parent
CREDENTIALS_FILE = PROJECT_ROOT / "hashed_pw.pkl"

# The old generator had no usernames in the file; the two hashes were paired
# positionally with these two users inside app.py. Keeping the pairing here
# lets flat legacy files keep logging in without a migration.
LEGACY_USERS: Tuple[Tuple[str, str], ...] = (
    ("pparker", "Peter Parker"),
    ("rmiller", "Rebecca Miller"),
)

FORMAT_NEW = "new"
FORMAT_LEGACY = "legacy"

# Banner / error copy lives here so the page and verify_auth.py can import
# the exact strings the UI renders.
LEGACY_BANNER = (
    "This site still uses the legacy flat credentials file "
    "(hashed_pw.pkl). Please migrate to the nested credentials format "
    "(run python generate_keys.py)."
)
MIGRATION_ERROR_PREFIX = "Credentials file cannot be used"
BAD_CREDENTIALS_MESSAGE = "Username/password is incorrect"
NO_INPUT_MESSAGE = "Please enter your username and password"


class MigrationError(Exception):
    """Raised when the credential store cannot be interpreted safely.

    The message always carries a concrete *reason* so the login page can
    echo it back to the operator. Callers must never fall back to empty
    credentials or silently switch formats when this is raised.
    """


class Credentials:
    """Parsed credentials and the state they were loaded in."""

    __slots__ = ("mapping", "state", "format", "reason")

    def __init__(
        self,
        mapping: Dict[str, Any],
        state: str,
        cred_format: str,
        reason: Optional[str] = None,
    ) -> None:
        self.mapping = mapping
        self.state = state
        self.format = cred_format
        self.reason = reason

    @property
    def is_legacy(self) -> bool:
        return self.format == FORMAT_LEGACY

    @property
    def usernames(self) -> Dict[str, Dict[str, str]]:
        return self.mapping["usernames"]

    def names_and_usernames(self) -> Tuple[list, list]:
        """Return ``(names, usernames)`` aligned by username order."""
        users = self.usernames
        names = [users[username].get("name", "") for username in users]
        return names, list(users.keys())

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Credentials(state={self.state!r}, format={self.format!r})"


# --- module level cache -----------------------------------------------------

_cache_lock = threading.RLock()
_cache: Dict[str, Any] = {
    "state": UNKNOWN,
    "format": None,
    "signature": None,  # (mtime_ns, size) of the file backing the cache
    "mapping": None,
}


def _file_signature(path: Path) -> Optional[Tuple[int, int]]:
    """Return ``(mtime_ns, size)``; both fields must match to hit the cache."""
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise MigrationError(
            f"{MIGRATION_ERROR_PREFIX}: cannot stat {path.name}: {exc}"
        ) from exc
    return stat.st_mtime_ns, stat.st_size


def _looks_like_bcrypt_hash(value: Any) -> bool:
    return isinstance(value, str) and stauth.Hasher.is_hash(value)


def _parse(raw: Any) -> Tuple[Dict[str, Any], str]:
    """Turn the raw pickled object into a new-format mapping.

    Returns ``(mapping, format)`` or raises :class:`MigrationError`.
    """
    # New nested format: {"usernames": {name: {name, password, ...}}}
    if isinstance(raw, dict) and isinstance(raw.get("usernames"), dict):
        users = raw["usernames"]
        if not users:
            raise MigrationError(
                f"{MIGRATION_ERROR_PREFIX}: new-format credentials contain "
                "no users"
            )
        for username, record in users.items():
            if not isinstance(username, str) or not isinstance(record, dict):
                raise MigrationError(
                    f"{MIGRATION_ERROR_PREFIX}: malformed user entry for "
                    f"{username!r}"
                )
            if "password" not in record or not _looks_like_bcrypt_hash(
                record["password"]
            ):
                raise MigrationError(
                    f"{MIGRATION_ERROR_PREFIX}: user {username!r} is missing "
                    "a bcrypt password hash"
                )
        return copy.deepcopy(raw), FORMAT_NEW

    # Legacy flat format: a plain list of bcrypt hashes paired positionally
    # with LEGACY_USERS.
    if isinstance(raw, (list, tuple)):
        if len(raw) != len(LEGACY_USERS):
            raise MigrationError(
                f"{MIGRATION_ERROR_PREFIX}: flat hash list has {len(raw)} "
                f"entries but {len(LEGACY_USERS)} legacy users are configured"
            )
        if not all(_looks_like_bcrypt_hash(item) for item in raw):
            raise MigrationError(
                f"{MIGRATION_ERROR_PREFIX}: flat hash list contains entries "
                "that are not bcrypt hashes"
            )
        mapping: Dict[str, Any] = {"usernames": {}}
        for (username, full_name), password_hash in zip(LEGACY_USERS, raw):
            mapping["usernames"][username] = {
                "name": full_name,
                "password": password_hash,
            }
        return mapping, FORMAT_LEGACY

    raise MigrationError(
        f"{MIGRATION_ERROR_PREFIX}: object of type {type(raw).__name__} is "
        "neither the nested credentials mapping nor a flat list of password "
        "hashes"
    )


def load(path: Optional[Path] = None) -> Credentials:
    """Load credentials from ``path`` (default :data:`CREDENTIALS_FILE`).

    Returns a :class:`Credentials` object with one of the documented states.
    Raises :class:`MigrationError` for missing / unreadable / malformed
    files; no empty credential set is ever returned.
    """
    cred_path = CREDENTIALS_FILE if path is None else Path(path)

    with _cache_lock:
        signature = _file_signature(cred_path)
        if signature is None:
            _cache["state"] = UNKNOWN
            _cache["format"] = None
            _cache["signature"] = None
            _cache["mapping"] = None
            raise MigrationError(
                f"{MIGRATION_ERROR_PREFIX}: {cred_path.name} was not found "
                f"at {cred_path}"
            )

        cached_mapping = _cache["mapping"]
        if cached_mapping is not None and signature == _cache["signature"]:
            # The authenticator mutates the mapping at runtime, so hand out
            # a copy and keep the cached master pristine.
            if _cache["format"] == FORMAT_LEGACY:
                hit_state = LEGACY
            elif _cache["state"] in (CURRENT, EXPIRED):
                # Cache was just (re)written by save(); this is the first
                # read of the current or freshly expired credentials.
                hit_state = _cache["state"]
                _cache["state"] = CACHED
            else:
                hit_state = CACHED
            return Credentials(
                copy.deepcopy(cached_mapping), hit_state, _cache["format"]
            )

        previous_state = (
            _cache["state"] if cached_mapping is not None else UNKNOWN
        )
        previous_format = _cache["format"]

        try:
            with cred_path.open("rb") as handle:
                raw = pickle.load(handle)
        except (pickle.PickleError, EOFError, ValueError, OSError) as exc:
            _cache.update(
                state=UNKNOWN, format=None, signature=None, mapping=None
            )
            raise MigrationError(
                f"{MIGRATION_ERROR_PREFIX}: {cred_path.name} is not a "
                f"readable pickle file ({exc})"
            ) from exc

        try:
            mapping, cred_format = _parse(raw)
        except MigrationError:
            _cache.update(
                state=UNKNOWN, format=None, signature=None, mapping=None
            )
            raise

        if cred_format == FORMAT_LEGACY:
            # Legacy is a property of the file's format, so every load from
            # a flat file reports LEGACY (with or without a warm cache).
            state = LEGACY
        elif previous_state in (CURRENT, CACHED, EXPIRED):
            # New-format file we already served once, whose mtime+size
            # signature changed -> the previous credentials went stale.
            state = EXPIRED
        elif previous_format == FORMAT_NEW:
            # Cache was warmed by save() in this process: this is the first
            # on-disk read of a current new-format file.
            state = CURRENT
        else:
            state = CURRENT

        _cache["state"] = state
        _cache["format"] = cred_format
        _cache["signature"] = signature
        _cache["mapping"] = copy.deepcopy(mapping)

        result = Credentials(mapping, state, cred_format)
        # The returned object reports CURRENT for this first read; the next
        # caller with the same file should already see a warm CACHED entry.
        if state in (CURRENT, EXPIRED):
            _cache["state"] = CACHED
        return result


def _atomic_write_pickle(path: Path, payload: Any) -> Tuple[int, int]:
    """Write ``payload`` to a temp file in the same dir, then rename.

    ``os.replace`` is atomic on both Windows and POSIX: a concurrent reader
    only ever sees the complete old file or the complete new file, never a
    half-written one.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except BaseException:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise
    stat = path.stat()
    return stat.st_mtime_ns, stat.st_size


def save(
    users: Dict[str, Dict[str, str]],
    path: Optional[Path] = None,
) -> Credentials:
    """Validate, hash and atomically persist a new-format credentials map.

        >>> save({"pparker": {"name": "Peter Parker", "password": "..."}})

    Plain text passwords are hashed through :class:`stauth.Hasher`; values
    that are already bcrypt hashes are stored untouched. The in-process
    cache is refreshed in the same critical section as the file swap.
    """
    cred_path = CREDENTIALS_FILE if path is None else Path(path)

    if not isinstance(users, dict) or not users:
        raise MigrationError(
            f"{MIGRATION_ERROR_PREFIX}: refusing to save an empty user set"
        )

    mapping: Dict[str, Any] = {"usernames": {}}
    for username, record in users.items():
        if not isinstance(username, str) or not username.strip():
            raise MigrationError(
                f"{MIGRATION_ERROR_PREFIX}: invalid username {username!r}"
            )
        if not isinstance(record, dict) or "password" not in record:
            raise MigrationError(
                f"{MIGRATION_ERROR_PREFIX}: user {username!r} needs a password"
            )
        password = record["password"]
        if not isinstance(password, str) or not password:
            raise MigrationError(
                f"{MIGRATION_ERROR_PREFIX}: empty password for {username!r}"
            )
        if not stauth.Hasher.is_hash(password):
            password = stauth.Hasher.hash(password)
        entry = dict(record)
        entry["password"] = password
        entry.setdefault("name", username)
        mapping["usernames"][username] = entry

    payload = copy.deepcopy(mapping)
    with _cache_lock:
        had_cache = _cache["mapping"] is not None
        signature = _atomic_write_pickle(cred_path, payload)
        _cache["mapping"] = copy.deepcopy(mapping)
        _cache["format"] = FORMAT_NEW
        _cache["signature"] = signature
        # First save in this process -> CURRENT; rewriting a file we already
        # served is reported as EXPIRED on the refresh.
        _cache["state"] = EXPIRED if had_cache else CURRENT
        return Credentials(copy.deepcopy(mapping), _cache["state"], FORMAT_NEW)


def verify_password(
    username: str, password: str, creds: Credentials
) -> bool:
    """Service-level credential check used by tests and available to pages.

    True only when the username exists *and* its stored bcrypt hash
    matches. A renamed/removed username or a wrong password is a flat False.
    """
    if not isinstance(username, str) or not isinstance(password, str):
        return False
    record = creds.usernames.get(username.strip().lower())
    if record is None:
        return False
    return stauth.Hasher.check_pw(password, record["password"])


def reset_cache() -> None:
    """Drop the in-memory cache (test helper)."""
    with _cache_lock:
        _cache.update(
            state=UNKNOWN, format=None, signature=None, mapping=None
        )
