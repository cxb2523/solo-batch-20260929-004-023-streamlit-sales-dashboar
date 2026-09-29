
"""Credential service for the sales dashboard.

Single entry point for every credential concern in this project:

* the Streamlit login route (``app.py``) calls :func:`load` to build the
  authenticator and :func:`verify_password` for service-level checks;
* the generator script (``generate_keys.py``) calls :func:`save_new_format`
  to write a fresh credential file.

Only :func:`load` and the ``CURRENT / CACHED / EXPIRED / LEGACY / UNKNOWN``
state constants are meant as the public read surface. Everything else is an
implementation detail.

Paths are anchored at this file's directory (the project root), never at the
process working directory, so ``python app.py`` works from anywhere.
"""

from __future__ import annotations

import copy
import os
import pickle
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import yaml
from streamlit_authenticator import Hasher

# --- credential file layout -------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
NEW_FORMAT_PATH = PROJECT_ROOT / "credentials.yaml"
LEGACY_FORMAT_PATH = PROJECT_ROOT / "hashed_pw.pkl"

# The old flat file held *only* a list of two bcrypt hashes; names/usernames
# were hard-coded in the original app. Keep that mapping so legacy logins keep
# working unchanged.
LEGACY_USERS = (
    ("pparker", "Peter Parker"),
    ("rmiller", "Rebecca Miller"),
)

# --- credential state machine ----------------------------------------------
# "current"  - fresh credential snapshot read straight from disk
# "cached"   - served from the in-memory cache, mtime+size still match
# "expired"  - cache existed but mtime and/or size changed, re-read from disk
# "legacy"   - serving the deprecated flat hashed_pw.pkl file
# "unknown"  - file missing or unrecognisable; MigrationError carries reason
CURRENT = "current"
CACHED = "cached"
EXPIRED = "expired"
LEGACY = "legacy"
UNKNOWN = "unknown"

# Banner shown on top of the login page while legacy credentials are in use.
LEGACY_BANNER = (
    "Legacy credential file 'hashed_pw.pkl' is in use. "
    "Please migrate to 'credentials.yaml'."
)


class MigrationError(Exception):
    """Raised when no usable credential file can be loaded.

    The page must surface :attr:`reason` verbatim; callers must never fall back
    to empty credentials or silently switch back to the legacy path.
    """

    def __init__(self, reason: str, path: Optional[Path] = None) -> None:
        self.reason = reason
        self.path = path
        self.state = UNKNOWN
        message = f"{reason} ({path})" if path is not None else reason
        super().__init__(message)


@dataclass(frozen=True)
class CredentialSnapshot:
    """A resolved set of credentials plus its state-machine status."""

    config: Dict[str, Dict[str, Any]]
    state: str
    path: Path

    @property
    def usernames(self) -> Dict[str, Dict[str, Any]]:
        return self.config["usernames"]


# --- cache + concurrency primitives ----------------------------------------
@dataclass(frozen=True)
class _CacheEntry:
    mtime_ns: int
    size: int
    config: Dict[str, Dict[str, Any]]
    state: str


_cache_lock = threading.RLock()
_file_lock = threading.Lock()
_cache: Dict[Path, _CacheEntry] = {}

_READ_STAT_RETRIES = 5


def reset_cache() -> None:
    """Drop every cached snapshot (used by the verification script)."""
    with _cache_lock:
        _cache.clear()


def _atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically.

    The payload is fully written and flushed into a temporary file in the same
    directory first, then moved into place with :func:`os.replace`, so any
    concurrent reader sees either the complete old file or the complete new
    file - never a half-written one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _stable_read(path: Path) -> Tuple[bytes, int, int]:
    """Read a file only when its (mtime_ns, size) pair is stable.

    Combined with atomic replacement this closes the TOCTOU window where a
    reader could grab a stat, then read a file that a writer is replacing.
    """
    last_error: Optional[BaseException] = None
    for _ in range(_READ_STAT_RETRIES):
        try:
            before = os.stat(path)
            with open(path, "rb") as handle:
                data = handle.read()
            after = os.stat(path)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            last_error = exc
            time.sleep(0.01)
            continue
        if (
            before.st_mtime_ns == after.st_mtime_ns
            and before.st_size == after.st_size
            and after.st_size == len(data)
        ):
            return data, after.st_mtime_ns, after.st_size
        time.sleep(0.01)
    if last_error is not None:
        raise MigrationError(f"Credential file became unreadable: {last_error}", path)
    raise MigrationError("Credential file kept changing while being read", path)


# --- format parsers ---------------------------------------------------------
def _parse_new_format(data: bytes, path: Path) -> Dict[str, Dict[str, Any]]:
    try:
        raw = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise MigrationError(f"Credential file is not valid YAML: {exc}", path)

    if not isinstance(raw, dict) or not isinstance(raw.get("usernames"), dict):
        raise MigrationError(
            "Credential file does not match the new format: expected a mapping "
            "with a 'usernames' section",
            path,
        )

    users = raw["usernames"]
    if not users:
        raise MigrationError("Credential file contains no users", path)

    for username, record in users.items():
        if not isinstance(record, dict):
            raise MigrationError(
                f"User entry for '{username}' must be a mapping of fields", path
            )
        if "name" not in record or not isinstance(record["name"], str):
            raise MigrationError(
                f"User '{username}' is missing a string 'name' field", path
            )
        password = record.get("password")
        if not isinstance(password, str) or not Hasher.is_hash(password):
            raise MigrationError(
                f"User '{username}' is missing a hashed 'password' field", path
            )

    return {"usernames": copy.deepcopy(users)}


def _parse_legacy_format(data: bytes, path: Path) -> Dict[str, Dict[str, Any]]:
    try:
        hashes = pickle.loads(data)
    except Exception as exc:
        # unpickling can raise arbitrary errors on hostile/truncated input
        raise MigrationError(
            f"Legacy credential file is corrupt and cannot be unpickled: {exc}",
            path,
        )

    if not isinstance(hashes, (list, tuple)) or len(hashes) != len(LEGACY_USERS):
        raise MigrationError(
            "Legacy credential file must hold a list of "
            f"{len(LEGACY_USERS)} bcrypt hashes",
            path,
        )

    users: Dict[str, Dict[str, Any]] = {}
    for (username, name), hashed in zip(LEGACY_USERS, hashes):
        if not isinstance(hashed, str) or not Hasher.is_hash(hashed):
            raise MigrationError(
                f"Legacy hash for '{username}' is not a bcrypt hash", path
            )
        users[username] = {
            "name": name,
            "email": f"{username}@legacy.local",
            "password": hashed,
        }
    return {"usernames": users}


def _read_and_parse(path: Path, parser) -> Tuple[Dict[str, Dict[str, Any]], int, int]:
    data, mtime_ns, size = _stable_read(path)
    return parser(data, path), mtime_ns, size


def load(path: Optional[Path] = None) -> CredentialSnapshot:
    """Load credentials as a :class:`CredentialSnapshot`.

    Resolution order:

    1. ``credentials.yaml`` (new format). A present but broken file raises
       :class:`MigrationError` - there is no silent fallback to the flat file.
    2. ``hashed_pw.pkl`` (legacy format), only when the new file is absent.
    3. Otherwise :class:`MigrationError` is raised.
    """
    new_path = Path(path) if path is not None else NEW_FORMAT_PATH
    with _file_lock:
        if new_path.exists():
            return _load_with_cache(new_path, _parse_new_format, legacy_state=False)
        if LEGACY_FORMAT_PATH.exists():
            snapshot = _load_with_cache(
                LEGACY_FORMAT_PATH, _parse_legacy_format, legacy_state=True
            )
            # Legacy files always report the legacy state regardless of cache.
            return CredentialSnapshot(snapshot.config, LEGACY, snapshot.path)
        raise MigrationError(
            "No credential file found: create 'credentials.yaml' via "
            "generate_keys.py",
            new_path,
        )


def _load_with_cache(
    path: Path, parser, *, legacy_state: bool
) -> CredentialSnapshot:
    with _cache_lock:
        stat = os.stat(path)
        fingerprint = (stat.st_mtime_ns, stat.st_size)
        cached = _cache.get(path)

    if cached is not None and (cached.mtime_ns, cached.size) == fingerprint:
        return CredentialSnapshot(
            copy.deepcopy(cached.config),
            LEGACY if legacy_state else CACHED,
            path,
        )

    # mtime and/or size changed (or first read): refresh from disk.
    config, mtime_ns, size = _read_and_parse(path, parser)
    fresh_state = (
        (LEGACY if legacy_state else EXPIRED)
        if cached is not None
        else (LEGACY if legacy_state else CURRENT)
    )
    with _cache_lock:
        _cache[path] = _CacheEntry(
            mtime_ns=mtime_ns, size=size, config=copy.deepcopy(config),
            state=fresh_state,
        )
    return CredentialSnapshot(config, fresh_state, path)


# --- service-level password verification -----------------------------------
def verify_password(username: str, password: str) -> bool:
    """Return True only when ``username`` exists *and* the password matches.

    A renamed/removed username or a wrong password both return False.

    Password hashing goes through ``stauth.Hasher``. bcrypt hashes embed their
    own salt - the 22 characters right after the ``$2b$12$`` cost prefix - and
    :meth:`Hasher.hash` mints that salt per password via ``bcrypt.gensalt()``,
    so no separate salt value is stored anywhere. Legacy hashes use the same
    bcrypt format, hence old hashes verify unchanged.
    """
    if not isinstance(username, str) or not isinstance(password, str):
        return False
    try:
        snapshot = load()
    except MigrationError:
        return False
    record = snapshot.usernames.get(username)
    if record is None:
        return False
    return Hasher.check_pw(password, record["password"])


# --- writer used by the generator ------------------------------------------
def save_new_format(
    users: Dict[str, Dict[str, str]], path: Optional[Path] = None
) -> Path:
    """Hash plaintext passwords and persist them via atomic replacement.

    After a successful write the cache entry is invalidated, so a password
    change takes effect on the very next login without restarting the app.
    """
    target = Path(path) if path is not None else NEW_FORMAT_PATH
    credentials = {"usernames": copy.deepcopy(users)}
    Hasher.hash_passwords(credentials)
    for record in credentials["usernames"].values():
        record.setdefault("email", "")
    payload = yaml.safe_dump(credentials, sort_keys=False, default_flow_style=False)

    with _file_lock:
        _atomic_write(target, payload.encode("utf-8"))
        with _cache_lock:
            _cache.pop(target, None)
            _cache.pop(LEGACY_FORMAT_PATH, None)
    return target
