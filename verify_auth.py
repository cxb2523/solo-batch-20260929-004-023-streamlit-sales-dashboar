
"""Acceptance tests for the credential service and the login page.

Run from anywhere:  ``python verify_auth.py``
Exit code is non-zero if a single check fails.
"""

from __future__ import annotations

import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

import credentials
from streamlit_authenticator import Hasher


PASS_COUNT = 0
FAIL_COUNT = 0
FAILURES = []


def check(label, condition, detail=""):
    global PASS_COUNT, FAIL_COUNT
    if condition:
        PASS_COUNT += 1
        print(f"  PASS  {label}")
    else:
        FAIL_COUNT += 1
        FAILURES.append((label, detail))
        print(f"  FAIL  {label}  {detail}")


class patched_paths:
    """Redirect every credential path used by the service to a temp dir."""

    def __init__(self, tmp: Path):
        self.tmp = Path(tmp)
        self.tmp.mkdir(parents=True, exist_ok=True)
        self._orig = None

    def __enter__(self):
        self._orig = (
            credentials.NEW_FORMAT_PATH,
            credentials.LEGACY_FORMAT_PATH,
        )
        credentials.NEW_FORMAT_PATH = self.tmp / "credentials.yaml"
        credentials.LEGACY_FORMAT_PATH = self.tmp / "hashed_pw.pkl"
        credentials.reset_cache()
        return self

    def __exit__(self, *exc):
        credentials.NEW_FORMAT_PATH, credentials.LEGACY_FORMAT_PATH = self._orig
        credentials.reset_cache()


def write_new(path: Path, password="abc123"):
    users = {
        "pparker": {"name": "Peter Parker", "email": "p@x.com", "password": password},
        "rmiller": {"name": "Rebecca Miller", "email": "r@x.com", "password": "def456"},
    }
    credentials.save_new_format(users, path)


def write_legacy(path: Path):
    shutil.copyfile(PROJECT_ROOT / "hashed_pw.pkl", path)


def test_state_machine(tmp: Path):
    print("[state machine] current / cached / expired / legacy / unknown")
    with patched_paths(tmp / "states"):
        new = credentials.NEW_FORMAT_PATH
        legacy = credentials.LEGACY_FORMAT_PATH

        write_new(new)
        first = credentials.load(new)
        check("first read is CURRENT", first.state == credentials.CURRENT)

        second = credentials.load(new)
        check("unchanged file is CACHED", second.state == credentials.CACHED)

        os.utime(new, ns=(time.time_ns() + 10_000_000, time.time_ns() + 10_000_000))
        after_mtime = credentials.load(new)
        check("mtime change -> EXPIRED", after_mtime.state == credentials.EXPIRED)
        check("post-expiry read is CACHED again",
              credentials.load(new).state == credentials.CACHED)

        stat_before = os.stat(new)
        # Reproduce an out-of-band rewrite (size changed, same mtime) without
        # touching the service's post-write cache invalidation.
        changed = {
            "usernames": {
                "pparker": {"name": "Peter Parker", "email": "p@x.com",
                            "roles": ["viewer", "analyst", "super-long-role-name"],
                            "password": Hasher.hash("newpw999")},
                "rmiller": {"name": "Rebecca Miller", "email": "r@x.com",
                            "password": Hasher.hash("def456")},
            }
        }
        credentials._atomic_write(new, yaml.safe_dump(changed).encode("utf-8"))
        os.utime(new, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
        resized = credentials.load(new)
        check("size change with same mtime -> EXPIRED",
              resized.state == credentials.EXPIRED)
        check("refreshed content exposes new password",
              credentials.verify_password("pparker", "newpw999"))

        new.unlink()
        write_legacy(legacy)
        legacy_snapshot = credentials.load()
        check("missing new + present flat -> LEGACY",
              legacy_snapshot.state == credentials.LEGACY)
        check("legacy stays LEGACY on repeat load",
              credentials.load().state == credentials.LEGACY)

        legacy.unlink()
        try:
            credentials.load()
            check("missing both files -> MigrationError", False)
        except credentials.MigrationError as error:
            check("missing both files -> MigrationError", True)
            check("error state is UNKNOWN", error.state == credentials.UNKNOWN)
            check("error carries a reason", bool(error.reason))


def test_verify_password(tmp: Path):
    print("[verify_password] old hashes, wrong pw, renamed user")
    with patched_paths(tmp / "verify"):
        new = credentials.NEW_FORMAT_PATH
        legacy = credentials.LEGACY_FORMAT_PATH

        write_new(new)
        check("correct new password accepted",
              credentials.verify_password("pparker", "abc123"))
        check("wrong password rejected",
              not credentials.verify_password("pparker", "nope"))
        check("missing/renamed username rejected",
              not credentials.verify_password("peter.p", "abc123"))
        check("non-string credentials rejected",
              not credentials.verify_password(None, 123))

        new.unlink()
        write_legacy(legacy)
        check("legacy hash pparker/abc123 still verifies",
              credentials.verify_password("pparker", "abc123"))
        check("legacy hash rmiller/def456 still verifies",
              credentials.verify_password("rmiller", "def456"))
        check("legacy wrong password rejected",
              not credentials.verify_password("rmiller", "abc123"))


def test_password_change_live(tmp: Path):
    print("[live reload] password change without restart")
    with patched_paths(tmp / "live"):
        new = credentials.NEW_FORMAT_PATH
        write_new(new, password="abc123")
        credentials.load()
        write_new(new, password="changed1")
        check("old password stops working after on-disk change",
              not credentials.verify_password("pparker", "abc123"))
        check("new password works with no restart or cache reset",
              credentials.verify_password("pparker", "changed1"))


def test_migration_errors(tmp: Path):
    print("[migration] broken files raise with reasons, no silent fallback")
    with patched_paths(tmp / "migration"):
        new = credentials.NEW_FORMAT_PATH
        legacy = credentials.LEGACY_FORMAT_PATH
        write_legacy(legacy)

        new.write_text(": : broken yaml\n x: [", encoding="utf-8")
        try:
            credentials.load()
            check("broken YAML raises MigrationError", False)
        except credentials.MigrationError as error:
            check("broken YAML raises MigrationError", True)
            check("yaml reason mentions YAML", "YAML" in error.reason, error.reason)
            check("broken new file does not silently fall back to legacy",
                  error.path == new, str(error.path))

        new.write_text(yaml.safe_dump({"wrong_shape": 1}), encoding="utf-8")
        try:
            credentials.load()
            check("wrong-shape YAML raises MigrationError", False)
        except credentials.MigrationError as error:
            check("wrong-shape YAML raises MigrationError", True)
            check("reason explains missing usernames section",
                  "usernames" in error.reason, error.reason)

        new.write_text(
            yaml.safe_dump({"usernames": {"pparker": {"name": "P",
                                                      "password": "plaintext"}}}),
            encoding="utf-8")
        try:
            credentials.load()
            check("plaintext password entry raises MigrationError", False)
        except credentials.MigrationError as error:
            check("plaintext password entry raises MigrationError", True)
            check("loader never accepts non-hashed credentials",
                  "hashed 'password'" in error.reason, error.reason)

        new.unlink()
        legacy.write_bytes(b"not a pickle at all")
        try:
            credentials.load()
            check("corrupt legacy pickle raises MigrationError", False)
        except credentials.MigrationError as error:
            check("corrupt legacy pickle raises MigrationError", True)
            check("legacy reason mentions unpickling",
                  "unpickled" in error.reason, error.reason)

        legacy.write_bytes(pickle.dumps(["only-one-hash"]))
        try:
            credentials.load()
            check("wrong legacy shape raises MigrationError", False)
        except credentials.MigrationError:
            check("wrong legacy shape raises MigrationError", True)

        legacy.unlink()
        try:
            credentials.load()
            check("no files at all raises MigrationError", False)
        except credentials.MigrationError:
            check("no files at all raises MigrationError", True)


def test_atomic_concurrency(tmp: Path):
    print("[concurrency] atomic replace never exposes half-written files")
    with patched_paths(tmp / "concurrent"):
        new = credentials.NEW_FORMAT_PATH
        write_new(new)
        stop = threading.Event()
        errors = []
        seen_users = set()

        def reader():
            while not stop.is_set():
                try:
                    snap = credentials.load()
                    assert set(snap.usernames) == {"pparker", "rmiller"}
                    for record in snap.usernames.values():
                        assert Hasher.is_hash(record["password"])
                        seen_users.add(record["name"])
                except Exception as exc:  # noqa: BLE001
                    errors.append(repr(exc))

        readers = [threading.Thread(target=reader) for _ in range(6)]
        for thread in readers:
            thread.start()

        for index in range(40):
            write_new(new, password=f"pass{index}")
            time.sleep(0.005)

        stop.set()
        for thread in readers:
            thread.join()

        leftovers = [p.name for p in credentials.NEW_FORMAT_PATH.parent.iterdir()
                     if p.suffix == ".tmp"]
        check("concurrent readers saw no parse errors", not errors, str(errors[:3]))
        check("every read returned the complete user set",
              seen_users == {"Peter Parker", "Rebecca Miller"}, str(seen_users))
        check("no temporary files left behind", not leftovers, str(leftovers))


def test_generator_and_root_anchoring(tmp: Path):
    print("[generator] generate_keys.py goes through the service")
    from generate_keys import build_users

    with patched_paths(tmp / "generator"):
        target = credentials.save_new_format(build_users())
        check("writer targets the project-root path constant",
              target == credentials.NEW_FORMAT_PATH)
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
        check("generator emits hashed, not plaintext passwords",
              all(Hasher.is_hash(u["password"]) for u in raw["usernames"].values()))
        check("generated pparker password works",
              credentials.verify_password("pparker", "abc123"))
        check("generated rmiller password works",
              credentials.verify_password("rmiller", "def456"))

    workdir = tmp / "somewhere_else"
    workdir.mkdir(exist_ok=True)
    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "generate_keys.py")],
        cwd=workdir,
        capture_output=True,
        text=True,
    )
    check("generate_keys exits 0 from another cwd", proc.returncode == 0,
          proc.stderr[-400:])
    root_file = PROJECT_ROOT / "credentials.yaml"
    check("script writes credentials.yaml at project root", root_file.exists())
    check("no credential file leaked into the launch cwd",
          not (workdir / "credentials.yaml").exists())


def _login(apptest, username, password):
    apptest.text_input[0].input(username).run()
    apptest.text_input[1].input(password).run()
    apptest.button[0].click().run()


def _title_values(apptest):
    return [getattr(t, "value", "") for t in apptest.title]


def test_pages(tmp: Path):
    from streamlit.testing.v1 import AppTest

    app_file = str(PROJECT_ROOT / "app.py")

    print("[page /login] new format")
    with patched_paths(tmp / "page_new"):
        write_new(credentials.NEW_FORMAT_PATH)
        at = AppTest.from_file(app_file, default_timeout=30).run()
        check("no script exception on new-format page", not at.exception,
              str(at.exception))
        check("no legacy banner for new format",
              credentials.LEGACY_BANNER not in [w.value for w in at.warning])
        check("initial prompt asks for username and password",
              any("enter your username and password" in w.value.lower()
                  for w in at.warning))

        _login(at, "pparker", "wrong")
        check("wrong password shows page error",
              any("Username/password is incorrect" in e.value for e in at.error))
        check("dashboard hidden on failed login",
              not any("Sales Dashboard" in value for value in _title_values(at)))

        _login(at, "ghost", "abc123")
        check("unknown user shows same page error",
              any("Username/password is incorrect" in e.value for e in at.error))

        at2 = AppTest.from_file(app_file, default_timeout=30).run()
        _login(at2, "pparker", "abc123")
        check("correct login succeeds",
              at2.session_state.get("authentication_status") is True)
        check("dashboard renders after login",
              any("Sales Dashboard" in value for value in _title_values(at2)),
              str(_title_values(at2)))

    print("[page /login] legacy format")
    with patched_paths(tmp / "page_legacy"):
        write_legacy(credentials.LEGACY_FORMAT_PATH)
        at = AppTest.from_file(app_file, default_timeout=30).run()
        check("legacy banner text is exactly the shared constant",
              credentials.LEGACY_BANNER in [w.value for w in at.warning])
        check("banner appears at top of the login page",
              any("migrate to 'credentials.yaml'" in w.value for w in at.warning))
        _login(at, "pparker", "abc123")
        check("legacy credentials log in",
              at.session_state.get("authentication_status") is True)
        check("banner keeps showing while on legacy file",
              credentials.LEGACY_BANNER in [w.value for w in at.warning])

    print("[page /login] deliberately broken file")
    with patched_paths(tmp / "page_broken"):
        credentials.NEW_FORMAT_PATH.write_text(": : broken yaml\n x: [",
                                               encoding="utf-8")
        write_legacy(credentials.LEGACY_FORMAT_PATH)
        at = AppTest.from_file(app_file, default_timeout=30).run()
        check("broken new file does not fall back to legacy",
              credentials.LEGACY_BANNER not in [w.value for w in at.warning])
        check("page echoes the migration error prefix",
              any("Credential migration error:" in e.value for e in at.error),
              str([e.value for e in at.error]))
        check("echoed reason matches the service reason text",
              any("not valid YAML" in e.value for e in at.error))
        check("login form not rendered after migration error",
              not at.text_input)
        check("dashboard not rendered after migration error",
              not any("Sales Dashboard" in value for value in _title_values(at)))


def main():
    tmp_root = Path(tempfile.mkdtemp(prefix="verify_auth_"))
    print(f"Using scratch directory: {tmp_root}\n")
    try:
        test_state_machine(tmp_root)
        test_verify_password(tmp_root)
        test_password_change_live(tmp_root)
        test_migration_errors(tmp_root)
        test_atomic_concurrency(tmp_root)
        test_generator_and_root_anchoring(tmp_root)
        test_pages(tmp_root)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT:
        for label, detail in FAILURES:
            print(f"  FAILED: {label} {detail}")
        return 1
    print("All auth checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
