"""Acceptance suite for the credentials refactor.

Run from anywhere::

    python verify_auth.py

Exit code is non-zero if a single check fails; the summary line reports the
exact failure count (must be 0).
"""

from __future__ import annotations

import logging
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

logging.disable(logging.CRITICAL)

PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit_authenticator as stauth  # noqa: E402
import credentials as cred  # noqa: E402

FAILURES: list[str] = []
PASSED = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASSED
    if condition:
        PASSED += 1
        print(f"  PASS  {label}")
    else:
        FAILURES.append(f"{label} {detail}".rstrip())
        print(f"  FAIL  {label} {detail}")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


LEGACY_HASHES = [
    "$2b$12$vBSjagYd7GQIXT9gMYL7teORuHfhdBSJXZ.s3gPYWSNy/5suIXm/S",
    "$2b$12$LjHNnhOLqC3foLlUj/72z.fvgJ5WGaW8JgCWZ1asBX2pK0jXahO3q",
]


def write_legacy(path: Path, hashes=None) -> None:
    with Path(path).open("wb") as handle:
        pickle.dump(list(LEGACY_HASHES if hashes is None else hashes), handle)


def make_apptest():
    from streamlit.testing.v1 import AppTest

    cred.reset_cache()
    app = AppTest.from_file(str(PROJECT_ROOT / "app.py"), default_timeout=30)
    app.run()
    return app


def login(app, username: str, password: str):
    app.text_input[0].input(username).run()
    app.text_input[1].input(password).run()
    app.button[0].click().run()
    return app


class CredFileGuard:
    """Back up the real hashed_pw.pkl around a test and always restore it."""

    def __init__(self) -> None:
        self.path = PROJECT_ROOT / "hashed_pw.pkl"
        self.backup = self.path.with_suffix(".pkl.verify_bak")

    def __enter__(self):
        shutil.copy(self.path, self.backup)
        cred.reset_cache()
        return self.path

    def __exit__(self, *exc_info):
        shutil.move(str(self.backup), str(self.path))
        cred.reset_cache()
        return False


def test_paths_are_root_anchored() -> None:
    section("paths are anchored at project root, not CWD")
    check(
        "CREDENTIALS_FILE is under project root",
        cred.CREDENTIALS_FILE.parent == PROJECT_ROOT,
        str(cred.CREDENTIALS_FILE),
    )
    old_cwd = Path.cwd()
    try:
        os.chdir(tempfile.gettempdir())
        check(
            "constant path does not follow CWD",
            cred.CREDENTIALS_FILE == PROJECT_ROOT / "hashed_pw.pkl",
        )
    finally:
        os.chdir(old_cwd)
    app_source = (PROJECT_ROOT / "app.py").read_text(encoding="utf-8")
    check(
        "excel path in app.py is built from project root",
        'cred.PROJECT_ROOT / "supermarkt_sales.xlsx"' in app_source,
    )
    generator_source = (PROJECT_ROOT / "generate_keys.py").read_text(
        encoding="utf-8"
    )
    check(
        "generator goes through credentials service",
        "cred.save(" in generator_source
        and "import credentials as cred" in generator_source,
    )


def test_state_machine() -> None:
    section("state machine: current/cached/expired/legacy/unknown")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "creds.pkl"

        saved = cred.save(
            {"pparker": {"name": "Peter Parker", "password": "abc123"}},
            path=path,
        )
        check("save() reports CURRENT on first write", saved.state == cred.CURRENT)

        first = cred.load(path)
        check("first new-format load is CURRENT", first.state == cred.CURRENT)

        second = cred.load(path)
        check("untouched reload is CACHED", second.state == cred.CACHED)

        signature = cred._file_signature(path)
        check(
            "signature is (mtime_ns, size)",
            isinstance(signature, tuple)
            and len(signature) == 2
            and isinstance(signature[0], int)
            and isinstance(signature[1], int),
            str(signature),
        )

        time.sleep(0.02)
        saved_again = cred.save(
            {
                "pparker": {"name": "Peter Parker", "password": "abc123"},
                "rmiller": {"name": "Rebecca Miller", "password": "abc123"},
            },
            path=path,
        )
        check("second save() reports EXPIRED", saved_again.state == cred.EXPIRED)

        changed = cred.load(path)
        check("changed file load is EXPIRED", changed.state == cred.EXPIRED)
        check("expired load exposes new users", "rmiller" in changed.usernames)

        write_legacy(path)
        legacy = cred.load(path)
        check("flat hash list loads as LEGACY", legacy.state == cred.LEGACY)
        check(
            "legacy maps usernames positionally",
            list(legacy.usernames) == ["pparker", "rmiller"],
        )
        check("legacy names are paired by position",
              legacy.usernames["rmiller"]["name"] == "Rebecca Miller")
        check("is_legacy flag", legacy.is_legacy is True)
        check("legacy file keeps reporting LEGACY", cred.load(path).state == cred.LEGACY)


def test_malformed_files() -> None:
    section("malformed files raise MigrationError with a reason")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "creds.pkl"

        def expect_migration_error(label: str, fragment: str = ""):
            cred.reset_cache()
            try:
                cred.load(path)
            except cred.MigrationError as exc:
                check(label + " -> MigrationError", True)
                if fragment:
                    check(label + " reason echoes " + fragment,
                          fragment in str(exc), str(exc))
            else:
                check(label + " -> MigrationError", False)

        path.write_bytes(b"not a pickle at all")
        expect_migration_error("garbage bytes", "readable pickle")

        with path.open("wb") as handle:
            pickle.dump({"unrelated": 1}, handle)
        expect_migration_error("unknown pickle shape", "dict")

        with path.open("wb") as handle:
            pickle.dump(["only-one"], handle)
        expect_migration_error("wrong-length flat list")

        with path.open("wb") as handle:
            pickle.dump(["not", "hashes"], handle)
        expect_migration_error("flat list with non-hash entries")

        with path.open("wb") as handle:
            pickle.dump({"usernames": {}}, handle)
        expect_migration_error("empty user mapping")

        with path.open("wb") as handle:
            pickle.dump(
                {"usernames": {"pparker": {"name": "Peter", "password": "plain"}}},
                handle,
            )
        expect_migration_error("plaintext password in new format")

        path.unlink()
        expect_migration_error("missing file", "not found")

        check(
            "cache is UNKNOWN after MigrationError (no empty creds)",
            cred._cache["mapping"] is None
            and cred._cache["state"] == cred.UNKNOWN,
        )


def test_password_verification() -> None:
    section("hashing goes through stauth.Hasher; old hashes still verify")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "creds.pkl"

        saved = cred.save(
            {"pparker": {"name": "Peter Parker", "password": "plain-text-pw"}},
            path=path,
        )
        stored = saved.usernames["pparker"]["password"]
        check("saved password is a bcrypt hash", stauth.Hasher.is_hash(stored), stored)
        check("plaintext is not stored verbatim", stored != "plain-text-pw")

        loaded = cred.load(path)
        check("correct password verifies",
              cred.verify_password("pparker", "plain-text-pw", loaded))
        check("wrong password rejected",
              not cred.verify_password("pparker", "nope", loaded))
        check("renamed/removed username rejected",
              not cred.verify_password("pparker_gone", "plain-text-pw", loaded))

        write_legacy(path)
        legacy = cred.load(path)
        check("legacy hash verifies", cred.verify_password("pparker", "abc123", legacy))
        check("legacy wrong password rejected",
              not cred.verify_password("rmiller", "bad", legacy))


def test_change_without_restart() -> None:
    section("password change on disk is picked up without restart")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "creds.pkl"
        cred.save(
            {"pparker": {"name": "Peter Parker", "password": "old-pw"}},
            path=path,
        )
        before = cred.load(path)
        check("old password works", cred.verify_password("pparker", "old-pw", before))

        # Simulate an external password change: new bcrypt hash, then bump
        # mtime explicitly. mtime must change even if size happened to match.
        time.sleep(0.02)
        new_hash = stauth.Hasher.hash("new-pw")
        with path.open("wb") as handle:
            pickle.dump(
                {
                    "usernames": {
                        "pparker": {"name": "Peter Parker", "password": new_hash}
                    }
                },
                handle,
            )
        now = time.time()
        os.utime(path, (now, now))

        refreshed = cred.load(path)
        check("external change detected as EXPIRED",
              refreshed.state == cred.EXPIRED, refreshed.state)
        check("new password works without restart",
              cred.verify_password("pparker", "new-pw", refreshed))
        check("old password now rejected",
              not cred.verify_password("pparker", "old-pw", refreshed))


def test_size_only_change_is_detected() -> None:
    section("mtime+size invalidation: a same-second size change is detected")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "creds.pkl"
        cred.save({"pparker": {"name": "P", "password": "pw"}}, path=path)
        cred.load(path)

        # Rewrite without touching mtime resolution windows: os.replace always
        # gives a fresh mtime on our writer, and size is part of the signature
        # anyway. Save a noticeably bigger mapping.
        cred.save(
            {
                "pparker": {"name": "P", "password": "pw"},
                "rmiller": {"name": "R", "password": "pw"},
                "third": {"name": "T", "password": "pw"},
            },
            path=path,
        )
        refreshed = cred.load(path)
        check("size-grown rewrite detected as EXPIRED",
              refreshed.state == cred.EXPIRED, refreshed.state)
        check("third user visible after refresh", "third" in refreshed.usernames)


def test_atomic_and_concurrency() -> None:
    section("atomic writes: concurrent readers never see a half file")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "creds.pkl"
        cred.save(
            {"u0": {"name": "User Zero", "password": "pw0"}},
            path=path,
        )

        stop = threading.Event()
        unexpected_errors: list[Exception] = []
        torn_payload_seen = threading.Event()

        def reader() -> None:
            while not stop.is_set():
                try:
                    found = cred.load(path)
                    for record in found.usernames.values():
                        if not stauth.Hasher.is_hash(record.get("password", "")):
                            torn_payload_seen.set()
                except cred.MigrationError:
                    # A clean refusal is acceptable; a torn raw pickle that
                    # parses into usable-but-garbage data is the failure.
                    pass
                except Exception as exc:  # noqa: BLE001
                    unexpected_errors.append(exc)

        def writer(rounds: int) -> None:
            for index in range(rounds):
                cred.save(
                    {
                        "pparker": {
                            "name": "Peter Parker",
                            "password": f"pw-a-{index}",
                        },
                        "rmiller": {
                            "name": "Rebecca Miller",
                            "password": f"pw-b-{index}",
                        },
                    },
                    path=path,
                )

        with ThreadPoolExecutor(max_workers=8) as pool:
            reader_futures = [pool.submit(reader) for _ in range(6)]
            writer_futures = [pool.submit(writer, 25) for _ in range(2)]
            for future in writer_futures:
                future.result()
            stop.set()
            for future in reader_futures:
                future.result()

        check("no unexpected reader exceptions",
              not unexpected_errors, repr(unexpected_errors[:3]))
        check("no half-written/torn payload parsed",
              not torn_payload_seen.is_set())

        leftovers = [
            item.name for item in path.parent.iterdir()
            if item.name.endswith(".tmp")
        ]
        check("temp files cleaned up", not leftovers, str(leftovers))

        final = cred.load(path)
        check("final file loads with both writers' users",
              set(final.usernames) == {"pparker", "rmiller"})


def test_generator_script() -> None:
    section("generate_keys.py goes through the service and writes new format")
    guard = CredFileGuard()
    with guard:
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        result = subprocess.run(
            [sys.executable, "generate_keys.py"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            env=env,
        )
        check("generator exits 0", result.returncode == 0, result.stderr[-300:])

        with (PROJECT_ROOT / "hashed_pw.pkl").open("rb") as handle:
            payload = pickle.load(handle)
        check("generator writes nested format",
              isinstance(payload, dict) and "usernames" in payload)
        check("generator writes both users",
              set(payload["usernames"]) == {"pparker", "rmiller"})

        generated = cred.load(PROJECT_ROOT / "hashed_pw.pkl")
        check("generated file loads as CURRENT",
              generated.state == cred.CURRENT, generated.state)
        check("generated password works",
              cred.verify_password("pparker", "abc123", generated))

        result2 = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "generate_keys.py")],
            cwd=tempfile.gettempdir(),
            capture_output=True,
            text=True,
            env=env,
        )
        check("generator is CWD-independent", result2.returncode == 0,
              result2.stderr[-300:])


def test_ui_legacy_login() -> None:
    section("UI: legacy file -> migration banner on top, login still works")
    with CredFileGuard() as path:
        write_legacy(path)
        app = make_apptest()
        check("no script exception", not app.exception,
              repr([e.value for e in app.exception])[:300])
        check("legacy banner rendered",
              any(cred.LEGACY_BANNER in w.value for w in app.warning),
              str([w.value for w in app.warning]))
        check("login form rendered",
              any(getattr(s, "value", "") == "Login" for s in app.subheader))
        check("no migration error on legacy",
              not any("Credentials file cannot be used" in e.value for e in app.error))

        # banner is at the top of the page (before the Login subheader)
        banner_index = next(
            (i for i, w in enumerate(app.warning) if cred.LEGACY_BANNER in w.value),
            None,
        )
        check("banner present for ordering", banner_index is not None)

        login(app, "pparker", "abc123")
        check(
            "legacy login succeeds via authenticator",
            app.session_state.get("authentication_status") is True,
            str(app.session_state.get("authentication_status")),
        )

    with CredFileGuard() as path:
        write_legacy(path)
        app = make_apptest()
        login(app, "pparker", "wrong-password")
        check("wrong password renders shared error copy",
              any(cred.BAD_CREDENTIALS_MESSAGE in e.value for e in app.error),
              str([e.value for e in app.error]))

    with CredFileGuard() as path:
        write_legacy(path)
        app = make_apptest()
        login(app, "pparker_gone", "abc123")
        check("removed username rejected by page",
              app.session_state.get("authentication_status") is False
              and any(cred.BAD_CREDENTIALS_MESSAGE in e.value for e in app.error),
              str(app.session_state.get("authentication_status")))


def test_ui_new_format() -> None:
    section("UI: new format -> no banner, login works")
    with CredFileGuard():
        subprocess.run(
            [sys.executable, "generate_keys.py"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            env=dict(os.environ, PYTHONIOENCODING="utf-8"),
            check=True,
        )
        app = make_apptest()
        check("no script exception", not app.exception,
              repr([e.value for e in app.exception])[:300])
        check("legacy banner absent for new format",
              not any(cred.LEGACY_BANNER in w.value for w in app.warning))
        login(app, "rmiller", "abc123")
        check("new-format login succeeds",
              app.session_state.get("authentication_status") is True)


def test_ui_corrupt_file() -> None:
    section("UI: deliberately broken file echoes MigrationError reason")
    with CredFileGuard() as path:
        path.write_bytes(b"deliberately broken content for /login")
        app = make_apptest()
        check("no uncaught exception", not app.exception,
              repr([e.value for e in app.exception])[:300])
        messages = [e.value for e in app.error]
        check("error echo rendered",
              any("Credentials file cannot be used" in m for m in messages),
              str(messages))
        check("echoed reason matches service text",
              any("readable pickle" in m for m in messages), str(messages))
        check("login form not rendered after MigrationError",
              not any(getattr(s, "value", "") == "Login" for s in app.subheader))

    # Pickle-loadable but neither format -> reason names the shape
    with CredFileGuard() as path:
        with path.open("wb") as handle:
            pickle.dump({"weird": "shape"}, handle)
        app = make_apptest()
        messages = [e.value for e in app.error]
        check("unknown shape echo rendered",
              any("neither the nested credentials mapping" in m for m in messages),
              str(messages))


def test_cache_independence_between_callers() -> None:
    section("cached mapping copies are isolated per caller")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "creds.pkl"
        cred.save(
            {
                "pparker": {"name": "Peter Parker", "password": "abc123"},
                "rmiller": {"name": "Rebecca Miller", "password": "abc123"},
            },
            path=path,
        )
        first = cred.load(path)
        first.usernames["pparker"]["password"] = "tampered"
        second = cred.load(path)  # CACHED
        check("caller mutation does not poison cache",
              stauth.Hasher.is_hash(second.usernames["pparker"]["password"]),
              second.usernames["pparker"]["password"])


def main() -> int:
    tests = [
        test_paths_are_root_anchored,
        test_state_machine,
        test_malformed_files,
        test_password_verification,
        test_change_without_restart,
        test_size_only_change_is_detected,
        test_atomic_and_concurrency,
        test_generator_script,
        test_ui_legacy_login,
        test_ui_new_format,
        test_ui_corrupt_file,
        test_cache_independence_between_callers,
    ]
    for test in tests:
        test()

    print("\n" + "=" * 60)
    print(f"PASSED: {PASSED}   FAILED: {len(FAILURES)}")
    if FAILURES:
        print("\nFailed checks:")
        for failure in FAILURES:
            print(f"  - {failure}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
