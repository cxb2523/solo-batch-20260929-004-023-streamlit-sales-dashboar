
"""Generate ``credentials.yaml`` for the sales dashboard.

All hashing and file writes go through the credentials service, so the
resulting file is written atomically and picked up without a restart.

Run from any working directory:  ``python generate_keys.py``
"""

from __future__ import annotations

import credentials


def build_users():
    return {
        "pparker": {
            "name": "Peter Parker",
            "email": "peter.parker@example.com",
            "password": "abc123",
        },
        "rmiller": {
            "name": "Rebecca Miller",
            "email": "rebecca.miller@example.com",
            "password": "def456",
        },
    }


def main() -> None:
    target = credentials.save_new_format(build_users())
    print(f"Wrote hashed credentials to {target}")
    print("Login as pparker / abc123 or rmiller / def456")


if __name__ == "__main__":
    main()
