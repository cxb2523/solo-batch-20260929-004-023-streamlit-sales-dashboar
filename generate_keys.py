"""Generate / migrate the credentials file through the credential service.

Writes the *new* nested format atomically (temp file + os.replace), so a
running app never observes a half-written pickle. Passwords are taken from
the environment when present, otherwise the tutorial defaults are used:

    $ python generate_keys.py
    $ PPARKER_PW=secret RMILLER_PW=secret python generate_keys.py
"""

import os

import credentials as cred


def build_users():
    """Return the new-format user mapping (plain passwords, service hashes)."""
    return {
        "pparker": {
            "name": "Peter Parker",
            "email": "peter.parker@example.com",
            "password": os.environ.get("PPARKER_PW", "abc123"),
        },
        "rmiller": {
            "name": "Rebecca Miller",
            "email": "rebecca.miller@example.com",
            "password": os.environ.get("RMILLER_PW", "abc123"),
        },
    }


def main() -> None:
    # save() resolves the path from the project root and performs the atomic
    # replace + bcrypt hashing itself -- never pickle the file directly.
    result = cred.save(build_users())
    print(
        f"Wrote {cred.CREDENTIALS_FILE} ({result.state}) for users: "
        + ", ".join(result.usernames)
    )


if __name__ == "__main__":
    main()
