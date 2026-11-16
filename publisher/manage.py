"""Ardea user administration from the command line (for recovery, e.g. a lost admin password).

    docker compose exec publisher python manage.py list-users
    docker compose exec publisher python manage.py reset-password <username>

reset-password sets a new one-time password (printed here), unlocks and enables the account, signs out
its sessions, and forces a password change at the next login.
"""
import sys

from sqlalchemy import text

import auth
from db import engine


def main(argv):
    auth.ensure_schema_and_admin()
    if argv[:1] == ["list-users"]:
        for u in auth.list_users():
            state = "disabled" if u["disabled"] else ("locked" if u["locked"] else "active")
            print(f"{u['username']:<32} {u['role']:<7} {state:<9} must_change_password={u['must_change_password']}")
        return 0
    if len(argv) == 2 and argv[0] == "reset-password":
        with engine.connect() as c:
            row = c.execute(text("SELECT id FROM users WHERE username = :u"), {"u": argv[1].strip().lower()}).first()
        if not row:
            print(f"no such user: {argv[1]}", file=sys.stderr)
            return 1
        name, password = auth.reset_password("command line", row[0], None)
        auth.set_disabled(-1, "command line", row[0], False, None)
        print(f"New one-time password for '{name}': {password}\nIt must be changed at the next login.")
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
