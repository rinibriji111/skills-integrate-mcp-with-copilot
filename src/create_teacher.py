import getpass
import hashlib
import json
import os
import secrets
from pathlib import Path


TEACHERS_FILE = Path(
    os.getenv("TEACHERS_FILE", str(Path(__file__).with_name("teachers.json")))
)
ITERATIONS = 310_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


def main() -> None:
    username = input("Teacher username: ").strip()
    if not username:
        raise SystemExit("Username cannot be empty")

    password = getpass.getpass("Teacher password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if not password or password != confirmation:
        raise SystemExit("Passwords must be non-empty and match")

    try:
        data = json.loads(TEACHERS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {"teachers": []}

    teachers = data.setdefault("teachers", [])
    record = {"username": username, "password_hash": hash_password(password)}
    for index, teacher in enumerate(teachers):
        if teacher.get("username") == username:
            teachers[index] = record
            break
    else:
        teachers.append(record)

    TEACHERS_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    TEACHERS_FILE.chmod(0o600)
    print(f"Teacher account saved to {TEACHERS_FILE}")


if __name__ == "__main__":
    main()