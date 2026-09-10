from __future__ import annotations

import base64
import hashlib
import json
import os
import pickle
import secrets
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("demo_users.db")
INSECURE_OUTPUT_DIR = Path(__file__).with_name("reports")
SECURE_OUTPUT_DIR = Path(__file__).with_name("secure_reports")


def setup_demo_db() -> None:
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("DROP TABLE IF EXISTS users")
        connection.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)"
        )
        connection.executemany(
            "INSERT INTO users (username, role) VALUES (?, ?)",
            [("alice", "researcher"), ("bob", "reviewer")],
        )


def insecure_find_user(username: str) -> list[tuple[str, str]]:
    with sqlite3.connect(DB_PATH) as connection:
        query = f"SELECT username, role FROM users WHERE username = '{username}'"
        return connection.execute(query).fetchall()


def secure_find_user(username: str) -> list[tuple[str, str]]:
    with sqlite3.connect(DB_PATH) as connection:
        return connection.execute(
            "SELECT username, role FROM users WHERE username = ?",
            (username,),
        ).fetchall()


def insecure_load_profile(encoded_pickle: str) -> dict:
    payload = base64.b64decode(encoded_pickle)
    return pickle.loads(payload)


def secure_load_profile(profile_json: str) -> dict:
    return json.loads(profile_json)


def insecure_password_digest(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def secure_password_digest(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}:{digest.hex()}"


def insecure_save_report(filename: str, contents: str) -> Path:
    target = INSECURE_OUTPUT_DIR / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(contents, encoding="utf-8")
    return target


def secure_save_report(filename: str, contents: str) -> Path:
    SECURE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    target = (SECURE_OUTPUT_DIR / Path(filename).name).resolve()
    secure_root = SECURE_OUTPUT_DIR.resolve()
    if target.parent != secure_root:
        raise ValueError("Refusing to write outside secure report directory")

    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(contents)
    return target


def build_demo_payload() -> tuple[str, str]:
    profile = {"name": "Alice", "language": "Python"}
    encoded_pickle = base64.b64encode(pickle.dumps(profile)).decode("ascii")
    encoded_json = json.dumps(profile)
    return encoded_pickle, encoded_json


def main() -> None:
    setup_demo_db()
    encoded_pickle, encoded_json = build_demo_payload()

    print("CWE-89 SQL Injection")
    print("Insecure:", insecure_find_user("' OR '1'='1"))
    print("Secure:", secure_find_user("' OR '1'='1"))
    print()

    print("CWE-502 Unsafe Deserialization")
    print("Insecure:", insecure_load_profile(encoded_pickle))
    print("Secure:", secure_load_profile(encoded_json))
    print()

    print("CWE-327 Broken or Risky Crypto")
    print("Insecure:", insecure_password_digest("ResearchPassword!"))
    print("Secure:", secure_password_digest("ResearchPassword!", salt=b"0123456789ABCDEF"))
    print()

    print("CWE-22 Path Traversal / CWE-732 Incorrect Permission Assignment")
    print("Insecure:", insecure_save_report("../shared/report.txt", "draft findings"))
    print("Secure:", secure_save_report("../shared/report.txt", "draft findings"))


if __name__ == "__main__":
    main()
