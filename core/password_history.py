# core/password_history.py

import hashlib
import hmac
import secrets
import sqlite3


class PasswordHistory:

    def __init__(self, database="password_history.db"):
        self.database = database
        self._initialize()

    def _initialize(self):

        with sqlite3.connect(self.database) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL
                )
            """)

    @staticmethod
    def hash_password(password: str, salt: bytes) -> str:

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            600_000
        )

        return password_hash.hex()

    def add_password(self, password: str):

        salt = secrets.token_bytes(32)

        password_hash = self.hash_password(
            password,
            salt
        )

        with sqlite3.connect(self.database) as conn:
            conn.execute(
                """
                INSERT INTO password_history
                (password_hash, salt)
                VALUES (?, ?)
                """,
                (
                    password_hash,
                    salt.hex()
                )
            )

    def was_used_before(self, password: str) -> bool:

        with sqlite3.connect(self.database) as conn:

            rows = conn.execute(
                """
                SELECT password_hash, salt
                FROM password_history
                """
            ).fetchall()

        for stored_hash, stored_salt in rows:

            salt = bytes.fromhex(stored_salt)

            calculated_hash = self.hash_password(
                password,
                salt
            )

            if hmac.compare_digest(
                calculated_hash,
                stored_hash
            ):
                return True

        return False