# core/generator.py

import secrets
import string


def generate_password(length: int = 16) -> str:

    if length < 12:
        raise ValueError(
            "Password length should be at least 12."
        )

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    numbers = string.digits
    symbols = "!@#$%^&*()-_=+"

    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(numbers),
        secrets.choice(symbols),
    ]

    alphabet = lowercase + uppercase + numbers + symbols

    for _ in range(length - 4):
        password.append(secrets.choice(alphabet))

    secrets.SystemRandom().shuffle(password)

    return "".join(password)