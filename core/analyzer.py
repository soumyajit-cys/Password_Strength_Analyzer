# core/analyzer.py

import math
import re
from dataclasses import dataclass


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "iloveyou",
    "abc123",
}


@dataclass
class PasswordAnalysis:
    score: int
    strength: str
    entropy: float
    suggestions: list[str]
    checks: dict[str, bool]


def calculate_entropy(password: str) -> float:
    """Estimate Shannon-style password entropy from character pool size."""

    if not password:
        return 0.0

    pool = 0

    if re.search(r"[a-z]", password):
        pool += 26

    if re.search(r"[A-Z]", password):
        pool += 26

    if re.search(r"[0-9]", password):
        pool += 10

    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32

    if pool == 0:
        return 0.0

    return len(password) * math.log2(pool)


def analyze_password(password: str) -> PasswordAnalysis:

    suggestions = []

    checks = {
        "Minimum length (8+)": len(password) >= 8,
        "Strong length (12+)": len(password) >= 12,
        "Lowercase letters": bool(re.search(r"[a-z]", password)),
        "Uppercase letters": bool(re.search(r"[A-Z]", password)),
        "Numbers": bool(re.search(r"[0-9]", password)),
        "Special characters": bool(
            re.search(r"[^a-zA-Z0-9]", password)
        ),
        "Not a common password": password.lower() not in COMMON_PASSWORDS,
    }

    score = 0

    # Length
    if len(password) >= 8:
        score += 20

    if len(password) >= 12:
        score += 15

    if len(password) >= 16:
        score += 10

    # Character diversity
    if checks["Lowercase letters"]:
        score += 10

    if checks["Uppercase letters"]:
        score += 10

    if checks["Numbers"]:
        score += 10

    if checks["Special characters"]:
        score += 10

    # Common password penalty
    if not checks["Not a common password"]:
        score -= 40
        suggestions.append(
            "Avoid commonly used passwords."
        )

    # Sequential patterns
    if re.search(r"(12345|23456|34567|qwerty|abcdef)", password.lower()):
        score -= 15
        suggestions.append(
            "Avoid predictable sequences."
        )

    # Repeated characters
    if re.search(r"(.)\1{2,}", password):
        score -= 10
        suggestions.append(
            "Avoid repeating the same character multiple times."
        )

    # Personal/common patterns
    if password.lower() in {
        "password",
        "admin",
        "welcome",
        "letmein",
    }:
        suggestions.append(
            "Use a unique passphrase instead."
        )

    entropy = calculate_entropy(password)

    if entropy < 40:
        suggestions.append(
            "Increase password length and character diversity."
        )
    elif entropy < 60:
        suggestions.append(
            "Consider using a longer passphrase."
        )

    if len(password) < 12:
        suggestions.append(
            "Use at least 12 characters."
        )

    if not checks["Uppercase letters"]:
        suggestions.append(
            "Add uppercase letters."
        )

    if not checks["Numbers"]:
        suggestions.append(
            "Add numbers."
        )

    if not checks["Special characters"]:
        suggestions.append(
            "Add special characters."
        )

    score = max(0, min(score, 100))

    if score < 30:
        strength = "Very Weak"
    elif score < 50:
        strength = "Weak"
    elif score < 70:
        strength = "Moderate"
    elif score < 85:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return PasswordAnalysis(
        score=score,
        strength=strength,
        entropy=round(entropy, 2),
        suggestions=list(dict.fromkeys(suggestions)),
        checks=checks,
    )