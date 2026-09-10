# 🔐 Password Strength Analyzer

A Python-based password security tool that evaluates the strength of user-entered passwords using **length, character complexity, entropy estimation, common-password detection, pattern analysis, and password-history checks**.

The project also provides a cryptographically secure password generator and an interactive **Streamlit web interface**.

---

## 📌 Overview

Weak and reused passwords are one of the most common causes of account compromise.

The **Password Strength Analyzer** helps users understand how resistant a password may be to common guessing attacks by analyzing several security characteristics.

The application:

- Evaluates password length
- Checks character diversity
- Detects common passwords
- Identifies predictable sequences
- Detects repeated characters
- Estimates password entropy
- Provides a security score
- Gives actionable recommendations
- Generates strong passwords
- Checks password reuse using a local database
- Never stores passwords in plaintext

---

## ✨ Features

### 🔍 Password Strength Analysis

The analyzer evaluates:

- Password length
- Lowercase characters
- Uppercase characters
- Numbers
- Special characters
- Common-password usage
- Predictable sequences
- Repeated characters
- Estimated entropy

---

### 📊 Security Score

Each password receives a score from:

```text
0 – 100

