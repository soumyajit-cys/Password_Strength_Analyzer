# app.py

import streamlit as st

from core.analyzer import analyze_password
from core.generator import generate_password
from core.password_history import PasswordHistory


st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔐",
    layout="centered",
)


st.title("🔐 Password Strength Analyzer")

st.write(
    "Analyze password strength using length, "
    "complexity, entropy and common-pattern checks."
)


history = PasswordHistory()


password = st.text_input(
    "Enter password",
    type="password",
    placeholder="Enter your password..."
)


if password:

    result = analyze_password(password)

    st.subheader("Security Score")

    st.progress(result.score / 100)

    st.metric(
        "Strength",
        result.strength,
        f"{result.score}/100"
    )

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Password Length",
            len(password)
        )

    with col2:
        st.metric(
            "Estimated Entropy",
            f"{result.entropy} bits"
        )

    st.subheader("Security Checks")

    for check, passed in result.checks.items():

        if passed:
            st.success(f"✓ {check}")

        else:
            st.error(f"✗ {check}")

    if result.suggestions:

        st.subheader("💡 Recommendations")

        for suggestion in result.suggestions:
            st.write(f"• {suggestion}")

    st.subheader("Password History")

    if history.was_used_before(password):

        st.warning(
            "⚠️ This password has been used previously."
        )

    else:

        st.success(
            "✓ This password was not found "
            "in your local password history."
        )


st.divider()

st.subheader("🎲 Generate Strong Password")

length = st.slider(
    "Password length",
    min_value=12,
    max_value=32,
    value=16
)


if st.button("Generate Password"):

    generated = generate_password(length)

    st.code(generated)

    st.info(
        "Generated using Python's cryptographically "
        "secure secrets module."
    )