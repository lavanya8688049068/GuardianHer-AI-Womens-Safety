# ============================================================
# GuardianHer AI — Streamlit Entry Point
# IBM Hackathon 2025 | AI for Social Good
# ============================================================
# This is the SINGLE entry point for the entire Streamlit app.
# Responsibilities:
#   - Page routing via sidebar navigation
#   - Session state initialisation
#   - Authentication gate (IBM App ID)
#   - Global layout (header, footer, theme)
#
# DO NOT add business logic here.
# Delegate everything to pages/ and services/.
# ============================================================
import streamlit as st

st.set_page_config(
    page_title="GuardianHer AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ GuardianHer AI")
st.write("Streamlit is working successfully!")