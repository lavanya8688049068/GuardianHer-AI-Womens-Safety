# GuardianHer AI

> **IBM Hackathon 2025 | AI for Social Good**
> An AI-powered women's safety platform with wearable integration.

---

## Overview

GuardianHer AI is a unified safety ecosystem that protects women **before**, **during**, and **after** emergencies through:

- **Proactive threat detection** — IBM watsonx.ai biometric anomaly scoring
- **Instant SOS dispatch** — Multi-channel alerts (SMS, call, push) in under 3 seconds
- **Safe-route intelligence** — Crime heatmap + AI-ranked navigation
- **Post-incident AI companion** — IBM Watson Assistant for recovery and report filing
- **Evidence preservation** — AES-256 encrypted vault with integrity hashing

---

## IBM Technologies Used

| Service | Purpose |
|---|---|
| IBM watsonx.ai | Threat scoring model, biometric anomaly detection |
| IBM Watson NLP | Distress keyword detection, sentiment analysis |
| IBM Watson STT/TTS | Voice SOS detection, multilingual audio alerts |
| IBM Watson Assistant | Post-incident AI companion chatbot |
| IBM IoT Platform | Wearable sensor stream ingestion (MQTT) |
| IBM Cloud Object Storage | Encrypted evidence vault |
| IBM App ID | OAuth 2.0 identity and RBAC |
| IBM AI Fairness 360 | Continuous bias audit on threat model |

---

## Project Structure

```
guardianher-ai/
├── app.py                  # Streamlit entry point
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
│
├── config/                 # Configuration layer
├── core/                   # Shared core utilities and base classes
├── pages/                  # Streamlit page modules (one per screen)
├── services/               # Business logic orchestration layer
├── modules/                # Functional feature modules (AI, maps, etc.)
├── database/               # Data access layer (repositories + schema)
├── ui/                     # Reusable UI components and theme
├── assets/                 # Static files (images, CSS, audio)
├── data/                   # Local data files (SQLite DB, sample data)
└── docs/                   # Architecture diagrams and documentation
```

---

## Quick Start

### 1. Clone and set up environment

```bash
git clone https://github.com/your-team/guardianher-ai.git
cd guardianher-ai
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment variables

```bash
cp .env.example .env
# Edit .env and fill in your IBM service credentials
```

### 3. Run the application

```bash
streamlit run app.py
```

---

## Environment Variables

See [`.env.example`](.env.example) for the complete list of required variables.

---

## Architecture

See [`docs/`](docs/) for:
- System Architecture Document
- Technology Stack Document
- Software Architecture Document
- Product Design Document (PRD)

---

## Team

IBM Hackathon 2025 — GuardianHer AI Team

---

## License

MIT License — See LICENSE file for details.
