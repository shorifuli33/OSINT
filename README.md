# Nahidx001 — ZeroLeak Threat Intelligence Dashboard

A professional, dark-themed cybersecurity threat intelligence platform for monitoring
password breaches using the SixEye ZeroLeak API.

---

## Features

- **Secure login** (password-protected)
- **Dual search modes**: URL/Domain and Email
- **Auto-classification**: Employee vs User credentials based on org domains
- **Password strength analysis** for every leaked credential
- **Interactive DataTable** with filtering, sorting, colour-coded strength
- **Analytics**: charts for breach distribution, top sources, timeline
- **Search history** stored locally in SQLite (reload past results)
- **Export**: CSV, JSON, PDF reports
- **Risk alerts**: banners for weak passwords and employee exposures
- **Settings**: configure API key, org domains, change login password

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

> **PDF export** requires WeasyPrint system dependencies.
> On Ubuntu/Debian: `sudo apt-get install libpango1.0-dev libgdk-pixbuf2.0-dev libffi-dev`

### 2. Configure secrets

Edit `.streamlit/secrets.toml`:

```toml
dashboard_password = "your_secure_password_here"
api_key = "your_zerolean_api_key_here"
```

> **Important:** `secrets.toml` is in `.gitignore` — it will never be committed.

### 3. Run the dashboard

```bash
streamlit run app.py
```

Then open `http://localhost:8501` in your browser.

**Default login:** `admin` / the password you set in `secrets.toml`

---

## Project Structure

```
OSINT/
├── app.py                  # Main Streamlit application
├── requirements.txt        # Python dependencies
├── helpers/
│   ├── __init__.py
│   ├── api_client.py       # ZeroLeak API integration
│   ├── password_strength.py # Password strength analyser
│   ├── database.py         # SQLite search history
│   └── export.py           # CSV / JSON / PDF export
├── .streamlit/
│   ├── config.toml         # Theme configuration
│   └── secrets.toml        # Credentials (NOT committed)
└── nahidx001.db            # Auto-created SQLite database (NOT committed)
```

---

## API

The tool uses the **SixEye ZeroLeak API**:

| Mode  | Endpoint |
|-------|----------|
| URL   | `https://sixeye.fwh.is/zeroleakapi.php?key=APIKEY&url=example.com` |
| Email | `https://sixeye.fwh.is/zeroleakapi.php?key=APIKEY&email=user@example.com` |

---

## Security Notes

- This tool is for **authorised security research and threat intelligence only**.
- Never share exported reports containing raw credentials.
- Rotate any exposed credentials immediately.
- The `secrets.toml` and `*.db` files are excluded from version control.

---

*NAHIDX001 v1.0 | CONFIDENTIAL | AUTHORIZED USE ONLY*
