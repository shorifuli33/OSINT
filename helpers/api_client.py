"""
Nahidx001 - SixEye ZeroLeak API Client
Handles all communication with the ZeroLeak API endpoint.
"""

import time
import requests


API_BASE = "https://sixeye.fwh.is/zeroleakapi.php"

# Browser-like headers to avoid being blocked by the API server
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://sixeye.fwh.is/",
    "Connection": "keep-alive",
}


def query_api(api_key: str, search_type: str, query: str, timeout: int = 45) -> dict:
    """
    Query the SixEye ZeroLeak API with retry logic.

    Args:
        api_key: The API authentication key.
        search_type: Either 'url' or 'email'.
        query: The domain or email to search.
        timeout: Request timeout in seconds.

    Returns:
        dict with keys: success (bool), data (list), error (str|None), raw (dict)
    """
    params = {"key": api_key, search_type: query}
    last_error = "Unknown error"

    # Retry up to 3 times with exponential backoff
    for attempt in range(3):
        if attempt > 0:
            time.sleep(2 ** attempt)  # 2s, 4s

        try:
            session = requests.Session()
            session.headers.update(HEADERS)

            resp = session.get(API_BASE, params=params, timeout=timeout)

            # Some APIs return 200 with error body — handle both paths
            if resp.status_code == 403:
                return {
                    "success": False,
                    "data": [],
                    "error": (
                        "API returned 403 Forbidden. The server may be blocking "
                        "cloud-hosted requests. Try running the app locally."
                    ),
                    "raw": {},
                }

            resp.raise_for_status()

            # Try JSON first
            try:
                raw = resp.json()
                records = _normalise_response(raw)
                return {"success": True, "data": records, "error": None, "raw": raw}
            except ValueError:
                pass

            # Fall back to plain-text parsing
            text = resp.text.strip()
            if text:
                records = _parse_text_response(text)
                raw = {"text": text}
                return {"success": True, "data": records, "error": None, "raw": raw}

            return {"success": True, "data": [], "error": None, "raw": {}}

        except requests.exceptions.Timeout:
            last_error = f"Request timed out (attempt {attempt + 1}/3)."
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection error: {e}"
        except requests.exceptions.HTTPError as e:
            # Non-retryable HTTP errors
            return {
                "success": False,
                "data": [],
                "error": f"HTTP {e.response.status_code}: {e.response.reason}",
                "raw": {},
            }
        except Exception as e:
            last_error = str(e)

    return {"success": False, "data": [], "error": last_error, "raw": {}}


def _normalise_response(raw) -> list:
    """Normalise various API response formats into a list of credential dicts."""
    records = []

    if isinstance(raw, list):
        for item in raw:
            records.append(_normalise_record(item))
    elif isinstance(raw, dict):
        # Check common wrapper keys
        for key in ("data", "results", "records", "leaks", "breaches"):
            if key in raw and isinstance(raw[key], list):
                for item in raw[key]:
                    records.append(_normalise_record(item))
                return records
        # Single record
        if any(k in raw for k in ("username", "email", "password", "url")):
            records.append(_normalise_record(raw))
    elif isinstance(raw, str):
        records = _parse_text_response(raw)

    return records


def _normalise_record(item) -> dict:
    """Normalise a single record into a standard dict."""
    if isinstance(item, str):
        parts = item.split(":")
        if len(parts) >= 2:
            return {
                "username": parts[0].strip(),
                "password": ":".join(parts[1:]).strip(),
                "url": "",
            }
        return {"username": item.strip(), "password": "", "url": ""}

    if isinstance(item, dict):
        return {
            "username": item.get("username") or item.get("email") or item.get("login") or item.get("user") or "",
            "password": item.get("password") or item.get("pass") or item.get("pwd") or "",
            "url": item.get("url") or item.get("domain") or item.get("source") or item.get("site") or "",
        }

    return {"username": str(item), "password": "", "url": ""}


def _parse_text_response(text: str) -> list:
    """Parse plain-text credential dumps (user:pass or user:pass@url per line)."""
    records = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            records.append({
                "username": parts[0].strip(),
                "password": ":".join(parts[1:]).strip(),
                "url": "",
            })
        else:
            records.append({"username": line, "password": "", "url": ""})
    return records
