"""
Nahidx001 - SixEye ZeroLeak API Client
Handles all communication with the ZeroLeak API endpoint.
"""

import requests
import streamlit as st
from typing import Optional


API_BASE = "https://sixeye.fwh.is/zeroleakapi.php"


def query_api(api_key: str, search_type: str, query: str, timeout: int = 30) -> dict:
    """
    Query the SixEye ZeroLeak API.

    Args:
        api_key: The API authentication key.
        search_type: Either 'url' or 'email'.
        query: The domain or email to search.
        timeout: Request timeout in seconds.

    Returns:
        dict with keys: success (bool), data (list), error (str|None), raw (dict)
    """
    params = {"key": api_key, search_type: query}

    try:
        resp = requests.get(API_BASE, params=params, timeout=timeout)
        resp.raise_for_status()
        raw = resp.json()

        # The API may return data in different structures.
        # We normalise to a flat list of credential dicts.
        records = _normalise_response(raw)

        return {"success": True, "data": records, "error": None, "raw": raw}

    except requests.exceptions.Timeout:
        return {"success": False, "data": [], "error": "Request timed out. Try again.", "raw": {}}
    except requests.exceptions.ConnectionError:
        return {"success": False, "data": [], "error": "Connection error. Check your network.", "raw": {}}
    except requests.exceptions.HTTPError as e:
        return {"success": False, "data": [], "error": f"HTTP {e.response.status_code}: {e.response.reason}", "raw": {}}
    except ValueError:
        # Non-JSON response - try to parse as text lines
        try:
            text = resp.text.strip()
            if text:
                records = _parse_text_response(text)
                return {"success": True, "data": records, "error": None, "raw": {"text": text}}
        except Exception:
            pass
        return {"success": False, "data": [], "error": "Invalid response from API.", "raw": {}}
    except Exception as e:
        return {"success": False, "data": [], "error": str(e), "raw": {}}


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
