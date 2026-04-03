"""
Nahidx001 - SixEye ZeroLeak API Client
Handles AES JS-challenge bypass and communication with the ZeroLeak API.
"""

import re
import time
import requests


API_BASE = "https://sixeye.fwh.is/zeroleakapi.php"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://sixeye.fwh.is/",
    "Connection": "keep-alive",
}


def _solve_aes_challenge(html: str) -> str:
    """
    Parse the slowAES JS challenge and compute the __test cookie value.

    The JS calls: slowAES.decrypt(c, 2, a, b)
    slowAES.decrypt signature: (ciphertext, mode, key, iv)
      → a = KEY, b = IV, c = CIPHERTEXT
      → cookie = hex(AES-CBC-decrypt(ciphertext=c, key=a, iv=b))
    """
    matches = re.findall(r'toNumbers\("([0-9a-fA-F]+)"\)', html)
    if len(matches) < 3:
        return ""
    # Variables appear in order: a, b, c
    a_hex, b_hex, c_hex = matches[0], matches[1], matches[2]
    try:
        from Crypto.Cipher import AES
        key = bytes.fromhex(a_hex)   # a = key
        iv  = bytes.fromhex(b_hex)   # b = iv
        ct  = bytes.fromhex(c_hex)   # c = ciphertext
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(ct).hex()
    except Exception:
        return ""


def _extract_redirect_url(html: str) -> str:
    """
    Extract the redirect URL from the JS challenge's location.href statement.
    e.g.: location.href="https://sixeye.fwh.is/zeroleakapi.php?key=...&i=2"
    The `i` parameter is dynamic so we must read it from the page.
    """
    match = re.search(r'location\.href\s*=\s*["\']([^"\']+)["\']', html)
    return match.group(1) if match else ""


def _build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    return s


def query_api(api_key: str, search_type: str, query: str, timeout: int = 90) -> dict:
    """
    Query the SixEye ZeroLeak API.

    Automatically handles the AES JS anti-bot challenge:
      1. GET the API URL → receive JS challenge page
      2. Solve AES decryption to obtain __test cookie
      3. Wait 12 seconds for the server to process
      4. GET the API URL again with cookie + &i=1 → real data

    Args:
        api_key:     The API authentication key.
        search_type: 'url' or 'email'.
        query:       Domain or email to search.
        timeout:     Per-request timeout in seconds (default 90).

    Returns:
        dict with keys: success (bool), data (list), error (str|None), raw (dict)
    """
    params = {"key": api_key, search_type: query}
    last_error = "Unknown error"

    for attempt in range(3):
        if attempt > 0:
            time.sleep(5)   # wait 5s between retries (not exponential — API is just slow)

        try:
            session = _build_session()

            # ── Step 1: Initial request (may return JS challenge) ──────────
            resp1 = session.get(API_BASE, params=params, timeout=timeout)

            if resp1.status_code == 403:
                return {
                    "success": False, "data": [],
                    "error": "API returned 403 Forbidden. The server is blocking this IP.",
                    "raw": {},
                }

            resp1.raise_for_status()

            # ── Step 2: Detect and solve JS challenge ──────────────────────
            body = resp1.text.strip()
            cookie_val = ""

            if "slowAES" in body or "__test" in body:
                cookie_val = _solve_aes_challenge(body)
                if not cookie_val:
                    return {
                        "success": False, "data": [],
                        "error": "Failed to solve anti-bot challenge.",
                        "raw": {"text": body},
                    }

                # ── Step 3: Extract the exact redirect URL from location.href ──
                # The JS contains: location.href="https://...&i=N"
                # The `i` value is dynamic (increments per request), so we must
                # read it from the JS rather than hardcoding &i=1.
                redirect_url = _extract_redirect_url(body)
                if not redirect_url:
                    return {
                        "success": False, "data": [],
                        "error": "Could not extract redirect URL from challenge page.",
                        "raw": {"text": body},
                    }

                # ── Step 4: Follow the redirect URL with the solved cookie ─────
                # Pass cookie directly in the Cookie header to avoid requests'
                # domain-matching dropping it silently.
                # Server processes during this request; takes 10-20s to respond.
                cookie_headers = {**HEADERS, "Cookie": f"__test={cookie_val}"}
                resp2 = session.get(redirect_url, timeout=timeout, headers=cookie_headers)
                resp2.raise_for_status()
                body = resp2.text.strip()

            # ── Step 4: Parse response ─────────────────────────────────────
            try:
                import json
                raw = json.loads(body)
                records = _normalise_response(raw)
                # Extract useful metadata from the response
                api_info = raw.get("api_info", {})
                rate_limit = raw.get("rate_limit", {})
                total = raw.get("results", {}).get("total", len(records)) if isinstance(raw.get("results"), dict) else len(records)
                return {
                    "success": True,
                    "data": records,
                    "error": None,
                    "raw": raw,
                    "api_info": api_info,
                    "rate_limit": rate_limit,
                    "total": total,
                }
            except (ValueError, json.JSONDecodeError):
                pass

            # Plain text fallback
            if body:
                records = _parse_text_response(body)
                return {"success": True, "data": records, "error": None, "raw": {"text": body}, "api_info": {}, "rate_limit": {}, "total": len(records)}

            return {"success": True, "data": [], "error": None, "raw": {}, "api_info": {}, "rate_limit": {}, "total": 0}

        except requests.exceptions.Timeout:
            last_error = f"Request timed out (attempt {attempt + 1}/3). The API is slow — try again."
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection error: {e}"
        except requests.exceptions.HTTPError as e:
            return {
                "success": False, "data": [],
                "error": f"HTTP {e.response.status_code}: {e.response.reason}",
                "raw": {},
            }
        except Exception as e:
            last_error = str(e)

    return {"success": False, "data": [], "error": last_error, "raw": {}}


# ── Response normalisers ────────────────────────────────────────────────────

def _normalise_response(raw) -> list:
    """
    Normalise various API response formats into a list of credential dicts.

    Handles the ZeroLeak structure:
      { "status": "success", "results": { "total": N, "data": [...] }, ... }
    """
    records = []

    if isinstance(raw, list):
        for item in raw:
            records.append(_normalise_record(item))

    elif isinstance(raw, dict):
        # ── Priority 1: results.data (ZeroLeak actual format) ──────────────
        results_block = raw.get("results")
        if isinstance(results_block, dict):
            data_list = results_block.get("data") or results_block.get("records") or []
            if isinstance(data_list, list):
                for item in data_list:
                    records.append(_normalise_record(item))
                return records

        # ── Priority 2: top-level list under common keys ────────────────────
        for key in ("data", "records", "leaks", "breaches", "credentials", "items", "results"):
            val = raw.get(key)
            if isinstance(val, list):
                for item in val:
                    records.append(_normalise_record(item))
                return records

        # ── Priority 3: any single key whose value is a list ───────────────
        list_values = [(k, v) for k, v in raw.items() if isinstance(v, list)]
        if len(list_values) == 1:
            for item in list_values[0][1]:
                records.append(_normalise_record(item))
            return records

        # ── Priority 4: treat the whole dict as a single record ─────────────
        records.append(_normalise_record(raw))

    elif isinstance(raw, str):
        records = _parse_text_response(raw)

    return [r for r in records if any(r.values())]


def _normalise_record(item) -> dict:
    """Normalise a single record into a standard dict."""
    if isinstance(item, str):
        return _parse_credential_line(item)

    if isinstance(item, dict):
        username = (
            item.get("username") or item.get("email") or item.get("login")
            or item.get("user") or item.get("name") or item.get("account")
            or item.get("mail") or item.get("uname") or ""
        )
        password = (
            item.get("password") or item.get("pass") or item.get("pwd")
            or item.get("passwd") or item.get("secret") or ""
        )
        url = (
            item.get("url") or item.get("domain") or item.get("source")
            or item.get("site") or item.get("origin") or item.get("host")
            or item.get("leak_source") or item.get("database") or ""
        )

        # No known keys — dump all values and try to parse
        if not username and not password and not url:
            values = [str(v) for v in item.values() if v]
            raw_line = " | ".join(values)
            return _parse_credential_line(raw_line) if ":" in raw_line else {
                "username": raw_line, "password": "", "url": ""
            }

        return {"username": str(username), "password": str(password), "url": str(url)}

    return {"username": str(item), "password": "", "url": ""}


def _parse_credential_line(line: str) -> dict:
    """
    Parse a single credential line. Handles:
      https://url:port/path:user:pass
      user:pass
      user@domain:pass
    """
    line = line.strip()
    if not line:
        return {"username": "", "password": "", "url": ""}

    parts = line.split(":")

    # Starts with http/https — reconstruct URL
    if len(parts) >= 3 and parts[0].lower() in ("http", "https"):
        url_part = f"{parts[0]}:{parts[1]}"
        remaining = parts[2:]
        if len(remaining) >= 2:
            return {
                "url": url_part,
                "username": remaining[0].strip(),
                "password": ":".join(remaining[1:]).strip(),
            }
        return {"url": url_part, "username": remaining[0].strip() if remaining else "", "password": ""}

    if len(parts) >= 2:
        return {
            "username": parts[0].strip(),
            "password": ":".join(parts[1:]).strip(),
            "url": "",
        }

    return {"username": line, "password": "", "url": ""}


def _parse_text_response(text: str) -> list:
    """Parse plain-text credential dumps (one credential per line)."""
    records = []
    for line in text.strip().splitlines():
        line = line.strip()
        if line:
            records.append(_parse_credential_line(line))
    return records
