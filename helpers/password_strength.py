"""
Nahidx001 - Password Strength Analyser
Uses zxcvbn-inspired logic to evaluate leaked password strength.
"""

import re
import math


def evaluate_password(password: str) -> dict:
    """
    Evaluate password strength and return a result dict.

    Returns:
        dict with keys: score (0-4), label, color, details
    """
    if not password:
        return {"score": 0, "label": "Empty", "color": "#ff2d55", "details": "No password"}

    score = 0
    details = []

    length = len(password)

    # Length scoring
    if length >= 16:
        score += 2
        details.append("Good length (16+)")
    elif length >= 10:
        score += 1
        details.append("Moderate length")
    else:
        details.append("Short password")

    # Character variety
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety = sum([has_lower, has_upper, has_digit, has_special])
    if variety >= 4:
        score += 2
        details.append("Excellent character variety")
    elif variety >= 3:
        score += 1
        details.append("Good character variety")
    else:
        details.append("Low character variety")

    # Common password patterns (penalise)
    common_patterns = [
        r"^123456", r"^password", r"^qwerty", r"^abc123",
        r"^letmein", r"^admin", r"^welcome", r"^monkey",
        r"^master", r"^dragon", r"^login", r"^princess",
        r"^solo", r"^football", r"^shadow", r"^sunshine",
        r"^trustno1", r"^iloveyou", r"^1234", r"^0000",
    ]
    lower_pwd = password.lower()
    is_common = any(re.search(p, lower_pwd) for p in common_patterns)
    if is_common:
        score = max(0, score - 2)
        details.append("Common password pattern detected")

    # Repetition check
    if re.search(r"(.)\1{3,}", password):
        score = max(0, score - 1)
        details.append("Excessive character repetition")

    # Sequential check
    if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde|def)", lower_pwd):
        score = max(0, score - 1)
        details.append("Sequential characters detected")

    # Entropy bonus
    if length > 0:
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32
        if charset_size > 0:
            entropy = length * math.log2(charset_size)
            if entropy > 60:
                score += 1

    # Clamp score
    score = max(0, min(4, score))

    labels = {
        0: ("Very Weak", "#ff2d55"),
        1: ("Weak", "#ff6b35"),
        2: ("Fair", "#ffb800"),
        3: ("Strong", "#34c759"),
        4: ("Very Strong", "#00d4aa"),
    }

    label, color = labels[score]

    return {
        "score": score,
        "label": label,
        "color": color,
        "details": " | ".join(details),
    }


def strength_badge(password: str) -> str:
    """Return an HTML badge string for inline display."""
    result = evaluate_password(password)
    return (
        f'<span style="background:{result["color"]}; color:#000; '
        f'padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600;">'
        f'{result["label"]}</span>'
    )
