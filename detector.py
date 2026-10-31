import re
import ipaddress
from urllib.parse import urlparse


def analyze_message(message):

    findings = []
    score = 0
    text = message.lower()

    # 1. Urgency and threats
    urgent_words = [
        "urgent", "immediately", "account blocked",
        "account suspended", "act now", "expire today",
        "failure to act", "within 24 hours",
        "within 2 hours", "permanently blocked",
        "final warning", "limited time"
    ]

    found_urgent = [
        word for word in urgent_words if word in text
    ]

    if found_urgent:
        score += 20
        findings.append(
            "Urgent or threatening language: "
            + ", ".join(found_urgent)
        )

    # 2. Sensitive information requests
    sensitive_words = [
        "password", "otp", "one-time password",
        "bank details", "credit card", "pin number",
        "atm pin", "atm pin number", "share your pin",
        "verify your account", "login credentials",
        "banking details", "account number"
    ]

    found_sensitive = [
        word for word in sensitive_words if word in text
    ]

    if found_sensitive:
        score += 30
        findings.append(
            "Sensitive information requests: "
            + ", ".join(found_sensitive)
        )

    # 3. Suspicious URLs
    urls = re.findall(
        r"""https?://[^\s<>"']+|www\.[^\s<>"']+""",
        message,
        flags=re.IGNORECASE
    )

    for url in urls:

        cleaned_url = url.rstrip(".,!?;:)")

        candidate = cleaned_url

        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate

        parsed = urlparse(candidate)
        hostname = (parsed.hostname or "").lower()

        reasons = []

        if parsed.scheme == "http":
            reasons.append("uses unencrypted HTTP")

        if "xn--" in hostname:
            reasons.append("contains encoded internationalized domain")

        if "secure-" in hostname or "verify" in hostname:
            reasons.append("contains security-related wording")

        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname):
            reasons.append("uses an IP address as hostname")

        if "@" in parsed.netloc:
            reasons.append("contains an @ symbol")

        if reasons:
            score += 20
            findings.append(
                "URL warning for " + cleaned_url + ": "
                + "; ".join(reasons)
            )

    # 4. Manipulation and financial fraud
    manipulation_words = [
        "you have won", "claim your prize",
        "free gift", "send money", "payment required",
        "click here", "verify now",
        "processing fee", "cash prize",
        "claim your reward", "pay immediately"
    ]

    found_manipulation = [
        word for word in manipulation_words if word in text
    ]

    if found_manipulation:
        score += 20
        findings.append(
            "Possible manipulation tactics: "
            + ", ".join(found_manipulation)
        )

    # 5. Account and banking threats
    banking_words = [
        "bank account", "atm card", "debit card",
        "credit card", "net banking", "bank account"
    ]

    found_banking = [
        word for word in banking_words if word in text
    ]

    if found_banking:
        score += 15
        findings.append(
            "Banking-related content detected: "
            + ", ".join(set(found_banking))
        )

    # 6. Score limitation
    score = min(score, 100)

    # 7. Risk classification
    if score >= 70:
        risk = "Critical"
    elif score >= 45:
        risk = "High"
    elif score >= 20:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append(
            "No warning signs from the current rule set were detected."
        )

    return score, risk, findings, urls

# ---------------- URL INVESTIGATION ENGINE ----------------

import ipaddress
from urllib.parse import urlparse



def analyze_url(url):

    findings = []
    score = 0

    url = url.strip()

    # 1. Basic URL validation
    if not url or any(char.isspace() for char in url):
        return 0, "Invalid", ["URL is empty or contains spaces."]

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        # Check hostname
        if not hostname:
            return 0, "Invalid", ["Invalid URL format."]

        hostname = hostname.lower().rstrip(".")

        # Validate port
        try:
            parsed.port
        except ValueError:
            return 0, "Invalid", ["URL contains an invalid port."]

        if parsed.scheme not in ("http", "https"):
            return 0, "Invalid", ["Unsupported URL protocol."]

    except Exception:
        return 0, "Invalid", ["Unable to parse this URL."]

    # 2. HTTP checking
    if parsed.scheme == "http":
        score += 15
        findings.append(
            "Website uses HTTP instead of HTTPS."
        )

    # 3. IP address detection
    try:
        ip = ipaddress.ip_address(hostname)

        score += 30
        findings.append(
            "URL uses an IP address instead of a domain name."
        )

        if not ip.is_global:
            score += 25
            findings.append(
                "URL uses a private or reserved IP address."
            )

    except ValueError:
        # 4. Domain validation
        if "." not in hostname:
            score += 15
            findings.append(
                "Domain does not contain a standard public domain structure."
            )

        labels = hostname.split(".")

        if any(not label or len(label) > 63 for label in labels):
            return 0, "Invalid", ["Invalid domain structure."]

        if len(hostname) > 253:
            return 0, "Invalid", ["Domain name is too long."]

    # 5. Suspicious domain words
    suspicious_words = [
        "login", "verify", "secure",
        "account", "update", "banking"
    ]

    found_words = [
        word for word in suspicious_words
        if word in hostname
    ]

    if found_words:
        score += 15
        findings.append(
            "Domain contains security-related words: "
            + ", ".join(found_words)
        )

    # 6. Username or password inside URL
    if parsed.username is not None or parsed.password is not None:
        score += 25
        findings.append(
            "URL contains embedded username or password information."
        )

    # 7. Excessive subdomains
    if len(hostname.split(".")) > 4:
        score += 20
        findings.append(
            "URL contains an unusually long subdomain chain."
        )

    # 8. Punycode detection
    if "xn--" in hostname:
        score += 25
        findings.append(
            "Domain contains encoded international characters."
        )

    # Limit score
    score = min(score, 100)

    # 9. Risk classification
    if score >= 70:
        risk = "Critical"
    elif score >= 45:
        risk = "High"
    elif score >= 20:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append(
            "No suspicious patterns detected by the current rules."
        )

    return score, risk, findings
