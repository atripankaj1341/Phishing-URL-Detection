"""
Phishing URL Detection System — Flask Backend
=============================================
Scoring approach:
  Each heuristic adds a risk score (0–100 total possible penalty points).
  A final score is clamped to [0, 100]; higher = more suspicious.

  Risk bands:
    0–29   → Safe (green)
   30–59   → Suspicious (yellow)
   60–100  → Likely Phishing (red)

Heuristics and their weights are documented in SCORING.md.
No URLs or user data are stored, logged to disk, or sent externally.
"""

from flask import Flask, render_template, request, jsonify
import re
import math
from urllib.parse import urlparse, unquote

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Scoring heuristics
# Each function returns (score_delta: int, reason: str | None)
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".gq", ".ml", ".cf", ".tk", ".ga",
    ".pw", ".click", ".link", ".loan", ".win", ".download", ".accountant",
    ".stream", ".faith", ".review", ".party", ".science", ".trade",
}

TRUSTED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "twitter", "netflix", "ebay", "linkedin", "dropbox",
    "bankofamerica", "chase", "wellsfargo", "citibank", "irs", "gov",
]

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "confirm",
    "banking", "password", "credential", "wallet", "support", "helpdesk",
    "billing", "invoice", "alert", "suspended", "unlock", "validate",
]


def check_url_length(url: str) -> tuple[int, str | None]:
    """Long URLs obscure the true destination. >75 chars adds risk."""
    length = len(url)
    if length > 100:
        return 15, f"URL is very long ({length} chars)"
    if length > 75:
        return 8, f"URL is long ({length} chars)"
    return 0, None


def check_ip_address(parsed) -> tuple[int, str | None]:
    """Legitimate sites use domain names, not bare IP addresses."""
    host = parsed.hostname or ""
    ipv4 = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)
    if ipv4:
        return 20, "Host is a raw IP address (no domain name)"
    return 0, None


def check_suspicious_tld(parsed) -> tuple[int, str | None]:
    """Several cheap/free TLDs are disproportionately used in phishing."""
    host = (parsed.hostname or "").lower()
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return 15, f"Domain uses a high-risk TLD ({tld})"
    return 0, None


def check_subdomain_depth(parsed) -> tuple[int, str | None]:
    """Phishers add sub-domains to fake legitimacy (e.g. paypal.verify.evil.com)."""
    host = (parsed.hostname or "").lower()
    parts = [p for p in host.split(".") if p]
    depth = len(parts) - 2  # subtract SLD + TLD
    if depth >= 3:
        return 15, f"Excessive sub-domain depth ({depth} levels)"
    if depth == 2:
        return 7, f"Multiple sub-domains ({depth} levels)"
    return 0, None


def check_brand_in_subdomain(parsed) -> tuple[int, str | None]:
    """A trusted brand name in a sub-domain but not in the SLD is classic phishing."""
    host = (parsed.hostname or "").lower()
    parts = host.split(".")
    if len(parts) < 3:
        return 0, None
    # Everything except the last two parts = sub-domains
    subdomains = ".".join(parts[:-2])
    sld = parts[-2]
    for brand in TRUSTED_BRANDS:
        if brand in subdomains and brand not in sld:
            return 20, f"Trusted brand '{brand}' appears in sub-domain only"
    return 0, None


def check_https(parsed) -> tuple[int, str | None]:
    """Plain HTTP provides no transport security."""
    if parsed.scheme == "http":
        return 8, "No HTTPS — connection is unencrypted"
    return 0, None


def check_special_chars(url: str) -> tuple[int, str | None]:
    """@ in URLs redirects; multiple dashes or encodings are evasion tricks."""
    score = 0
    reasons = []
    if "@" in url:
        score += 15
        reasons.append("URL contains '@' (can redirect to different host)")
    double_slash = re.findall(r"(?<!:)//", url)
    if double_slash:
        score += 10
        reasons.append("URL contains '//' outside of protocol")
    dash_count = url.count("-")
    if dash_count >= 4:
        score += 5
        reasons.append(f"URL contains many hyphens ({dash_count})")
    return score, "; ".join(reasons) if reasons else None


def check_phishing_keywords(url: str) -> tuple[int, str | None]:
    """Security-sensitive words in the path/query are common lures."""
    lower = url.lower()
    found = [kw for kw in PHISHING_KEYWORDS if kw in lower]
    if len(found) >= 3:
        return 15, f"Multiple phishing keywords: {', '.join(found[:5])}"
    if found:
        return 7, f"Phishing keyword(s) detected: {', '.join(found[:3])}"
    return 0, None


def check_url_encoding(url: str) -> tuple[int, str | None]:
    """Heavy percent-encoding is used to obscure malicious paths."""
    encoded_count = len(re.findall(r"%[0-9A-Fa-f]{2}", url))
    if encoded_count >= 5:
        return 10, f"Heavy URL encoding ({encoded_count} encoded chars)"
    return 0, None


def check_port(parsed) -> tuple[int, str | None]:
    """Non-standard ports are unusual for legitimate web services."""
    port = parsed.port
    if port and port not in (80, 443, 8080, 8443):
        return 10, f"Non-standard port ({port})"
    return 0, None


def check_path_depth(parsed) -> tuple[int, str | None]:
    """Very deep paths can indicate redirect chains."""
    path = parsed.path or ""
    depth = len([p for p in path.split("/") if p])
    if depth >= 6:
        return 8, f"Very deep URL path ({depth} segments)"
    return 0, None


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

HEURISTICS = [
    check_url_length,
    check_ip_address,
    check_suspicious_tld,
    check_subdomain_depth,
    check_brand_in_subdomain,
    check_https,
    check_special_chars,
    check_phishing_keywords,
    check_url_encoding,
    check_port,
    check_path_depth,
]


def analyse_url(url: str) -> dict:
    """
    Run all heuristics and return a result dict.
    score: 0 (safe) – 100 (certain phishing).
    """
    url = url.strip()
    if not url:
        return {"error": "No URL provided"}

    # Normalise — add scheme if missing so urlparse works correctly
    if not re.match(r"^[a-zA-Z][a-zA-Z\d+\-.]*://", url):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return {"error": "Could not parse URL"}

    total_score = 0
    flags = []

    for heuristic in HEURISTICS:
        try:
            # Functions that only need the parsed object
            import inspect
            sig = inspect.signature(heuristic)
            param = list(sig.parameters.keys())[0]
            delta, reason = heuristic(parsed) if param == "parsed" else heuristic(url)
        except Exception:
            continue

        if delta > 0:
            total_score += delta
            if reason:
                flags.append(reason)

    total_score = min(total_score, 100)

    if total_score < 30:
        verdict = "Safe"
        band = "safe"
    elif total_score < 60:
        verdict = "Suspicious"
        band = "suspicious"
    else:
        verdict = "Likely Phishing"
        band = "danger"

    improvements = _suggest_improvements(band, flags)

    return {
        "url": url,
        "score": total_score,
        "verdict": verdict,
        "band": band,
        "flags": flags,
        "improvements": improvements,
    }


def _suggest_improvements(band: str, flags: list[str]) -> list[str]:
    """Return actionable suggestions for the URL owner (not the checker user)."""
    suggestions = []
    flag_text = " ".join(flags).lower()

    if "http" in flag_text and "https" not in flag_text:
        suggestions.append("Enable HTTPS with a valid TLS certificate.")
    if "ip address" in flag_text:
        suggestions.append("Use a registered domain name instead of a bare IP.")
    if "sub-domain" in flag_text:
        suggestions.append("Reduce sub-domain nesting to one level where possible.")
    if "tld" in flag_text:
        suggestions.append("Register on a well-established TLD (.com, .org, .net).")
    if "keyword" in flag_text:
        suggestions.append("Avoid security-sensitive words in URLs unless necessary.")
    if "long" in flag_text:
        suggestions.append("Shorten the URL; very long URLs reduce user trust.")
    if "encoding" in flag_text:
        suggestions.append("Avoid heavy percent-encoding in publicly shared URLs.")
    if "port" in flag_text:
        suggestions.append("Serve on standard ports (80/443) for public-facing URLs.")
    if not suggestions and band != "safe":
        suggestions.append("Review the flagged issues and restructure the URL path.")
    return suggestions


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyse", methods=["POST"])
def api_analyse():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    result = analyse_url(url)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
