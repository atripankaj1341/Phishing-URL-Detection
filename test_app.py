"""
tests/test_app.py — Automated Tests for PhishGuard
====================================================
Covers:
  • Individual heuristic functions
  • The analyse_url aggregator
  • Flask API endpoint (/api/analyse)
  • Edge cases (empty input, malformed URLs, boundary scores)

Run with:
    pytest tests/test_app.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from urllib.parse import urlparse

from app import (
    app,
    analyse_url,
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
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ── Helper ───────────────────────────────────────────────────────────────────

def parsed(url: str):
    return urlparse(url)


# ═══════════════════════════════════════════════════════════════════════════
# Individual heuristic tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckUrlLength:
    def test_short_url_no_penalty(self):
        score, reason = check_url_length("http://example.com")
        assert score == 0 and reason is None

    def test_moderately_long_url(self):
        url = "http://example.com/" + "a" * 60   # ~80 chars
        score, reason = check_url_length(url)
        assert score == 8

    def test_very_long_url(self):
        url = "http://example.com/" + "a" * 90   # ~110 chars
        score, reason = check_url_length(url)
        assert score == 15

    def test_exactly_75_chars_no_penalty(self):
        url = "h" * 75
        score, _ = check_url_length(url)
        assert score == 0

    def test_exactly_76_chars_moderate_penalty(self):
        url = "h" * 76
        score, _ = check_url_length(url)
        assert score == 8


class TestCheckIpAddress:
    def test_domain_no_penalty(self):
        score, _ = check_ip_address(parsed("http://example.com"))
        assert score == 0

    def test_ipv4_penalised(self):
        score, reason = check_ip_address(parsed("http://192.168.1.1/login"))
        assert score == 20
        assert reason is not None

    def test_partial_ip_no_penalty(self):
        score, _ = check_ip_address(parsed("http://192.168.domain.com"))
        assert score == 0


class TestCheckSuspiciousTld:
    def test_common_tld_safe(self):
        score, _ = check_suspicious_tld(parsed("http://google.com"))
        assert score == 0

    def test_xyz_tld_penalised(self):
        score, reason = check_suspicious_tld(parsed("http://login-paypal.xyz"))
        assert score == 15

    def test_tk_tld_penalised(self):
        score, _ = check_suspicious_tld(parsed("http://free-stuff.tk"))
        assert score == 15

    def test_org_tld_safe(self):
        score, _ = check_suspicious_tld(parsed("http://wikipedia.org"))
        assert score == 0


class TestCheckSubdomainDepth:
    def test_no_subdomain(self):
        score, _ = check_subdomain_depth(parsed("http://example.com"))
        assert score == 0

    def test_single_subdomain_www(self):
        score, _ = check_subdomain_depth(parsed("http://www.example.com"))
        assert score == 0

    def test_two_level_subdomain(self):
        score, reason = check_subdomain_depth(parsed("http://a.b.example.com"))
        assert score == 7

    def test_three_level_subdomain(self):
        score, reason = check_subdomain_depth(parsed("http://a.b.c.example.com"))
        assert score == 15


class TestCheckBrandInSubdomain:
    def test_no_brand(self):
        score, _ = check_brand_in_subdomain(parsed("http://mysite.com"))
        assert score == 0

    def test_brand_in_sld_only_no_penalty(self):
        # paypal is in the SLD, not only in subdomain
        score, _ = check_brand_in_subdomain(parsed("http://www.paypal.com"))
        assert score == 0

    def test_brand_only_in_subdomain(self):
        score, reason = check_brand_in_subdomain(
            parsed("http://paypal.secure-login.com")
        )
        assert score == 20
        assert "paypal" in reason.lower()

    def test_google_in_subdomain(self):
        score, _ = check_brand_in_subdomain(
            parsed("http://google.accounts.evil.net")
        )
        assert score == 20


class TestCheckHttps:
    def test_https_no_penalty(self):
        score, _ = check_https(parsed("https://example.com"))
        assert score == 0

    def test_http_penalised(self):
        score, reason = check_https(parsed("http://example.com"))
        assert score == 8
        assert reason is not None


class TestCheckSpecialChars:
    def test_clean_url_no_penalty(self):
        score, _ = check_special_chars("https://example.com/page")
        assert score == 0

    def test_at_sign_penalised(self):
        score, reason = check_special_chars("http://user@evil.com")
        assert score >= 15

    def test_double_slash_penalised(self):
        score, reason = check_special_chars("http://evil.com//redirect")
        assert score >= 10

    def test_many_hyphens_penalised(self):
        score, _ = check_special_chars("http://my-long-hyphen-test-site.com")
        assert score >= 5

    def test_combined_penalties(self):
        score, _ = check_special_chars("http://user@site.com//path-a-b-c-d")
        # @ (15) + double-slash (10) + hyphens (5) = 30
        assert score >= 25


class TestCheckPhishingKeywords:
    def test_no_keywords(self):
        score, _ = check_phishing_keywords("https://example.com/products")
        assert score == 0

    def test_one_keyword(self):
        score, reason = check_phishing_keywords("https://example.com/login")
        assert score == 7

    def test_three_keywords(self):
        score, _ = check_phishing_keywords(
            "https://example.com/secure/account/verify"
        )
        assert score == 15

    def test_keywords_case_insensitive(self):
        score, _ = check_phishing_keywords("https://example.com/LOGIN/VERIFY/SECURE")
        assert score == 15


class TestCheckUrlEncoding:
    def test_no_encoding(self):
        score, _ = check_url_encoding("https://example.com/path")
        assert score == 0

    def test_light_encoding_no_penalty(self):
        score, _ = check_url_encoding("https://example.com/%20foo%20bar")
        assert score == 0   # only 2 encoded chars

    def test_heavy_encoding_penalised(self):
        encoded = "https://example.com/%2F%2F%65%76%69%6C%2E%63%6F%6D"
        score, _ = check_url_encoding(encoded)
        assert score == 10


class TestCheckPort:
    def test_standard_https_port(self):
        score, _ = check_port(parsed("https://example.com:443/page"))
        assert score == 0

    def test_standard_http_port(self):
        score, _ = check_port(parsed("http://example.com:80/page"))
        assert score == 0

    def test_non_standard_port(self):
        score, reason = check_port(parsed("http://example.com:8888/admin"))
        assert score == 10

    def test_no_port_specified(self):
        score, _ = check_port(parsed("https://example.com/page"))
        assert score == 0


class TestCheckPathDepth:
    def test_shallow_path(self):
        score, _ = check_path_depth(parsed("https://example.com/a/b"))
        assert score == 0

    def test_deep_path(self):
        score, _ = check_path_depth(parsed("https://example.com/a/b/c/d/e/f/g"))
        assert score == 8

    def test_exactly_6_segments(self):
        score, _ = check_path_depth(parsed("https://example.com/a/b/c/d/e/f"))
        assert score == 8


# ═══════════════════════════════════════════════════════════════════════════
# analyse_url aggregator tests
# ═══════════════════════════════════════════════════════════════════════════

class TestAnalyseUrl:
    def test_empty_string_returns_error(self):
        result = analyse_url("")
        assert "error" in result

    def test_safe_url(self):
        result = analyse_url("https://www.google.com")
        assert result["score"] < 30
        assert result["band"] == "safe"

    def test_clearly_phishing_url(self):
        # IP (20) + no-HTTPS (8) + keywords ≥3 (15) + path depth (8) = 51 → suspicious
        # Use a URL that also hits subdomain + TLD to push into danger territory
        url = "http://paypal.secure-verify.xyz:9999/login/verify/account/billing"
        result = analyse_url(url)
        assert result["score"] >= 60
        assert result["band"] == "danger"

    def test_suspicious_url(self):
        url = "http://paypal-secure-login.xyz/account/verify"
        result = analyse_url(url)
        assert result["score"] >= 30

    def test_score_capped_at_100(self):
        # Pile on every possible signal
        url = (
            "http://user@paypal.secure-login-verify-account.xyz:9999"
            "/login/secure/verify/account/update/billing/"
            + "%2F" * 10
            + "-".join(["x"] * 10)
        )
        result = analyse_url(url)
        assert result["score"] <= 100

    def test_result_has_all_keys(self):
        result = analyse_url("https://example.com")
        for key in ("url", "score", "verdict", "band", "flags", "improvements"):
            assert key in result

    def test_url_without_scheme_accepted(self):
        result = analyse_url("example.com")
        assert "error" not in result

    def test_verdict_matches_band(self):
        result = analyse_url("https://www.github.com")
        band_verdicts = {"safe": "Safe", "suspicious": "Suspicious", "danger": "Likely Phishing"}
        assert result["verdict"] == band_verdicts[result["band"]]


# ═══════════════════════════════════════════════════════════════════════════
# Flask API endpoint tests
# ═══════════════════════════════════════════════════════════════════════════

class TestApiEndpoint:
    def test_get_root_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"PhishGuard" in resp.data

    def test_api_analyse_valid_url(self, client):
        resp = client.post(
            "/api/analyse",
            json={"url": "https://www.example.com"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "score" in data
        assert "band" in data

    def test_api_analyse_missing_url(self, client):
        resp = client.post("/api/analyse", json={})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "error" in data

    def test_api_analyse_phishing_url(self, client):
        resp = client.post(
            "/api/analyse",
            json={"url": "http://192.168.1.1/secure/login/verify"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["band"] in ("suspicious", "danger")

    def test_api_content_type_json(self, client):
        resp = client.post(
            "/api/analyse",
            json={"url": "https://example.com"},
        )
        assert "application/json" in resp.content_type

    def test_api_no_json_body(self, client):
        resp = client.post("/api/analyse", data="not json",
                           content_type="text/plain")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "error" in data

    def test_api_very_long_url(self, client):
        url = "http://example.com/" + "a" * 200
        resp = client.post("/api/analyse", json={"url": url})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["score"] > 0


# ═══════════════════════════════════════════════════════════════════════════
# Edge cases
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_whitespace_only_url(self):
        result = analyse_url("   ")
        assert "error" in result

    def test_url_with_unicode(self):
        result = analyse_url("https://müller.de")
        assert "error" not in result

    def test_ftp_scheme(self):
        result = analyse_url("ftp://files.example.com/data")
        assert "error" not in result

    def test_no_path_url(self):
        result = analyse_url("https://example.com")
        assert result["score"] >= 0

    def test_flags_is_list(self):
        result = analyse_url("https://example.com")
        assert isinstance(result["flags"], list)

    def test_improvements_is_list(self):
        result = analyse_url("https://example.com")
        assert isinstance(result["improvements"], list)
