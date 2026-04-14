from __future__ import annotations

from secure_app.security import sanitize_output, validate_url


def test_sanitize_output_escapes_html_special_characters():
    payload = '<script>alert("xss")</script>'

    assert sanitize_output(payload) == "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"
    assert sanitize_output(42) == 42


def test_login_template_auto_escapes_reflected_identifier(client):
    payload = '<script>alert("xss")</script>'

    response = client.post(
        "/login",
        data={"identifier": payload, "password": "WrongPass!123"},
    )

    assert response.status_code == 400
    assert payload.encode("utf-8") not in response.data
    assert b"&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;" in response.data


def test_validate_url_accepts_public_https_url():
    is_valid, message = validate_url("https://example.com/documents?id=42")

    assert is_valid is True
    assert message == "URL is valid."


def test_validate_url_rejects_private_or_unsafe_urls():
    assert validate_url("http://example.com")[0] is False
    assert validate_url("https://localhost:8443")[0] is False
    assert validate_url("https://192.168.1.10/admin")[0] is False
    assert validate_url("https://user:pass@example.com")[0] is False


def test_security_headers_include_all_required_headers(client):
    response = client.get("/")
    headers = response.headers

    assert "Content-Security-Policy" in headers
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "connect-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp

    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-XSS-Protection"] == "1; mode=block"
    assert "strict-origin-when-cross-origin" in headers["Referrer-Policy"]
    assert "geolocation=()" in headers["Permissions-Policy"]
