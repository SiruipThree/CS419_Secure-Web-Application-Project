def test_homepage_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Secure Document Sharing System" in response.data


def test_security_headers_are_set(client):
    response = client.get("/")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in response.headers


def test_hsts_header_is_added_for_https_requests(client):
    response = client.get("/", base_url="https://localhost")
    assert response.headers["Strict-Transport-Security"] == (
        "max-age=31536000; includeSubDomains"
    )


def test_http_is_redirected_to_https_when_enabled(client, flask_app):
    flask_app.config["FORCE_HTTPS"] = True

    response = client.get("/", base_url="http://localhost", follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["Location"] == "https://localhost/"
