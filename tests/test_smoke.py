def test_homepage_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"CypherShield" in response.data


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

    assert response.status_code == 301
    assert response.headers["Location"] == "https://localhost/"


def test_internal_server_error_uses_custom_error_page(client, flask_app):
    original_index = flask_app.view_functions["index"]
    original_propagate = flask_app.config.get("PROPAGATE_EXCEPTIONS")

    def broken_index():
        raise RuntimeError("boom")

    flask_app.view_functions["index"] = broken_index
    flask_app.config["PROPAGATE_EXCEPTIONS"] = False
    try:
        response = client.get("/")
    finally:
        flask_app.view_functions["index"] = original_index
        flask_app.config["PROPAGATE_EXCEPTIONS"] = original_propagate

    assert response.status_code == 500
    assert b"500 Internal Server Error" in response.data
