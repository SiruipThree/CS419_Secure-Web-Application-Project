def test_homepage_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Secure Document Sharing System" in response.data


def test_security_headers_are_set(client):
    response = client.get("/")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in response.headers
