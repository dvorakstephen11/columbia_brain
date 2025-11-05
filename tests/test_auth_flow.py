from app.security import make_numeric_code


def _ensure_csrf(client):
    response = client.get("/auth/csrf")
    assert response.status_code == 200
    token = client.cookies.get("csrf_token")
    assert token
    return token


def _register(client, email, password):
    csrf = _ensure_csrf(client)
    response = client.post(
        "/auth/register",
        json={"email": email, "password": password},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200
    return response.json()


def test_make_numeric_code_format():
    seen = set()
    for _ in range(200):
        code, digest = make_numeric_code()
        assert len(code) == 6
        assert code.isdigit()
        assert len(digest) == 64
        seen.add(code)
    # Ensure codes are not trivially repeating
    assert len(seen) > 150


def test_registration_flow_success(client):
    email = "person@example.com"
    password = "hunter2!"
    register_payload = _register(client, email, password)

    assert register_payload["pending_verification"] is True
    verification_code = register_payload["mock_verification_code"]
    registration_token = register_payload["registration_token"]
    assert len(verification_code) == 6

    # Login should fail before verification
    csrf = _ensure_csrf(client)
    login_response = client.post(
        "/auth/login",
        json={"email": email, "password": password},
        headers={"X-CSRF-Token": csrf},
    )
    assert login_response.status_code == 403

    verify_response = client.post(
        "/auth/verify-code",
        json={"code": verification_code, "registration_token": registration_token},
    )
    assert verify_response.status_code == 200
    verify_payload = verify_response.json()
    assert verify_payload["verified"] is True
    assert verify_payload["username_required"] is True
    username_token = verify_payload["registration_token"]

    username_response = client.post(
        "/auth/username",
        json={"username": "calendarfan", "registration_token": username_token},
    )
    assert username_response.status_code == 200
    assert username_response.json()["username"] == "calendarfan"

    csrf = _ensure_csrf(client)
    login_response = client.post(
        "/auth/login",
        json={"email": email, "password": password},
        headers={"X-CSRF-Token": csrf},
    )
    assert login_response.status_code == 200

    me_response = client.get("/auth/me")
    assert me_response.status_code == 200
    me_payload = me_response.json()
    assert me_payload["email"] == email
    assert me_payload["is_email_verified"] is True
    assert me_payload["username"] == "calendarfan"


def test_duplicate_username_rejected(client):
    first = _register(client, "one@example.com", "hunter2!")
    verify_first = client.post(
        "/auth/verify-code",
        json={"code": first["mock_verification_code"], "registration_token": first["registration_token"]},
    )
    assert verify_first.status_code == 200
    token_one = verify_first.json()["registration_token"]
    response = client.post("/auth/username", json={"username": "takenname", "registration_token": token_one})
    assert response.status_code == 200

    # New visitor with a brand new session
    client.cookies.clear()
    second = _register(client, "two@example.com", "hunter2!")
    verify_second = client.post(
        "/auth/verify-code",
        json={"code": second["mock_verification_code"], "registration_token": second["registration_token"]},
    )
    assert verify_second.status_code == 200
    token_two = verify_second.json()["registration_token"]
    dup_response = client.post(
        "/auth/username",
        json={"username": "takenname", "registration_token": token_two},
    )
    assert dup_response.status_code == 400
    assert dup_response.json()["detail"] == "Username already in use"


def test_verify_code_requires_identifier(client):
    payload = _register(client, "anon@example.com", "hunter2!")
    response = client.post("/auth/verify-code", json={"code": payload["mock_verification_code"]})
    assert response.status_code == 400
    assert response.json()["detail"] == "Registration token or email is required"
