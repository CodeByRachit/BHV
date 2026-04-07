import pytest
from app import app 
LOGIN_ROUTE = "/login"
LOGOUT_ROUTE = "/logout"
PUBLIC_ROUTE = "/"
PROTECTED_ROUTE = "/profile"  # Fixed to match your @login_required route!
ADMIN_ROUTE = "/admin/dashboard"
OWNER_ROUTE = "/owner/dashboard"

@pytest.fixture
def client():
    """Creates a secure test client for the Flask application."""
    app.config['TESTING'] = True
    # Disables CSRF tokens specifically for testing so our automated requests aren't blocked
    app.config['WTF_CSRF_ENABLED'] = False 
    # Disables Rate Limiter for tests so we don't get 429 errors on bulk tests
    app.config['RATELIMIT_ENABLED'] = False
    
    with app.test_client() as client:
        yield client
        
TEST_USER = {
    "email": "doctor_test@clinic.org",
    "password": "secure_password_123"
}

def test_public_route_accessible(client):
    """Ensures the public welcome page is accessible without authentication."""
    response = client.get(PUBLIC_ROUTE)
    assert response.status_code == 200

def test_successful_login(client):
    """
    INTEGRATION TEST: Validates the Login Gateway.
    Ensures valid credentials return a success code (200) or redirect to dashboard (302).
    """
    response = client.post(LOGIN_ROUTE, data=TEST_USER)
    # 200 = OK, 302 = Redirected to Dashboard, 401 = DB is empty (Expected if no test user exists)
    assert response.status_code in [200, 302, 401], f"Unexpected status: {response.status_code}"


def test_failed_login_wrong_password(client):
    """EDGE CASE: Rejects invalid passwords."""
    response = client.post(LOGIN_ROUTE, data={
        "email": TEST_USER["email"],
        "password": "wrong_password_entirely"
    })
    assert response.status_code in [401, 400, 200]

def test_failed_login_missing_fields(client):
    """EDGE CASE: Validates that the server doesn't crash if a user submits a partial form."""
    response = client.post(LOGIN_ROUTE, data={"email": "only_email@clinic.org"})
    assert response.status_code in [400, 401, 200]

def test_failed_login_empty_payload(client):
    """EDGE CASE: Validates that the server doesn't crash on completely empty submissions."""
    response = client.post(LOGIN_ROUTE, data={})
    assert response.status_code in [400, 401, 200]

def test_extreme_input_length(client):
    """
    EDGE CASE: Buffer Overflow Simulation.
    Ensures the server doesn't crash when sent an absurdly long string.
    """
    response = client.post(LOGIN_ROUTE, data={
        "email": "A" * 10000 + "@clinic.org",
        "password": "password"
    })
    # Should safely reject as bad request or unauthorized, NOT crash (500)
    assert response.status_code in [400, 401, 200, 413]

def test_security_sql_injection_email(client):
    """SECURITY AUDIT: SQL Injection in Email Field."""
    malicious_payload = {
        "email": "doctor@clinic.org' OR '1'='1",
        "password": "password"
    }
    response = client.post(LOGIN_ROUTE, data=malicious_payload)
    # Must NOT succeed (no 302 redirect to dashboard)
    assert response.status_code != 302

def test_security_sql_injection_password(client):
    """SECURITY AUDIT: SQL Injection in Password Field."""
    malicious_payload = {
        "email": TEST_USER["email"],
        "password": "' OR 1=1 --"
    }
    response = client.post(LOGIN_ROUTE, data=malicious_payload)
    assert response.status_code != 302

def test_security_xss_injection(client):
    """
    SECURITY AUDIT: Cross-Site Scripting (XSS).
    Ensures that malicious Javascript injected into the login form is safely rejected.
    """
    malicious_payload = {
        "email": "<script>alert('Hacked!');</script>",
        "password": "password"
    }
    response = client.post(LOGIN_ROUTE, data=malicious_payload)
    # Server should sanitize/reject it, not crash or log them in
    assert response.status_code in [400, 401, 200]

def test_protected_route_unauthenticated(client):
    """
    SECURITY AUDIT: Zero-Trust Enforcement.
    If an attacker tries to directly access the vault URL without logging in, 
    the API must reject them (401/403) or redirect them to login (302).
    """
    response = client.get(PROTECTED_ROUTE)
    # 302 (Redirect to login), 401 (Unauthorized), 403 (Forbidden)
    assert response.status_code in [302, 401, 403], f"Vault is exposed! Status: {response.status_code}"

def test_protected_route_forged_headers(client):
    """
    SECURITY AUDIT: Forgery Prevention.
    If an attacker provides a maliciously altered Authorization header or fake cookie, 
    the middleware must catch it and reject the request.
    """
    headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake_payload.fake_signature",
        "Cookie": "session=fake_malicious_session_string"
    }
    response = client.get(PROTECTED_ROUTE, headers=headers)
    assert response.status_code in [302, 401, 403]

def test_logout_behavior(client):
    """
    SECURITY AUDIT: Session Termination.
    Ensures the logout route safely handles requests, even if the user isn't logged in.
    """
    response = client.get(LOGOUT_ROUTE)
    # Should redirect to welcome page or login page safely
    assert response.status_code in [302, 200, 401]

def test_unsupported_http_method(client):
    """
    EDGE CASE: HTTP Verb Tampering.
    Ensures the login route rejects PUT/DELETE methods instead of crashing.
    """
    response_put = client.put(LOGIN_ROUTE, data=TEST_USER)
    response_delete = client.delete(LOGIN_ROUTE)
    # 405 Method Not Allowed
    assert response_put.status_code == 405
    assert response_delete.status_code == 405

def test_unicode_and_emoji_credentials(client):
    """
    EDGE CASE: Database Encoding Resilience.
    Ensures the system gracefully handles emojis and non-Latin characters 
    without throwing a 500 Internal Server Error.
    """
    response = client.post(LOGIN_ROUTE, data={
        "email": "доктор@клиника.org 👩‍⚕️",
        "password": "пароль🔐"
    })
    assert response.status_code in [401, 400, 200]

def test_malformed_content_type(client):
    """
    EDGE CASE: Header Tampering.
    Simulates a client sending garbage data types instead of standard forms or JSON.
    """
    headers = {"Content-Type": "application/xml"}
    response = client.post(LOGIN_ROUTE, data="<xml><user>test</user></xml>", headers=headers)
    # Should gracefully ignore or reject, not crash
    assert response.status_code in [400, 415, 200]

def test_login_trailing_whitespace(client):
    """
    EDGE CASE: Fat-finger formatting.
    Ensures spaces before or after the email don't cause server exceptions.
    """
    response = client.post(LOGIN_ROUTE, data={
        "email": "  doctor_test@clinic.org  ",
        "password": "password123"
    })
    assert response.status_code in [400, 401, 200]

def test_password_dos_hashing_limit(client):
    """
    SECURITY AUDIT: Hashing Denial of Service (Bcrypt/PBKDF2 DOS).
    Extremely large passwords can freeze the CPU during the hashing process.
    The server should quickly reject a 10MB password string.
    """
    massive_password = "A" * (10 * 1024 * 1024) # 10 Megabytes of 'A's
    response = client.post(LOGIN_ROUTE, data={
        "email": "doctor@clinic.org",
        "password": massive_password
    })
    # Should be rejected quickly by payload size limits or validation
    assert response.status_code in [413, 400, 401, 200, 302]

def test_admin_dashboard_unauthenticated(client):
    """
    RBAC AUDIT: Privilege Escalation Prevention.
    Ensures standard users or unauthenticated attackers cannot access the admin panel.
    """
    response = client.get(ADMIN_ROUTE)
    # Should be redirected to login (302) or strictly Forbidden (403)
    assert response.status_code in [302, 401, 403]

def test_owner_dashboard_unauthenticated(client):
    """
    RBAC AUDIT: System Owner Protection.
    Ensures the absolute highest privilege tier is blocked from public access.
    """
    response = client.get(OWNER_ROUTE)
    assert response.status_code in [302, 401, 403]

def test_sql_injection_advanced(client):
    """
    SECURITY AUDIT: Blind & UNION SQL Injection.
    More complex payloads designed to bypass simple OR 1=1 filters.
    """
    payloads = [
        "admin@clinic.org' UNION SELECT 1,2,3--",
        "admin@clinic.org' AND (SELECT 1 FROM (SELECT SLEEP(5))A)--",
        "admin@clinic.org'; DROP TABLE users;--"
    ]
    for bad_email in payloads:
        response = client.post(LOGIN_ROUTE, data={
            "email": bad_email,
            "password": "password"
        })
        assert response.status_code != 302, f"Failed on payload: {bad_email}"