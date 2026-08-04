import base64
import hashlib
import hmac
import os
import secrets
import struct
import time


def make_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def make_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def code(secret: str) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded)
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}"


PASSWORD = "Strong-Test-Password!123"
SECRET = make_secret()
os.environ["SCOUT_USERNAME"] = "scout-test"
os.environ["SCOUT_PASSWORD_HASH"] = make_hash(PASSWORD)
os.environ["SCOUT_TOTP_SECRET"] = SECRET
os.environ["SCOUT_SECURE_COOKIE"] = "false"

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.6.0"}


def test_login_dashboard_and_users():
    response = client.post("/api/auth/login", json={"username": "scout-test", "password": PASSWORD, "totp": code(SECRET)})
    assert response.status_code == 200
    csrf = response.json()["csrf"]
    dashboard = client.get("/api/dashboard")
    assert dashboard.status_code == 200
    payload = dashboard.json()
    assert payload["meta"]["two_factor"] is True
    assert "users" in payload
    assert isinstance(payload["users"]["users"], list)
    logout = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logout.status_code == 200
