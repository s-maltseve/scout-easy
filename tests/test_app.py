import os

os.environ["SCOUT_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.4.0"}


def test_dashboard_shape_and_secret_is_not_exposed():
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    payload = response.json()
    assert payload["meta"]["read_only"] is True
    assert "action_token" not in payload["meta"]
    assert "system" in payload
    assert "ssh" in payload
    assert "fail2ban" in payload
    assert "network" in payload
    assert "traffic" in payload
    assert "current" in payload["traffic"]
    assert "total" in payload["traffic"]
