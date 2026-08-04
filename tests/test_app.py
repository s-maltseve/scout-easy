import os

os.environ["SCOUT_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_dashboard_shape():
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    payload = response.json()
    assert payload["meta"]["read_only"] is True
    assert "system" in payload
    assert "ssh" in payload
    assert "fail2ban" in payload
    assert "network" in payload
