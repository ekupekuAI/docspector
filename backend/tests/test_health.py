from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_returns_docspector_identity():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["product"] == "Docspector"
    assert data["tagline"] == "Inspect. Verify. Trust."
    assert data["status"] == "development"


def test_health_endpoint_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "Docspector"
    assert data["version"] == "0.1.0"
    assert data["environment"] == "development"
