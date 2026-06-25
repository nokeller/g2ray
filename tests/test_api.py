import time

from fastapi.testclient import TestClient

from g2recon.pipeline import STEP_ORDER
from g2recon.server import app


def _login(client):
    r = client.post("/api/login", json={"user": "admin", "password": "test-password"})
    assert r.status_code == 200, r.text


def test_authenticated_target_import_and_subdomain_run():
    with TestClient(app) as client:
        assert client.get("/healthz").json()["ok"] is True
        assert client.get("/api/targets").status_code == 401

        _login(client)

        r = client.post("/api/targets", json={"name": "adjust.com", "scope_note": "*.adjust.com"})
        assert r.status_code == 200, r.text
        tid = r.json()["id"]

        subindex = b"api.adjust.com\nbad.example.net\ncdn.adjust.com/path\n"
        r = client.post(
            f"/api/targets/{tid}/upload_subdomains",
            files={"file": ("adjust.com_subindex_output.txt", subindex, "text/plain")},
        )
        assert r.status_code == 200, r.text
        assert r.json()["lines"] == 3

        params = b"q\nredirect_uri\nnext\n"
        r = client.post(
            f"/api/targets/{tid}/upload_params",
            files={"file": ("params.txt", params, "text/plain")},
        )
        assert r.status_code == 200, r.text

        excluded = [s for s in STEP_ORDER if s != "subdomains"]
        r = client.post(
            f"/api/targets/{tid}/start",
            json={"excluded_steps": excluded, "subdomain_sources": []},
        )
        assert r.status_code == 200, r.text

        for _ in range(50):
            data = client.get(f"/api/targets/{tid}").json()
            if data["job"]["status"] in {"done", "error"}:
                break
            time.sleep(0.1)

        data = client.get(f"/api/targets/{tid}").json()
        assert data["job"]["status"] == "done", data
        assert data["counts"]["subdomains"] == 3

        hosts = {x["host"] for x in client.get(f"/api/targets/{tid}/subdomains").json()["items"]}
        assert {"adjust.com", "api.adjust.com", "cdn.adjust.com"} <= hosts
        assert "bad.example.net" not in hosts

        r = client.get(f"/api/targets/{tid}/export/subdomains.csv")
        assert r.status_code == 200
        assert "api.adjust.com" in r.text

        r = client.get(f"/api/targets/{tid}/master/adjust.com_subdomains.txt")
        assert r.status_code == 200
        assert "cdn.adjust.com" in r.text
