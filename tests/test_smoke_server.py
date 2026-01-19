"""Smoke test for the FastMCP resource registry."""

from mcp_scansage.mcp import server


def test_server_exposes_health_resource() -> None:
    """Registry must contain the health resource and publish a status."""

    assert "health" in server.RESOURCE_REGISTRY
    health = server.RESOURCE_REGISTRY["health"]
    response = health()

    assert response["status"] == "ok"
    assert "ScanSage" in response["detail"]
