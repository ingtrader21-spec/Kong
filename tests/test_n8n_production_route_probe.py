from scripts import probe_n8n_production_routes as probe


def test_probe_uses_exact_registered_endpoint_shapes():
    assert probe.PROBES == (
        ("POST", "/v1/integrations/n8n/commands"),
        ("GET", "/v1/integrations/n8n/operations/00000000-0000-0000-0000-000000000000"),
    )
    assert all("vicidial" not in path for _, path in probe.PROBES)


def test_framework_404_is_blocking_but_domain_not_found_is_reachable():
    assert probe.is_framework_404(404, '{"detail":"Not Found"}') is True
    assert probe.is_framework_404(404, '{"message":"no Route matched with those values"}') is True
    assert probe.is_framework_404(404, '{"error":{"code":"command_not_found"}}') is False
    assert probe.is_framework_404(401, '{"detail":"Not Found"}') is False
