from pathlib import Path

CONFIG = Path('config/marketing-stage4-routes.yaml')
REQUIRED = ['/v1/marketing', '/v1/ai', '/v1/communications', '/v1/social']
REQUIRED_SERVICES = ['codestra-marketing', 'codestra-ai', 'codestra-communication', 'codestra-social']


def main() -> None:
    text = CONFIG.read_text(encoding='utf-8')
    lower = text.lower()
    for route in REQUIRED:
        assert route in text, f'missing_route:{route}'
    for service in REQUIRED_SERVICES:
        assert f'name: {service}' in text, f'missing_service:{service}'
    assert lower.count('name: correlation-id') >= 4, 'correlation_id_plugin_required_per_service'
    assert 'admin_listen' not in lower and 'admin_gui' not in lower, 'admin_api_must_not_be_exposed_by_fragment'
    assert 'production_apply: true' not in lower
    assert '0.0.0.0:8001' not in lower
    assert 'promotion requirement' in lower and ('oidc' in lower or 'jwt' in lower), 'auth_promotion_gate_required'
    assert 'rate limit' in lower, 'rate_limit_promotion_gate_required'
    assert 'rollback' in lower, 'rollback_promotion_gate_required'
    print('MARKETING_EDGE_STAGE5_CERTIFICATION=PASS')


if __name__ == '__main__':
    main()
