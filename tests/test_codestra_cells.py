from pathlib import Path
import importlib.util


def _module():
    script = Path(__file__).resolve().parents[1] / "scripts" / "validate_codestra_cells.py"
    spec = importlib.util.spec_from_file_location("validate_codestra_cells", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cell_platform_contract_is_valid():
    _module().validate()


def test_all_effect_capabilities_are_disabled():
    module = _module()
    cells = module.load("codestra-kong-cells.v1.json")
    assert cells["capabilities"]
    assert not any(cells["capabilities"].values())


def test_all_routes_target_middleware():
    module = _module()
    routes = module.load("codestra-kong-route-registry.v1.json")
    assert all(route["upstream"].startswith("middleware-") for route in routes["routes"])
