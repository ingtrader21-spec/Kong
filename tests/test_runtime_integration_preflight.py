import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_runtime_integration.py"


def module():
    spec = importlib.util.spec_from_file_location("runtime_preflight", SCRIPT)
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def fixture(networks, healthy=True):
    return {
        "State": {"Running": True, "Paused": False, "Restarting": False,
                  "Health": {"Status": "healthy" if healthy else "unhealthy"}},
        "NetworkSettings": {"Networks": {name: {} for name in networks}},
    }


def test_helpers_require_running_healthy_container_and_exact_networks():
    preflight = module()
    container = fixture(["codestra_edge", "codestra_backend"])
    assert preflight.healthy(container)
    assert preflight.networks(container) == {"codestra_edge", "codestra_backend"}
    assert not preflight.healthy(fixture(["codestra_edge"], healthy=False))


def test_compose_places_kong_on_redis_backend():
    source = (ROOT / "deploy/kong/compose.kong.yaml").read_text()
    assert "codestra_backend: {}" in source
    assert "name: codestra_backend" in source


def test_script_never_reads_or_prints_container_environment():
    source = SCRIPT.read_text()
    assert 'Config"]["Env' not in source
    assert "docker exec" not in source
    assert "password" not in source.lower()


def test_each_hop_requires_its_designated_network():
    source = SCRIPT.read_text()
    assert '("caddy", "kong", "codestra_edge")' in source
    assert '("kong", "redis", "codestra_backend")' in source
    assert "required_network in networks" in source


class RuntimeReadinessTests(unittest.TestCase):
    def run_preflight(self, preflight, readback, args=()):
        output = io.StringIO()
        with patch.object(preflight, "inspect", side_effect=readback) as reader, \
                patch("sys.argv", [str(SCRIPT), *args]), contextlib.redirect_stdout(output):
            code = preflight.main()
        return code, output.getvalue(), reader

    def test_default_requires_appolon_without_legacy_fallback(self):
        preflight = module()
        self.assertEqual(preflight.DEFAULTS["middleware"],
                         "codestra-appolon-middleware-integration-api-1")
        def readback(name):
            if name == "codestra-appolon-middleware-integration-api-1":
                raise RuntimeError("private diagnostic must not be printed")
            return fixture(["codestra_edge", "codestra_backend"])
        code, output, reader = self.run_preflight(preflight, readback)
        self.assertEqual(code, 2)
        self.assertEqual(output, "RUNTIME_INTEGRATION=FAIL reason=middleware_container_readback_unavailable\n")
        self.assertNotIn("codestra-middleware-integration-api-1",
                         [call.args[0] for call in reader.call_args_list])

    def test_healthy_appolon_topology_passes(self):
        preflight = module()
        code, output, reader = self.run_preflight(
            preflight, lambda _: fixture(["codestra_edge", "codestra_backend"]))
        self.assertEqual((code, output), (0, "RUNTIME_INTEGRATION=PASS\n"))
        self.assertIn("codestra-appolon-middleware-integration-api-1",
                      [call.args[0] for call in reader.call_args_list])

    def test_explicit_middleware_override_is_preserved(self):
        preflight = module()
        code, _, reader = self.run_preflight(
            preflight, lambda _: fixture(["codestra_edge", "codestra_backend"]),
            ["--middleware", "isolated-appolon-api"])
        self.assertEqual(code, 0)
        self.assertIn("isolated-appolon-api", [call.args[0] for call in reader.call_args_list])

    def test_paused_restarting_or_unknown_state_is_not_healthy(self):
        preflight = module()
        for field in ("Paused", "Restarting"):
            for value in (True, None, "false", 0):
                with self.subTest(field=field, value=value):
                    container = fixture(["codestra_edge", "codestra_backend"])
                    container["State"][field] = value
                    self.assertFalse(preflight.healthy(container))
            container = fixture(["codestra_edge", "codestra_backend"])
            del container["State"][field]
            self.assertFalse(preflight.healthy(container))

    def test_paused_gateway_cannot_pass_main(self):
        preflight = module()
        def readback(name):
            container = fixture(["codestra_edge", "codestra_backend"])
            container["State"]["Paused"] = name == preflight.DEFAULTS["kong"]
            return container
        code, output, _ = self.run_preflight(preflight, readback)
        self.assertEqual(code, 2)
        self.assertIn("kong_not_healthy", output)

    def test_each_missing_designated_hop_fails(self):
        preflight = module()
        cases = (("caddy", "codestra_edge", "caddy_kong"),
                 ("middleware", "codestra_edge", "kong_middleware"),
                 ("kong", "codestra_backend", "kong_redis"),
                 ("middleware", "codestra_backend", "middleware_redis"))
        for role, network, label in cases:
            with self.subTest(hop=label):
                def readback(name):
                    container = fixture(["codestra_edge", "codestra_backend"])
                    if name == preflight.DEFAULTS[role]:
                        del container["NetworkSettings"]["Networks"][network]
                    return container
                code, output, _ = self.run_preflight(preflight, readback)
                self.assertEqual(code, 2)
                self.assertIn(label + "_missing_" + network, output)

    def test_arbitrary_shared_network_does_not_substitute_for_required_networks(self):
        preflight = module()
        code, output, _ = self.run_preflight(preflight, lambda _: fixture(["shared-other"]))
        self.assertEqual(code, 2)
        self.assertEqual(output.count("_missing_"), 4)

    def test_malformed_docker_shape_is_reported_without_traceback(self):
        preflight = module()
        for value in ({}, {"State": [], "NetworkSettings": {}},
                      {"State": {}, "NetworkSettings": {"Networks": []}},
                      {"State": {"Health": []}, "NetworkSettings": {"Networks": {}}}):
            with self.subTest(value=value):
                result = subprocess.CompletedProcess([], 0, json.dumps(value), "")
                output = io.StringIO()
                with patch.object(preflight.subprocess, "run", return_value=result), \
                        patch("sys.argv", [str(SCRIPT)]), contextlib.redirect_stdout(output):
                    self.assertEqual(preflight.main(), 2)
                self.assertEqual(output.getvalue(),
                                 "RUNTIME_INTEGRATION=FAIL reason=caddy_container_readback_unavailable\n")

    def test_docker_daemon_is_local_and_only_selected_metadata_is_requested(self):
        preflight = module()
        result = subprocess.CompletedProcess([], 0, json.dumps(fixture(["codestra_edge"])), "")
        with patch.object(preflight.subprocess, "run", return_value=result) as command:
            preflight.inspect("isolated-appolon-api")
        argv = command.call_args.args[0]
        self.assertEqual(argv[:4], ["docker", "--host", "unix:///var/run/docker.sock", "inspect"])
        self.assertEqual(argv[-1], "isolated-appolon-api")
        self.assertNotIn(".Config", argv[-2])
        self.assertEqual(command.call_args.kwargs["timeout"], 10)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RuntimeReadinessTests)
    for name, test in list(globals().items()):
        if name.startswith("test_") and callable(test):
            suite.addTest(unittest.FunctionTestCase(test))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
