from __future__ import annotations
import copy,importlib.util,json
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("mcr",ROOT/"scripts/validate_kong_mcr_routes.py")
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
BASE=json.loads((ROOT/"config/kong-mcr-routes.v1.json").read_text())

def test_contract_passes(): mod.validate(copy.deepcopy(BASE))
def test_execute_activation_fails():
 d=copy.deepcopy(BASE);d["productionEffectsAuthorized"]=True
 with pytest.raises(ValueError,match="production effects"): mod.validate(d)
def test_direct_provider_upstream_fails():
 d=copy.deepcopy(BASE);d["routes"][0]["serviceHost"]="klyrow"
 with pytest.raises(ValueError,match="direct provider"): mod.validate(d)
def test_delivery_signature_header_removal_fails():
 d=copy.deepcopy(BASE);r=next(x for x in d["routes"] if x["pathTemplate"]=="/platform/v1/delivery-events");r["requiredHeaders"].remove("X-Codestra-Signature")
 with pytest.raises(ValueError,match="headers"): mod.validate(d)
def test_authorization_strip_fails():
 d=copy.deepcopy(BASE);d["headerPolicy"]["authorization"]="strip"
 with pytest.raises(ValueError,match="Authorization"): mod.validate(d)
def test_route_loss_fails():
 d=copy.deepcopy(BASE);d["routes"]=d["routes"][:-1]
 with pytest.raises(ValueError,match="route set"): mod.validate(d)
