#!/usr/bin/env python3
from __future__ import annotations
import json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/"config/kong-mcr-routes.v1.json"
EXPECTED={
 ("POST","/platform/v1/campaign-engine/plan"):"campaign.engine.plan",
 ("POST","/platform/v1/campaign-engine/execute"):"campaign.engine.execute",
 ("GET","/platform/v1/leads/{lead_id}/journey"):"leads.journey.read",
 ("GET","/platform/v1/leads/{lead_id}/next-action"):"campaign.engine.read",
 ("GET","/platform/v1/campaigns/{campaign_id}/eligible-leads"):"campaign.engine.read",
 ("POST","/platform/v1/delivery-events"):"campaign.delivery_events.publish",
 ("POST","/platform/v1/suppressions"):"campaign.suppressions.write",
 ("GET","/platform/v1/campaign-engine/status"):"campaign.engine.read",
}
WRITE_HEADERS={
 "/platform/v1/campaign-engine/execute":{"Idempotency-Key"},
 "/platform/v1/delivery-events":{"Idempotency-Key","X-Codestra-Event-ID","X-Codestra-Timestamp","X-Codestra-Signature"},
 "/platform/v1/suppressions":{"Idempotency-Key"},
}
PLUGINS={"openid-connect","post-function","correlation-id","rate-limiting","request-size-limiting"}

def validate(data):
    if data.get("schema")!="codestra.kong.mcr-routes.v1": raise ValueError("schema drift")
    if data.get("runtimeApplyAuthorized") is not False: raise ValueError("runtime apply must remain disabled")
    if data.get("productionEffectsAuthorized") is not False: raise ValueError("production effects must remain disabled")
    svc=data.get("service",{})
    if (svc.get("host"),svc.get("port")) != ("middleware-integration-api",8095):
        raise ValueError("MCR must route only to canonical Middleware :8095")
    boundary=data["routingBoundary"]
    if not all(boundary[k] is True for k in ("directProviderRoutingForbidden","directPublicMiddlewareExposureForbidden","internalAndMetricsPublicForbidden")):
        raise ValueError("routing boundary weakened")
    if data["headerPolicy"].get("authorization")!="preserve":
        raise ValueError("Authorization must be preserved")
    got={}
    for route in data.get("routes",[]):
        key=(route["method"],route["pathTemplate"])
        if key in got: raise ValueError("duplicate MCR route")
        got[key]=route["requiredScope"]
        if (route["serviceHost"],route["servicePort"]) != ("middleware-integration-api",8095):
            raise ValueError("direct provider/noncanonical upstream")
        if route["stripPath"] is not False or route["preserveHost"] is not True:
            raise ValueError("path/host forwarding drift")
        if set(route["requiredPlugins"]) != PLUGINS:
            raise ValueError("plugin chain drift")
        headers=set(route["requiredHeaders"])
        if not {"X-Tenant-ID","X-Correlation-ID"} <= headers:
            raise ValueError("required MCR request context missing")
        if not WRITE_HEADERS.get(route["pathTemplate"],set()) <= headers:
            raise ValueError("write/signature headers missing")
        if "/internal" in route["pathTemplate"] or "/metrics" in route["pathTemplate"]:
            raise ValueError("internal route exposure")
    if got != EXPECTED: raise ValueError(f"MCR route set drift: {got}")
    execute=next(r for r in data["routes"] if r["pathTemplate"]=="/platform/v1/campaign-engine/execute")
    if execute["effects"]!="hard_denied_by_middleware":
        raise ValueError("execute boundary must remain hard denied")

def main():
    validate(json.loads(PATH.read_text()))
    print("KONG_MCR_ROUTE_CONTRACT=PASS")
    print("MCR_ROUTE_COUNT=8")
    print("MCR_PRODUCTION_EFFECTS_AUTHORIZED=false")
    return 0
if __name__=="__main__": raise SystemExit(main())
