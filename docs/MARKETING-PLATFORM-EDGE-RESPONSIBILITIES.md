# Kong — Marketing Platform Edge Responsibilities

Kong is the API gateway for the Codestra marketing platform. Its role is to provide a consistent entry point, route requests to the correct owning service, enforce approved access policy, apply traffic controls, propagate request identifiers, and provide gateway-level observability.

Business logic stays in the owning services. Marketing owns campaign state, Communication owns customer messaging policy, Social owns the enterprise social API, AI owns shared AI capabilities, Middleware owns durable integrations, Odoo owns CRM records, and Keycloak owns identity.

The gateway configuration should maintain explicit service mappings for Marketing, Communication, Social, AI and Middleware. The canonical Communication edge route is `/v1/communications/*`. Changes should be validated first outside production, including expected success responses, denied-access behavior, unavailable-upstream behavior and rollback readiness.

Certification is read-only and must never commit to the PR branch. Governed migration manifest synchronization is a separate, manifest-only automation step; certification fails closed if committed manifests do not match the reviewed source tree.

Production gateway changes must be version-controlled and reviewed. A route should not be promoted until the corresponding upstream service contract exists and has been validated in the target environment.
