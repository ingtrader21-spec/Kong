# Gateway network plan

Only host Caddy publishes 80/443; approved SSH remains with the host authority.
Kong proxy, Admin, Manager, cluster, PostgreSQL, Redis and application ports are
never published by either topology. `network-boundaries.yaml` lists exact external
network names and requires every Docker dependency network to be internal.

The private upstream gateway bridges the approved Caddy path to `kong_proxy`.
Hybrid DPs join proxy, cluster, rate-limit, observability and Middleware networks.
They have no database network, PostgreSQL credential or Admin listener. The CP
joins cluster, Admin, database and observability networks and has no proxy listener.
CP/DP traffic is mutually authenticated with private PKI and exact SNI.

Traditional proxy nodes join the dedicated database as required by that topology.
A separate management node alone enables Admin on container loopback and has no
proxy network. The private balancer targets both proxy nodes. Database, Redis,
upstream and backup network membership must be verified against the existing
authorities before runtime admission; source declarations do not prove live state.
