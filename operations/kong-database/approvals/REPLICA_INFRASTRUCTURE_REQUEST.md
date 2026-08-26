# Independent Kong PostgreSQL replica request

Requested decision: allocate and approve a host outside the primary physical
failure domain.

Minimum: PostgreSQL 17.11 support; 4 vCPU; 8 GiB RAM; 150 GiB persistent SSD/NVMe
with expansion path; private primary connectivity; TLS identity; monitoring and
off-host backup egress; provider/network fencing; no public PostgreSQL listener.

```text
REPLICA_HOST=PENDING
PRIVATE_IP=PENDING
PRIVATE_CIDR=PENDING
PROVIDER=PENDING
REGION=PENDING
FAILURE_DOMAIN=PENDING
CPU=PENDING
RAM=PENDING
STORAGE=PENDING
NETWORK_PATH=PENDING
TLS_IDENTITY=PENDING
FENCING_INTERFACE=PENDING
PUBLIC_DB_PORTS=0
```

Acceptance commands after allocation (never include credentials):

```bash
hostnamectl
nproc
free -h
df -hT
ip -brief address
getent hosts kong-db.internal.codestra.agency
ss -lnt
openssl s_client -connect <private-primary>:5432 -starttls postgres -verify_return_error
pg_isready -h <private-primary> -p 5432
```

Then verify `pg_is_in_recovery()=true`, read-only mode, streaming WAL receiver,
active physical slot, private-only reachability, certificate SAN/expiry, and
independent failure-domain evidence. Allocation is rejected if co-located with
the primary or lacking enforceable fencing.
