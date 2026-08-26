# Security policy

Never commit Kong Admin credentials, database passwords, object-storage keys,
private keys, live certificates, consumer credentials, API keys, bearer tokens,
cookies, database data, backup archives, or runtime logs.

Public routes must bind exact hosts, methods, paths, protocols, services,
upstreams, plugin names, and plugin configurations. Name-only allowlists and
credential-bearing exports are prohibited.
