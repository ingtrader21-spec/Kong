# Telephony safety and Kong canary authority request

Requested decision: authorize only the existing restricted operator's sanitized,
read-only Asterisk safety action and, after safe results, one narrow authenticated
Kong canary. This is not dialing approval.

Required sanitized output:

```text
TELEPHONY_PROBE=PASS
ACTIVE_CALLS=<integer>
ACTIVE_CHANNELS=<integer>
ACTIVE_BRIDGES=<integer>
PJSIP_CONTACTS=<integer>
PJSIP_ENDPOINTS=<integer>
PJSIP_REGISTRATIONS=<sanitized integer/classification>
OPERATOR_ACTIVATION_SAFE=YES/NO
```

Canary prerequisites are `ACTIVE_CALLS=0`, `ACTIVE_CHANNELS=0`, probe PASS,
fail-closed safety flags, monitoring PASS, and an accountable telephony operator
approval. The canary remains authenticated, rate-limited, request-ID enabled,
audited, harmless, and immediately reversible.

Explicitly prohibited: broad root shell, unrestricted Asterisk CLI, dialing,
channel manipulation, SIP credential disclosure, caller PII, or overriding
operator evidence. Any nonzero/unknown activity preserves maintenance mode.
