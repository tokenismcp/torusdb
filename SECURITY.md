# Security Policy

## Reporting a vulnerability

Email **jlabsrd@gmail.com** with the subject `TorusDB security` (PGP on request).
Please include the affected component and version, a reproduction, and the impact
you believe it has. Do not open a public issue for an undisclosed vulnerability.

We aim to acknowledge within **3 business days**, to give an initial assessment
within **10 business days**, and to ship a fix or mitigation for confirmed
high-severity issues within **90 days**, crediting the reporter unless asked not to.

## Scope

In scope: the dialect/validator, drivers, server, wire protocol, vault log, and
the documented cryptographic guarantees (confidentiality of `ENC`/`PAIRED`
columns at the server; integrity in authenticated mode; vault sealing).

Out of scope (documented limitations, not vulnerabilities): metadata visible to
the server (PLAIN columns, schema, row counts, access patterns, join keys, timing);
lack of integrity checking when `authenticated=False`; denial of service by an
authenticated admin; physical side channels. See `docs/threat-model.md`.

## Supported versions

Only the latest minor release receives security fixes while the project is
pre-1.0.

## Cryptographic status

The design has had internal review and an internal audit
(`docs/crypto-review-packet.md` §11). **It has not been independently audited.**
We welcome and will credit external review; the review packet lists the specific
questions we want answered.
