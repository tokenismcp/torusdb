<p align="center"><img src="https://raw.githubusercontent.com/tokenismcp/torusdb/main/assets/logo-128.png" alt="TorusDB" width="96"></p>

# torusdb-server

The **keyless** TorusDB server. It stores schema, plaintext columns and
one-time-padded scalars, evaluates affine aggregates (Π_lin) and multiplication
openings (Π_mult) on blinded values, and **never holds a key or a mask** — a full
breach of this process (memory, disk, backups) reveals nothing about encrypted
columns (I(M;V_S)=0).

```bash
torusdb-server --db /var/lib/torusdb/main.db --token-file /etc/torusdb/tokens \
    --tls --cert server.crt --key server.key --metrics-port 9433
```

See `docs/ops-guide.md` in the repository for authentication roles,
transactions, durability (snapshot + journal), backups, metrics and hardening.
