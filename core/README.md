<p align="center"><img src="https://raw.githubusercontent.com/tokenismcp/torusdb/main/assets/logo-128.png" alt="TorusDB" width="96"></p>

# torusdb-core

The keyless engine of [TorusDB](https://torusdb.io): SQL planner, the owner-side
blinding client (`NoKeyClient`), the keyless server-side store (`NoKeyServer`) and
the no-key delegation primitives (`torusdb_core.protocol`: encode/decode,
Π_lin, Π_mult with Beaver triples). Pure Python, Apache-2.0, depends only on
`torussql-parser`.

You normally install `torussql` (driver) or `torusdb-server`, which depend on this.

The server side never holds a key or a mask; see
[`docs/threat-model.md`](../docs/threat-model.md). Not externally audited.
