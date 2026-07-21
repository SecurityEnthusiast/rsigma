# TAXII live integration harness

Wiremock tests (`tests/taxii_client.rs`, **58** tests) cover HTTP semantics on plain HTTP.  
This directory is **optional infrastructure** for you to run **real TLS / mTLS / DNS SRV** on a machine with Docker.

**Honest scope:** what exists today vs what you must run manually.

| Item | Status |
| ---- | ------ |
| Docker Compose (Wiremock + Caddy + CoreDNS) | **Present** in this directory |
| `generate-certs.sh` (CA, server, client PEM) | **Present** |
| Rust live tests (`tests/taxii_live.rs`) | **3 tests**, all `#[ignore]`, gated on `RSTIX_TAXII_LIVE=1` |
| `live_https_discovery_over_tls` | **Coded** — HTTPS GET `/taxii2/` via SPKI pin |
| `live_mtls_discovery` | **Coded** — HTTPS on `:8444` with client cert |
| `live_discover_via_srv` | **Coded but soft** — prints skip message on DNS failure; does **not** fail the test |
| TLS 1.3 proof in Rust | **Not coded** — use `openssl s_client` manually (below) |
| DANE live test | **Not coded** — library has `ServerTrustPolicy::Dane` + `resolve_tlsa`; no live test or TLSA in zone |
| `TaxiiClientConfig::dns_nameserver()` | **Not coded** — SRV needs OS resolver split or manual `dig` |
| PKCS#12 live test | **Not coded** — PEM only in live tests |
| Run in default CI | **No** |

---

## Prerequisites (VM or laptop)

- Docker + Compose v2
- OpenSSL CLI
- Rust toolchain (same as workspace; run tests from **repo root**)
- Optional: `dig` for manual DNS checks

Everything is designed to run on **one machine** with client + Docker on the same host (`127.0.0.1`). A different VM IP only matters if the client runs on a **different** machine than Docker (see end).

---

## Quick start — Phase 1 (TLS)

```bash
# From repo root
cd crates/rstix/tests/taxii-live
./generate-certs.sh
docker compose up -d --wait

# Back to repo root
cd ../../../../..

export RSTIX_TAXII_LIVE=1
export RSTIX_TAXII_LIVE_BASE_URL=https://127.0.0.1:8443
# Optional override (default shown):
# export RSTIX_TAXII_LIVE_SERVER_CERT=crates/rstix/tests/taxii-live/fixtures/certs/server.pem

cargo test -p rstix --features taxii --test taxii_live live_https_discovery_over_tls -- --ignored --nocapture
```

**What this proves if it passes:** rustls HTTPS to Caddy, TAXII discovery JSON parsed. Trust is **SPKI pin from server.pem**, not Web PKI.

**TLS 1.3:** Not asserted by the Rust test. Confirm manually:

```bash
openssl s_client -connect 127.0.0.1:8443 -tls1_3 \
  -CAfile crates/rstix/tests/taxii-live/fixtures/certs/ca.pem </dev/null 2>&1 | head -5
```

The **library** enables TLS 1.2 and 1.3 in `build_rustls_config()`; Caddy negotiates the highest mutual version.

---

## Phase 3 — mTLS

```bash
export RSTIX_TAXII_LIVE=1
export RSTIX_TAXII_LIVE_MTLS_URL=https://127.0.0.1:8444
export RSTIX_TAXII_LIVE_CLIENT_CERT=crates/rstix/tests/taxii-live/fixtures/certs/client.pem
export RSTIX_TAXII_LIVE_CLIENT_KEY=crates/rstix/tests/taxii-live/fixtures/certs/client-key.pem
export RSTIX_TAXII_LIVE_SERVER_CERT=crates/rstix/tests/taxii-live/fixtures/certs/server.pem

cargo test -p rstix --features taxii --test taxii_live live_mtls_discovery -- --ignored --nocapture
```

**Not covered here:** PKCS#12 (needs `taxii-native-tls` feature + separate setup).

---

## Phase 2 — DNS SRV (manual / fragile)

CoreDNS in Compose listens on host **127.0.0.1:5353**. The client uses the **system resolver**, not that port directly.

1. Check records manually:

```bash
dig @127.0.0.1 -p 5353 _taxii2._tcp.taxii.test SRV +short
```

2. Configure the OS so `taxii.test` queries `127.0.0.1:5353` (macOS: `/etc/resolver/taxii.test`; Linux: systemd-resolved or dnsmasq — OS-specific).

3. Run (may **pass without asserting** if DNS fails):

```bash
export RSTIX_TAXII_LIVE=1
export RSTIX_TAXII_LIVE_SRV_DOMAIN=taxii.test
export RSTIX_TAXII_LIVE_SERVER_CERT=crates/rstix/tests/taxii-live/fixtures/certs/server.pem

cargo test -p rstix --features taxii --test taxii_live live_discover_via_srv -- --ignored --nocapture
```

Read stderr: if resolver is wrong, the test **prints a skip message and still passes**. Treat manual `dig` as the real gate until resolver wiring or `dns_nameserver()` exists.

---

## Phase 4 — DANE

**Not implemented** in this harness (no DNSSEC zone, no TLSA records, no live test). Library code exists (`ServerTrustPolicy::Dane`, `resolve_tlsa`); validating it live is future work.

---

## Environment variables (actually read by `taxii_live.rs`)

| Variable | Used by tests | Notes |
| -------- | ------------- | ----- |
| `RSTIX_TAXII_LIVE` | all | Must be `1` |
| `RSTIX_TAXII_LIVE_BASE_URL` | Phase 1 | e.g. `https://127.0.0.1:8443` |
| `RSTIX_TAXII_LIVE_SERVER_CERT` | all | Default: `crates/rstix/tests/taxii-live/fixtures/certs/server.pem` |
| `RSTIX_TAXII_LIVE_MTLS_URL` | Phase 3 | Default: `https://127.0.0.1:8444` |
| `RSTIX_TAXII_LIVE_CLIENT_CERT` | Phase 3 | Required for mTLS test |
| `RSTIX_TAXII_LIVE_CLIENT_KEY` | Phase 3 | Required for mTLS test |
| `RSTIX_TAXII_LIVE_SRV_DOMAIN` | Phase 2 | Default: `taxii.test` |

Variables **not** read by current live tests: `RSTIX_TAXII_LIVE_CA`, `RSTIX_TAXII_LIVE_DNS`, `RSTIX_TAXII_LIVE_TLSA`.

---

## Stop stack

```bash
cd crates/rstix/tests/taxii-live
docker compose down
```

Regenerate certs: `rm -rf fixtures/certs && ./generate-certs.sh`

---

## Copy to VM (git Option A)

On your dev machine: **commit and push** the branch (live files are uncommitted until you commit).

On VM:

```bash
git clone <repo-url> rsigma && cd rsigma
git checkout feat/rstix-taxii-client
```

Then run Phase 1 steps on the VM. Regenerate certs on the VM; do not copy `fixtures/certs/` from another host.

If client and Docker are on the **same VM**, keep `127.0.0.1`. If Docker is on the VM but you run tests from **another** host, change `RSTIX_TAXII_LIVE_BASE_URL` to `https://<VM_IP>:8443`, update firewall, and adjust `coredns/taxii.test.zone` + cert SANs — that path is not automated.

---

## Before pushing to VM — tests required?

| Test | Required before push? |
| ---- | --------------------- |
| `cargo test -p rstix --features taxii --test taxii_client` (58 wiremock tests) | **Yes** — confirms library on plain HTTP |
| `cargo clippy -p rstix --all-targets --features taxii -- -D warnings` | Recommended |
| Live tests on dev machine | **No** — purpose of VM run |
| Live tests passing on VM | **Yes** — that is your validation of Phases 1–3 |
