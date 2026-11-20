# firewalla-msp-broker

Fine-grained access control for the Firewalla MSP API. One upstream token in, many scoped keys out: per-box (or box-group) scope, per-resource read/write permissions, an audit trail with recorded previous values and reversion, key expiry, IP allowlists and rotation windows. Built for AI agents and scripts that should not hold a Full Access token.

> **Disclaimer:** this is an independent community project. It is not affiliated with, endorsed by or supported by Firewalla Inc. "Firewalla" is a trademark of Firewalla Inc., used here only to describe what the software works with.

The binary, Docker image and command are called `mspbroker`.

Status: pre-alpha, under construction. See [docs/SPEC.md](docs/SPEC.md). Milestone 1 (read path and plumbing) is what runs today: a read-only data API with scoped keys, an admin API to create, list and edit keys, and the audit log. Writes, key rotation, the CLI and the container image come in later milestones.

## Run it locally against the mock

No MSP account and no Docker needed. You need Go 1.27 and `curl`. Everything below uses placeholder data: the mock serves five fake boxes in two groups, and nothing leaves your machine.

Build once:

```sh
go build -o mspbroker ./cmd/mspbroker
```

**1. Start the mock upstream** (the stand-in for the MSP API). It listens on `127.0.0.1:8099` and prints the placeholder token it accepts:

```sh
./mspbroker mock-upstream
```

**2. In a second terminal, start the broker** against it:

```sh
export MSP_BASE_URL=http://127.0.0.1:8099
export MSP_TOKEN=mock-upstream-token-example
export DATA_DIR=./data
export LISTEN_ADDR=127.0.0.1:8080
./mspbroker serve --check     # validates the config and reaches the upstream, then exits
./mspbroker serve
```

On the very first start the broker creates an admin key named `bootstrap` and logs its secret **once**:

```
level=WARN msg="bootstrap admin key created; this secret is shown once and cannot be recovered" ... secret=mb_...
```

Copy it now. To have it written to `$DATA_DIR/bootstrap-admin-secret` (mode 0600) instead, start with `BOOTSTRAP_SECRET_FILE=true`. The documented first step in a real install is to create a named admin key and disable `bootstrap`.

**3. Create a key** for an agent: read access to alarms and boxes, on box `…0001` only. The reply contains the key's `secret`, again shown only once.

```sh
export ADMIN=mb_...       # the bootstrap secret
curl -s -X POST http://127.0.0.1:8080/admin/v1/keys \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"demo-agent","kind":"data",
       "scope":{"type":"boxes","gids":["00000000-0000-0000-0000-000000000001"]},
       "permissions":{"boxes":"read","alarms":"read"}}'
```

Scope can also be `{"type":"all"}` (including boxes added later), `{"type":"groups","group_ids":["group-a"]}` or both lists with `"boxes+groups"`. The mock has the groups `group-a` and `group-b`.

**4. Call the data API with the new key:**

```sh
export KEY=mb_...         # the secret from the previous reply
curl -s http://127.0.0.1:8080/api/v1/me -H "Authorization: Bearer $KEY"
curl -s http://127.0.0.1:8080/api/v1/alarms -H "Authorization: Bearer $KEY"
```

`/api/v1/me` tells the key what it may do. Anything outside it is refused with a reason code (`out_of_scope`, `permission`, `kind`, ...):

```sh
curl -s http://127.0.0.1:8080/api/v1/boxes/00000000-0000-0000-0000-000000000002/alarms -H "Authorization: Bearer $KEY"
# {"error":"forbidden","code":"out_of_scope","detail":"box 00000000-0000-0000-0000-000000000002 is not in this key's scope"}
```

Every API request, allowed or refused, is in the audit log, which the admin key can read:

```sh
curl -s "http://127.0.0.1:8080/admin/v1/audit?limit=5" -H "Authorization: Bearer $ADMIN"
```

Other things to look at: `GET /api/openapi.json` (the full API description, no key needed), `GET /healthz` and `GET /readyz`. Stop either process with Ctrl-C; the broker finishes requests in flight first. To see the post-filter earn its keep, restart the mock as `./mspbroker mock-upstream --ignore-filters` (it then ignores every filter and returns everything) and repeat step 4: the key still sees only its own box.

Configuration is by environment variable; see [docs/SPEC.md](docs/SPEC.md) section 12 and `docs/DECISIONS.md` for the choices made where the spec is silent.

## License

GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE).
