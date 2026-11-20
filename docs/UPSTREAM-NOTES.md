# Upstream notes (MSP API)

Status: M1, written without access to the public documentation. **Nothing was browsed and nothing was probed live** (no Firewalla or MSP host was contacted; all code runs against the project's own mock). Every statement below carries one of three labels:

| Label | Meaning |
|---|---|
| `VERIFIED-FROM-DOCS` | Read in the public documentation by the person recording it, with a date and page. **No entry in this file has this label yet.** |
| `PER-SPEC` | "Per SPEC, from docs, not re-verified": SPEC.md §5 says the public docs show this. It is a claim copied from the SPEC text, not something re-checked here. |
| `UNKNOWN` | Not known. May include a hypothesis; a hypothesis is a thing to test, not evidence. |

The SPEC itself says (§5) the docs "may lag the product" and that statements must be re-verified at build time. The first item of the real-account integration (SPEC §15, Read Only token, never from the development environment) is to turn each `PER-SPEC` and `UNKNOWN` below into `VERIFIED-FROM-DOCS` or `VERIFIED-BY-PROBE` and date it.

How the code treats each unknown is in the last column of the summary and in the per-item "Code today" lines. The rule throughout: where the shape or behaviour is unknown, the client is tolerant of the plausible variants and the broker does not depend on the answer for safety, because the post-filter on `gid`/`owner` is the control (SPEC §5.2).

## Summary

| # | SPEC §5 unknown | State | What the code assumes |
|---|---|---|---|
| 1 | `stats` / `trends` paths | `PER-SPEC` for the prefixes, `UNKNOWN` for everything after them | client takes a plain-identifier name, passes params through, returns raw JSON |
| 2 | `stats` / `trends` accept box filters | `UNKNOWN` | none; broker must post-filter if rows carry a gid, otherwise treat as all-boxes data and require `all` scope |
| 3 | Rate limits and their error shape | `UNKNOWN` (SPEC says only that a 429 passthrough is expected) | typed `*Error` with status and `Retry-After`; body parsed best-effort |
| 4 | `archive` can be undone | `UNKNOWN` | revert matrix stays `revertible: false` (SPEC §9 default) |
| 5 | `GET /v2/boxes` `group` field | `PER-SPEC` that the field exists; encoding `UNKNOWN` | string id, or object with `id`; null/absent = no group |
| 6 | Groups listing endpoint | `UNKNOWN` | none exists; groups are derived from the box list |
| 7 | Auth scheme word | `UNKNOWN` | `Bearer`, configurable |
| 8 | List response envelope | `UNKNOWN` | bare array or `{count, results, next_cursor}`; both decoded |
| 9 | Multi-value filters and multi-box query syntax | `UNKNOWN` | see item 9; the broker's post-filter makes a wrong guess harmless |

## 1. Statistics and trends: paths

- `PER-SPEC`: SPEC §5 table lists `GET /v2/stats/...` and `GET /v2/trends/...` "per docs; probe exact shapes", no write operations, box id in path "varies".
- `UNKNOWN`: the names after the prefix, the query parameters, the response shape.
- Hypothesis only (unverified recollection, not evidence, to be tested first): stats names such as `topBoxesByBlockedFlows`, `topBoxesBySecurityAlarms`, `topRegionsByBlockedFlows`; trends names `flows`, `alarms`, `rules`.
- Code today: `upstream.Client.Stats(ctx, name, params)` and `Trends(...)` take any identifier matching `[A-Za-z][A-Za-z0-9_-]{0,63}` and return the body undecoded. The mock implements `topBoxesByBlockedFlows`, `topBoxesBySecurityAlarms` (stats) and `flows`, `alarms`, `rules` (trends) with **mock-only shapes** (arrays of rows with `gid`); they exist so the broker's handling can be tested, not to describe the service. Any other name is a 404 in the mock.

## 2. Statistics and trends: box filter support

- `UNKNOWN`: whether they accept `box=`, `group=`, `query=box.id:` or nothing, and whether rows carry a `gid`.
- Consequence for the broker: if a response is not per-box rows with a `gid`, it cannot be post-filtered and therefore cannot be served to a key whose scope is narrower than the data. Until probed, the safe default (a recommendation for card 3, not implemented here) is: the `stats` permission is served only when the response can be proven to respect the key's scope, otherwise 403 `out_of_scope`.
- Code today: the mock honours `box=` and `group=` on stats and trends and ignores them under the ignore-filters switch. That is the mock's choice.

## 3. Rate limits and error shape

- `PER-SPEC`: SPEC §7 says upstream `429`s are passed through unchanged and audited. Nothing in the SPEC states the limit values or the body.
- `UNKNOWN`: the limits (per second/minute/day, per token or per box), whether `Retry-After` is sent, the error body shape (including for 400/401/403/404), whether the 429 body names the limit.
- Code today: any non-2xx is `*upstream.Error{Status, RetryAfter, Code, Message, Body}`. `Retry-After` is read as delta-seconds or an HTTP date, capped at 24 h, zero if absent or unusable. `Code` and `Message` are read from `{"error": "...", "message": "..."}` when the body looks like that, otherwise only the redacted, truncated `Body` is kept. The handler layer should relay 429 with its `Retry-After`, and should **not** relay upstream 401/403 as the client's 401/403 (that is a broker misconfiguration, see `Error.IsAuth()`); mapping it to a 502-style error is a card-3 decision, not made here.
- The mock can inject a 429 with `Retry-After` and arbitrary status/body (`Mock.InjectFault`) to exercise this. Its error body `{"error", "message"}` is invented.

## 4. Can `archive` be undone?

- `PER-SPEC`: SPEC §5 table: `POST /v2/alarms/:gid/:aid/archive` exists; revert "unknown (probe)". `DELETE` is irreversible; `mute` creates a box-side exception and its revert is unknown.
- `UNKNOWN`: whether any endpoint un-archives, whether archived alarms still appear in `GET /v2/alarms` (and with what field or query term), whether mute exceptions can be listed or removed.
- Code today: nothing (writes are M2). SPEC §9 already says alarm archive/mute are `revertible: false` until proven. The mock has no write endpoints and answers 404 for them.
- Probe needs a Full Access token, which this project never uses from the development environment; this item can only be settled from the docs, or by an operator on a disposable box.

## 5. `GET /v2/boxes` and the `group` field

- `PER-SPEC`: SPEC §6.2 says group membership is read from the `group` field of `GET /v2/boxes`; SPEC §5 lists `?group=<box-group>` on devices.
- `UNKNOWN`: the encoding of `group` (plain id string? object with id and name? array, for a box in several groups?), whether ungrouped boxes omit the field or send `null`, whether a box can be in more than one group, whether group ids and the `group=` filter value are the same identifier, the full field set of a box.
- Code today: `Box.Group` is read from `group` if it is a string, or from `group.id` if it is an object with a string `id`; anything else (null, absent, number, array) means "no group". If the real encoding is an array, group scoping would **fail closed** (boxes appear ungrouped, so group-scoped keys see nothing) rather than open. The mock sends a string id (`group-a`, `group-b`) and `null` for the ungrouped box.
- Because a wrong decoding fails closed, a probe of this field is required before a group-scoped key is trusted in production, but a wrong guess cannot widen access.

## 6. Groups listing endpoint

- `UNKNOWN`: whether any endpoint lists box groups or their names.
- Code today: none is modelled; the store's `box_cache` derives groups from each box's `group` field (DECISIONS). `GET /admin/v1/boxes` can therefore show group ids but possibly not group names. The mock answers 404 for `/v2/groups`, and a test asserts it, so no code can come to depend on an endpoint nobody has seen.

## 7. Authentication scheme

- `PER-SPEC`: SPEC §3 and §11 call the upstream credential a token; SPEC does not state the header scheme. (The M1 task brief says "bearer"; that is a working assumption, not documentation.)
- `UNKNOWN`: whether the header is `Authorization: Bearer <t>` or `Authorization: Token <t>` or something else.
- Code today: `Bearer` by default, `upstream.Config.AuthScheme` switches the scheme word (letters only). The mock accepts `Bearer` and `Token`. There is no environment variable for the scheme yet; add one if the probe shows `Bearer` is wrong.

## 8. List response shape and pagination

- `PER-SPEC`: alarms and flows are "cursor paginated" (SPEC §5, §7); flows `≤500` per request. Rules are listed with `query` only; devices, boxes and target lists have no pagination mentioned.
- `UNKNOWN`: whether lists are bare arrays or envelopes, the envelope keys, the name of the cursor field in responses (`next_cursor`? `nextCursor`?), the default and maximum `limit` for each endpoint, whether `count` is the page size or the total, whether rules and target lists paginate, whether a cursor is bound to the query that produced it.
- Code today: `decodeList` accepts a bare array or an object with a `results` array, a numeric `count`, and `next_cursor` or `nextCursor`; anything else is `ErrUnexpectedResponse`. `Page.Count` is the upstream `count` when sent, else `len(Results)`; the broker must not present it as a total. The mock uses envelopes for alarms/rules/flows and bare arrays for the rest, `limit` default 200, clamped to 500, opaque offset cursors over the filtered set (all invented).
- SPEC §5.3 already accepts that post-filtering can shrink a page; the broker returns short pages with a cursor.

## 9. Filter syntax and multi-value parameters

- `PER-SPEC`: `query=box.id:<gid>` on alarms, rules and flows; `box=<gid>` / `group=<box-group>` on devices; `owner=global,<gid>` on target lists (the SPEC writes the owner list comma-separated).
- `UNKNOWN`:
  - how to express several boxes in `query` (`box.id:A,B`? `(box.id:A OR box.id:B)`? repeated terms?), and whether `-box.id:` negation is supported. `acl.ScopeQuery` emits `(box.id:A OR box.id:B)` and `-box.id:A`; this is an assumption (DECISIONS). The alternative the foundation card suggested is one upstream request per gid (`ScopedQuery.GIDs`), which needs no multi-box syntax;
  - whether `box=` / `group=` accept comma lists;
  - how unknown or malformed query terms are reported (400? silently ignored?);
  - case sensitivity of gids in filters; whether a filter on a nonexistent box returns an empty list or an error.
- Code today: the client sends whatever string it is given. The mock implements the query subset in `internal/upstream/mock/query.go` (key:value, quotes, AND/OR/NOT/`-`, parentheses, comma and parenthesised value lists, `*` wildcards, dotted field paths, bare words) and `box=`/`group=`/`owner=` comma lists, case-insensitively. That is a reading of the syntax the SPEC implies, not a statement about the service.
- Why a wrong guess is harmless: if the upstream ignored or misread the filter it would return too much, never less than asked, and the post-filter removes everything out of scope. It could return **too little** (a filter that matches nothing), which is a correctness bug, not a security one, and shows up in the probe.

## 10. Other things the code assumes and nobody has verified

| Assumption | Where | Failure mode |
|---|---|---|
| Base URL is `scheme://host[/prefix]` and paths are `/v2/...` appended to it. SPEC §3 shows two forms (a per-account MSP domain, and a shared host with an `/api` prefix) | `upstream.Config.BaseURL` | wrong prefix: every call 404, caught by `serve --check` |
| Ids used in paths (gid, alarm id, target-list id) fit `[A-Za-z0-9._:-]{1,128}` | `checkSegment` | an id with other characters is refused locally with `ErrInvalidArgument`; widen with evidence |
| Upstream does not redirect | `CheckRedirect` refuses to follow | a 3xx becomes a typed error instead of a followed request |
| Numbers in responses can exceed float precision (alarm timestamps, counters) | `json.Number` is kept | none, they pass through textually |
| Each alarm id is unique within a gid | mock seed, `GET /v2/alarms/:gid/:aid` | n/a |
| Devices carry the owning box in a `gid` field (needed for post-filtering) | mock seed; `acl.OwnerOf` reads `gid`/`owner` | a device without it is dropped by the post-filter (default deny), so devices would vanish rather than leak |
| Target lists carry `owner` (`global` or a gid) | SPEC §5 | same default-deny behaviour |

## 11. What the mock is, in one paragraph

`internal/upstream/mock` (also `mspbroker mock-upstream`) is the project's own stand-in. Its response shapes, error bodies, limits, cursor format and filter semantics are the mock's, documented in its package comment. It exists to make the broker testable and demoable. A passing test against the mock proves the broker's behaviour given those shapes, and **says nothing about the real service** until the items above are probed.

## 12. Probe plan (when a Read Only token is available, outside the development environment)

1. `GET /v2/boxes`: record the field set, the `group` encoding, null vs absent, a box in two groups if one exists. Settles items 5 and 8 for boxes.
2. `GET /v2/devices?box=`, `?group=`, comma lists, nonexistent ids. Items 8, 9.
3. `GET /v2/alarms?limit=`, cursors, `query=box.id:`, two-box syntaxes, negation, a bad term. Items 8, 9 and the page ceiling.
4. `GET /v2/flows`, `GET /v2/rules`, `GET /v2/target-lists?owner=` with `global` and gids. Items 8, 9.
5. `GET /v2/stats/...`, `GET /v2/trends/...` from the public page names; with and without box filters. Items 1, 2.
6. Only if the docs give no numbers and the operator explicitly agrees: record the 429 body and `Retry-After` from a deliberate overrun against a token the operator is willing to have throttled. Otherwise leave item 3 `UNKNOWN`; the client already copes with any shape.
7. Write down the date, the docs page or probe, and the result next to each item above; change the label.
