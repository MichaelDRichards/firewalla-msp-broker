package api

import (
	"encoding/json"
	"sort"
	"strings"
)

// The OpenAPI document is written by hand, separately from the route table,
// on purpose: TestOpenAPICoversEveryRoute fails when a registered route has
// no operation here (and when an operation here has no route), so the
// document cannot silently fall behind the handlers.

type qparam struct {
	name, desc string
	typ        string // JSON schema type; default string
	extra      map[string]any
}

type opDoc struct {
	method, path, tag, id, summary string
	desc                           string
	query                          []qparam
	reqBody                        string // schema name
	okStatus                       string // default 200
	okSchema                       string
	public                         bool
	errs                           []string // component response names
}

var (
	listQueryParams = []qparam{
		{name: "query", desc: "Upstream search syntax. box.id qualifiers outside the key's scope are rejected with 403 out_of_scope; the broker appends its own box filter."},
		{name: "limit", desc: "Page size, 1-500 (larger values are clamped).", typ: "integer"},
		{name: "cursor", desc: "Opaque cursor from a previous page's next_cursor."},
		{name: "groupBy", desc: "Passed through to the upstream. Grouped rows without a gid are dropped by the post-filter."},
		{name: "sortBy", desc: "Passed through to the upstream, for example ts:desc."},
	}
	dataErrs  = []string{"BadRequest", "Unauthorized", "Forbidden", "MethodNotAllowed", "TooManyRequests", "UpstreamError"}
	adminErrs = []string{"BadRequest", "Unauthorized", "Forbidden", "NotFound", "MethodNotAllowed", "TooManyRequests"}
)

func operations() []opDoc {
	scopedList := func(path, tag, id, summary string, paging bool) opDoc {
		q := listQueryParams
		if !paging {
			q = listQueryParams[:1]
		}
		return opDoc{method: "GET", path: path, tag: tag, id: id, summary: summary, query: q, okSchema: "List", errs: dataErrs}
	}
	return []opDoc{
		{method: "GET", path: "/healthz", tag: "ops", id: "healthz", summary: "Liveness: the process is up", public: true, okSchema: "Health"},
		{method: "GET", path: "/readyz", tag: "ops", id: "readyz", summary: "Readiness: database open and upstream reachable within the check interval", public: true, okSchema: "Ready", errs: []string{"NotReady"}},
		{method: "GET", path: "/api/openapi.json", tag: "ops", id: "openapi", summary: "This document", public: true, okSchema: "OpenAPI"},

		{method: "GET", path: "/api/v1/me", tag: "data", id: "getMe", summary: "The calling key: scope (resolved), permissions, expiry and rotation state", okSchema: "Me", errs: dataErrs},
		{method: "GET", path: "/api/v1/boxes", tag: "data", id: "listBoxes", summary: "Boxes in the key's scope", okSchema: "List", errs: dataErrs},
		{method: "GET", path: "/api/v1/boxes/{gid}", tag: "data", id: "getBox", summary: "One box", okSchema: "Object", errs: append([]string{"NotFound"}, dataErrs...)},
		{method: "GET", path: "/api/v1/boxes/{gid}/devices", tag: "data", id: "listDevices", summary: "Devices of one box", okSchema: "List", errs: dataErrs},
		scopedList("/api/v1/boxes/{gid}/alarms", "data", "listBoxAlarms", "Alarms of one box", true),
		{method: "GET", path: "/api/v1/boxes/{gid}/alarms/{aid}", tag: "data", id: "getAlarm", summary: "One alarm", okSchema: "Object", errs: append([]string{"NotFound"}, dataErrs...)},
		scopedList("/api/v1/alarms", "data", "listAlarms", "Alarms across the key's scope", true),
		scopedList("/api/v1/boxes/{gid}/rules", "data", "listBoxRules", "Rules of one box", false),
		scopedList("/api/v1/rules", "data", "listRules", "Rules across the key's scope", false),
		scopedList("/api/v1/boxes/{gid}/flows", "data", "listBoxFlows", "Flows of one box", true),
		scopedList("/api/v1/flows", "data", "listFlows", "Flows across the key's scope", true),
		{method: "GET", path: "/api/v1/target-lists", tag: "data", id: "listTargetLists", summary: "Target lists owned by boxes in scope, plus global lists when global_target_lists >= read",
			query:    []qparam{{name: "owner", desc: "Comma-separated owners: box ids and/or global."}},
			okSchema: "List", errs: dataErrs},
		{method: "GET", path: "/api/v1/target-lists/{id}", tag: "data", id: "getTargetList", summary: "One target list", okSchema: "Object", errs: append([]string{"NotFound"}, dataErrs...)},

		{method: "POST", path: "/admin/v1/keys", tag: "admin", id: "createKey", summary: "Create a key; the secret is returned once", reqBody: "KeyCreate", okStatus: "201", okSchema: "KeyCreated", errs: append([]string{"Conflict"}, adminErrs...)},
		{method: "GET", path: "/admin/v1/keys", tag: "admin", id: "listKeys", summary: "List keys (never secrets)", okSchema: "KeyList", errs: adminErrs},
		{method: "GET", path: "/admin/v1/keys/{id}", tag: "admin", id: "getKey", summary: "One key (never secrets)", okSchema: "Key", errs: adminErrs},
		{method: "PATCH", path: "/admin/v1/keys/{id}", tag: "admin", id: "patchKey", summary: "Update any field except kind; effective on the next request", reqBody: "KeyPatch", okSchema: "Key", errs: append([]string{"Conflict"}, adminErrs...)},
		{method: "GET", path: "/admin/v1/boxes", tag: "admin", id: "adminBoxes", summary: "All upstream boxes with their groups, for scope pickers", okSchema: "AdminBoxList", errs: append([]string{"UpstreamError"}, adminErrs...)},
		{method: "GET", path: "/admin/v1/audit", tag: "admin", id: "listAudit", summary: "Audit entries, newest first",
			query: []qparam{
				{name: "key_id", desc: "Only entries of this key."},
				{name: "gid", desc: "Only entries about this box."},
				{name: "resource", desc: "For example alarms, keys, audit."},
				{name: "outcome", desc: "ok, upstream_error or blocked.", extra: map[string]any{"enum": []string{"ok", "upstream_error", "blocked"}}},
				{name: "since", desc: "RFC 3339, inclusive."},
				{name: "until", desc: "RFC 3339, exclusive."},
				{name: "cursor", desc: "next_cursor of a previous page."},
				{name: "limit", desc: "1-1000, default 100.", typ: "integer"},
			},
			okSchema: "AuditList", errs: adminErrs},
		{method: "GET", path: "/admin/v1/audit/{id}", tag: "admin", id: "getAudit", summary: "One audit entry", okSchema: "AuditEntry", errs: adminErrs},
	}
}

func ref(name string) map[string]any { return map[string]any{"$ref": "#/components/schemas/" + name} }

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func str(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func nullable(typ string, extra map[string]any) map[string]any {
	m := map[string]any{"type": []string{typ, "null"}}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func levelSchema(max string) map[string]any {
	enum := []string{"none", "read", "write"}
	if max == "read" {
		enum = enum[:2]
	}
	return map[string]any{"type": "string", "enum": enum}
}

func schemas() map[string]any {
	return map[string]any{
		"Error": obj(map[string]any{
			"error":  str("Short error class, for example forbidden or not_found."),
			"code":   str("Stable reason code. 403: out_of_scope, permission, kind (or an authentication code: disabled, ip). 401: auth, expired. 429: rate_limit."),
			"detail": str("Human-readable explanation."),
		}, "error", "code", "detail"),
		"Object": map[string]any{"type": "object", "additionalProperties": true, "description": "An upstream object, passed through unchanged."},
		"List": obj(map[string]any{
			"count":       map[string]any{"type": "integer", "description": "Number of results in this page after scope filtering."},
			"results":     map[string]any{"type": "array", "items": ref("Object")},
			"next_cursor": str("Present when more results exist. Pages may be short because out-of-scope objects are dropped after the upstream answers."),
		}, "count", "results"),
		"Health": obj(map[string]any{"status": str("ok"), "version": str("Build version.")}, "status"),
		"Ready": obj(map[string]any{
			"status": map[string]any{"type": "string", "enum": []string{"ready", "not_ready"}},
			"checks": obj(map[string]any{"database": str("ok or error"), "upstream": str("ok or error")}),
		}, "status", "checks"),
		"OpenAPI": map[string]any{"type": "object", "description": "An OpenAPI 3.1 document."},
		"Scope": obj(map[string]any{
			"type":      map[string]any{"type": "string", "enum": []string{"all", "boxes", "groups", "boxes+groups"}},
			"gids":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"group_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "type"),
		"Permissions": obj(map[string]any{
			"boxes":               levelSchema("read"),
			"devices":             levelSchema("write"),
			"alarms":              levelSchema("write"),
			"rules":               levelSchema("write"),
			"flows":               levelSchema("read"),
			"target_lists":        levelSchema("write"),
			"stats":               levelSchema("read"),
			"global_target_lists": levelSchema("write"),
		}),
		"RateLimit": obj(map[string]any{"per_minute": map[string]any{"type": "integer", "minimum": 0, "description": "0 = unlimited."}}, "per_minute"),
		"Me": obj(map[string]any{
			"key": obj(map[string]any{
				"id": str(""), "name": str(""), "kind": map[string]any{"type": "string", "enum": []string{"data"}}, "enabled": map[string]any{"type": "boolean"},
			}),
			"scope":                 ref("Scope"),
			"resolved_gids":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Boxes the key can reach right now (groups and all expanded)."},
			"permissions":           ref("Permissions"),
			"expires_at":            nullable("string", map[string]any{"format": "date-time"}),
			"ip_allow":              map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"rate_limit_per_minute": map[string]any{"type": "integer"},
			"rotation": obj(map[string]any{
				"in_progress": map[string]any{"type": "boolean"},
				"secrets": map[string]any{"type": "array", "items": obj(map[string]any{
					"prefix": str(""), "created_at": map[string]any{"type": "string", "format": "date-time"},
					"expires_at": nullable("string", map[string]any{"format": "date-time"}), "current": map[string]any{"type": "boolean"},
				})},
			}),
		}),
		"Key": obj(map[string]any{
			"id":           str("Stable key id."),
			"name":         str("Friendly name, unique among active keys."),
			"kind":         map[string]any{"type": "string", "enum": []string{"data", "admin"}},
			"enabled":      map[string]any{"type": "boolean"},
			"expires_at":   nullable("string", map[string]any{"format": "date-time"}),
			"ip_allow":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"scope":        map[string]any{"oneOf": []any{ref("Scope"), map[string]any{"type": "null"}}, "description": "Null for admin keys."},
			"permissions":  map[string]any{"oneOf": []any{ref("Permissions"), map[string]any{"type": "null"}}, "description": "Null for admin keys."},
			"rate_limit":   map[string]any{"oneOf": []any{ref("RateLimit"), map[string]any{"type": "null"}}},
			"notes":        str(""),
			"created_at":   map[string]any{"type": "string", "format": "date-time"},
			"updated_at":   map[string]any{"type": "string", "format": "date-time"},
			"last_used_at": nullable("string", map[string]any{"format": "date-time"}),
			"secrets": map[string]any{"type": "array", "description": "Prefixes and validity windows only; secret values are never returned after creation.",
				"items": obj(map[string]any{
					"id": str(""), "prefix": str(""),
					"created_at": map[string]any{"type": "string", "format": "date-time"},
					"expires_at": nullable("string", map[string]any{"format": "date-time"}),
					"revoked_at": nullable("string", map[string]any{"format": "date-time"}),
				})},
		}, "id", "name", "kind", "enabled"),
		"KeyCreated": map[string]any{"allOf": []any{ref("Key"), obj(map[string]any{"secret": str("The full secret. Shown exactly once.")}, "secret")}},
		"KeyList":    obj(map[string]any{"count": map[string]any{"type": "integer"}, "results": map[string]any{"type": "array", "items": ref("Key")}}, "count", "results"),
		"KeyCreate": obj(map[string]any{
			"name":        str("Required."),
			"kind":        map[string]any{"type": "string", "enum": []string{"data", "admin"}},
			"enabled":     map[string]any{"type": "boolean", "default": true},
			"scope":       map[string]any{"allOf": []any{ref("Scope")}, "description": "Required for data keys; not allowed for admin keys."},
			"permissions": map[string]any{"allOf": []any{ref("Permissions")}, "description": "Omitted resources are none. Not allowed for admin keys."},
			"expires_at":  map[string]any{"type": "string", "format": "date-time"},
			"ip_allow":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "CIDRs or bare addresses."},
			"rate_limit":  ref("RateLimit"),
			"notes":       str(""),
		}, "name", "kind"),
		"KeyPatch": obj(map[string]any{
			"name":        str(""),
			"enabled":     map[string]any{"type": "boolean"},
			"scope":       map[string]any{"allOf": []any{ref("Scope")}, "description": "Replaces the scope."},
			"permissions": map[string]any{"allOf": []any{ref("Permissions")}, "description": "Merged per resource; omitted resources keep their level."},
			"expires_at":  nullable("string", map[string]any{"format": "date-time", "description": "null clears the expiry."}),
			"ip_allow":    map[string]any{"type": []string{"array", "null"}, "items": map[string]any{"type": "string"}},
			"rate_limit":  map[string]any{"oneOf": []any{ref("RateLimit"), map[string]any{"type": "null"}}, "description": "null restores the default."},
			"notes":       str(""),
		}),
		"AdminBoxList": obj(map[string]any{"count": map[string]any{"type": "integer"}, "results": map[string]any{"type": "array", "items": obj(map[string]any{
			"gid": str(""), "name": str(""), "group": map[string]any{"type": []string{"string", "null"}},
		}, "gid", "name", "group")}}, "count", "results"),
		"AuditEntry": obj(map[string]any{
			"id": map[string]any{"type": "integer"}, "ts": map[string]any{"type": "string", "format": "date-time"},
			"key_id": str(""), "key_name_at_time": str(""), "secret_prefix": str(""), "client_ip": str(""),
			"outcome":      map[string]any{"type": "string", "enum": []string{"ok", "upstream_error", "blocked"}},
			"block_reason": str("auth, expired, disabled, ip, rate_limit, kind, permission, out_of_scope, unmodelled, bad_request, not_found, conflict or internal."),
			"method":       str(""), "path": str(""), "query": str(""), "resource": str(""), "action": str(""),
			"gid": str(""), "object_id": str(""), "upstream_status": map[string]any{"type": "integer"},
			"before": map[string]any{}, "after": map[string]any{},
			"revert_of": map[string]any{"type": "integer"}, "reverted_by": map[string]any{"type": "integer"},
			"result_count": map[string]any{"type": "integer", "description": "Reads: objects returned after filtering."},
		}, "id", "ts", "outcome", "method", "path"),
		"AuditList": obj(map[string]any{"count": map[string]any{"type": "integer"}, "results": map[string]any{"type": "array", "items": ref("AuditEntry")},
			"next_cursor": str("")}, "count", "results"),
	}
}

func errResponse(desc string, extraHeaders map[string]any) map[string]any {
	r := map[string]any{
		"description": desc,
		"content":     map[string]any{"application/json": map[string]any{"schema": ref("Error")}},
	}
	if extraHeaders != nil {
		r["headers"] = extraHeaders
	}
	return r
}

func responses() map[string]any {
	return map[string]any{
		"BadRequest":       errResponse("Malformed request: unknown or repeated query parameter, bad value, bad query syntax, invalid body.", nil),
		"Unauthorized":     errResponse("Missing, malformed, unknown, revoked or expired credentials (code auth or expired). Unknown and revoked are indistinguishable.", map[string]any{"WWW-Authenticate": map[string]any{"schema": map[string]any{"type": "string"}}}),
		"Forbidden":        errResponse("error=forbidden. code: out_of_scope, permission or kind; or disabled / ip from authentication.", nil),
		"NotFound":         errResponse("No such object, or the endpoint is not modelled.", nil),
		"Conflict":         errResponse("The request conflicts with current state, for example the key name is taken.", nil),
		"MethodNotAllowed": errResponse("The method is not modelled for this path. Writes to the data API are not available yet.", map[string]any{"Allow": map[string]any{"schema": map[string]any{"type": "string"}}}),
		"TooManyRequests":  errResponse("Per-key rate limit (code rate_limit) or an upstream 429 passed through (code upstream_rate_limit).", map[string]any{"Retry-After": map[string]any{"schema": map[string]any{"type": "integer"}}}),
		"UpstreamError":    errResponse("The upstream failed or was unreachable (502/504) or rejected the parameters (400).", nil),
		"NotReady": map[string]any{"description": "Not ready.",
			"content": map[string]any{"application/json": map[string]any{"schema": ref("Ready")}}},
	}
}

// buildOpenAPI renders the document.
func buildOpenAPI(version string) ([]byte, error) {
	if version == "" {
		version = "0.0.0-dev"
	}
	paths := map[string]any{}
	for _, o := range operations() {
		item, _ := paths[o.path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[o.path] = item
		}
		item[strings.ToLower(o.method)] = o.render()
	}
	doc := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "mspbroker",
			"version":     version,
			"description": "Scoped, audited access to the Firewalla MSP API. Data API under /api/v1 (data keys), admin API under /admin/v1 (admin keys). Everything not listed here is denied.",
			"license":     map[string]any{"name": "Elastic License 2.0", "identifier": "Elastic-2.0"},
		},
		"servers": []any{map[string]any{"url": "/"}},
		"tags": []any{
			map[string]any{"name": "ops", "description": "Probes and documentation; no authentication."},
			map[string]any{"name": "data", "description": "Read endpoints for data keys."},
			map[string]any{"name": "admin", "description": "Key management and audit browsing for admin keys."},
		},
		"paths": paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{"bearer": map[string]any{"type": "http", "scheme": "bearer", "description": "A key secret issued by mspbroker (mb_...)."}},
			"schemas":         schemas(),
			"responses":       responses(),
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func (o opDoc) render() map[string]any {
	m := map[string]any{"operationId": o.id, "summary": o.summary, "tags": []string{o.tag}}
	if o.desc != "" {
		m["description"] = o.desc
	}
	var params []any
	for _, seg := range strings.Split(o.path, "/") {
		if len(seg) > 2 && seg[0] == '{' {
			name := seg[1 : len(seg)-1]
			params = append(params, map[string]any{"name": name, "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
		}
	}
	for _, q := range o.query {
		typ := q.typ
		if typ == "" {
			typ = "string"
		}
		schema := map[string]any{"type": typ}
		for k, v := range q.extra {
			schema[k] = v
		}
		params = append(params, map[string]any{"name": q.name, "in": "query", "description": q.desc, "schema": schema})
	}
	if params != nil {
		m["parameters"] = params
	}
	if o.reqBody != "" {
		m["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": ref(o.reqBody)}}}
	}
	status := o.okStatus
	if status == "" {
		status = "200"
	}
	resp := map[string]any{status: map[string]any{
		"description": "Success.",
		"content":     map[string]any{"application/json": map[string]any{"schema": ref(o.okSchema)}},
	}}
	errs := append([]string(nil), o.errs...)
	sort.Strings(errs)
	for _, e := range errs {
		code := map[string]string{"BadRequest": "400", "Unauthorized": "401", "Forbidden": "403", "NotFound": "404",
			"MethodNotAllowed": "405", "Conflict": "409", "TooManyRequests": "429", "UpstreamError": "502", "NotReady": "503"}[e]
		if _, dup := resp[code]; !dup {
			resp[code] = map[string]any{"$ref": "#/components/responses/" + e}
		}
	}
	m["responses"] = resp
	if o.public {
		m["security"] = []any{}
	} else {
		m["security"] = []any{map[string]any{"bearer": []string{}}}
	}
	return m
}
