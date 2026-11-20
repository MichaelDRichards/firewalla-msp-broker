package api_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"mspbroker/internal/api"
)

// missingFromDoc lists routes that the document does not describe, and
// documented operations that no route serves.
func missingFromDoc(routes []api.RouteInfo, doc []byte) (undocumented, unserved []string, err error) {
	var d struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, nil, err
	}
	registered := map[string]bool{}
	for _, r := range routes {
		key := strings.ToLower(r.Method) + " " + r.Pattern
		registered[key] = true
		if _, ok := d.Paths[r.Pattern][strings.ToLower(r.Method)]; !ok {
			undocumented = append(undocumented, r.Method+" "+r.Pattern)
		}
	}
	httpMethods := map[string]bool{"get": true, "put": true, "post": true, "delete": true, "options": true, "head": true, "patch": true, "trace": true}
	for path, item := range d.Paths {
		for m := range item {
			if httpMethods[m] && !registered[m+" "+path] {
				unserved = append(unserved, strings.ToUpper(m)+" "+path)
			}
		}
	}
	sort.Strings(undocumented)
	sort.Strings(unserved)
	return undocumented, unserved, nil
}

// Every registered route is in the OpenAPI document, and every documented
// operation is a registered route.
func TestOpenAPICoversEveryRoute(t *testing.T) {
	h := newHarness(t)
	routes := h.srv.Routes()
	if len(routes) < 20 {
		t.Fatalf("only %d routes registered", len(routes))
	}
	// Fetched over HTTP, unauthenticated, as a client would.
	r := h.get("", "/api/openapi.json")
	if r.status != 200 || !strings.HasPrefix(r.hdr.Get("Content-Type"), "application/json") {
		t.Fatalf("%d %v", r.status, r.hdr)
	}
	undoc, unserved, err := missingFromDoc(routes, r.body)
	if err != nil {
		t.Fatal(err)
	}
	if len(undoc) > 0 {
		t.Errorf("routes missing from the OpenAPI document: %v", undoc)
	}
	if len(unserved) > 0 {
		t.Errorf("documented operations with no route: %v", unserved)
	}
	if string(r.body) != string(h.srv.OpenAPI()) {
		t.Error("served document differs from Server.OpenAPI()")
	}
}

// The coverage check itself fails when a route is missing, so it can be
// trusted to catch the next endpoint someone adds without documenting.
func TestOpenAPICoverageCheckHasTeeth(t *testing.T) {
	h := newHarness(t)
	routes := append(h.srv.Routes(),
		api.RouteInfo{Method: "POST", Pattern: "/api/v1/boxes/{gid}/rules"},
		api.RouteInfo{Method: "GET", Pattern: "/api/v1/brand-new"})
	undoc, _, err := missingFromDoc(routes, h.srv.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	if len(undoc) != 2 {
		t.Errorf("undocumented routes found: %v", undoc)
	}
	// And in the other direction: a route removed from the registry leaves a
	// documented operation without a route.
	_, unserved, _ := missingFromDoc(h.srv.Routes()[1:], h.srv.OpenAPI())
	if len(unserved) != 1 {
		t.Errorf("unserved operations found: %v", unserved)
	}
}

func TestOpenAPIDocumentIsWellFormed(t *testing.T) {
	h := newHarness(t)
	var doc map[string]any
	if err := json.Unmarshal(h.srv.OpenAPI(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Errorf("openapi: %v", doc["openapi"])
	}
	info := doc["info"].(map[string]any)
	if info["title"] == "" || info["version"] != "test" {
		t.Errorf("info: %v", info)
	}

	// Every $ref resolves.
	refs := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				if k == "$ref" {
					refs[c.(string)] = true
				}
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(doc)
	for ref := range refs {
		parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
		var cur any = doc
		for _, p := range parts {
			m, ok := cur.(map[string]any)
			if !ok || m[p] == nil {
				t.Errorf("unresolved $ref %s", ref)
				break
			}
			cur = m[p]
		}
	}

	// Per operation: unique ids, every path parameter declared, a success
	// response, auth declared unless public.
	seen := map[string]bool{}
	public := map[string]bool{"/healthz": true, "/readyz": true, "/api/openapi.json": true}
	for path, item := range doc["paths"].(map[string]any) {
		for method, o := range item.(map[string]any) {
			op := o.(map[string]any)
			id, _ := op["operationId"].(string)
			if id == "" || seen[id] {
				t.Errorf("%s %s: operationId %q missing or duplicated", method, path, id)
			}
			seen[id] = true
			declared := map[string]bool{}
			for _, p := range asSlice(op["parameters"]) {
				pm := p.(map[string]any)
				if pm["in"] == "path" {
					declared[pm["name"].(string)] = true
				}
			}
			for _, seg := range strings.Split(path, "/") {
				if strings.HasPrefix(seg, "{") && !declared[strings.Trim(seg, "{}")] {
					t.Errorf("%s %s: path parameter %s undeclared", method, path, seg)
				}
			}
			resp := op["responses"].(map[string]any)
			ok := false
			for code := range resp {
				if strings.HasPrefix(code, "2") {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s %s: no 2xx response", method, path)
			}
			sec := asSlice(op["security"])
			if public[path] && len(sec) != 0 {
				t.Errorf("%s %s: public route requires auth in the document", method, path)
			}
			if !public[path] {
				if len(sec) == 0 {
					t.Errorf("%s %s: no security requirement", method, path)
				}
				if resp["401"] == nil || resp["403"] == nil {
					t.Errorf("%s %s: 401/403 not documented", method, path)
				}
			}
		}
	}
	// Both surfaces are covered.
	paths := doc["paths"].(map[string]any)
	for _, must := range []string{"/api/v1/me", "/api/v1/boxes", "/api/v1/alarms", "/api/v1/target-lists/{id}", "/admin/v1/keys", "/admin/v1/keys/{id}", "/admin/v1/audit", "/admin/v1/boxes"} {
		if paths[must] == nil {
			t.Errorf("path %s missing", must)
		}
	}
	// Nothing in the document can leak an environment: no hosts or tokens.
	text := string(h.srv.OpenAPI())
	for _, bad := range []string{"http://", "https://", upstreamCanary} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(bad)) {
			t.Errorf("document mentions %q", bad)
		}
	}
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}
