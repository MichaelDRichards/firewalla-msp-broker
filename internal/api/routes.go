package api

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"mspbroker/internal/acl"
)

// surfacePublic marks routes that need no key: probes and the OpenAPI
// document. They expose nothing about boxes, keys or the audit log.
const surfacePublic acl.Surface = "public"

const (
	surfaceData  = acl.SurfaceData
	surfaceAdmin = acl.SurfaceAdmin
)

// route is one registered endpoint. The route table is the single source of
// truth: dispatch, permission checks, audit labels and the OpenAPI coverage
// test all read it.
type route struct {
	method  string
	pattern string
	segs    []string
	surface acl.Surface

	// need lists the resources of which the key must hold read on at least
	// one (data routes). Empty means any data key.
	need []acl.Resource

	auditResource string
	auditAction   string

	handler func(*call) *result
	public  func(*Server, http.ResponseWriter, *http.Request)
}

func (s *Server) add(rt *route) {
	if !strings.HasPrefix(rt.pattern, "/") {
		panic("api: route pattern must start with /: " + rt.pattern)
	}
	rt.segs = strings.Split(rt.pattern[1:], "/")
	s.routes = append(s.routes, rt)
}

type matched struct {
	route  *route
	params map[string]string
	// allow lists the methods the path supports when it matches routes but
	// not for this method (405).
	allow []string
	// prefix is the surface implied by the path alone.
	prefix acl.Surface
}

// surface is the API surface this request addresses: that of the matched
// route, else the one the path prefix implies, else none.
func (m matched) surface() acl.Surface {
	if m.route != nil && m.route.surface != surfacePublic {
		return m.route.surface
	}
	if m.route != nil {
		return ""
	}
	return m.prefix
}

// match finds the route for a request. The path is the escaped path, split
// on "/" before any decoding, so an encoded slash never changes the number
// of segments; each segment is decoded afterwards. Empty segments (double or
// trailing slashes) match nothing: there is no path cleaning to argue with.
func (s *Server) match(method, escapedPath string) matched {
	var m matched
	if !strings.HasPrefix(escapedPath, "/") {
		return m
	}
	raw := strings.Split(escapedPath[1:], "/")
	segs := make([]string, len(raw))
	for i, r := range raw {
		d, err := url.PathUnescape(r)
		if err != nil || d == "" || strings.ContainsAny(d, "\x00/") {
			segs = nil
			break
		}
		segs[i] = d
	}
	if len(raw) >= 2 && raw[0] == "api" && raw[1] == "v1" {
		m.prefix = surfaceData
	} else if len(raw) >= 2 && raw[0] == "admin" && raw[1] == "v1" {
		m.prefix = surfaceAdmin
	}
	if segs == nil {
		return m
	}
	allow := map[string]bool{}
	for _, rt := range s.routes {
		params, ok := matchSegs(rt.segs, segs)
		if !ok {
			continue
		}
		if rt.method == method {
			m.route, m.params = rt, params
			return m
		}
		allow[rt.method] = true
	}
	for a := range allow {
		m.allow = append(m.allow, a)
	}
	sort.Strings(m.allow)
	return m
}

func matchSegs(pattern, segs []string) (map[string]string, bool) {
	if len(pattern) != len(segs) {
		return nil, false
	}
	var params map[string]string
	for i, p := range pattern {
		if len(p) > 2 && p[0] == '{' && p[len(p)-1] == '}' {
			if params == nil {
				params = map[string]string{}
			}
			params[p[1:len(p)-1]] = segs[i]
			continue
		}
		if p != segs[i] {
			return nil, false
		}
	}
	return params, true
}

// registerRoutes declares every endpoint. Anything not listed here is
// denied.
func (s *Server) registerRoutes() {
	// Public probes and documentation.
	s.add(&route{method: "GET", pattern: "/healthz", surface: surfacePublic, public: (*Server).healthz})
	s.add(&route{method: "GET", pattern: "/readyz", surface: surfacePublic, public: (*Server).readyz})
	s.add(&route{method: "GET", pattern: "/api/openapi.json", surface: surfacePublic, public: (*Server).openapi})

	// Data API: reads only in M1.
	d := func(pattern, resource, action string, need []acl.Resource, h func(*call) *result) {
		s.add(&route{method: "GET", pattern: pattern, surface: surfaceData, need: need,
			auditResource: resource, auditAction: action, handler: h})
	}
	d("/api/v1/me", "me", "read", nil, (*call).me)
	d("/api/v1/boxes", "boxes", "list", res(acl.Boxes), (*call).listBoxes)
	d("/api/v1/boxes/{gid}", "boxes", "read", res(acl.Boxes), (*call).getBox)
	d("/api/v1/boxes/{gid}/devices", "devices", "list", res(acl.Devices), (*call).listDevices)
	d("/api/v1/boxes/{gid}/alarms", "alarms", "list", res(acl.Alarms), (*call).listBoxAlarms)
	d("/api/v1/boxes/{gid}/alarms/{aid}", "alarms", "read", res(acl.Alarms), (*call).getAlarm)
	d("/api/v1/alarms", "alarms", "list", res(acl.Alarms), (*call).listAlarms)
	d("/api/v1/boxes/{gid}/rules", "rules", "list", res(acl.Rules), (*call).listBoxRules)
	d("/api/v1/rules", "rules", "list", res(acl.Rules), (*call).listRules)
	d("/api/v1/boxes/{gid}/flows", "flows", "list", res(acl.Flows), (*call).listBoxFlows)
	d("/api/v1/flows", "flows", "list", res(acl.Flows), (*call).listFlows)
	d("/api/v1/target-lists", "target_lists", "list", res(acl.TargetLists, acl.GlobalTargetLists), (*call).listTargetLists)
	d("/api/v1/target-lists/{id}", "target_lists", "read", res(acl.TargetLists, acl.GlobalTargetLists), (*call).getTargetList)

	// Admin API: key management and audit browsing.
	a := func(method, pattern, resource, action string, h func(*call) *result) {
		s.add(&route{method: method, pattern: pattern, surface: surfaceAdmin,
			auditResource: resource, auditAction: action, handler: h})
	}
	a("POST", "/admin/v1/keys", "keys", "create", (*call).createKey)
	a("GET", "/admin/v1/keys", "keys", "list", (*call).listKeys)
	a("GET", "/admin/v1/keys/{id}", "keys", "read", (*call).getKey)
	a("PATCH", "/admin/v1/keys/{id}", "keys", "update", (*call).patchKey)
	a("GET", "/admin/v1/boxes", "boxes", "list", (*call).adminBoxes)
	a("GET", "/admin/v1/audit", "audit", "list", (*call).listAudit)
	a("GET", "/admin/v1/audit/{id}", "audit", "read", (*call).getAudit)
}

func res(r ...acl.Resource) []acl.Resource { return r }
