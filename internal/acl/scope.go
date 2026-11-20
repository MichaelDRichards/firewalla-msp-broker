package acl

import (
	"sort"
	"strings"
)

// Box is the part of an upstream box the ACL needs: its id and the group it
// belongs to ("" for none).
type Box struct {
	GID     string
	GroupID string
}

// Effective is a key's box set for one request, computed once by Resolve and
// then used for filter injection, ownership checks and post-filtering. The
// zero value and nil both deny everything.
type Effective struct {
	all  bool
	gids map[string]struct{}
}

func norm(gid string) string { return strings.ToLower(strings.TrimSpace(gid)) }

// Resolve computes the effective box set from a scope and the current
// upstream box list (with group membership). An invalid or unknown scope
// resolves to the empty set.
//
// Explicit gids are kept even if absent from the box list: the list is only
// needed to expand groups, and a stale cache must not revoke an explicit grant.
func Resolve(s Scope, boxes []Box) *Effective {
	e := &Effective{gids: map[string]struct{}{}}
	if s.Validate() != nil {
		return e
	}
	switch s.Type {
	case ScopeAll:
		e.all = true
		return e
	case ScopeBoxes, ScopeBoxesGroups:
		for _, g := range s.GIDs {
			e.gids[norm(g)] = struct{}{}
		}
	}
	if s.Type == ScopeGroups || s.Type == ScopeBoxesGroups {
		groups := make(map[string]struct{}, len(s.GroupIDs))
		for _, g := range s.GroupIDs {
			groups[strings.TrimSpace(g)] = struct{}{}
		}
		for _, b := range boxes {
			if b.GroupID == "" || norm(b.GID) == "" {
				continue
			}
			if _, ok := groups[strings.TrimSpace(b.GroupID)]; ok {
				e.gids[norm(b.GID)] = struct{}{}
			}
		}
	}
	return e
}

// All reports whether the scope covers every box, including future ones.
func (e *Effective) All() bool { return e != nil && e.all }

// Empty reports whether no box is in scope.
func (e *Effective) Empty() bool { return e == nil || (!e.all && len(e.gids) == 0) }

// Contains reports whether gid is in scope. An empty gid is never in scope.
func (e *Effective) Contains(gid string) bool {
	g := norm(gid)
	if e == nil || g == "" {
		return false
	}
	if e.all {
		return true
	}
	_, ok := e.gids[g]
	return ok
}

// GIDs returns the explicit gids in scope, sorted. For an All scope it
// returns nil; check All first.
func (e *Effective) GIDs() []string {
	if e == nil || e.all {
		return nil
	}
	out := make([]string, 0, len(e.gids))
	for g := range e.gids {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// GlobalOwner is the owner value of MSP-owned (global) objects.
const GlobalOwner = "global"

// Owner extracts who owns an upstream object from its decoded JSON. Boxes,
// devices, alarms and rules carry "gid"; target lists carry "owner" (a gid or
// "global"). If both are present they must agree about being global or in
// scope, so every identifier present is checked by Allows.
type Owner struct {
	ids []string
}

// OwnerOf collects the ownership identifiers of obj. ok is false if the
// object carries none, or one of them is not a non-empty string.
func OwnerOf(obj map[string]any) (o Owner, ok bool) {
	for _, k := range []string{"gid", "owner"} {
		v, present := obj[k]
		if !present {
			continue
		}
		s, isStr := v.(string)
		if !isStr || norm(s) == "" {
			return Owner{}, false
		}
		o.ids = append(o.ids, norm(s))
	}
	return o, len(o.ids) > 0
}

// Allows reports whether every identifier of the owner is acceptable.
// "global" is accepted only when allowGlobal is set (the key holds
// global_target_lists >= read); any other id must be in scope.
func (e *Effective) Allows(o Owner, allowGlobal bool) bool {
	if len(o.ids) == 0 {
		return false
	}
	for _, id := range o.ids {
		if id == GlobalOwner {
			if !allowGlobal {
				return false
			}
			continue
		}
		if !e.Contains(id) {
			return false
		}
	}
	return true
}

// AllowsObject is Allows(OwnerOf(obj)); objects with no usable owner are
// denied. Keys that spell gid or owner in another case are ownership claims
// too: an object carrying one that is not in scope is denied. Nested objects
// are not looked at here; ScopeObject does that.
func (e *Effective) AllowsObject(obj map[string]any, allowGlobal bool) bool {
	o, ok := OwnerOf(obj)
	return ok && e.Allows(o, allowGlobal) && e.claimsOK(obj, allowGlobal)
}

// isOwnerKey reports whether k names an ownership field in any case.
func isOwnerKey(k string) bool {
	k = strings.TrimSpace(k)
	return strings.EqualFold(k, "gid") || strings.EqualFold(k, "owner")
}

// claimsOK checks every key of m that spells gid or owner (in any case):
// each must hold a non-empty string that Allows accepts. A map with no such
// key passes.
func (e *Effective) claimsOK(m map[string]any, allowGlobal bool) bool {
	for k, v := range m {
		if !isOwnerKey(k) {
			continue
		}
		s, isStr := v.(string)
		if !isStr || norm(s) == "" || !e.Allows(Owner{ids: []string{norm(s)}}, allowGlobal) {
			return false
		}
	}
	return true
}

// ScopeObject applies the post-filter to one object and to everything nested
// in it. ok is false when the object itself is out of scope (see
// AllowsObject). Otherwise the returned copy has every nested object that
// carries a gid or owner outside the key's scope removed: dropped from its
// array, or deleted from the object holding it. Nested objects with no gid or
// owner are plain data and stay, but are searched in turn. Anything with an
// unusable owner (not a string, empty) counts as out of scope. The input is
// not modified.
func ScopeObject(obj map[string]any, e *Effective, allowGlobal bool) (out map[string]any, ok bool) {
	if !e.AllowsObject(obj, allowGlobal) {
		return nil, false
	}
	return e.pruneMap(obj, allowGlobal), true
}

func (e *Effective) pruneMap(m map[string]any, allowGlobal bool) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if pv, keep := e.pruneValue(v, allowGlobal); keep {
			out[k] = pv
		}
	}
	return out
}

func (e *Effective) pruneValue(v any, allowGlobal bool) (any, bool) {
	switch x := v.(type) {
	case map[string]any:
		if !e.claimsOK(x, allowGlobal) {
			return nil, false
		}
		return e.pruneMap(x, allowGlobal), true
	case []any:
		out := make([]any, 0, len(x))
		for _, el := range x {
			if pe, keep := e.pruneValue(el, allowGlobal); keep {
				out = append(out, pe)
			}
		}
		return out, true
	}
	return v, true
}

// FilterObjects is the post-filter: it returns only the objects whose
// gid/owner is in scope, each with out-of-scope nested objects removed
// (ScopeObject). Objects with no usable gid/owner are dropped. The input
// slice and its objects are not modified; the result is never nil.
func FilterObjects(objs []map[string]any, e *Effective, allowGlobal bool) []map[string]any {
	out := make([]map[string]any, 0, len(objs))
	for _, o := range objs {
		if so, ok := ScopeObject(o, e, allowGlobal); ok {
			out = append(out, so)
		}
	}
	return out
}

// Filter is the typed post-filter for callers that decode into structs.
// ownerOf returns the identifiers of an item; no identifiers means drop.
func Filter[T any](items []T, e *Effective, allowGlobal bool, ownerOf func(T) []string) []T {
	out := make([]T, 0, len(items))
	for _, it := range items {
		ids := ownerOf(it)
		o := Owner{}
		okAll := len(ids) > 0
		for _, id := range ids {
			if norm(id) == "" {
				okAll = false
				break
			}
			o.ids = append(o.ids, norm(id))
		}
		if okAll && e.Allows(o, allowGlobal) {
			out = append(out, it)
		}
	}
	return out
}
