// Package acl evaluates key scope and permissions. Everything here is a pure
// function of its arguments: no I/O, no clocks, no global state.
package acl

import (
	"fmt"
	"strings"
)

// Level is a permission level. Write implies read.
type Level int

// Permission levels.
const (
	None Level = iota
	Read
	Write
)

func (l Level) String() string {
	switch l {
	case None:
		return "none"
	case Read:
		return "read"
	case Write:
		return "write"
	}
	return fmt.Sprintf("invalid(%d)", int(l))
}

// MarshalText implements encoding.TextMarshaler.
func (l Level) MarshalText() ([]byte, error) {
	if l < None || l > Write {
		return nil, fmt.Errorf("invalid permission level %d", int(l))
	}
	return []byte(l.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (l *Level) UnmarshalText(b []byte) error {
	switch string(b) {
	case "none":
		*l = None
	case "read":
		*l = Read
	case "write":
		*l = Write
	default:
		return fmt.Errorf("invalid permission level %q (want none, read or write)", b)
	}
	return nil
}

// Resource is a class of upstream objects.
type Resource string

// Resources (SPEC 6.3).
const (
	Boxes             Resource = "boxes"
	Devices           Resource = "devices"
	Alarms            Resource = "alarms"
	Rules             Resource = "rules"
	Flows             Resource = "flows"
	TargetLists       Resource = "target_lists"
	Stats             Resource = "stats"
	GlobalTargetLists Resource = "global_target_lists"
)

// Resources lists every modelled resource.
var Resources = []Resource{Boxes, Devices, Alarms, Rules, Flows, TargetLists, Stats, GlobalTargetLists}

// Action is what a request wants to do with a resource.
type Action string

// Actions. Delete, archive, mute, pause, resume, create and rename are all
// "write" for permission purposes (SPEC 6.3).
const (
	ActionRead  Action = "read"
	ActionWrite Action = "write"
)

// maxLevel is the highest level a resource can hold. Resources without write
// operations upstream cap at Read.
func maxLevel(r Resource) (Level, bool) {
	switch r {
	case Boxes, Flows, Stats:
		return Read, true
	case Devices, Alarms, Rules, TargetLists, GlobalTargetLists:
		return Write, true
	}
	return None, false
}

// Permissions is the per-resource permission set of a key.
type Permissions struct {
	Boxes             Level `json:"boxes"`
	Devices           Level `json:"devices"`
	Alarms            Level `json:"alarms"`
	Rules             Level `json:"rules"`
	Flows             Level `json:"flows"`
	TargetLists       Level `json:"target_lists"`
	Stats             Level `json:"stats"`
	GlobalTargetLists Level `json:"global_target_lists"`
}

// Level returns the configured level for a resource, or None for an
// unknown resource.
func (p Permissions) Level(r Resource) Level {
	switch r {
	case Boxes:
		return p.Boxes
	case Devices:
		return p.Devices
	case Alarms:
		return p.Alarms
	case Rules:
		return p.Rules
	case Flows:
		return p.Flows
	case TargetLists:
		return p.TargetLists
	case Stats:
		return p.Stats
	case GlobalTargetLists:
		return p.GlobalTargetLists
	}
	return None
}

// Set returns a copy with one resource's level changed. Unknown resources
// are an error.
func (p Permissions) Set(r Resource, l Level) (Permissions, error) {
	switch r {
	case Boxes:
		p.Boxes = l
	case Devices:
		p.Devices = l
	case Alarms:
		p.Alarms = l
	case Rules:
		p.Rules = l
	case Flows:
		p.Flows = l
	case TargetLists:
		p.TargetLists = l
	case Stats:
		p.Stats = l
	case GlobalTargetLists:
		p.GlobalTargetLists = l
	default:
		return p, fmt.Errorf("unknown resource %q", r)
	}
	return p, nil
}

// Validate rejects levels a resource cannot hold (e.g. flows=write).
func (p Permissions) Validate() error {
	for _, r := range Resources {
		l := p.Level(r)
		if l < None || l > Write {
			return fmt.Errorf("%s: invalid permission level %d", r, int(l))
		}
		if m, _ := maxLevel(r); l > m {
			return fmt.Errorf("%s: %s is not supported (max %s)", r, l, m)
		}
	}
	return nil
}

// Allows reports whether the permission set grants action on resource.
// Unknown resources and unknown actions are denied. Write implies read.
func (p Permissions) Allows(r Resource, a Action) bool {
	m, ok := maxLevel(r)
	if !ok {
		return false
	}
	have := p.Level(r)
	if have < None || have > Write {
		return false // corrupt stored value: deny rather than guess
	}
	if have > m {
		have = m
	}
	switch a {
	case ActionRead:
		return have >= Read
	case ActionWrite:
		return have >= Write
	}
	return false
}

// Kind separates keys that manage the broker from keys that use it.
type Kind string

// Key kinds.
const (
	KindData  Kind = "data"
	KindAdmin Kind = "admin"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return k == KindData || k == KindAdmin }

// Surface is which API a request targets.
type Surface string

// API surfaces.
const (
	SurfaceData  Surface = "data"
	SurfaceAdmin Surface = "admin"
)

// Code is a stable 403 reason code.
type Code string

// Reason codes returned in 403 bodies and written to the audit log.
const (
	CodeKind       Code = "kind"
	CodePermission Code = "permission"
	CodeOutOfScope Code = "out_of_scope"
)

// Denial is a failed authorization. It is an error so callers can return it.
type Denial struct {
	Code   Code
	Detail string
}

func (d *Denial) Error() string { return string(d.Code) + ": " + d.Detail }

// CheckKind enforces admin/data separation: admin keys cannot use the data
// API and data keys cannot use the admin API. Unknown kinds and surfaces
// are denied.
func CheckKind(k Kind, s Surface) *Denial {
	switch {
	case k == KindData && s == SurfaceData, k == KindAdmin && s == SurfaceAdmin:
		return nil
	case k.Valid() && (s == SurfaceData || s == SurfaceAdmin):
		return &Denial{CodeKind, fmt.Sprintf("%s keys cannot use the %s API", k, s)}
	}
	return &Denial{CodeKind, "unknown key kind or API surface"}
}

// Authorize runs the kind check then the resource permission check
// (SPEC 6.4 steps 2 and 3) for the data API. Admin endpoints need only
// CheckKind.
func Authorize(k Kind, p Permissions, r Resource, a Action) *Denial {
	if d := CheckKind(k, SurfaceData); d != nil {
		return d
	}
	if !p.Allows(r, a) {
		return &Denial{CodePermission, fmt.Sprintf("key has no %s access to %s", a, r)}
	}
	return nil
}

// ScopeType selects how a key's boxes are chosen.
type ScopeType string

// Scope types.
const (
	ScopeAll         ScopeType = "all"
	ScopeBoxes       ScopeType = "boxes"
	ScopeGroups      ScopeType = "groups"
	ScopeBoxesGroups ScopeType = "boxes+groups"
)

// Scope is the set of boxes a data key may act on.
type Scope struct {
	Type     ScopeType `json:"type"`
	GIDs     []string  `json:"gids,omitempty"`
	GroupIDs []string  `json:"group_ids,omitempty"`
}

// Validate checks that the scope is internally consistent: the lists
// required by the type are present and no list the type forbids is.
func (s Scope) Validate() error {
	switch s.Type {
	case ScopeAll:
		if len(s.GIDs) > 0 || len(s.GroupIDs) > 0 {
			return fmt.Errorf("scope all takes no gids or group_ids")
		}
	case ScopeBoxes:
		if len(s.GroupIDs) > 0 {
			return fmt.Errorf("scope boxes takes no group_ids")
		}
		if len(s.GIDs) == 0 {
			return fmt.Errorf("scope boxes needs at least one gid")
		}
	case ScopeGroups:
		if len(s.GIDs) > 0 {
			return fmt.Errorf("scope groups takes no gids")
		}
		if len(s.GroupIDs) == 0 {
			return fmt.Errorf("scope groups needs at least one group id")
		}
	case ScopeBoxesGroups:
		if len(s.GIDs) == 0 || len(s.GroupIDs) == 0 {
			return fmt.Errorf("scope boxes+groups needs gids and group_ids")
		}
	default:
		return fmt.Errorf("unknown scope type %q", s.Type)
	}
	for _, g := range s.GIDs {
		if !ValidGID(g) {
			return fmt.Errorf("invalid gid %q", g)
		}
	}
	for _, g := range s.GroupIDs {
		if strings.TrimSpace(g) == "" {
			return fmt.Errorf("empty group id")
		}
	}
	return nil
}

// ValidGID reports whether s is a plausible box id: 1-64 characters of
// [A-Za-z0-9-]. It deliberately excludes whitespace, wildcards, commas,
// colons and parentheses so a gid can never alter query structure.
func ValidGID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}
