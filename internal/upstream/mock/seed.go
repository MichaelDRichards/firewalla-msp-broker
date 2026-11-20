package mock

import "fmt"

// Placeholder identifiers used by the seed data. Tests import these.
const (
	// DefaultToken is the token the mock accepts unless configured otherwise.
	// It is a placeholder, not a credential.
	DefaultToken = "mock-upstream-token-example"

	GID1 = "00000000-0000-0000-0000-000000000001"
	GID2 = "00000000-0000-0000-0000-000000000002"
	GID3 = "00000000-0000-0000-0000-000000000003"
	GID4 = "00000000-0000-0000-0000-000000000004"
	GID5 = "00000000-0000-0000-0000-000000000005"

	GroupA = "group-a"
	GroupB = "group-b"

	// GlobalOwner is the owner value of MSP-owned (global) target lists.
	GlobalOwner = "global"

	// DeviceMAC is the only MAC used in fixtures.
	DeviceMAC = "AA:BB:CC:DD:EE:FF"
)

// baseTS is the epoch-seconds origin of seeded timestamps.
const baseTS = 1700000000

// Seed returns the standard seed state:
//
//   - five boxes: GID1, GID2 in GroupA; GID3, GID4 in GroupB; GID5 in no group
//   - per box: one device, three alarms, two rules, four flows
//   - target lists: two global, one each owned by GID1, GID3 and GID5
//
// Every identifier, address and name is a documented placeholder.
func Seed() State {
	var s State
	boxes := []struct {
		gid, name, group string
	}{
		{GID1, "Example Box 1", GroupA},
		{GID2, "Example Box 2", GroupA},
		{GID3, "Example Box 3", GroupB},
		{GID4, "Example Box 4", GroupB},
		{GID5, "Example Box 5 (ungrouped)", ""},
	}
	for i, b := range boxes {
		n := i + 1
		box := Object{
			"gid":      b.gid,
			"name":     b.name,
			"model":    "example-model",
			"online":   true,
			"publicIP": fmt.Sprintf("203.0.113.%d", n),
			"group":    nil,
		}
		if b.group != "" {
			box["group"] = b.group
		}
		s.Boxes = append(s.Boxes, box)

		s.Devices = append(s.Devices, Object{
			"id":        DeviceMAC,
			"gid":       b.gid,
			"name":      fmt.Sprintf("Example Device %d", n),
			"ip":        fmt.Sprintf("192.0.2.%d", 10+n),
			"macVendor": "Example Vendor",
			"online":    true,
		})

		for a := 1; a <= 3; a++ {
			s.Alarms = append(s.Alarms, Object{
				"aid":     fmt.Sprintf("%d%d", n, a),
				"gid":     b.gid,
				"ts":      baseTS + n*1000 + a*10,
				"type":    a,
				"status":  1,
				"message": fmt.Sprintf("Example alarm %d on box %d", a, n),
				"device":  Object{"id": DeviceMAC, "name": fmt.Sprintf("Example Device %d", n), "ip": fmt.Sprintf("192.0.2.%d", 10+n)},
				"remote":  Object{"domain": "example.com"},
			})
		}

		for r := 1; r <= 2; r++ {
			status := "active"
			if r == 2 {
				status = "paused"
			}
			s.Rules = append(s.Rules, Object{
				"id":        fmt.Sprintf("rule-%d%d", n, r),
				"gid":       b.gid,
				"action":    "block",
				"direction": "bidirection",
				"status":    status,
				"target":    Object{"type": "domain", "value": fmt.Sprintf("blocked%d.example.net", r)},
				"ts":        baseTS + n*1000 + r*10,
			})
		}

		for f := 1; f <= 4; f++ {
			domain := "example.com"
			if f%2 == 0 {
				domain = "example.net"
			}
			s.Flows = append(s.Flows, Object{
				"gid":       b.gid,
				"ts":        baseTS + n*1000 + f*10,
				"protocol":  "tcp",
				"direction": "outbound",
				"block":     f == 4,
				"count":     f,
				"domain":    domain,
				"device":    Object{"id": DeviceMAC, "ip": fmt.Sprintf("192.0.2.%d", 10+n)},
				"remoteIP":  fmt.Sprintf("198.51.100.%d", f),
			})
		}
	}

	s.TargetLists = []Object{
		{"id": "tl-global-1", "owner": GlobalOwner, "name": "Example global list 1", "targets": []any{"example.com"}, "category": "custom"},
		{"id": "tl-global-2", "owner": GlobalOwner, "name": "Example global list 2", "targets": []any{"example.net", "198.51.100.7"}, "category": "custom"},
		{"id": "tl-1", "owner": GID1, "name": "Example list for box 1", "targets": []any{"example.com"}, "category": "custom"},
		{"id": "tl-3", "owner": GID3, "name": "Example list for box 3", "targets": []any{"example.net"}, "category": "custom"},
		{"id": "tl-5", "owner": GID5, "name": "Example list for box 5", "targets": []any{"203.0.113.9"}, "category": "custom"},
	}
	return s
}
