package acl

import (
	"encoding/json"
	"reflect"
	"testing"
)

// decode parses JSON the way the upstream client does.
func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func encode(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Nested objects that carry a gid or owner are held to the same rule as the
// top level: out of scope means gone.
func TestScopeObjectPrunesNested(t *testing.T) {
	e := Resolve(Scope{Type: ScopeBoxes, GIDs: []string{g1}}, nil)
	cases := []struct {
		name, in, want string
		global         bool
	}{
		{"nested foreign in array",
			`{"gid":"` + g1 + `","related":[{"gid":"` + g2 + `","name":"x"}]}`,
			`{"gid":"` + g1 + `","related":[]}`, false},
		{"reviewer payload",
			`{"gid":"` + g1 + `","name":"mine","related":[{"gid":"` + g2 + `","name":"nested-foreign","tokenish":"should-not-pass"}]}`,
			`{"gid":"` + g1 + `","name":"mine","related":[]}`, false},
		{"nested in scope kept",
			`{"gid":"` + g1 + `","related":[{"gid":"` + g1 + `","n":1},{"gid":"` + g2 + `"}]}`,
			`{"gid":"` + g1 + `","related":[{"gid":"` + g1 + `","n":1}]}`, false},
		{"nested foreign as a map value",
			`{"gid":"` + g1 + `","parent":{"gid":"` + g2 + `"},"keep":1}`,
			`{"gid":"` + g1 + `","keep":1}`, false},
		{"foreign owner nested",
			`{"gid":"` + g1 + `","list":{"owner":"` + g3 + `","n":1}}`,
			`{"gid":"` + g1 + `"}`, false},
		{"deeply nested",
			`{"gid":"` + g1 + `","a":{"b":[{"c":[{"gid":"` + g2 + `"}],"d":2}]}}`,
			`{"gid":"` + g1 + `","a":{"b":[{"c":[],"d":2}]}}`, false},
		{"array of arrays",
			`{"gid":"` + g1 + `","a":[[{"gid":"` + g2 + `"},{"gid":"` + g1 + `"}]]}`,
			`{"gid":"` + g1 + `","a":[[{"gid":"` + g1 + `"}]]}`, false},
		{"nested without an owner is plain data",
			`{"gid":"` + g1 + `","stats":{"hits":3},"tags":["a","b"],"x":null}`,
			`{"gid":"` + g1 + `","stats":{"hits":3},"tags":["a","b"],"x":null}`, false},
		{"nested gid of the wrong type fails closed",
			`{"gid":"` + g1 + `","a":[{"gid":2},{"gid":null},{"gid":["` + g1 + `"]},{"gid":""},{"gid":"  "}],"b":{"owner":7}}`,
			`{"gid":"` + g1 + `","a":[]}`, false},
		{"nested key in another case",
			`{"gid":"` + g1 + `","a":[{"GID":"` + g2 + `"},{"Owner":"` + g2 + `"},{"Gid":"` + g1 + `"}]}`,
			`{"gid":"` + g1 + `","a":[{"Gid":"` + g1 + `"}]}`, false},
		{"nested global owner needs the permission",
			`{"owner":"` + g1 + `","a":[{"owner":"global"}]}`,
			`{"owner":"` + g1 + `","a":[]}`, false},
		{"nested global owner allowed",
			`{"owner":"` + g1 + `","a":[{"owner":"global"}]}`,
			`{"owner":"` + g1 + `","a":[{"owner":"global"}]}`, true},
		{"nested one id in scope, the other not",
			`{"gid":"` + g1 + `","a":[{"gid":"` + g1 + `","owner":"` + g2 + `"}]}`,
			`{"gid":"` + g1 + `","a":[]}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := decode(t, c.in)
			before := encode(t, in)
			got, ok := ScopeObject(in, e, c.global)
			if !ok {
				t.Fatal("top-level object was refused")
			}
			if g, w := encode(t, got), encode(t, decode(t, c.want)); g != w {
				t.Errorf("got  %s\nwant %s", g, w)
			}
			if encode(t, in) != before {
				t.Error("the input object was modified")
			}
		})
	}
}

// An extra key spelled another way at the top level is also an ownership
// claim: if it names a box out of scope the whole object goes.
func TestScopeObjectTopLevelStaysStrict(t *testing.T) {
	e := Resolve(Scope{Type: ScopeBoxes, GIDs: []string{g1}}, nil)
	for name, in := range map[string]string{
		"extra GID foreign":      `{"gid":"` + g1 + `","GID":"` + g2 + `"}`,
		"extra Owner foreign":    `{"gid":"` + g1 + `","Owner":"` + g2 + `"}`,
		"extra GID wrong type":   `{"gid":"` + g1 + `","GID":5}`,
		"foreign gid":            `{"gid":"` + g2 + `"}`,
		"no gid":                 `{"name":"x"}`,
		"gid and owner differ":   `{"gid":"` + g1 + `","owner":"` + g2 + `"}`,
		"only a nested in-scope": `{"a":{"gid":"` + g1 + `"}}`,
	} {
		if got, ok := ScopeObject(decode(t, in), e, false); ok {
			t.Errorf("%s: kept as %s", name, encode(t, got))
		}
	}
	if _, ok := ScopeObject(decode(t, `{"gid":"`+g1+`","GID":"`+g1+`"}`), e, false); !ok {
		t.Error("an extra GID naming the same in-scope box was refused")
	}
}

func TestFilterObjectsPrunesNested(t *testing.T) {
	e := Resolve(Scope{Type: ScopeBoxes, GIDs: []string{g1}}, nil)
	in := []map[string]any{
		decode(t, `{"gid":"`+g1+`","related":[{"gid":"`+g2+`"}]}`),
		decode(t, `{"gid":"`+g2+`"}`),
	}
	got := FilterObjects(in, e, false)
	if len(got) != 1 || !reflect.DeepEqual(got[0]["related"], []any{}) {
		t.Errorf("FilterObjects = %s", encode(t, got))
	}
}
