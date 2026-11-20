package acl

import (
	"errors"
	"strings"
	"testing"
)

func listScope() *Effective { return Resolve(Scope{Type: ScopeBoxes, GIDs: []string{g1, g2}}, fleet) }
func allScope() *Effective  { return Resolve(Scope{Type: ScopeAll}, fleet) }

const (
	b1   = "box.id:" + g1
	b2   = "box.id:" + g2
	both = "(" + b1 + " OR " + b2 + ")"
)

type qcase struct {
	name  string
	in    string
	final string // expected Final, when accepted
	query string // expected stripped Query, when accepted
}

func TestScopeQueryListScopeAccepted(t *testing.T) {
	cases := []qcase{
		{"empty", "", both, ""},
		{"plain term", "status:active", "status:active " + both, "status:active"},
		{"several terms", "status:active type:2", "status:active type:2 " + both, "status:active type:2"},
		{"phrase", `"hello world"`, `"hello world" ` + both, `"hello world"`},
		{"quoted value", `device.name:"my laptop"`, `device.name:"my laptop" ` + both, `device.name:"my laptop"`},
		{"top-level OR is parenthesised", "a OR b", "(a OR b) " + both, "a OR b"},
		{"lowercase or", "a or b", "(a OR b) " + both, "a OR b"},
		{"explicit AND", "a AND b", "a AND b " + both, "a AND b"},
		{"negated term kept", "-type:2", "-type:2 " + both, "-type:2"},
		{"NOT term kept", "NOT type:2", "NOT type:2 " + both, "NOT type:2"},
		{"group kept", "(a OR b) c", "(a OR b) c " + both, "(a OR b) c"},

		{"in-scope qualifier narrows", b1, b1, ""},
		{"upper-case key", "BOX.ID:" + g1, b1, ""},
		{"mixed-case key", "Box.Id:" + g1, b1, ""},
		{"quoted key double", `"box.id":` + g1, b1, ""},
		{"quoted key single", `'box.id':` + g1, b1, ""},
		{"quoted value", `box.id:"` + g1 + `"`, b1, ""},
		{"single-quoted value", `box.id:'` + g1 + `'`, b1, ""},
		{"upper-case gid value", "box.id:" + strings.ToUpper(g1), b1, ""},
		{"comma list", "box.id:" + g1 + "," + g2, both, ""},
		{"comma list with spaces in quotes", `box.id:"` + g1 + ", " + g2 + `"`, both, ""},
		{"value group OR", "box.id:(" + g1 + " OR " + g2 + ")", both, ""},
		{"value group implicit", "box.id:(" + g1 + " " + g2 + ")", both, ""},
		{"qualifier with other term", "status:active " + b1, "status:active " + b1, "status:active"},
		{"qualifier first", b1 + " status:active", "status:active " + b1, "status:active"},
		{"qualifier OR other (stripped, narrowed)", b1 + " OR type:2", "type:2 " + b1, "type:2"},
		{"other OR qualifier", "type:2 OR " + b1, "type:2 " + b1, "type:2"},
		{"qualifier in parens with OR", "(" + b1 + " OR type:2)", "(type:2) " + b1, "(type:2)"},
		{"qualifier alone in parens", "(" + b1 + ")", b1, ""},
		{"nested parens", "((" + b1 + "))", b1, ""},
		{"duplicates collapse", b1 + " " + b1 + " " + strings.ToUpper(b1), b1, ""},
		{"two qualifiers", b1 + " " + b2, both, ""},
		{"dangling OR dropped", "a OR", "a " + both, "a"},
		{"leading OR is a word", "OR a", "OR a " + both, "OR a"},
		{"AND between removed and kept", b1 + " AND type:2", "type:2 " + b1, "type:2"},

		{"exclusion", "-" + b2, b1, ""},
		{"exclusion with NOT", "NOT " + b2, b1, ""},
		{"exclusion with bang", "!" + b2, b1, ""},
		{"exclusion of in-scope box plus term", "status:active -" + b1, "status:active " + b2, "status:active"},
		{"double negation is positive", "--" + b1, b1, ""},
		{"NOT NOT is positive", "NOT NOT " + b1, b1, ""},
		{"negated group inverts parity", "-(" + b1 + ")", b2, ""},
		{"percent-encoded colon", "box.id%3A" + g1, b1, ""},
		{"percent-encoded dot", "box%2Eid:" + g1, b1, ""},
		{"percent-encoded dot lowercase hex", "box%2eid:" + g1, b1, ""},
		{"percent-encoded first letter", "%62ox.id:" + g1, b1, ""},
		{"fully encoded key", "%62%6f%78%2e%69%64%3a" + g1, b1, ""},
		{"double encoded", "box%252Eid%253A" + g1, b1, ""},
		{"triple encoded", "box%25252Eid%25253A" + g1, b1, ""},
		{"encoded space between terms", "status:active%20" + b1, "status:active " + b1, "status:active"},
		{"encoded newline between terms", "status:active%0A" + b1, "status:active " + b1, "status:active"},
		{"encoded value quote", "box.id:%22" + g1 + "%22", b1, ""},
		{"invalid escape left alone", "name:100%zz " + b1, "name:100%zz " + b1, "name:100%zz"},
		{"invalid escape does not block decoding", "%zz box%2Eid:" + g1, "%zz " + b1, "%zz"},
		{"trailing percent", "name:abc%", "name:abc% " + both, "name:abc%"},
		{"tab separated", "status:active\t" + b1, "status:active " + b1, "status:active"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := ScopeQuery(c.in, listScope())
			if err != nil {
				t.Fatalf("ScopeQuery(%q): %v", c.in, err)
			}
			if r.Final != c.final {
				t.Errorf("Final = %q, want %q", r.Final, c.final)
			}
			if r.Query != c.query {
				t.Errorf("Query = %q, want %q", r.Query, c.query)
			}
			assertInvariant(t, r, listScope())
		})
	}
}

func TestScopeQueryResultFields(t *testing.T) {
	r, err := ScopeQuery("-"+b2+" "+b1, listScope())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Requested, ",") != g1 || strings.Join(r.Excluded, ",") != g2 || strings.Join(r.GIDs, ",") != g1 || r.Unrestricted || r.Empty {
		t.Errorf("%+v", r)
	}
	// Requested and excluded the same box: nothing left.
	r, err = ScopeQuery(b1+" -"+b1, listScope())
	if err != nil || !r.Empty || r.Final != "" || len(r.GIDs) != 0 || r.GIDs == nil {
		t.Errorf("want empty, got %+v %v", r, err)
	}
	// Excluding every box in scope.
	r, err = ScopeQuery("-(box.id:"+g1+" OR box.id:"+g2+")", listScope())
	if err != nil || !r.Empty {
		t.Errorf("want empty, got %+v %v", r, err)
	}
	// No boxes in scope at all.
	r, err = ScopeQuery("status:active", Resolve(Scope{Type: ScopeGroups, GroupIDs: []string{"group-z"}}, fleet))
	if err != nil || !r.Empty || r.Final != "" {
		t.Errorf("want empty, got %+v %v", r, err)
	}
	r, err = ScopeQuery("status:active", nil)
	if err != nil || !r.Empty {
		t.Errorf("nil scope must be empty, got %+v %v", r, err)
	}
}

func TestScopeQueryGroupScope(t *testing.T) {
	e := Resolve(Scope{Type: ScopeGroups, GroupIDs: []string{"group-a"}}, fleet)
	r, err := ScopeQuery("type:2", e)
	if err != nil || r.Final != "type:2 "+both {
		t.Errorf("%+v %v", r, err)
	}
	if _, err := ScopeQuery("box.id:"+g3, e); !isDenial(err, CodeOutOfScope) {
		t.Errorf("group-b box via group-a key: %v", err)
	}
	if r, err := ScopeQuery("box.id:"+g2, e); err != nil || r.Final != b2 {
		t.Errorf("%+v %v", r, err)
	}
}

func TestScopeQueryAllScope(t *testing.T) {
	cases := []qcase{
		{"empty stays empty", "", "", ""},
		{"term untouched", "status:active", "status:active", "status:active"},
		{"OR untouched, no wrap needed", "a OR b", "a OR b", "a OR b"},
		{"named box (even a future one)", "box.id:" + g5, "box.id:" + g5, ""},
		{"two boxes", "box.id:" + g4 + "," + g5, "(box.id:" + g4 + " OR box.id:" + g5 + ")", ""},
		{"exclusion becomes negative filter", "-box.id:" + g3, "-box.id:" + g3, ""},
		{"exclusion plus term", "type:2 -box.id:" + g3, "type:2 -box.id:" + g3, "type:2"},
		{"two exclusions", "-box.id:" + g4 + " -box.id:" + g3, "-box.id:" + g3 + " -box.id:" + g4, ""},
		{"OR with exclusion is wrapped", "a OR b -box.id:" + g3, "(a OR b) -box.id:" + g3, "a OR b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := ScopeQuery(c.in, allScope())
			if err != nil {
				t.Fatal(err)
			}
			if r.Final != c.final || r.Query != c.query {
				t.Errorf("Final=%q Query=%q want %q / %q", r.Final, r.Query, c.final, c.query)
			}
			assertInvariant(t, r, allScope())
		})
	}
	r, _ := ScopeQuery("x", allScope())
	if !r.Unrestricted || r.GIDs != nil || r.Empty {
		t.Errorf("all scope: %+v", r)
	}
	r, _ = ScopeQuery("box.id:"+g5+" -box.id:"+g5, allScope())
	if !r.Empty {
		t.Errorf("requested and excluded: %+v", r)
	}
}

func TestScopeQueryRejectsOutOfScope(t *testing.T) {
	bad := []string{
		"box.id:" + g3,
		"BOX.ID:" + g3,
		"-box.id:" + g3,
		"NOT box.id:" + g3,
		"!box.id:" + g3,
		"--box.id:" + g3,
		"box.id:" + g1 + "," + g3,
		"box.id:" + g3 + "," + g1,
		"box.id:(" + g1 + " OR " + g3 + ")",
		"box.id:(" + g3 + ")",
		"status:active box.id:" + g3,
		"(a OR box.id:" + g3 + ")",
		"a OR box.id:" + g3,
		b1 + " OR box.id:" + g3,
		"((a (b OR (box.id:" + g3 + "))))",
		`"box.id":` + g3,
		`'box.id':` + g3,
		`box.id:"` + g3 + `"`,
		"box.id:" + g5,                   // a box that exists but is not in scope
		"box.id:*",                       // wildcard
		"box.id:" + g1 + "*",             // prefix wildcard
		"box.id:0000*",                   // wildcard
		"box.id:?",                       // glob
		"box.id:" + g1 + ";" + g3,        // separator trickery
		"box.id:" + g1 + "|" + g3,        // separator trickery
		"box.id:" + g1 + "/" + g3,        // separator trickery
		"box.id:[" + g1 + "," + g3 + "]", // brackets
		"box.id:" + g1 + `"` + g3,        // stray quote
		"box.id:.*",                      // regex
		"box.id:" + strings.Repeat("a", 65),

		// encoded variants
		"box.id%3A" + g3,
		"box%2Eid:" + g3,
		"box%2eid%3a" + g3,
		"%62ox.id:" + g3,
		"%42%4F%58.id:" + g3,
		"box%252Eid%253A" + g3,
		"box%25252Eid%25253A" + g3,
		"%2D" + "box.id:" + g3,
		"%28box.id:" + g3 + "%29",
		"a%20OR%20box.id:" + g3,
		"a%0Abox.id:" + g3,
		"a%09box.id:" + g3,
		"%22box.id%22:" + g3,
		"box.id:%22" + g3 + "%22",
		"box.id:" + g1 + "%2C" + g3,
		"box.id:%28" + g1 + "%20OR%20" + g3 + "%29",

		// structure the parser must not be fooled by
		"box.id :" + g3,                   // space before colon
		"box.id : " + g3,                  // spaces around colon
		"box.id",                          // bare key
		"box.id:" + g3 + ")(",             // unbalanced -> caught earlier or here
		"x:(box.id:" + g3 + ")",           // value group of another key
		"x:(y:(box.id:" + g3 + "))",       // nested value groups
		`"foo box.id:` + g3 + `"`,         // inside a phrase
		`name:"box.id:` + g3 + `"`,        // inside a quoted value
		`name:"x" "box.id" ` + b1,         // bare phrase mentioning it
		"a+box.id:" + g3,                  // plus as separator after a second decode
		"a,box.id:" + g3,                  // comma glue
		"a;box.id:" + g3,                  // semicolon glue
		"a&box.id:" + g3,                  // ampersand glue
		"a\\box.id:" + g3,                 // backslash
		"\\box.id:" + g3,                  // backslash prefix
		"a\"box.id:" + g3,                 // stray quote then key (quote handling)
		"x\"box.id:" + g3 + "\"",          // quote glued to a word
		"box.id:" + g3 + "\"",             // trailing quote
		"box..id:" + g3 + " box.id:" + g3, // one bad one, one weird
	}
	for _, in := range bad {
		t.Run(in, func(t *testing.T) {
			r, err := ScopeQuery(in, listScope())
			if err == nil {
				t.Fatalf("accepted %q -> %+v", in, r)
			}
			var d *Denial
			var qe *QueryError
			switch {
			case errors.As(err, &d):
				if d.Code != CodeOutOfScope {
					t.Errorf("code %q", d.Code)
				}
			case errors.As(err, &qe):
				// A syntax rejection is acceptable for the structurally broken cases.
			default:
				t.Errorf("unexpected error type %T", err)
			}
		})
	}
}

func TestScopeQueryRejectsOutOfScopeEvenForAllWhenMalformed(t *testing.T) {
	for _, in := range []string{"box.id:*", "box.id:", `box.id:""`, "box.id:,", "box.id :" + g1, "box.id", `"x box.id"`} {
		if r, err := ScopeQuery(in, allScope()); err == nil {
			t.Errorf("all scope accepted %q -> %+v", in, r)
		}
	}
}

func TestScopeQueryDenialCodeIsOutOfScope(t *testing.T) {
	_, err := ScopeQuery("box.id:"+g3, listScope())
	var d *Denial
	if !errors.As(err, &d) || d.Code != CodeOutOfScope {
		t.Fatalf("want out_of_scope denial, got %v", err)
	}
	if !strings.Contains(d.Detail, g3) {
		t.Errorf("detail should name the box: %q", d.Detail)
	}
	if long := strings.Repeat("z", 500); true {
		_, err = ScopeQuery("box.id:"+long, listScope())
		if !errors.As(err, &d) || len(d.Detail) > 200 {
			t.Errorf("detail must be clipped: %v", err)
		}
	}
}

func TestScopeQuerySyntaxErrors(t *testing.T) {
	bad := []string{
		"(a",
		"a)",
		"((a)",
		"(a))",
		")",
		"(",
		`"unterminated`,
		"name:'unterminated",
		"box.id:(" + g1,
		"%00",
		"a%07b",
		"a\x00b",
		"a\x7fb",
		overEncoded(10),
		strings.Repeat("a", maxQueryLen+1),   // too long
		strings.Repeat("(", maxGroupDepth+2), // too deep
	}
	for _, in := range bad {
		r, err := ScopeQuery(in, listScope())
		var qe *QueryError
		if err == nil || !errors.As(err, &qe) {
			t.Errorf("%q: want QueryError, got %v %+v", in, err, r)
		}
	}
	// A lone NOT / OR / AND are plain words.
	for _, w := range []string{"NOT", "OR", "AND", "-", "!", "not"} {
		r, err := ScopeQuery(w, listScope())
		if err != nil || !strings.HasPrefix(r.Final, w) {
			t.Errorf("%q: %+v %v", w, r, err)
		}
	}
}

func TestDecodeFully(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		"a%20b":       "a b",
		"a%2520b":     "a b",
		"%2525252541": "A",
		"100%":        "100%",
		"%4":          "%4",
		"%zz%41":      "%zzA",
		"a+b":         "a+b",
		"%25":         "%",
		"%2541":       "A", // %25 -> % then %41 -> A: decoded until stable
		"50%25off":    "50%off",
		"%E2%82%AC":   "\u20ac",
	}
	for in, want := range cases {
		got, err := decodeFully(in)
		if err != nil || got != want {
			t.Errorf("decodeFully(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func overEncoded(n int) string {
	s := "%41"
	for i := 0; i < n; i++ {
		s = strings.ReplaceAll(s, "%", "%25")
	}
	return s
}

func isDenial(err error, c Code) bool {
	var d *Denial
	return errors.As(err, &d) && d.Code == c
}

// assertInvariant: nothing the caller wrote can leave a box.id behind, and
// every box.id in Final is one the broker wrote for an in-scope gid.
func assertInvariant(t *testing.T, r *ScopedQuery, e *Effective) {
	t.Helper()
	if strings.Contains(strings.ToLower(r.Query), "box.id") {
		t.Errorf("Query still contains box.id: %q", r.Query)
	}
	if r.Empty {
		if r.Final != "" {
			t.Errorf("Empty but Final=%q", r.Final)
		}
		return
	}
	want := len(r.GIDs)
	if r.Unrestricted {
		want = len(r.Excluded)
	}
	if got := strings.Count(strings.ToLower(r.Final), "box.id"); got != want {
		t.Errorf("Final %q has %d box.id terms, want %d", r.Final, got, want)
	}
	for _, g := range r.GIDs {
		if !e.Contains(g) {
			t.Errorf("GIDs contains out-of-scope %s", g)
		}
	}
	for _, g := range r.Requested {
		if !e.Contains(g) {
			t.Errorf("Requested contains out-of-scope %s", g)
		}
	}
	if !r.Unrestricted && len(r.GIDs) == 0 {
		t.Errorf("bounded result with no gids: %+v", r)
	}
	if r.Final != "" && decodedDiffers(r.Final) {
		t.Errorf("Final still has percent-escapes: %q", r.Final)
	}
}

func decodedDiffers(s string) bool { d, err := decodeFully(s); return err != nil || d != s }

func FuzzScopeQuery(f *testing.F) {
	seeds := []string{
		"", "status:active", b1, "-" + b1, "(" + b1 + " OR a)", "box%2Eid:" + g1, `"box.id":` + g1,
		"box.id:" + g3, "NOT (a OR -" + b2 + ")", "box.id:(" + g1 + "," + g2 + ")", "a OR b OR box.id:" + g1,
		"box.id :" + g3, `x:"box.id:` + g3 + `"`, "((((", "))))", "%252525", "\tbox.id:" + g1,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	e := listScope()
	f.Fuzz(func(t *testing.T, in string) {
		r, err := ScopeQuery(in, e)
		if err != nil {
			var d *Denial
			var q *QueryError
			if !errors.As(err, &d) && !errors.As(err, &q) {
				t.Fatalf("unexpected error type %T", err)
			}
			return
		}
		assertInvariant(t, r, e)
	})
}
