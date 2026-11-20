package repocheck

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// exceptions are the tracked files the scan applies to with an allowance.
// Each is explained in docs/DECISIONS.md. docs/SPEC.md is NOT here: it is
// scanned like every other file.
//
//   - go.mod and go.sum are NOT here: they get no allowance, but the
//     `host/` of each module path in them is removed before the scan
//     (modules.go), so only that position is excused.
//   - LICENSE is the verbatim AGPL text, which names the licensor's site
//     in its header; only that one host is excused, and only in that file.
//   - docs/SPEC.md is HQ's file, taken verbatim. It is scanned in full; the
//     one host it names that is not on the SPEC 15 list is the container
//     registry in its Dockerfile line, so that single host is excused there
//     and nothing else. HQ can drop this entry by rewording that line.
var exceptions = map[string]func(normalised string) bool{
	"LICENSE":      func(h string) bool { return h == "fsf"+".org" },
	"docs/SPEC.md": func(h string) bool { return h == "gcr"+".io" },
}

// join builds test inputs from pieces, so this file itself holds no
// look-alike host and passes the tree scan it defines.
func join(parts ...string) string { return strings.Join(parts, "") }

// listFiles lists the tree's files: what git tracks when root is a git
// checkout, otherwise (an exported tree) every file except the .git
// directory at the root.
func listFiles(root string) ([]string, error) {
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		if out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output(); err == nil {
			var files []string
			for _, f := range bytes.Split(out, []byte{0}) {
				if len(f) > 0 {
					files = append(files, string(f))
				}
			}
			return files, nil
		}
		// not a usable repository (an exported tree that kept a .git): walk it
	}
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() && rel == ".git" {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	return files, err
}

// readTree returns the raw text of every file listFiles finds, by path. No
// file is skipped, not even one with NUL bytes: a binary format that holds a
// host is exactly what the scan is for, and the patterns stop at a NUL, so
// the text on either side of it is scanned.
func readTree(root string) (map[string]string, error) {
	files, err := listFiles(root)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		out[rel] = string(data)
	}
	return out, nil
}

// scanTree scans every file and returns the hits by path. go.mod and go.sum
// lose only the `host/` of their module paths; .go files lose only the
// `host/` of those modules where it starts an import path (modules.go);
// so do .md files, which name module paths in prose.
func scanTree(files map[string]string) map[string][]string {
	var hosts []string
	if mod, ok := files["go.mod"]; ok {
		hosts = ModuleHosts(mod, false)
	}
	out := map[string][]string{}
	for rel, text := range files {
		switch {
		case rel == "go.mod":
			text = StripModulePaths(text, false)
		case rel == "go.sum":
			text = StripModulePaths(text, true)
		case strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, ".md"):
			text = StripImports(text, hosts)
		}
		if hits := Scan(text, exceptions[rel]); len(hits) > 0 {
			out[rel] = hits
		}
	}
	return out
}

// scanDir reads and scans the tree at root.
func scanDir(root string) (map[string][]string, error) {
	files, err := readTree(root)
	if err != nil {
		return nil, err
	}
	return scanTree(files), nil
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// plant writes files into a fresh directory (not a git checkout, so the
// walker is used) and scans it.
func plant(t *testing.T, files map[string]string) map[string][]string {
	t.Helper()
	dir := t.TempDir()
	for rel, text := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	hits, err := scanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

// The red-team regression for finding 3: the tree holds no real domains,
// emails or IPs. docs/SPEC.md is scanned too (round 2: its exception is gone).
func TestRedTeamTreeHasNoRealHostsEmailsOrIPs(t *testing.T) {
	files, err := readTree(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 20 {
		t.Fatalf("only %d files found: the scan proves nothing", len(files))
	}
	if _, ok := files["docs/SPEC.md"]; !ok {
		t.Fatal("docs/SPEC.md is not scanned")
	}
	for rel, hits := range scanTree(files) {
		for _, h := range hits {
			t.Errorf("%s: %s is not a placeholder or an allowed host", rel, h)
		}
	}
}

// The tree never names the company that runs this development environment.
func TestTreeHasNoCompanyName(t *testing.T) {
	files, err := readTree(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	needle := join("pilot", "co")
	for rel, text := range files {
		if strings.Contains(strings.ToLower(text), needle) {
			t.Errorf("%s contains %q", rel, needle)
		}
	}
}

// Round 2b, finding 1: go.mod and go.sum excuse nothing but the host of a
// module path. A customer host in a comment, a replace line or anywhere else
// in them fails, and so does a module path under one.
func TestRedTeamGoModAndSumExcuseOnlyModuleHosts(t *testing.T) {
	cust := join("customer.", "firewalla.net")
	reg := join("modernc", ".org")
	mod := "module mspbroker\n\ngo 1.27.3\n\nrequire " + reg + "/sqlite v1.62.0\n"
	sum := reg + "/sqlite v1.62.0 h1:abc=\n" + reg + "/sqlite v1.62.0/go.mod h1:def=\n"
	src := "import \"" + reg + "/sqlite\"\n"
	clean := map[string]string{"go.mod": mod, "go.sum": sum, "src.go": src}
	if hits := plant(t, clean); len(hits) != 0 {
		t.Fatalf("clean module files flagged: %v", hits)
	}
	with := func(over map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range clean {
			m[k] = v
		}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	plants := map[string]map[string]string{
		"comment in go.mod":              with(map[string]string{"go.mod": mod + "// planted " + cust + "\n"}),
		"trailing comment in go.mod":     with(map[string]string{"go.mod": strings.Replace(mod, "v1.62.0", "v1.62.0 // "+cust, 1)}),
		"extra line in go.sum":           with(map[string]string{"go.sum": sum + "# planted " + cust + "\n"}),
		"replace target":                 with(map[string]string{"go.mod": mod + "replace " + reg + "/sqlite => " + cust + "/fork v1.0.0\n"}),
		"require under customer":         with(map[string]string{"go.mod": mod + "require " + cust + "/mod v1.0.0\n"}),
		"sum line under customer":        with(map[string]string{"go.sum": sum + cust + "/mod v1.0.0 h1:abc=\n"}),
		"subdomain of an allowed host":   with(map[string]string{"go.mod": mod + "require " + join("api.", "github.com") + "/x v1.0.0\n"}),
		"bare unknown host in a comment": with(map[string]string{"go.mod": mod + "// see " + join("registry.", "acme-corp", ".io") + "\n"}),
		"email in go.mod":                with(map[string]string{"go.mod": mod + "// ops" + "@" + join("modernc", ".org") + "\n"}),
		"public IP in go.sum":            with(map[string]string{"go.sum": sum + "# " + join("8.", "8.", "8.", "8") + "\n"}),
		"import under customer":          with(map[string]string{"src.go": "import \"" + cust + "/mod\"\n"}),
		"customer under a module host":   with(map[string]string{"src.go": "import \"" + "customer." + reg + "/x\"\n"}),
		"customer require not erased from source": with(map[string]string{
			"go.mod": mod + "require " + cust + "/mod v1.0.0\n",
			"src.go": "import \"" + cust + "/mod\"\n",
		}),
	}
	for name, files := range plants {
		if hits := plant(t, files); len(hits) == 0 {
			t.Errorf("%s: not reported", name)
		}
	}
}

// Every allowed host passes, exactly as written, in a URL, in prose, in
// upper case (hosts are case-insensitive) and with one trailing root dot.
func TestAllowedHostsPass(t *testing.T) {
	for h := range AllowedHosts {
		for _, s := range []string{
			"https://" + h + "/path?q=1",
			"see " + h + " for details",
			"https://" + strings.ToUpper(h) + "/X",
			"fqdn " + h + ".",
			"at " + h + ":8443",
			"(" + h + ")",
		} {
			if hits := Scan(s, nil); len(hits) != 0 {
				t.Errorf("%q flagged: %v", s, hits)
			}
		}
	}
	if len(AllowedHosts) != 11 {
		t.Errorf("allowlist has %d hosts, SPEC 15 lists 11", len(AllowedHosts))
	}
}

// Tricky look-alikes are judged by exact host match after normalisation, so
// none of these is let through by the allowlist.
func TestLookAlikeHostsAreFlagged(t *testing.T) {
	bad := map[string]string{
		"subdomain of allowed":        "https://" + join("evil.", "firewalla.net") + "/x",
		"customer MSP subdomain":      "https://" + join("acme-corp.", "firewalla.net") + "/v2",
		"www not listed":              join("www.", "firewalla.com"),
		"docs on the .com":            join("docs.", "firewalla.com"),
		"other tld of allowed name":   join("firewalla", ".org"),
		"allowed host as a prefix":    join("firewalla.net.", "example"),
		"allowed host then evil tld":  join("firewalla.net.", "evil", ".com"),
		"upper case then evil":        join("FIREWALLA.NET.", "evil", ".com"),
		"mixed case subdomain":        join("Evil.", "Firewalla.", "Net"),
		"trailing dot subdomain":      "https://" + join("evil.", "firewalla.net.") + "/x",
		"trailing dot on lookalike":   join("evil", ".com."),
		"two trailing dots":           "see " + join("firewalla.net", ".."),
		"hyphen suffix":               join("firewalla.net-", "evil", ".com"),
		"github subdomain":            join("api.", "github.com"),
		"allowed host under evil":     join("github.com.", "evil", ".com"),
		"punycode label":              join("xn--", "e1afmkfd", ".net"),
		"punycode subdomain":          join("docs.", "xn--firewalla-9ea", ".net"),
		"unicode homograph":           join("f", string(rune(0x456)), "rewalla", ".net"),
		"percent-encoded dot":         join("evil%2E", "firewalla.net"),
		"percent-encoded dot (lower)": join("evil%2e", "firewalla.net"),
		"double percent-encoded dot":  join("evil%252E", "firewalla.net"),
		"percent-encoded suffix":      join("firewalla%2Enet%2E", "evil", ".com"),
		"percent-encoded letter":      join("%66irewalla", ".net"),
		"userinfo trick":              join("https://firewalla.net@", "evil", ".com/"),
		"email at allowed host":       join("ops@", "firewalla.net"),
		"email at allowed .com":       join("ops@", "firewalla.com"),
	}
	for name, s := range bad {
		if len(Scan(s, nil)) == 0 {
			t.Errorf("%s: not flagged: %q", name, s)
		}
	}
}

func TestNormalise(t *testing.T) {
	for in, want := range map[string]string{
		"firewalla.net":       "firewalla.net",
		"FIREWALLA.NET":       "firewalla.net",
		"Docs.Firewalla.Net.": "docs.firewalla.net",
	} {
		if got, ok := Normalise(in); !ok || got != want {
			t.Errorf("Normalise(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", ".", join("firewalla", ".net", ".."), "a..b", join("f", string(rune(0x456)), "rewalla", ".net")} {
		if got, ok := Normalise(in); ok {
			t.Errorf("Normalise(%q) = %q, want failure", in, got)
		}
	}
	if HostAllowed(join("evil.", "firewalla.net"), nil) || HostAllowed(join("firewalla.net.", "example"), nil) {
		t.Error("a look-alike passed HostAllowed")
	}
	if !HostAllowed("FIREWALLA.NET.", nil) {
		t.Error("case and one trailing dot should normalise to the allowed host")
	}
}

// The scanner itself: it must flag real-looking names (built here from
// pieces, so this file is clean) and pass placeholders.
func TestScannerFlagsRealLookingNamesAndPassesPlaceholders(t *testing.T) {
	bad := []string{
		"see https://" + "docs." + "acme-corp" + ".net/x",
		"host: " + "msp." + "firewalla" + ".com",
		"mail ops" + "@" + "acme-corp" + ".com now",
		"mail ops" + "@" + "sub." + "acme-corp" + ".io",
		"peer " + "8." + "8." + "8." + "8",
		"peer " + "10." + "1." + "2." + "3",
		"peer " + "172." + "16." + "0." + "9",
		"peer " + "2606:" + "4700:" + "4700:" + ":" + "1111",
		"peer " + "::ffff:" + "8." + "8." + "4." + "4",
		"fake " + "example.com.evil" + ".com",
		"fake " + "notexample" + ".com",
		"fsf host outside LICENSE: " + "fsf" + ".org",
	}
	for _, s := range bad {
		if len(Scan(s, nil)) == 0 {
			t.Errorf("not flagged: %q", s)
		}
	}
	good := []string{
		"https://msp.example.com/v2 and example.net and a.b.example.org",
		"user@msp.example.com, someone@example.org, a@b.test, c@x.localhost, d@e.invalid",
		"peers 192.0.2.10 198.51.100.7 203.0.113.9 127.0.0.1 0.0.0.0 198.51.100.0/24",
		"v6 2001:db8::1 ::1 :: ::ffff:203.0.113.10",
		"code s.cfg.Upstream, check.sh, README.md, box.id:abc, 12:00:00, 2026-11-09T12:00:00Z, logger.Info",
		"mac aa:bb:cc:dd:ee:ff",
		"format %s.%d and 100%.",
	}
	for _, s := range good {
		if hits := Scan(s, nil); len(hits) != 0 {
			t.Errorf("%q flagged: %v", s, hits)
		}
	}
}

// Exceptions are narrow: the LICENSE allowance covers its one host only, and
// there is no exception for docs/SPEC.md any more.
func TestExceptionsAreNarrow(t *testing.T) {
	lic := exceptions["LICENSE"]
	if hits := Scan("<https://"+"fsf"+".org/>", lic); len(hits) != 0 {
		t.Errorf("licensor URL flagged: %v", hits)
	}
	if hits := Scan("<https://"+"acme-corp"+".org/>", lic); len(hits) == 0 {
		t.Error("another host passed under the LICENSE exception")
	}
	if hits := Scan("<https://"+"evil."+"fsf"+".org/>", lic); len(hits) == 0 {
		t.Error("a subdomain of the licensor passed under the LICENSE exception")
	}
	if hits := Scan("ops@"+"fsf"+".org", lic); len(hits) == 0 {
		t.Error("an email at the licensor's host passed under the LICENSE exception")
	}
	spec := exceptions["docs/SPEC.md"]
	if hits := Scan("image "+"gcr"+".io/x", spec); len(hits) != 0 {
		t.Errorf("registry host flagged in SPEC: %v", hits)
	}
	if hits := Scan(join("see ", "firewalla.net.", "evil", ".com"), spec); len(hits) == 0 {
		t.Error("a look-alike host passed under the SPEC.md allowance")
	}
	if hits := Scan(join("see ", "evil.", "gcr", ".io"), spec); len(hits) == 0 {
		t.Error("a subdomain of the registry passed under the SPEC.md allowance")
	}
	for name := range exceptions {
		if name != "LICENSE" && name != "docs/SPEC.md" {
			t.Errorf("unexpected exception %q: document it in docs/DECISIONS.md and here", name)
		}
	}
	// go.mod and go.sum have no allowance function: only the host of a
	// module path is removed, so each bypass below must still be reported.
	reg := join("modernc", ".org")
	for _, goSum := range []bool{false, true} {
		for name, in := range map[string]string{
			"customer in a comment":   reg + "/m v1.0.0 // " + join("customer.", "firewalla.net"),
			"customer as module":      join("customer.", "firewalla.net") + "/m v1.0.0",
			"allowed host plus label": join("github.com.", "evil", ".io") + "/m v1.0.0",
			"second host on the line": reg + "/m v1.0.0 " + join("registry.acme-corp", ".io"),
			"email":                   reg + "/m v1.0.0 ops" + "@" + reg,
			"public IP":               reg + "/m v1.0.0 " + join("8.", "8.", "8.", "8"),
			"bare host":               "// see " + reg,
		} {
			if hits := Scan(StripModulePaths(in, goSum), nil); len(hits) == 0 {
				t.Errorf("goSum=%v %s: not reported: %q", goSum, name, in)
			}
		}
		if hits := Scan(StripModulePaths(reg+"/m v1.0.0 h1:abc=\n"+reg+"/m v1.0.0/go.mod h1:def=\n", goSum), nil); len(hits) != 0 {
			t.Errorf("goSum=%v: module host flagged: %v", goSum, hits)
		}
	}
}

func TestModuleHostOK(t *testing.T) {
	for _, h := range []string{join("modernc", ".org"), join("golang", ".org"), "github.com", join("go.uber", ".org"), join("gopkg", ".in")} {
		if !moduleHostOK(h) {
			t.Errorf("%q should be a module host", h)
		}
	}
	for _, h := range []string{
		"", "nodots", join("UPPER", ".org"), join("a..", "org"), ".org", join("xn--", "e1afmkfd", ".org"),
		join("customer.", "firewalla.net"), join("firewalla", ".org"), join("evil.", "github.com"),
		join("github.com.", "evil", ".io"), join("x.", "go.dev", ".io"),
	} {
		if moduleHostOK(h) {
			t.Errorf("%q should not be excusable as a module host", h)
		}
	}
}

// The module hosts the project really uses are pinned: adding a dependency
// from a new registry is a conscious change to this list.
func TestModuleHostsArePinned(t *testing.T) {
	files, err := readTree(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"github.com", join("golang", ".org"), join("modernc", ".org")}, ",")
	if got := strings.Join(ModuleHosts(files["go.mod"], false), ","); got != want {
		t.Errorf("go.mod module hosts = %v, want %v", got, want)
	}
	if got := strings.Join(ModuleHosts(files["go.sum"], true), ","); got != want {
		t.Errorf("go.sum module hosts = %v, want %v", got, want)
	}
}

// Import paths lose only a leading `host/`.
func TestStripImports(t *testing.T) {
	h := join("modernc", ".org")
	hosts := []string{h}
	if got := StripImports("import \""+h+"/m\"\nimport y \""+h+"/n\"\n", hosts); strings.Contains(got, h) {
		t.Errorf("import path not stripped: %q", got)
	}
	for _, in := range []string{
		"https://" + h + "/m", "ops@" + h + "/m", "evil." + h + "/m", "a-" + h + "/m", h, "see " + h + ".",
	} {
		if got := StripImports(in, hosts); got != in {
			t.Errorf("StripImports(%q) = %q, want unchanged", in, got)
		}
	}
}

// Round 2b, finding 2: a NUL byte does not make a file skippable. The text on
// both sides of it is scanned, and a customer host next to one fails.
func TestRedTeamNulByteDoesNotHideAFile(t *testing.T) {
	cust := join("customer.", "firewalla.net")
	for name, text := range map[string]string{
		"host then NUL":       cust + "\x00",
		"NUL then host":       "\x00" + cust,
		"host between NULs":   "\x00\x00" + cust + "\x00",
		"host after binary":   "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00 see " + cust + "\n",
		"email next to NUL":   "ops" + "@" + join("acme-corp", ".com") + "\x00",
		"address next to NUL": "\x00" + join("8.", "8.", "8.", "8") + "\x00",
	} {
		hits := plant(t, map[string]string{"planted/nul.txt": text})
		if len(hits["planted/nul.txt"]) == 0 {
			t.Errorf("%s: not reported", name)
		}
	}
	if hits := plant(t, map[string]string{"clean.bin": "\x00\x01\x02 plain \x00 text with example.com\x00"}); len(hits) != 0 {
		t.Errorf("clean file with NULs flagged: %v", hits)
	}
}

// Round 2b, finding 7: outside a git checkout the walker skips only the .git
// directory at the root; bin/ and a nested bin/ are scanned.
func TestRedTeamWalkerScansBinAndSkipsOnlyDotGit(t *testing.T) {
	cust := join("customer.", "firewalla.net")
	hits := plant(t, map[string]string{
		"bin/sneak.md":   cust,
		"a/bin/sneak.md": cust,
		"dist/sneak.md":  cust,
		".git/config":    cust,
		"sub/.git/sneak": cust,
	})
	for _, want := range []string{"bin/sneak.md", "a/bin/sneak.md", "dist/sneak.md", "sub/.git/sneak"} {
		if len(hits[want]) == 0 {
			t.Errorf("%s: not reported", want)
		}
	}
	if len(hits[".git/config"]) != 0 {
		t.Error("the root .git directory should be skipped")
	}
}

// Round 2b, finding 3: a host that contains an allowed name as a prefix or
// in the middle is a look-alike in any letter case, including a title-case
// top-level label. Code such as logger.Info stays clean.
func TestRedTeamMixedCaseTLDLookAlikes(t *testing.T) {
	for _, s := range []string{
		join("firewalla.net.", "evil", ".Com"),
		join("firewalla.net.", "evil", ".cOm"),
		join("Firewalla.Net.", "Evil", ".Com"),
		join("github.com.", "evil", ".Org"),
		join("x.", "Firewalla.Net.", "evil", ".Io"),
		join("docs.firewalla.net.", "evil", ".Net"),
		join("evil.", "Firewalla.Net"),
		join("FIREWALLA.NET.", "EVIL", ".Com"),
	} {
		if len(Scan("see https://"+s+"/x", nil)) == 0 {
			t.Errorf("not flagged: %q", s)
		}
	}
	for _, s := range []string{"logger.Info", "s.cfg.Upstream", "Firewalla.Net", "Docs.Firewalla.Net.", "t.Fatal", "a.Do", "log.Printf(x.Net)"} {
		if hits := Scan(s, nil); len(hits) != 0 {
			t.Errorf("%q flagged: %v", s, hits)
		}
	}
}

// Round 2b, finding 4: dots that are not U+002E are label separators.
func TestRedTeamUnicodeDotsSeparateLabels(t *testing.T) {
	for _, r := range []rune{0xFF0E, 0x3002, 0xFF61, 0x2024, 0xFE52} {
		d := string(r)
		for _, s := range []string{
			join("evil", d, "firewalla", d, "net"),
			join("evil", d, "firewalla.net"),
			join("evil.firewalla", d, "net"),
			join("firewalla.net", d, "evil", d, "com"),
			join("acme-corp", d, "com"),
			join("ops@acme-corp", d, "com"),
		} {
			if len(Scan("see "+s, nil)) == 0 {
				t.Errorf("U+%04X: not flagged: %q", r, s)
			}
		}
		// A separator inside an allowed host leaves the allowed host.
		if hits := Scan(join("see firewalla", d, "net"), nil); len(hits) != 0 {
			t.Errorf("U+%04X: allowed host written with a Unicode dot flagged: %v", r, hits)
		}
	}
}

// Round 2b, finding 5: after decoding, a CR, LF or TAB inside a label cannot
// hide a host (URL parsers drop them), and HTML numeric dot entities are
// decoded like percent-escapes.
func TestRedTeamEncodedBreaksAndEntities(t *testing.T) {
	for _, s := range []string{
		join("evil.firewalla.%0a", "net"),
		join("evil.firewalla.%0d", "net"),
		join("evil.firewalla.%0D%0A", "net"),
		join("evil.firewalla.%09", "net"),
		join("evil.%0a", "firewalla.net"),
		join("evil.firewalla.%250a", "net"),
		join("evil&#46;firewalla&#46;", "net"),
		join("evil&#x2e;firewalla&#x2E;", "net"),
		join("evil&#X2E;firewalla&#x2e;", "net"),
		join("evil&#46firewalla&#46", "net"),
		join("evil&#0046;firewalla&#00046;", "net"),
		join("evil&period;firewalla&period;", "net"),
		join("evil&#xFF0E;firewalla.", "net"),
		join("evil&#38;#46;firewalla&#38;#46;", "net"),
		join("evil%26%2346%3Bfirewalla.", "net"),
		join("acme-corp&#46;", "com"),
	} {
		if len(Scan("see https://"+s+"/x", nil)) == 0 {
			t.Errorf("not flagged: %q", s)
		}
	}
	hits := Scan("ok line\nsee "+join("evil.firewalla.%0a", "net")+"\n", nil)
	if len(hits) == 0 || !strings.HasPrefix(hits[0], "line 2:") {
		t.Errorf("hits = %v, want a line 2 hit", hits)
	}
	for _, s := range []string{"100%0a", "a&#46;b", "R&amp;D, &#8212; dash, a&lt;b", "tab%09separated and x&#10;y"} {
		if h := Scan(s, nil); len(h) != 0 {
			t.Errorf("%q flagged: %v", s, h)
		}
	}
}
