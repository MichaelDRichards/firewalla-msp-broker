// Package upstream is the typed client for the MSP API. It is the only
// package that holds the upstream token. The token lives in a
// config.Secret, is revealed only to build the Authorization header, and
// every string that leaves this package (error text, log lines, copies of
// response bodies) passes through a redactor that replaces it with
// [redacted].
//
// Only the endpoints the broker models are present, and only reads (M1).
// Everything not listed here is unreachable through the broker by design.
//
// What the client does not know about the real service is listed in
// docs/UPSTREAM-NOTES.md. Where the client is tolerant of two possible
// shapes, the comment says so.
package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"mspbroker/internal/config"
)

// Defaults.
const (
	DefaultTimeout          = 30 * time.Second
	DefaultMaxResponseBytes = 16 << 20
	DefaultAuthScheme       = "Bearer"
	userAgent               = "mspbroker-upstream/1"
)

// Config configures a Client.
type Config struct {
	// BaseURL is the upstream root, for example https://msp.example.com.
	// API paths (/v2/...) are appended to it.
	BaseURL string
	// Token is the upstream token. It must be set.
	Token config.Secret
	// Timeout bounds each request including reading the body. Default 30s.
	Timeout time.Duration
	// AuthScheme is the Authorization scheme word. Default "Bearer". Whether
	// the real service wants Bearer or Token is UNKNOWN (UPSTREAM-NOTES).
	AuthScheme string
	// MaxResponseBytes caps a response body. Default 16 MiB.
	MaxResponseBytes int64
	// Logger receives one debug line per request and warnings. Its output is
	// redacted. Nil discards.
	Logger *slog.Logger
	// Transport overrides the HTTP transport (tests). Nil uses the default.
	Transport http.RoundTripper
}

// Client talks to the upstream. It is safe for concurrent use.
type Client struct {
	base    *url.URL
	token   config.Secret
	scheme  string
	timeout time.Duration
	maxBody int64
	http    *http.Client
	log     *slog.Logger
	red     *redactor
	now     func() time.Time
}

// New validates cfg and builds a Client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("upstream: base URL must be an absolute http(s) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("upstream: base URL must not contain credentials, a query or a fragment")
	}
	if !cfg.Token.IsSet() {
		return nil, fmt.Errorf("upstream: token is required")
	}
	scheme := cfg.AuthScheme
	if scheme == "" {
		scheme = DefaultAuthScheme
	}
	for _, r := range scheme {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return nil, fmt.Errorf("upstream: auth scheme must be letters only")
		}
	}
	c := &Client{
		base:    u,
		token:   cfg.Token,
		scheme:  scheme,
		timeout: cfg.Timeout,
		maxBody: cfg.MaxResponseBytes,
		red:     newRedactor(cfg.Token.Reveal()),
		now:     time.Now,
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.maxBody <= 0 {
		c.maxBody = DefaultMaxResponseBytes
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	c.log = slog.New(c.red.handler(logger.Handler()))
	c.http = &http.Client{
		Transport: cfg.Transport,
		// Never follow redirects: the Authorization header must not travel
		// to a host the operator did not configure. A 3xx is an error.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

// String describes the client without the token.
func (c Client) String() string {
	return fmt.Sprintf("upstream.Client{base:%s token:%s}", c.base.Redacted(), Redacted)
}

// Format keeps every fmt verb away from the struct fields. Value receivers,
// so a copied Client is as safe to print as a pointer.
func (c Client) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue implements slog.LogValuer.
func (c Client) LogValue() slog.Value { return slog.StringValue(c.String()) }

// ---- types ----

// Object is one upstream JSON object, kept whole so the broker can pass
// through fields it does not model. Numbers are json.Number.
type Object = map[string]any

// Box is a box with the two fields the broker needs for scoping. Object has
// the complete upstream representation.
type Box struct {
	GID  string
	Name string
	// Group is the box-group id, empty when the box is in no group.
	Group  string
	Object Object
}

// Page is one page of a cursor-paginated list.
type Page struct {
	// Count is the upstream's count when it sent one, else len(Results).
	Count   int
	Results []Object
	// NextCursor is empty on the last page.
	NextCursor string
}

// ListParams are the parameters of the paginated list endpoints.
type ListParams struct {
	Query  string // upstream query syntax, sent as `query`
	Cursor string
	Limit  int // 0 = upstream default
	// GroupBy and SortBy are passed through as `groupBy` and `sortBy`. Their
	// accepted values and the shape of grouped results are UNKNOWN.
	GroupBy string
	SortBy  string
}

// DevicesParams filter devices. Values may be comma-separated lists;
// whether the upstream accepts lists is UNKNOWN.
type DevicesParams struct {
	Box   string
	Group string
}

// ---- endpoints ----

// Boxes lists all boxes (GET /v2/boxes). Boxes without a gid are skipped
// and logged: they cannot be scoped.
func (c *Client) Boxes(ctx context.Context) ([]Box, error) {
	body, err := c.get(ctx, []string{"v2", "boxes"}, nil)
	if err != nil {
		return nil, err
	}
	objs, _, _, err := c.decodeList(body)
	if err != nil {
		return nil, c.shapeError("GET", "/v2/boxes", err)
	}
	out := make([]Box, 0, len(objs))
	for _, o := range objs {
		gid, _ := o["gid"].(string)
		if gid == "" {
			c.log.Warn("upstream box without gid skipped")
			continue
		}
		name, _ := o["name"].(string)
		out = append(out, Box{GID: gid, Name: name, Group: groupOf(o["group"]), Object: o})
	}
	return out, nil
}

// groupOf reads a box's group id. The encoding is UNKNOWN; accept a string
// or an object with a string `id`. Anything else means no group.
func groupOf(v any) string {
	switch g := v.(type) {
	case string:
		return g
	case map[string]any:
		if id, ok := g["id"].(string); ok {
			return id
		}
	}
	return ""
}

// Devices lists devices (GET /v2/devices?box=&group=).
func (c *Client) Devices(ctx context.Context, p DevicesParams) ([]Object, error) {
	q := url.Values{}
	setIf(q, "box", p.Box)
	setIf(q, "group", p.Group)
	body, err := c.get(ctx, []string{"v2", "devices"}, q)
	if err != nil {
		return nil, err
	}
	objs, _, _, err := c.decodeList(body)
	if err != nil {
		return nil, c.shapeError("GET", "/v2/devices", err)
	}
	return objs, nil
}

// Alarms lists alarms (GET /v2/alarms?query=&cursor=&limit=).
func (c *Client) Alarms(ctx context.Context, p ListParams) (*Page, error) {
	return c.page(ctx, []string{"v2", "alarms"}, p)
}

// Alarm gets one alarm (GET /v2/alarms/{gid}/{aid}).
func (c *Client) Alarm(ctx context.Context, gid, aid string) (Object, error) {
	return c.object(ctx, "v2", "alarms", gid, aid)
}

// Rules lists rules (GET /v2/rules?query=). A cursor is returned if the
// upstream sends one; the client does not send cursor or limit for rules
// because the docs as summarised in the SPEC list only `query`.
func (c *Client) Rules(ctx context.Context, query string) (*Page, error) {
	return c.page(ctx, []string{"v2", "rules"}, ListParams{Query: query})
}

// Flows lists flows (GET /v2/flows?query=&cursor=&limit=).
func (c *Client) Flows(ctx context.Context, p ListParams) (*Page, error) {
	return c.page(ctx, []string{"v2", "flows"}, p)
}

// TargetLists lists target lists (GET /v2/target-lists?owner=). owner is a
// comma-separated list of "global" and gids; empty means no filter.
func (c *Client) TargetLists(ctx context.Context, owner string) ([]Object, error) {
	q := url.Values{}
	setIf(q, "owner", owner)
	body, err := c.get(ctx, []string{"v2", "target-lists"}, q)
	if err != nil {
		return nil, err
	}
	objs, _, _, err := c.decodeList(body)
	if err != nil {
		return nil, c.shapeError("GET", "/v2/target-lists", err)
	}
	return objs, nil
}

// TargetList gets one target list (GET /v2/target-lists/{id}).
func (c *Client) TargetList(ctx context.Context, id string) (Object, error) {
	return c.object(ctx, "v2", "target-lists", id)
}

// Stats fetches /v2/stats/{name} and returns the body as JSON. The paths,
// shapes and box-filter support of statistics are UNKNOWN, so nothing is
// decoded and params are passed through unchanged. name must be a plain
// identifier.
func (c *Client) Stats(ctx context.Context, name string, params url.Values) (json.RawMessage, error) {
	return c.raw(ctx, "stats", name, params)
}

// Trends fetches /v2/trends/{name}; see Stats.
func (c *Client) Trends(ctx context.Context, name string, params url.Values) (json.RawMessage, error) {
	return c.raw(ctx, "trends", name, params)
}

// ---- plumbing ----

func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func (c *Client) page(ctx context.Context, path []string, p ListParams) (*Page, error) {
	if p.Limit < 0 {
		return nil, fmt.Errorf("%w: limit must not be negative", ErrInvalidArgument)
	}
	q := url.Values{}
	setIf(q, "query", p.Query)
	setIf(q, "cursor", p.Cursor)
	setIf(q, "groupBy", p.GroupBy)
	setIf(q, "sortBy", p.SortBy)
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	body, err := c.get(ctx, path, q)
	if err != nil {
		return nil, err
	}
	objs, count, next, err := c.decodeList(body)
	if err != nil {
		return nil, c.shapeError("GET", "/"+strings.Join(path, "/"), err)
	}
	return &Page{Count: count, Results: objs, NextCursor: next}, nil
}

func (c *Client) object(ctx context.Context, parts ...string) (Object, error) {
	for _, s := range parts[2:] {
		if err := checkSegment(s); err != nil {
			return nil, err
		}
	}
	body, err := c.get(ctx, parts, nil)
	if err != nil {
		return nil, err
	}
	o, err := c.decodeObject(body)
	if err != nil {
		return nil, c.shapeError("GET", "/"+strings.Join(parts, "/"), err)
	}
	return o, nil
}

func (c *Client) raw(ctx context.Context, kind, name string, params url.Values) (json.RawMessage, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	body, err := c.get(ctx, []string{"v2", kind, name}, params)
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, c.shapeError("GET", "/v2/"+kind+"/"+name, fmt.Errorf("not JSON"))
	}
	return json.RawMessage(body), nil
}

func (c *Client) shapeError(method, path string, err error) error {
	return fmt.Errorf("%w: %s %s: %s", ErrUnexpectedResponse, method, path, c.red.String(err.Error()))
}

// checkSegment limits path segments to a conservative alphabet: ids seen in
// the docs (UUIDs, numbers, MACs) fit, and nothing can add path structure
// or an encoded separator.
func checkSegment(s string) error {
	if s == "" || len(s) > 128 || s == "." || s == ".." {
		return fmt.Errorf("%w: bad path segment", ErrInvalidArgument)
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		ok := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
			ch == '-' || ch == '_' || ch == '.' || ch == ':'
		if !ok {
			return fmt.Errorf("%w: bad path segment", ErrInvalidArgument)
		}
	}
	return nil
}

// checkName: a stats or trends name is an identifier.
func checkName(s string) error {
	if s == "" || len(s) > 64 || !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		return fmt.Errorf("%w: bad name", ErrInvalidArgument)
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return fmt.Errorf("%w: bad name", ErrInvalidArgument)
		}
	}
	return nil
}

// get performs one GET and returns the redacted body of a 2xx answer.
func (c *Client) get(ctx context.Context, path []string, q url.Values) ([]byte, error) {
	u := c.base.JoinPath(path...)
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	display := u.EscapedPath()
	if !strings.HasPrefix(display, "/") {
		display = "/" + display
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, c.transportError("GET", display, err)
	}
	req.Header.Set("Authorization", c.scheme+" "+c.token.Reveal())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	start := time.Now()
	res, err := c.http.Do(req)
	if err != nil {
		terr := c.transportError("GET", display, err)
		c.log.Warn("upstream request failed", "path", display, "query", u.RawQuery, "error", terr, "elapsed", time.Since(start))
		return nil, terr
	}
	defer res.Body.Close()

	limit := c.maxBody
	if res.StatusCode < 200 || res.StatusCode > 299 {
		limit = maxErrorRead
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		terr := c.transportError("GET", display, err)
		c.log.Warn("upstream read failed", "path", display, "error", terr)
		return nil, terr
	}
	if int64(len(body)) > limit {
		if limit == maxErrorRead { // oversize error body: keep what we have
			body = body[:limit]
		} else {
			return nil, fmt.Errorf("%w: GET %s", ErrResponseTooLarge, display)
		}
	}
	body = c.red.Bytes(body)

	elapsed := time.Since(start)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		e := c.statusError("GET", display, res, body)
		c.log.Warn("upstream error", "path", display, "query", u.RawQuery, "status", e.Status, "retry_after", e.RetryAfter, "elapsed", elapsed)
		return nil, e
	}
	c.log.Debug("upstream request", "path", display, "query", u.RawQuery, "status", res.StatusCode, "bytes", len(body), "elapsed", elapsed)
	return body, nil
}

// ---- decoding ----

func decodeJSON(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data after JSON value")
	}
	return nil
}

// decodeObject and decodeList decode a body whose raw bytes were already
// redacted, then redact the decoded values again: a JSON \uXXXX escape is not
// the token string, so the raw-byte pass cannot see it, yet decoding turns it
// back into the token. Keys, values and the cursor are all covered.
func (c *Client) decodeObject(body []byte) (Object, error) {
	o, err := decodeObject(body)
	if err != nil {
		return nil, err
	}
	return c.red.Object(o), nil
}

func (c *Client) decodeList(body []byte) (objs []Object, count int, next string, err error) {
	objs, count, next, err = decodeList(body)
	if err != nil {
		return nil, 0, "", err
	}
	for i, o := range objs {
		objs[i] = c.red.Object(o)
	}
	return objs, count, c.red.String(next), nil
}

func decodeObject(body []byte) (Object, error) {
	var o Object
	if err := decodeJSON(body, &o); err != nil {
		return nil, err
	}
	if o == nil {
		return nil, fmt.Errorf("expected a JSON object")
	}
	return o, nil
}

// decodeList accepts either a bare array of objects or an envelope
// {"count": n, "results": [...], "next_cursor": "..."} (also "nextCursor").
// Which one a given real endpoint uses is UNKNOWN, so both are accepted for
// every list endpoint.
func decodeList(body []byte) (objs []Object, count int, next string, err error) {
	objs, count, next, err = decodeListShape(body)
	if err != nil {
		return nil, 0, "", err
	}
	for _, o := range objs {
		if o == nil {
			return nil, 0, "", fmt.Errorf("list contains null instead of an object")
		}
	}
	return objs, count, next, nil
}

func decodeListShape(body []byte) (objs []Object, count int, next string, err error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, 0, "", fmt.Errorf("empty body")
	}
	if trimmed[0] == '[' {
		if err := decodeJSON(trimmed, &objs); err != nil {
			return nil, 0, "", err
		}
		return nonNilObjs(objs), len(objs), "", nil
	}
	var env struct {
		Count      *json.Number `json:"count"`
		Results    []Object     `json:"results"`
		NextCursor string       `json:"next_cursor"`
		NextCamel  string       `json:"nextCursor"`
	}
	raw := map[string]json.RawMessage{}
	if err := decodeJSON(trimmed, &raw); err != nil {
		return nil, 0, "", err
	}
	if _, ok := raw["results"]; !ok {
		return nil, 0, "", fmt.Errorf("object has no results array")
	}
	if err := decodeJSON(trimmed, &env); err != nil {
		return nil, 0, "", err
	}
	count = len(env.Results)
	if env.Count != nil {
		if n, err := env.Count.Int64(); err == nil && n >= 0 {
			count = int(n)
		}
	}
	next = env.NextCursor
	if next == "" {
		next = env.NextCamel
	}
	return nonNilObjs(env.Results), count, next, nil
}

func nonNilObjs(o []Object) []Object {
	if o == nil {
		return []Object{}
	}
	return o
}
