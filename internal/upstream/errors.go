package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors.
var (
	// ErrInvalidArgument: the caller passed a value the client refuses to
	// put into a request path or query. Nothing was sent.
	ErrInvalidArgument = errors.New("upstream: invalid argument")
	// ErrUnexpectedResponse: the upstream answered 2xx with a body that is
	// not one of the shapes the client knows.
	ErrUnexpectedResponse = errors.New("upstream: unexpected response")
	// ErrResponseTooLarge: the body exceeded the client's size cap.
	ErrResponseTooLarge = errors.New("upstream: response too large")
)

const (
	maxBodyKept   = 512 // bytes of an error body kept in Error.Body
	maxErrorRead  = 64 << 10
	maxRetryAfter = 24 * time.Hour
)

// Error is a non-2xx answer from the upstream. Text fields have already been
// passed through the redactor.
type Error struct {
	Method string
	Path   string
	Status int
	// RetryAfter is the parsed Retry-After header; zero when absent or
	// unparseable.
	RetryAfter time.Duration
	// Code and Message come from a JSON body of the form
	// {"error": "...", "message": "..."} when present (the real error shape
	// is UNKNOWN, see docs/UPSTREAM-NOTES.md).
	Code    string
	Message string
	// Body is the start of the response body, redacted and truncated.
	Body string
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "upstream %s %s: %d %s", e.Method, e.Path, e.Status, http.StatusText(e.Status))
	switch {
	case e.Message != "":
		b.WriteString(": " + e.Message)
	case e.Code != "":
		b.WriteString(": " + e.Code)
	}
	if e.RetryAfter > 0 {
		fmt.Fprintf(&b, " (retry after %s)", e.RetryAfter)
	}
	return b.String()
}

// IsRateLimited reports whether the upstream answered 429.
func (e *Error) IsRateLimited() bool { return e.Status == http.StatusTooManyRequests }

// IsNotFound reports whether the upstream answered 404.
func (e *Error) IsNotFound() bool { return e.Status == http.StatusNotFound }

// IsAuth reports whether the upstream rejected the token (401 or 403). That
// is a broker misconfiguration, never something to relay to a broker client.
func (e *Error) IsAuth() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
}

// AsError returns the *Error in err's chain, if any.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// TransportError is a failure to get any HTTP answer: DNS, connect, TLS,
// timeout, cancellation, a refused redirect target. Its text is redacted; the
// original error is not retained, only whether it was a timeout or a
// cancellation, so no unredacted text can leak through Unwrap.
type TransportError struct {
	Method string
	Path   string
	msg    string
	kind   error // context.DeadlineExceeded, context.Canceled or nil
	to     bool
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("upstream %s %s: %s", e.Method, e.Path, e.msg)
}

// Unwrap exposes context.DeadlineExceeded or context.Canceled when that was
// the cause, so errors.Is works.
func (e *TransportError) Unwrap() error { return e.kind }

// Timeout reports whether the request timed out.
func (e *TransportError) Timeout() bool { return e.to }

func (c *Client) transportError(method, path string, err error) error {
	te := &TransportError{Method: method, Path: path, msg: c.red.String(err.Error())}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		te.kind, te.to = context.DeadlineExceeded, true
	case errors.Is(err, context.Canceled):
		te.kind = context.Canceled
	default:
		var t interface{ Timeout() bool }
		if errors.As(err, &t) && t.Timeout() {
			te.to = true
		}
	}
	return te
}

func (c *Client) statusError(method, path string, res *http.Response, body []byte) *Error {
	e := &Error{Method: method, Path: path, Status: res.StatusCode}
	e.RetryAfter = parseRetryAfter(res.Header.Get("Retry-After"), c.now())

	var shape struct {
		Error   any    `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &shape) == nil {
		if s, ok := shape.Error.(string); ok {
			e.Code = c.red.String(clip(s, 128))
		}
		e.Message = c.red.String(clip(shape.Message, 256))
	}
	red := c.red.String(string(body))
	e.Body = clip(red, maxBodyKept)
	return e
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// parseRetryAfter reads delta-seconds or an HTTP date. Unusable values give
// zero; huge ones are capped.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n <= 0 {
			return 0
		}
		if n > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d <= 0 {
			return 0
		}
		return min(d, maxRetryAfter)
	}
	return 0
}
