package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"mspbroker/internal/acl"
	"mspbroker/internal/audit"
	"mspbroker/internal/store"
	"mspbroker/internal/upstream"
)

// apiError is the body of every error response (SPEC 7).
type apiError struct {
	Error  string `json:"error"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// listBody is the envelope of every list response, whatever the upstream
// shape of the underlying endpoint.
type listBody struct {
	Count      int               `json:"count"`
	Results    []upstream.Object `json:"results"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

// result is what a handler returns. The pipeline turns it into one audit row
// and one HTTP response, in that order.
type result struct {
	status int
	body   any
	header http.Header

	// Audit.
	outcome        string // default: ok below 400, blocked otherwise
	reason         string // block reason, required when outcome is blocked
	resource       string // overrides the route's
	action         string // overrides the route's
	gid            string
	objectID       string
	upstreamStatus int
	count          *int
	before, after  json.RawMessage
}

func (r *result) setHeader(k, v string) *result {
	if r.header == nil {
		r.header = http.Header{}
	}
	r.header.Set(k, v)
	return r
}

func okResult(status int, body any) *result {
	return &result{status: status, body: body, outcome: store.OutcomeOK}
}

func listResult(objs []upstream.Object, next string) *result {
	if objs == nil {
		objs = []upstream.Object{}
	}
	n := len(objs)
	r := okResult(http.StatusOK, listBody{Count: n, Results: objs, NextCursor: next})
	r.count = &n
	r.upstreamStatus = http.StatusOK
	return r
}

// failure is a response the broker generates itself. reason is the audit block
// reason (one of the audit.Reason* constants).
func failure(status int, errName, code, detail, reason string) *result {
	return &result{
		status:  status,
		body:    apiError{Error: errName, Code: code, Detail: detail},
		outcome: store.OutcomeBlocked,
		reason:  reason,
	}
}

func badRequest(detail string) *result {
	return failure(http.StatusBadRequest, "bad_request", "bad_request", detail, audit.ReasonBadRequest)
}

func notFound(detail string) *result {
	return failure(http.StatusNotFound, "not_found", "not_found", detail, audit.ReasonNotFound)
}

func internalError(detail string) *result {
	return failure(http.StatusInternalServerError, "internal", "internal", detail, audit.ReasonInternal)
}

// denial renders an acl.Denial as the SPEC 6.4 403 body.
func denial(d *acl.Denial) *result {
	return failure(http.StatusForbidden, "forbidden", string(d.Code), d.Detail, string(d.Code))
}

// upstreamFailure maps an upstream client error to a broker response. Nothing
// from the error text reaches the client: the detail strings are fixed, and
// the error itself goes to the log (already redacted by the client). An
// upstream 401/403 means the broker's own token is wrong; that is the
// operator's problem, never the client's, so it is a 502.
func (s *Server) upstreamFailure(ctx context.Context, err error, single bool) *result {
	mk := func(status int, name, code, detail string, upStatus int) *result {
		r := &result{
			status:         status,
			body:           apiError{Error: name, Code: code, Detail: detail},
			outcome:        store.OutcomeUpstreamError,
			upstreamStatus: upStatus,
		}
		return r
	}
	if ue, ok := upstream.AsError(err); ok {
		s.log.WarnContext(ctx, "upstream returned an error", "status", ue.Status, "error", err)
		switch {
		case ue.IsRateLimited():
			r := mk(http.StatusTooManyRequests, "rate_limited", "upstream_rate_limit",
				"the upstream service is rate limiting this broker; retry later", ue.Status)
			if ue.RetryAfter > 0 {
				secs := int((ue.RetryAfter + time.Second - 1) / time.Second)
				r.setHeader("Retry-After", strconv.Itoa(max(secs, 1)))
			}
			return r
		case ue.IsAuth():
			return mk(http.StatusBadGateway, "upstream_error", "upstream_auth",
				"the broker's own upstream credentials were rejected; contact the operator", ue.Status)
		case ue.IsNotFound() && single:
			return mk(http.StatusNotFound, "not_found", "not_found", "the upstream has no such object", ue.Status)
		case ue.Status == http.StatusBadRequest:
			return mk(http.StatusBadRequest, "bad_request", "upstream_rejected",
				"the upstream rejected the request parameters", ue.Status)
		}
		return mk(http.StatusBadGateway, "upstream_error", "upstream_error",
			"the upstream service returned an error", ue.Status)
	}
	s.log.WarnContext(ctx, "upstream request failed", "error", err)
	var te *upstream.TransportError
	switch {
	case errors.As(err, &te) && te.Timeout():
		return mk(http.StatusGatewayTimeout, "upstream_error", "upstream_timeout", "the upstream service did not answer in time", 0)
	case errors.Is(err, upstream.ErrUnexpectedResponse), errors.Is(err, upstream.ErrResponseTooLarge):
		return mk(http.StatusBadGateway, "upstream_error", "upstream_unexpected", "the upstream service sent a response the broker cannot use", 0)
	case errors.Is(err, upstream.ErrInvalidArgument):
		return mk(http.StatusBadRequest, "bad_request", "bad_request", "a parameter is not acceptable", 0)
	}
	return mk(http.StatusBadGateway, "upstream_error", "upstream_unavailable", "the upstream service is unreachable", 0)
}

// writeJSON writes status and body. Marshalling happens first so a failure
// still produces a clean 500, and the marshalled bytes are scrubbed of the
// upstream token before they leave: whatever path a string took through the
// upstream client, the outbound body is the last place to catch it. Only
// literals are scrubbed, never broker-secret shapes, because the response that
// creates a key must carry its one-time secret.
func (s *Server) writeJSON(w http.ResponseWriter, status int, body any, extra http.Header) {
	b, err := json.Marshal(body)
	if err != nil {
		status = http.StatusInternalServerError
		b = []byte(`{"error":"internal","code":"internal","detail":"response could not be encoded"}`)
		extra = nil
	}
	b = s.scrub.LiteralBytes(b)
	for k, vs := range extra {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)+1))
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
