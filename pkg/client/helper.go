package client

import (
	"errors"
	"net/http"
	"strconv"
)

// ErrNotFound is joined onto errors returned from wrapper methods when the
// Datadog API responds with HTTP 404. Callers use IsNotFound to detect this
// without depending on the SDK error message format.
var ErrNotFound = errors.New("baton-datadog: not found")

// ErrApplicationKeyOwnerUnknown is joined onto the errors
// FindApplicationKeyOwner returns when the provider answered successfully and
// its answer names no owner for the key. That is the one owner-lookup failure
// a retry cannot fix, so callers branch on it -- with errors.Is, not with a
// gRPC code -- to refuse permanently.
//
// A gRPC code cannot carry this. These errors reach a caller as codes.Unknown,
// but so does anything wrapOfficialClientError classifies through
// uhttp.GrpcCodeFromHTTPStatus's default arm, which is every status outside
// 4xx/5xx -- including a 2xx or 3xx whose body the generated Datadog client
// could not unmarshal. Treating that code as "no owner exists" would turn a
// retryable transport failure into a permanent refusal.
var ErrApplicationKeyOwnerUnknown = errors.New("baton-datadog: application key owner unknown")

// IsNotFound reports whether err was returned for a 404 response.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// ReqOpt represents a request option that can be applied to an HTTP request.
type ReqOpt func(*http.Request) *http.Request

// WithQueryParam adds a query parameter to the request.
func WithQueryParam(key, value string) ReqOpt {
	return func(req *http.Request) *http.Request {
		q := req.URL.Query()
		q.Add(key, value)
		req.URL.RawQuery = q.Encode()
		return req
	}
}

// WithPageSize adds a page size query parameter to the request.
func WithPageSize(pageSize int) ReqOpt {
	if pageSize <= 0 {
		pageSize = PageSize // Default to the maximum allowed by Datadog API
	}
	return WithQueryParam("page[size]", strconv.Itoa(pageSize))
}

// WithPage adds a page number query parameter to the request.
func WithPage(page int) ReqOpt {
	return WithQueryParam("page[number]", strconv.Itoa(page))
}
