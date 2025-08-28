package client

import (
	"net/http"
	"strconv"
)

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
