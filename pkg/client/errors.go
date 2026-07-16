package client

import (
	"fmt"
	"net/http"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"google.golang.org/grpc/codes"
)

// wrapOfficialClientError maps an error returned by the official Datadog SDK
// (datadog-api-client-go) to a gRPC-coded error, mirroring how uhttp.BaseHttpClient
// classifies HTTP responses for baton-sdk's sync/retry engine. The official client
// bypasses uhttp entirely, so without this mapping errors from ListUsers, ListTeams,
// ListRoles, etc. carry no gRPC code and the sync engine cannot tell a transient
// rate-limit (429) from a permanent failure, so a sync fails instead of retrying.
func wrapOfficialClientError(operation string, httpRes *http.Response, err error) error {
	if err == nil {
		return nil
	}

	if httpRes == nil {
		// No response means a network-level failure (timeout, connection reset, etc.);
		// treat it the same way uhttp does for transient errors so the sync can retry.
		return uhttp.WrapErrors(codes.Unavailable, fmt.Sprintf("baton-datadog: %s: network or connection error", operation), err)
	}

	// Use the SDK's own HTTP-status-to-gRPC-code mapping (the same mapping
	// uhttp.BaseHttpClient.Do applies) so both HTTP paths in this connector are
	// classified consistently. Notably, this maps 429 to codes.Unavailable, not
	// codes.ResourceExhausted, which is what the sync engine's retry loop checks for.
	code := uhttp.GrpcCodeFromHTTPStatus(httpRes.StatusCode)
	return uhttp.WrapErrorsWithRateLimitInfo(code, httpRes, err)
}
