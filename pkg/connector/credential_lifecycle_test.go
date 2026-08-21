package connector

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newCredentialLifecycleServer stands in for Datadog across an Issue+Delete
// round trip. It answers FindAPIKeyByName (GET, empty match), CreateAPIKey
// (POST, returns handle+secret), and DeleteAPIKey (DELETE by handle). Every
// request the connector actually sends is recorded so tests can assert on it.
type recordedRequest struct {
	method string
	path   string
	query  string
	header http.Header
	body   string
}

func newCredentialLifecycleServer(t *testing.T, handle, secret, name string) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	requests := &[]recordedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes := make([]byte, 0)
		if r.Body != nil {
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(r.Body)
			bodyBytes = buf.Bytes()
		}
		*requests = append(*requests, recordedRequest{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			header: r.Header.Clone(),
			body:   string(bodyBytes),
		})
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":{"id":"` + handle + `","type":"api_keys","attributes":{"key":"` + secret + `","name":"` + name + `"}}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/api_keys/"+handle:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	return server, requests
}

func newLifecycleTestWrapper(serverURL string) *client.DatadogClient {
	cfg := datadog.NewConfiguration()
	cfg.Servers = datadog.ServerConfigurations{{URL: serverURL}}
	return client.NewDatadogClient(nil, datadog.NewAPIClient(cfg), "example.com", "connector-api-key", "connector-app-key")
}

func issueTestCredential(t *testing.T, ctx context.Context, wrapper *client.DatadogClient) *connectorbuilder.CredentialIssueOutput {
	t.Helper()
	issuer := newCredentialUserBuilder(wrapper)
	out, err := issuer.Issue(ctx, &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: "user-1"},
		RequestID:  "req-1",
	})
	require.NoError(t, err)
	return out
}

// (a) Connector-level delete-by-handle: apiTokenBuilder.Delete must issue the
// provider DELETE for the resource handle, and the plaintext secret must
// never appear anywhere in that request (path, query, headers, or body).
func TestApiTokenBuilderDeleteUsesHandleNotSecret(t *testing.T) {
	const (
		handle = "handle-abc123"
		secret = "super-secret-plaintext-value"
		name   = "c1-req-1"
	)
	server, requests := newCredentialLifecycleServer(t, handle, secret, name)
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)
	ctx := context.Background()

	// Issue first so the fake provider has a real handle/secret pair on record,
	// then delete strictly by handle -- the way the connector actually calls it.
	issued := issueTestCredential(t, ctx, wrapper)
	require.Equal(t, handle, issued.Secret.GetId().GetResource())
	require.Equal(t, secret, string(issued.PlaintextData[0].GetBytes()))

	deleter := newApiTokenBuilder(wrapper)
	_, err := deleter.Delete(ctx, issued.Secret.GetId(), nil)
	require.NoError(t, err)

	var deleteReq *recordedRequest
	for i := range *requests {
		if (*requests)[i].method == http.MethodDelete {
			deleteReq = &(*requests)[i]
		}
	}
	require.NotNil(t, deleteReq, "expected a DELETE request to reach the provider")
	require.Equal(t, "/api/v2/api_keys/"+handle, deleteReq.path)

	if strings.Contains(deleteReq.path, secret) || strings.Contains(deleteReq.query, secret) || strings.Contains(deleteReq.body, secret) {
		t.Fatalf("delete request leaked the plaintext secret: %+v", deleteReq)
	}
	for name, values := range deleteReq.header {
		for _, v := range values {
			if strings.Contains(v, secret) {
				t.Fatalf("delete request header %q leaked the plaintext secret: %q", name, v)
			}
		}
	}
}

// (b) Malformed/missing handle must fail closed before any provider request.
// nil ResourceId, an empty ResourceId.Resource, and a non-empty malformed
// handle (whitespace-only or containing a control character) are all
// validated by pkg/connector/api_token.go:29-36 / isMalformedAPIKeyHandle.
func TestApiTokenBuilderDeleteRejectsMissingHandle(t *testing.T) {
	tests := []struct {
		name       string
		resourceID *v2.ResourceId
	}{
		{name: "nil ResourceId", resourceID: nil},
		{name: "empty ResourceId.Resource", resourceID: &v2.ResourceId{ResourceType: apiTokenResourceType.Id, Resource: ""}},
		{name: "whitespace-only handle", resourceID: &v2.ResourceId{ResourceType: apiTokenResourceType.Id, Resource: "   "}},
		{name: "handle with control character", resourceID: &v2.ResourceId{ResourceType: apiTokenResourceType.Id, Resource: "handle-\n123"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("provider should not be contacted for a %s, got %s %s", tt.name, r.Method, r.URL.Path)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			wrapper := newLifecycleTestWrapper(server.URL)

			deleter := newApiTokenBuilder(wrapper)
			_, err := deleter.Delete(context.Background(), tt.resourceID, nil)
			require.Error(t, err)
		})
	}
}

// (c) Handle/secret separation regression at the issuer/connector boundary:
// the returned secret resource ID must equal the provider handle, and must
// never equal the plaintext secret bytes.
func TestIssueHandleAndSecretAreDistinct(t *testing.T) {
	const (
		handle = "handle-distinct-1"
		secret = "plaintext-distinct-secret"
		name   = "c1-req-1"
	)
	server, _ := newCredentialLifecycleServer(t, handle, secret, name)
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)

	issued := issueTestCredential(t, context.Background(), wrapper)

	secretResourceID := issued.Secret.GetId().GetResource()
	plaintext := string(issued.PlaintextData[0].GetBytes())

	require.NotEmpty(t, secretResourceID)
	require.NotEmpty(t, plaintext)
	require.NotEqual(t, plaintext, secretResourceID, "the secret resource id must not be (or equal) the plaintext secret")
	require.Equal(t, handle, secretResourceID, "the secret resource id must equal the provider-issued handle")
}

// (d) Secret-log assertion: capture every log record emitted across a full
// Issue + Delete cycle and assert the synthetic plaintext secret never
// appears in them.
func TestIssueAndDeleteNeverLogSecret(t *testing.T) {
	const (
		handle = "handle-logtest-1"
		secret = "plaintext-should-never-be-logged"
		name   = "c1-req-1"
	)
	server, _ := newCredentialLifecycleServer(t, handle, secret, name)
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)

	var logBuf bytes.Buffer
	encoderCfg := zap.NewProductionEncoderConfig()
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), zapcore.AddSync(&logBuf), zapcore.DebugLevel)
	logger := zap.New(core)
	ctx := ctxzap.ToContext(context.Background(), logger)

	issued := issueTestCredential(t, ctx, wrapper)
	require.Equal(t, secret, string(issued.PlaintextData[0].GetBytes()))

	deleter := newApiTokenBuilder(wrapper)
	_, err := deleter.Delete(ctx, issued.Secret.GetId(), nil)
	require.NoError(t, err)
	require.NoError(t, logger.Sync())

	if strings.Contains(logBuf.String(), secret) {
		t.Fatalf("captured logs leaked the plaintext secret:\n%s", logBuf.String())
	}
}

// TestIssueRefusesDuplicateRequest exercises the FindAPIKeyByName exact-match
// branch as consumed by Issue: when the provider already has a key named for
// this request, Issue must refuse with AlreadyExists and must never call
// CreateAPIKey (POST /api/v2/api_keys).
func TestIssueRefusesDuplicateRequest(t *testing.T) {
	const (
		requestID  = "req-dup-1"
		name       = "c1-" + requestID
		existingID = "handle-existing-1"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/api_keys":
			_, _ = w.Write([]byte(`{"data":[{"id":"` + existingID + `","type":"api_keys","attributes":{"name":"` + name + `"}}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/api_keys":
			t.Errorf("CreateAPIKey should not be called when a key for this request already exists")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)

	issuer := newCredentialUserBuilder(wrapper)
	out, err := issuer.Issue(context.Background(), &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: "user-1"},
		RequestID:  requestID,
	})
	require.Nil(t, out)
	require.Error(t, err)
	require.Equal(t, codes.AlreadyExists, status.Code(err))
}
