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

// recordedRequest captures one request the connector sent to the fake
// Datadog provider, so tests can assert on exactly what left the connector
// (path, query, headers, body) without trusting a success return alone.
type recordedRequest struct {
	method string
	path   string
	query  string
	header http.Header
	body   string
}

func newLifecycleTestWrapper(serverURL string) *client.DatadogClient {
	cfg := datadog.NewConfiguration()
	cfg.Servers = datadog.ServerConfigurations{{URL: serverURL}}
	return client.NewDatadogClient(nil, datadog.NewAPIClient(cfg), "example.com", "connector-api-key", "connector-app-key")
}

func recordRequest(t *testing.T, requests *[]recordedRequest, r *http.Request) recordedRequest {
	t.Helper()
	bodyBytes := make([]byte, 0)
	if r.Body != nil {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		bodyBytes = buf.Bytes()
	}
	rec := recordedRequest{
		method: r.Method,
		path:   r.URL.Path,
		query:  r.URL.RawQuery,
		header: r.Header.Clone(),
		body:   string(bodyBytes),
	}
	*requests = append(*requests, rec)
	return rec
}

// --- organization API key (apiTokenBuilder) coverage -----------------------
//
// apiTokenBuilder / the "api-key" resource type is unchanged by the SPEC-07
// rework: it still syncs and deletes organization API keys exactly as
// before. It is no longer wired to Issue (see the service-account
// application key coverage below), so these tests seed a fixture directly
// via the client wrapper's CreateAPIKey instead of going through Issue.

func newOrgAPIKeyServer(t *testing.T, handle, secret, name string) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	requests := &[]recordedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordRequest(t, requests, r)
		w.Header().Set("Content-Type", "application/json")
		switch {
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

// TestApiTokenBuilderDeleteUsesHandleNotSecret: apiTokenBuilder.Delete must
// issue the provider DELETE for the resource handle, and the plaintext
// secret must never appear anywhere in that request (path, query, headers,
// or body).
func TestApiTokenBuilderDeleteUsesHandleNotSecret(t *testing.T) {
	const (
		handle = "handle-abc123"
		secret = "super-secret-plaintext-value"
		name   = "c1-req-1"
	)
	server, requests := newOrgAPIKeyServer(t, handle, secret, name)
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)
	ctx := context.Background()

	issued, err := wrapper.CreateAPIKey(ctx, name)
	require.NoError(t, err)
	require.Equal(t, handle, issued.ID)
	require.Equal(t, secret, issued.Secret)

	deleter := newApiTokenBuilder(wrapper)
	resourceID := &v2.ResourceId{ResourceType: apiTokenResourceType.Id, Resource: issued.ID}
	_, err = deleter.Delete(ctx, resourceID, nil)
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

// TestApiTokenBuilderDeleteRejectsMissingHandle: malformed/missing handle
// must fail closed before any provider request. nil ResourceId, an empty
// ResourceId.Resource, and a non-empty malformed handle (whitespace-only or
// containing a control character) are all validated by
// pkg/connector/api_token.go / isMalformedAPIKeyHandle.
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
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

// --- service-account application key (credentialUserBuilder.Issue /
// applicationKeyBuilder.Delete) coverage ------------------------------------
//
// This is the SPEC-07 mapping: Issue targets a Datadog service account
// (live-rechecked via GetUser) and mints an application key scoped to it;
// Delete removes that key through the service-account application-key API
// using the bare application-key id as the handle plus the owning service
// account carried via parentResourceID (see application_key.go's Delete doc
// comment for why parentResourceID, not a packed handle string).

const (
	testServiceAccountID = "sa-1"
)

// newServiceAccountAppKeyServer stands in for Datadog across an Issue+Delete
// round trip against a service account. It answers GetUser (service account
// check), the find-by-name list (empty match), CreateServiceAccountApplicationKey
// (returns handle+secret), and DeleteServiceAccountApplicationKey (DELETE by
// handle, scoped to the service account in the request path). Every request
// the connector actually sends is recorded.
func newServiceAccountAppKeyServer(t *testing.T, serviceAccountID, handle, secret, name string) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	requests := &[]recordedRequest{}
	appKeysPath := "/api/v2/service_accounts/" + serviceAccountID + "/application_keys"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordRequest(t, requests, r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/"+serviceAccountID:
			_, _ = w.Write([]byte(`{"data":{"id":"` + serviceAccountID + `","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == appKeysPath:
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == appKeysPath:
			_, _ = w.Write([]byte(`{"data":{"id":"` + handle + `","type":"application_keys","attributes":{"key":"` + secret + `","name":"` + name + `"}}}`))
		case r.Method == http.MethodDelete && r.URL.Path == appKeysPath+"/"+handle:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	return server, requests
}

func issueServiceAccountAppKey(t *testing.T, ctx context.Context, wrapper *client.DatadogClient, serviceAccountID, requestID string) *connectorbuilder.CredentialIssueOutput {
	t.Helper()
	issuer := newCredentialUserBuilder(wrapper)
	out, err := issuer.Issue(ctx, &connectorbuilder.CredentialIssueInput{
		IdentityID:        &v2.ResourceId{ResourceType: userResourceType.Id, Resource: serviceAccountID},
		RequestID:         requestID,
		CredentialOptions: v2.CredentialIssueOptions_builder{ApiKey: v2.CredentialIssueOptions_ApiKey_builder{}.Build()}.Build(),
	})
	require.NoError(t, err)
	return out
}

// TestIssueRequiresServiceAccount: Issue must live-recheck (via GetUser) that
// the target Datadog user is a service account, accepting one and rejecting
// a human user with InvalidArgument, without ever calling
// CreateServiceAccountApplicationKey for the rejected case.
func TestIssueRequiresServiceAccount(t *testing.T) {
	t.Run("accepts a service account", func(t *testing.T) {
		const (
			handle = "appkey-sa-accept"
			secret = "test-fixture-value-accept"
			name   = "c1-req-accept"
		)
		server, _ := newServiceAccountAppKeyServer(t, testServiceAccountID, handle, secret, name)
		defer server.Close()
		wrapper := newLifecycleTestWrapper(server.URL)

		out := issueServiceAccountAppKey(t, context.Background(), wrapper, testServiceAccountID, "req-accept")
		require.Equal(t, handle, out.Secret.GetId().GetResource())
		require.Equal(t, testServiceAccountID, out.Secret.GetParentResourceId().GetResource(), "the issued secret must record its owning service account as its parent resource")
	})

	t.Run("rejects a human user", func(t *testing.T) {
		const humanUserID = "user-human-1"
		appKeysPath := "/api/v2/service_accounts/" + humanUserID + "/application_keys"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/"+humanUserID:
				_, _ = w.Write([]byte(`{"data":{"id":"` + humanUserID + `","type":"users","attributes":{"service_account":false}}}`))
			case r.Method == http.MethodPost && r.URL.Path == appKeysPath:
				t.Errorf("CreateServiceAccountApplicationKey should not be called for a non-service-account target")
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
			IdentityID:        &v2.ResourceId{ResourceType: userResourceType.Id, Resource: humanUserID},
			RequestID:         "req-reject",
			CredentialOptions: v2.CredentialIssueOptions_builder{ApiKey: v2.CredentialIssueOptions_ApiKey_builder{}.Build()}.Build(),
		})
		require.Nil(t, out)
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

// TestIssueRefusesDuplicateRequest exercises the
// FindServiceAccountApplicationKeyByName exact-match branch as consumed by
// Issue: when the provider already has an application key named for this
// request (scoped to this service account), Issue must refuse with
// AlreadyExists and must never call CreateServiceAccountApplicationKey.
func TestIssueRefusesDuplicateRequest(t *testing.T) {
	const (
		requestID  = "req-dup-1"
		name       = "c1-" + requestID
		existingID = "appkey-existing-1"
	)
	appKeysPath := "/api/v2/service_accounts/" + testServiceAccountID + "/application_keys"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/"+testServiceAccountID:
			_, _ = w.Write([]byte(`{"data":{"id":"` + testServiceAccountID + `","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == appKeysPath:
			_, _ = w.Write([]byte(`{"data":[{"id":"` + existingID + `","type":"application_keys","attributes":{"name":"` + name + `"}}]}`))
		case r.Method == http.MethodPost && r.URL.Path == appKeysPath:
			t.Errorf("CreateServiceAccountApplicationKey should not be called when a key for this request already exists")
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
		IdentityID:        &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID},
		RequestID:         requestID,
		CredentialOptions: v2.CredentialIssueOptions_builder{ApiKey: v2.CredentialIssueOptions_ApiKey_builder{}.Build()}.Build(),
	})
	require.Nil(t, out)
	require.Error(t, err)
	require.Equal(t, codes.AlreadyExists, status.Code(err))
}

// TestIssueHandleAndSecretAreDistinct: handle/secret separation regression at
// the issuer/connector boundary -- the returned secret resource ID must be
// the bare provider application-key id, and must never equal the plaintext
// secret bytes.
func TestIssueHandleAndSecretAreDistinct(t *testing.T) {
	const (
		handle = "handle-distinct-1"
		secret = "plaintext-distinct-secret"
		name   = "c1-req-1"
	)
	server, _ := newServiceAccountAppKeyServer(t, testServiceAccountID, handle, secret, name)
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)

	issued := issueServiceAccountAppKey(t, context.Background(), wrapper, testServiceAccountID, "req-1")

	secretResourceID := issued.Secret.GetId().GetResource()
	plaintext := string(issued.PlaintextData[0].GetBytes())

	require.NotEmpty(t, secretResourceID)
	require.NotEmpty(t, plaintext)
	require.NotEqual(t, plaintext, secretResourceID, "the secret resource id must not be (or equal) the plaintext secret")
	require.Equal(t, handle, secretResourceID, "the secret resource id must equal the provider-issued application key id")
}

// TestIssueAndDeleteNeverLogSecret: capture every log record emitted across a
// full Issue + Delete cycle and assert the synthetic plaintext secret never
// appears in them.
func TestIssueAndDeleteNeverLogSecret(t *testing.T) {
	const (
		handle = "handle-logtest-1"
		secret = "plaintext-should-never-be-logged"
		name   = "c1-req-1"
	)
	server, _ := newServiceAccountAppKeyServer(t, testServiceAccountID, handle, secret, name)
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)

	var logBuf bytes.Buffer
	encoderCfg := zap.NewProductionEncoderConfig()
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), zapcore.AddSync(&logBuf), zapcore.DebugLevel)
	logger := zap.New(core)
	ctx := ctxzap.ToContext(context.Background(), logger)

	issued := issueServiceAccountAppKey(t, ctx, wrapper, testServiceAccountID, "req-1")
	require.Equal(t, secret, string(issued.PlaintextData[0].GetBytes()))

	deleter := newApplicationKeyBuilder(wrapper)
	_, err := deleter.Delete(ctx, issued.Secret.GetId(), issued.Secret.GetParentResourceId())
	require.NoError(t, err)
	require.NoError(t, logger.Sync())

	if strings.Contains(logBuf.String(), secret) {
		t.Fatalf("captured logs leaked the plaintext secret:\n%s", logBuf.String())
	}
}

// TestApplicationKeyBuilderDeleteUsesServiceAccountAPI: applicationKeyBuilder.Delete
// must issue the provider DELETE against the service-account-scoped
// application-key path, using the handle (resourceID) and the owning
// service account (parentResourceID, exactly as Issue recorded it on the
// returned secret's ParentResourceId), and the plaintext secret must never
// appear anywhere in that request.
func TestApplicationKeyBuilderDeleteUsesServiceAccountAPI(t *testing.T) {
	const (
		handle = "handle-sa-delete-1"
		secret = "super-secret-app-key-plaintext"
		name   = "c1-req-1"
	)
	server, requests := newServiceAccountAppKeyServer(t, testServiceAccountID, handle, secret, name)
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)
	ctx := context.Background()

	issued := issueServiceAccountAppKey(t, ctx, wrapper, testServiceAccountID, "req-1")
	require.Equal(t, secret, string(issued.PlaintextData[0].GetBytes()))

	deleter := newApplicationKeyBuilder(wrapper)
	_, err := deleter.Delete(ctx, issued.Secret.GetId(), issued.Secret.GetParentResourceId())
	require.NoError(t, err)

	var deleteReq *recordedRequest
	for i := range *requests {
		if (*requests)[i].method == http.MethodDelete {
			deleteReq = &(*requests)[i]
		}
	}
	require.NotNil(t, deleteReq, "expected a DELETE request to reach the provider")
	require.Equal(t, "/api/v2/service_accounts/"+testServiceAccountID+"/application_keys/"+handle, deleteReq.path)

	if strings.Contains(deleteReq.path, secret) || strings.Contains(deleteReq.query, secret) || strings.Contains(deleteReq.body, secret) {
		t.Fatalf("delete request leaked the plaintext secret: %+v", deleteReq)
	}
}

// TestApplicationKeyBuilderDeleteRejectsMalformedHandle: nil ResourceId, an
// empty or control-character handle, a missing/wrong-type/malformed
// parentResourceID (the owning service account) must all fail closed before
// any provider request. Datadog's DeleteServiceAccountApplicationKey needs
// both ids; parentResourceID carries the service account id (see
// application_key.go's Delete doc comment for why that parameter, not a
// packed handle string).
func TestApplicationKeyBuilderDeleteRejectsMalformedHandle(t *testing.T) {
	validParent := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID}
	tests := []struct {
		name             string
		resourceID       *v2.ResourceId
		parentResourceID *v2.ResourceId
	}{
		{
			name:             "nil ResourceId",
			resourceID:       nil,
			parentResourceID: validParent,
		},
		{
			name:             "empty ResourceId.Resource",
			resourceID:       &v2.ResourceId{ResourceType: serviceAccountApplicationKeyResourceType.Id, Resource: ""},
			parentResourceID: validParent,
		},
		{
			name:             "handle with control character",
			resourceID:       &v2.ResourceId{ResourceType: serviceAccountApplicationKeyResourceType.Id, Resource: "appkey-\n1"},
			parentResourceID: validParent,
		},
		{
			name:             "nil parentResourceID (owning service account missing)",
			resourceID:       &v2.ResourceId{ResourceType: serviceAccountApplicationKeyResourceType.Id, Resource: "appkey-1"},
			parentResourceID: nil,
		},
		{
			name:             "wrong-type parentResourceID",
			resourceID:       &v2.ResourceId{ResourceType: serviceAccountApplicationKeyResourceType.Id, Resource: "appkey-1"},
			parentResourceID: &v2.ResourceId{ResourceType: apiTokenResourceType.Id, Resource: testServiceAccountID},
		},
		{
			name:             "empty parentResourceID.Resource",
			resourceID:       &v2.ResourceId{ResourceType: serviceAccountApplicationKeyResourceType.Id, Resource: "appkey-1"},
			parentResourceID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: ""},
		},
		{
			name:             "parentResourceID with control character",
			resourceID:       &v2.ResourceId{ResourceType: serviceAccountApplicationKeyResourceType.Id, Resource: "appkey-1"},
			parentResourceID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: "sa-\n1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("provider should not be contacted for a %s, got %s %s", tt.name, r.Method, r.URL.Path)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			wrapper := newLifecycleTestWrapper(server.URL)

			deleter := newApplicationKeyBuilder(wrapper)
			_, err := deleter.Delete(context.Background(), tt.resourceID, tt.parentResourceID)
			require.Error(t, err)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}
