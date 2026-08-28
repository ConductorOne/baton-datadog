package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
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
	appendRequest(requests, rec)
	return rec
}

// recordMu guards the recorded-request slices. A fake provider's handler runs on
// the httptest server's goroutine while the test body reads what it recorded,
// and net/http promises no happens-before edge between the two -- relying on one
// is relying on runtime implementation detail rather than on the memory model.
// The race detector does not currently report this shape, which is why it has to
// be reasoned about rather than discovered.
var recordMu sync.Mutex

func appendRequest(requests *[]recordedRequest, rec recordedRequest) {
	recordMu.Lock()
	defer recordMu.Unlock()
	*requests = append(*requests, rec)
}

// snapshotRequests copies the recorded requests under the lock so the test body
// can iterate them without racing a handler still appending.
func snapshotRequests(requests *[]recordedRequest) []recordedRequest {
	recordMu.Lock()
	defer recordMu.Unlock()
	out := make([]recordedRequest, len(*requests))
	copy(out, *requests)
	return out
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

	deleter := newDeletableAPITokenBuilder(wrapper)
	resourceID := &v2.ResourceId{ResourceType: apiTokenResourceType.Id, Resource: issued.ID}
	_, err = deleter.Delete(ctx, resourceID, nil)
	require.NoError(t, err)

	var deleteReq *recordedRequest
	recorded := snapshotRequests(requests)
	for i := range recorded {
		if recorded[i].method == http.MethodDelete {
			deleteReq = &recorded[i]
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

			deleter := newDeletableAPITokenBuilder(wrapper)
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
	issuer := newCredentialUserBuilder(wrapper, false)
	out, err := issuer.Issue(ctx, &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: serviceAccountID},
		RequestID:  requestID,
		CredentialOptions: v2.CredentialIssueOptions_builder{
			SecretResourceTypeId: serviceAccountApplicationKeyResourceType.Id,
			ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{}.Build(),
		}.Build(),
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

		issuer := newCredentialUserBuilder(wrapper, false)
		out, err := issuer.Issue(context.Background(), &connectorbuilder.CredentialIssueInput{
			IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: humanUserID},
			RequestID:  "req-reject",
			CredentialOptions: v2.CredentialIssueOptions_builder{
				SecretResourceTypeId: serviceAccountApplicationKeyResourceType.Id,
				ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{}.Build(),
			}.Build(),
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

	issuer := newCredentialUserBuilder(wrapper, false)
	out, err := issuer.Issue(context.Background(), &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID},
		RequestID:  requestID,
		CredentialOptions: v2.CredentialIssueOptions_builder{
			SecretResourceTypeId: serviceAccountApplicationKeyResourceType.Id,
			ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{}.Build(),
		}.Build(),
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
	recorded := snapshotRequests(requests)
	for i := range recorded {
		if recorded[i].method == http.MethodDelete {
			deleteReq = &recorded[i]
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

// --- applicationKeyBuilder.List paging ------------------------------------

// newAppKeyListServer fakes the two endpoints applicationKeyBuilder.List
// walks. usersPages[n] is the JSON "data" array for users page n, and
// appKeyPages[serviceAccountID][n] is that service account's application-key
// page n. A service account id present in forbidden gets a 403 instead, which
// is what a Datadog role without service_account_write returns.
func newAppKeyListServer(
	t *testing.T,
	usersPages []string,
	appKeyPages map[string][]string,
	forbidden map[string]bool,
) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	requests := &[]recordedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordRequest(t, requests, r)
		w.Header().Set("Content-Type", "application/json")
		page := 0
		if raw := r.URL.Query().Get("page[number]"); raw != "" {
			if _, err := fmt.Sscanf(raw, "%d", &page); err != nil {
				t.Errorf("unparsable page[number]=%q", raw)
			}
		}

		if r.URL.Path == "/api/v2/users" {
			body := "[]"
			if page < len(usersPages) {
				body = usersPages[page]
			}
			_, _ = w.Write([]byte(`{"data":` + body + `}`))
			return
		}

		const prefix = "/api/v2/service_accounts/"
		const suffix = "/application_keys"
		if strings.HasPrefix(r.URL.Path, prefix) && strings.HasSuffix(r.URL.Path, suffix) {
			serviceAccountID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), suffix)
			if forbidden[serviceAccountID] {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":["Forbidden"]}`))
				return
			}
			pages := appKeyPages[serviceAccountID]
			body := "[]"
			if page < len(pages) {
				body = pages[page]
			}
			_, _ = w.Write([]byte(`{"data":` + body + `}`))
			return
		}

		t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	return server, requests
}

// appKeyPageJSON builds one application-key page of count keys, named by prefix.
func appKeyPageJSON(prefix string, count int) string {
	keys := make([]string, 0, count)
	for i := 0; i < count; i++ {
		keys = append(keys, fmt.Sprintf(`{"id":"%s-%d","type":"application_keys","attributes":{"name":"%s-%d"}}`, prefix, i, prefix, i))
	}
	return "[" + strings.Join(keys, ",") + "]"
}

// drainAppKeyList runs List to exhaustion the way the SDK does -- feeding each
// call the previous call's NextPageToken -- and reports, per call, how many
// provider requests that single call issued.
func drainAppKeyList(t *testing.T, builder *applicationKeyBuilder, requests *[]recordedRequest) ([]*v2.Resource, []int) {
	t.Helper()
	ctx := context.Background()
	var all []*v2.Resource
	var requestsPerCall []int
	token := ""
	// The guard keeps a paging regression from hanging the suite.
	const maxCalls = 100
	for call := 0; ; call++ {
		require.Less(t, call, maxCalls, "List did not terminate")
		before := len(snapshotRequests(requests))
		got, results, err := builder.List(ctx, nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		require.NoError(t, err)
		requestsPerCall = append(requestsPerCall, len(snapshotRequests(requests))-before)
		all = append(all, got...)
		require.NotNil(t, results)
		if results.NextPageToken == "" {
			return all, requestsPerCall
		}
		token = results.NextPageToken
	}
}

// TestApplicationKeyBuilderListReturnsOnePagePerCall: List must issue at most
// one provider list request per call and must not drain a service account's
// application-key pages inside a single call (criteria F2), while still
// returning every key across the whole walk.
func TestApplicationKeyBuilderListReturnsOnePagePerCall(t *testing.T) {
	usersPages := []string{
		`[{"id":"sa-1","type":"users","attributes":{"service_account":true}},` +
			`{"id":"human-1","type":"users","attributes":{"service_account":false}},` +
			`{"id":"sa-2","type":"users","attributes":{"service_account":true}}]`,
	}
	appKeyPages := map[string][]string{
		// sa-1 spans two pages: a full page forces a second request.
		"sa-1": {appKeyPageJSON("sa1key", defaultV2PageSize), appKeyPageJSON("sa1key-p2", 1)},
		"sa-2": {appKeyPageJSON("sa2key", 2)},
	}
	server, requests := newAppKeyListServer(t, usersPages, appKeyPages, nil)
	defer server.Close()

	got, requestsPerCall := drainAppKeyList(t, newApplicationKeyBuilder(newLifecycleTestWrapper(server.URL)), requests)

	for call, n := range requestsPerCall {
		require.LessOrEqualf(t, n, 1, "List call %d issued %d provider requests; at most one page per call is allowed", call, n)
	}
	// The walk needs a users page, three application-key pages (two for sa-1,
	// one for sa-2) and a final empty users page. Spreading those over
	// separate calls is the point: draining them inside one call is what F2
	// forbids, and would show up here as a single call issuing them all.
	require.GreaterOrEqual(t, len(requestsPerCall), 5, "the walk must span multiple List calls, one provider page each")
	require.Len(t, snapshotRequests(requests), len(requestsPerCall), "one provider request per List call")

	require.Len(t, got, defaultV2PageSize+1+2, "every application key across both service accounts must be returned")

	ids := make(map[string]bool, len(got))
	for _, r := range got {
		ids[r.GetId().GetResource()] = true
		require.Equal(t, serviceAccountApplicationKeyResourceType.Id, r.GetId().GetResourceType())
	}
	require.True(t, ids["sa1key-0"], "first page of sa-1 keys must be present")
	require.True(t, ids["sa1key-p2-0"], "second page of sa-1 keys must be present")
	require.True(t, ids["sa2key-0"], "sa-2 keys must be present")

	// A human user must never be queried for service-account application keys.
	for _, req := range snapshotRequests(requests) {
		require.NotContains(t, req.path, "human-1")
	}
}

// TestApplicationKeyBuilderListFailsHardOnForbiddenServiceAccount: a 403 from
// ListServiceAccountApplicationKeys -- what an install whose Datadog role lacks
// service_account_write gets -- must fail the sync. Skipping the service
// account would report a successful sync missing its application keys, and C1
// reads a resource absent from a completed sync as deleted, so the keys would
// be retired from the inventory instead of the permission problem surfacing.
// The error has to name the permission, because nothing else does: C1 does not
// consume a connector's advertised CapabilityPermissions, so this message is
// the only place an operator learns what to grant.
func TestApplicationKeyBuilderListFailsHardOnForbiddenServiceAccount(t *testing.T) {
	usersPages := []string{
		`[{"id":"sa-forbidden","type":"users","attributes":{"service_account":true}},` +
			`{"id":"sa-ok","type":"users","attributes":{"service_account":true}}]`,
	}
	appKeyPages := map[string][]string{"sa-ok": {appKeyPageJSON("okkey", 1)}}
	server, requests := newAppKeyListServer(t, usersPages, appKeyPages, map[string]bool{"sa-forbidden": true})
	defer server.Close()

	builder := newApplicationKeyBuilder(newLifecycleTestWrapper(server.URL))
	ctx := context.Background()
	token := ""
	for call := 0; call < 10; call++ {
		_, results, err := builder.List(ctx, nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		if err != nil {
			require.ErrorContains(t, err, "service_account_write",
				"the error must name the permission the operator has to grant")
			require.ErrorContains(t, err, "sa-forbidden",
				"the error must name the service account that could not be read")
			attempted := false
			for _, req := range snapshotRequests(requests) {
				if strings.Contains(req.path, "sa-forbidden") {
					attempted = true
				}
			}
			require.True(t, attempted, "the forbidden service account must actually have been attempted")
			return
		}
		require.NotNil(t, results)
		require.NotEmpty(t, results.NextPageToken, "sync ended without surfacing the 403")
		token = results.NextPageToken
	}
	t.Fatal("List never surfaced the 403")
}

// TestApplicationKeyBuilderListFailsHardOnMissingServiceAccount: a 404 is
// treated exactly like a 403. Datadog documents both on this endpoint without
// saying which failures produce which, so a 404 cannot be assumed to mean the
// service account is genuinely gone rather than invisible to this role --
// and a role masked behind 404s would otherwise sync an empty credential
// inventory while reporting success.
func TestApplicationKeyBuilderListFailsHardOnMissingServiceAccount(t *testing.T) {
	requests := &[]recordedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordRequest(t, requests, r)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v2/users" {
			_, _ = w.Write([]byte(`{"data":[{"id":"sa-gone","type":"users","attributes":{"service_account":true}}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":["Not Found"]}`))
	}))
	defer server.Close()

	builder := newApplicationKeyBuilder(newLifecycleTestWrapper(server.URL))
	ctx := context.Background()
	token := ""
	for call := 0; call < 10; call++ {
		_, results, err := builder.List(ctx, nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		if err != nil {
			require.ErrorContains(t, err, "sa-gone")
			return
		}
		require.NotNil(t, results)
		require.NotEmpty(t, results.NextPageToken, "sync ended without surfacing the 404")
		token = results.NextPageToken
	}
	t.Fatal("List never surfaced the 404")
}

// TestApplicationKeyBuilderListFailsHardOnUnexpectedError: every provider
// error aborts the sync; this covers the non-403/404 path, where the error
// carries no permission or missing-service-account hint of its own.
func TestApplicationKeyBuilderListFailsHardOnUnexpectedError(t *testing.T) {
	requests := &[]recordedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordRequest(t, requests, r)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v2/users" {
			_, _ = w.Write([]byte(`{"data":[{"id":"sa-1","type":"users","attributes":{"service_account":true}}]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":["boom"]}`))
	}))
	defer server.Close()

	builder := newApplicationKeyBuilder(newLifecycleTestWrapper(server.URL))
	ctx := context.Background()
	token := ""
	for call := 0; call < 10; call++ {
		_, results, err := builder.List(ctx, nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		if err != nil {
			return // expected: the 5xx aborted the sync
		}
		require.NotNil(t, results)
		require.NotEmpty(t, results.NextPageToken, "sync ended without surfacing the provider 5xx")
		token = results.NextPageToken
	}
	t.Fatal("List never surfaced the provider 5xx")
}

// --- application-key scopes on the resource profile -----------------------

// profileScopes reads the scopes list out of a resource profile. The second
// return reports whether the key was present at all, which is the distinction
// the representation turns on: absent means Datadog never reported scopes,
// present-and-empty means Datadog reported an unscoped key.
func profileScopes(t *testing.T, r *v2.Resource) ([]string, bool) {
	t.Helper()
	profile := r.GetProfile()
	if profile == nil {
		return nil, false
	}
	value, ok := profile.GetFields()[applicationKeyScopesProfileKey]
	if !ok {
		return nil, false
	}
	list := value.GetListValue()
	require.NotNil(t, list, "scopes must always be a list when present, never null")
	out := make([]string, 0, len(list.GetValues()))
	for _, item := range list.GetValues() {
		out = append(out, item.GetStringValue())
	}
	return out, true
}

// TestApplicationKeyResourceScopesProfile: SecretTrait has no scopes field, so
// scopes ride on Resource.Profile. Datadog's scopes field is a three-state
// nullable list, and the profile must collapse it to two states without ever
// claiming a key is unscoped when the provider did not say so. Attributes are
// decoded from JSON rather than hand-built so the real wire shapes are what
// gets exercised.
func TestApplicationKeyResourceScopesProfile(t *testing.T) {
	tests := []struct {
		name       string
		attrsJSON  string
		wantScopes []string
		wantKey    bool
	}{
		{
			name:       "scopes reported",
			attrsJSON:  `{"name":"k","scopes":["dashboards_read","dashboards_write"]}`,
			wantScopes: []string{"dashboards_read", "dashboards_write"},
			wantKey:    true,
		},
		{
			name:       "explicit null means unscoped",
			attrsJSON:  `{"name":"k","scopes":null}`,
			wantScopes: []string{},
			wantKey:    true,
		},
		{
			name:       "empty list also means unscoped",
			attrsJSON:  `{"name":"k","scopes":[]}`,
			wantScopes: []string{},
			wantKey:    true,
		},
		{
			name:      "field absent means not reported, so no claim is made",
			attrsJSON: `{"name":"k"}`,
			wantKey:   false,
		},
	}
	parent := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var attrs datadogV2.PartialApplicationKeyAttributes
			require.NoError(t, json.Unmarshal([]byte(tc.attrsJSON), &attrs))

			res, err := applicationKeyResource("appkey-1", parent, &attrs, nil)
			require.NoError(t, err)

			got, present := profileScopes(t, res)
			require.Equalf(t, tc.wantKey, present, "profile key presence for %s", tc.attrsJSON)
			if tc.wantKey {
				require.Equal(t, tc.wantScopes, got)
			}

			// Setting the profile must not cost the secret trait:
			// NewSecretResource applies WithSecretTrait after the caller's
			// resource options, and its trait-to-resource copy is guarded on
			// the resource having no profile.
			trait := &v2.SecretTrait{}
			annos := annotations.Annotations(res.GetAnnotations())
			found, err := annos.Pick(trait)
			require.NoError(t, err)
			require.True(t, found, "secret trait must survive alongside the profile")
			require.Equal(t, "datadog.service_account_application_key", trait.GetCredentialDetail())
		})
	}
}

// TestApplicationKeyListCarriesScopes: the scopes reach the resources the sync
// actually emits, not just the constructor, and a key whose scopes change
// between syncs reports the new value rather than a cached one.
func TestApplicationKeyListCarriesScopes(t *testing.T) {
	scoped := `{"id":"k-scoped","type":"application_keys","attributes":{"name":"scoped","scopes":["logs_read"]}}`
	unscoped := `{"id":"k-unscoped","type":"application_keys","attributes":{"name":"unscoped","scopes":null}}`
	usersPages := []string{`[{"id":"sa-1","type":"users","attributes":{"service_account":true}}]`}

	// The upstream key set is swapped between drains to simulate a rescope. The
	// handler reads it on the server's goroutine while the test body rewrites it,
	// so it is guarded: net/http gives no happens-before edge between the two.
	// The same server serves both drains on purpose -- giving each drain its own
	// server would stop exercising the rescope-mid-life path this test exists for.
	var keysMu sync.Mutex
	currentKeys := "[" + scoped + "," + unscoped + "]"
	setKeys := func(v string) {
		keysMu.Lock()
		defer keysMu.Unlock()
		currentKeys = v
	}
	getKeys := func() string {
		keysMu.Lock()
		defer keysMu.Unlock()
		return currentKeys
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		page := 0
		if raw := r.URL.Query().Get("page[number]"); raw != "" {
			_, _ = fmt.Sscanf(raw, "%d", &page)
		}
		switch {
		case r.URL.Path == "/api/v2/users":
			body := "[]"
			if page < len(usersPages) {
				body = usersPages[page]
			}
			_, _ = w.Write([]byte(`{"data":` + body + `}`))
		case strings.HasSuffix(r.URL.Path, "/application_keys"):
			body := "[]"
			if page == 0 {
				body = getKeys()
			}
			_, _ = w.Write([]byte(`{"data":` + body + `}`))
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	builder := newApplicationKeyBuilder(newLifecycleTestWrapper(server.URL))
	drain := func() map[string][]string {
		t.Helper()
		out := map[string][]string{}
		token := ""
		for call := 0; call < 50; call++ {
			got, results, err := builder.List(context.Background(), nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
			require.NoError(t, err)
			for _, r := range got {
				scopes, present := profileScopes(t, r)
				require.True(t, present, "synced key %s must report scopes", r.GetId().GetResource())
				out[r.GetId().GetResource()] = scopes
			}
			require.NotNil(t, results)
			if results.NextPageToken == "" {
				return out
			}
			token = results.NextPageToken
		}
		t.Fatal("List did not terminate")
		return nil
	}

	first := drain()
	require.Equal(t, []string{"logs_read"}, first["k-scoped"])
	require.Equal(t, []string{}, first["k-unscoped"], "an unscoped key reports an empty list, not a missing key")

	// The same key, rescoped upstream, on the same live server.
	setKeys(`[{"id":"k-scoped","type":"application_keys","attributes":{"name":"scoped","scopes":["logs_read","metrics_read"]}}]`)
	second := drain()
	require.Equal(t, []string{"logs_read", "metrics_read"}, second["k-scoped"], "a rescoped key must report its new scopes")
}

// TestIssuePassesScopesToProviderAndProfile: the requested scopes must actually
// reach Datadog's create call -- a pass-through that no test exercised before --
// and the issued resource must carry the scopes the provider echoed back, so a
// freshly vended key agrees with what the next sync will report for it.
func TestIssuePassesScopesToProviderAndProfile(t *testing.T) {
	const handle = "handle-scoped-1"
	requested := []string{"logs_read", "metrics_read"}

	// createBody is written on the server's goroutine and read by the test body,
	// so it is guarded for the same reason as the key set above.
	var (
		bodyMu     sync.Mutex
		createBody string
	)
	setCreateBody := func(v string) {
		bodyMu.Lock()
		defer bodyMu.Unlock()
		createBody = v
	}
	getCreateBody := func() string {
		bodyMu.Lock()
		defer bodyMu.Unlock()
		return createBody
	}
	appKeysPath := "/api/v2/service_accounts/" + testServiceAccountID + "/application_keys"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/"+testServiceAccountID:
			_, _ = w.Write([]byte(`{"data":{"id":"` + testServiceAccountID + `","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == appKeysPath:
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == appKeysPath:
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(r.Body)
			setCreateBody(buf.String())
			// Echo the scopes back, as Datadog does.
			_, _ = w.Write([]byte(`{"data":{"id":"` + handle + `","type":"application_keys","attributes":{"key":"plaintext","name":"c1-req-scoped","scopes":["logs_read","metrics_read"]}}}`))
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	issuer := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), false)
	out, err := issuer.Issue(context.Background(), &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID},
		RequestID:  "req-scoped",
		CredentialOptions: v2.CredentialIssueOptions_builder{
			SecretResourceTypeId: serviceAccountApplicationKeyResourceType.Id,
			ApiKey:               v2.CredentialIssueOptions_ApiKey_builder{Scopes: requested}.Build(),
		}.Build(),
	})
	require.NoError(t, err)

	// The pass-through into the provider request.
	sentBody := getCreateBody()
	require.NotEmpty(t, sentBody, "create request body must have been captured")
	var sent struct {
		Data struct {
			Attributes struct {
				Scopes *[]string `json:"scopes"`
			} `json:"attributes"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(sentBody), &sent))
	require.NotNil(t, sent.Data.Attributes.Scopes, "requested scopes must be sent to Datadog")
	require.Equal(t, requested, *sent.Data.Attributes.Scopes)

	// And onto the issued resource.
	scopes, present := profileScopes(t, out.Secret)
	require.True(t, present, "an issued key must report its scopes immediately")
	require.Equal(t, requested, scopes)
}

// TestIssueOmitsScopesProfileWhenProviderSilent: when the create response says
// nothing about scopes, the issued resource must not claim the key is unscoped.
func TestIssueOmitsScopesProfileWhenProviderSilent(t *testing.T) {
	const handle = "handle-silent-1"
	server, _ := newServiceAccountAppKeyServer(t, testServiceAccountID, handle, "plaintext", "c1-req-silent")
	defer server.Close()

	out := issueServiceAccountAppKey(t, context.Background(), newLifecycleTestWrapper(server.URL), testServiceAccountID, "req-silent")

	_, present := profileScopes(t, out.Secret)
	require.False(t, present, "a silent provider response must not be reported as an unscoped key")
}

// --- malformed created_at, and users page size ---------------------------

// TestApplicationKeyResourceMalformedCreatedAt: a created_at this connector
// cannot parse must drop the field and still produce a usable resource, and it
// must report the problem to its caller. Failing here would mean one bad
// timestamp from the provider hides every application key in the organization
// from C1, which is a worse outcome than a missing display value.
func TestApplicationKeyResourceMalformedCreatedAt(t *testing.T) {
	parent := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: testServiceAccountID}

	t.Run("malformed value drops the field and reports", func(t *testing.T) {
		var attrs datadogV2.PartialApplicationKeyAttributes
		require.NoError(t, json.Unmarshal([]byte(`{"name":"k","created_at":"not-a-timestamp"}`), &attrs))

		var gotID, gotRaw string
		var gotErr error
		res, err := applicationKeyResource("appkey-bad-ts", parent, &attrs,
			func(appKeyID, raw string, parseErr error) {
				gotID, gotRaw, gotErr = appKeyID, raw, parseErr
			})

		require.NoError(t, err, "a malformed created_at must not fail resource construction")
		require.NotNil(t, res)
		require.Equal(t, "appkey-bad-ts", res.GetId().GetResource(), "the key must still be syncable")
		require.Nil(t, res.GetCreatedAt(), "an unparseable created_at must be dropped, not guessed")

		require.Equal(t, "appkey-bad-ts", gotID, "the report must name the key")
		require.Equal(t, "not-a-timestamp", gotRaw, "the report must carry the value that failed")
		require.Error(t, gotErr, "the report must carry the parse error")
	})

	t.Run("a parseable value is still recorded", func(t *testing.T) {
		var attrs datadogV2.PartialApplicationKeyAttributes
		require.NoError(t, json.Unmarshal([]byte(`{"name":"k","created_at":"2026-08-22T04:01:01.5Z"}`), &attrs))

		called := false
		res, err := applicationKeyResource("appkey-good-ts", parent, &attrs,
			func(string, string, error) { called = true })

		require.NoError(t, err)
		require.False(t, called, "a parseable created_at must not be reported as malformed")
		require.NotNil(t, res.GetCreatedAt(), "a parseable created_at must be recorded")
		require.Equal(t, 2026, res.GetCreatedAt().AsTime().Year())
	})

	t.Run("a nil callback is tolerated", func(t *testing.T) {
		var attrs datadogV2.PartialApplicationKeyAttributes
		require.NoError(t, json.Unmarshal([]byte(`{"name":"k","created_at":"nope"}`), &attrs))
		res, err := applicationKeyResource("appkey-nil-cb", parent, &attrs, nil)
		require.NoError(t, err)
		require.Nil(t, res.GetCreatedAt())
	})
}

// TestApplicationKeyListSurvivesMalformedCreatedAt: the whole walk must complete
// when the provider returns an unparseable created_at, the affected key must
// still be synced, and every affected key must be reported. The timestamp is
// decorative -- nothing about identifying, attributing or revoking the key
// depends on it -- so dropping the field beats losing sight of the credential.
func TestApplicationKeyListSurvivesMalformedCreatedAt(t *testing.T) {
	const keys = 12
	entries := make([]string, 0, keys)
	for i := 0; i < keys; i++ {
		entries = append(entries, fmt.Sprintf(
			`{"id":"bad-ts-%02d","type":"application_keys","attributes":{"name":"k%02d","created_at":"not-a-timestamp"}}`, i, i))
	}
	usersPages := []string{`[{"id":"sa-1","type":"users","attributes":{"service_account":true}}]`}
	appKeyPages := map[string][]string{"sa-1": {"[" + strings.Join(entries, ",") + "]"}}

	server, _ := newAppKeyListServer(t, usersPages, appKeyPages, nil)
	defer server.Close()

	var logBuf bytes.Buffer
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&logBuf),
		zapcore.DebugLevel,
	)
	ctx := ctxzap.ToContext(context.Background(), zap.New(core))

	builder := newApplicationKeyBuilder(newLifecycleTestWrapper(server.URL))
	var synced []*v2.Resource
	token := ""
	for call := 0; call < 50; call++ {
		got, results, err := builder.List(ctx, nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		require.NoError(t, err, "a malformed created_at must never fail the walk")
		synced = append(synced, got...)
		require.NotNil(t, results)
		if results.NextPageToken == "" {
			break
		}
		token = results.NextPageToken
	}

	require.Len(t, synced, keys, "every key must still be synced despite the bad timestamp")
	for _, r := range synced {
		require.Nil(t, r.GetCreatedAt(), "the unparseable timestamp must be dropped, not guessed")
	}

	warned := 0
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Msg string `json:"msg"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		if rec.Msg != "baton-datadog: application key created_at could not be parsed; syncing the key without it" {
			continue
		}
		warned++
	}
	require.Equal(t, keys, warned, "every key with an unparseable created_at must be reported")
}

// TestApplicationKeySyncRequestsFullUsersPage: the users walk must ask for the
// same page size the rest of the connector uses. Datadog's documented default is
// 10, so omitting it costs ten times the round-trips for the same users.
func TestApplicationKeySyncRequestsFullUsersPage(t *testing.T) {
	usersPages := []string{`[{"id":"sa-1","type":"users","attributes":{"service_account":true}}]`}
	appKeyPages := map[string][]string{"sa-1": {appKeyPageJSON("k", 1)}}
	server, requests := newAppKeyListServer(t, usersPages, appKeyPages, nil)
	defer server.Close()

	drainAppKeyList(t, newApplicationKeyBuilder(newLifecycleTestWrapper(server.URL)), requests)

	sawUsersPage := false
	for _, req := range snapshotRequests(requests) {
		if req.path != "/api/v2/users" {
			continue
		}
		sawUsersPage = true
		require.Containsf(t, req.query, fmt.Sprintf("page%%5Bsize%%5D=%d", defaultV2PageSize),
			"users walk must request the shared page size; query was %q", req.query)
	}
	require.True(t, sawUsersPage, "the walk must have listed users at least once")
}

// TestApiTokenListSurvivesMalformedTimestamps: the organization API-key sync
// must not abort because a provider timestamp will not parse. This mirrors the
// application-key behavior; deleting an org API key depends on the handle alone,
// so a bad created_at or modified_at is not worth a whole-sync outage.
func TestApiTokenListSurvivesMalformedTimestamps(t *testing.T) {
	const keys = 12
	entries := make([]string, 0, keys)
	for i := 0; i < keys; i++ {
		entries = append(entries, fmt.Sprintf(
			`{"id":"key-%02d","type":"api_keys","attributes":{"name":"n%02d","created_at":"not-a-timestamp","modified_at":"also-bad"}}`, i, i))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		page := 0
		if raw := r.URL.Query().Get("page[number]"); raw != "" {
			_, _ = fmt.Sscanf(raw, "%d", &page)
		}
		if r.URL.Path != "/api/v2/api_keys" {
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if page > 0 {
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[` + strings.Join(entries, ",") + `]}`))
	}))
	defer server.Close()

	var logBuf bytes.Buffer
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&logBuf),
		zapcore.DebugLevel,
	)
	ctx := ctxzap.ToContext(context.Background(), zap.New(core))

	builder := newApiTokenBuilder(newLifecycleTestWrapper(server.URL))
	var synced []*v2.Resource
	token := ""
	for call := 0; call < 50; call++ {
		got, results, err := builder.List(ctx, nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		require.NoError(t, err, "a malformed timestamp must never fail the org API-key walk")
		synced = append(synced, got...)
		require.NotNil(t, results)
		if results.NextPageToken == "" {
			break
		}
		token = results.NextPageToken
	}

	require.Len(t, synced, keys, "every org API key must still be synced despite bad timestamps")
	for _, r := range synced {
		require.Nil(t, r.GetCreatedAt(), "an unparseable created_at must be dropped, not guessed")
	}

	warned := 0
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Msg   string `json:"msg"`
			Field string `json:"field"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		if rec.Msg != "baton-datadog: organization API key timestamp could not be parsed; syncing the key without it" {
			continue
		}
		warned++
		require.Contains(t, []string{"created_at", "modified_at"}, rec.Field, "the warning must name the field")
	}
	// Every key carries two unparseable fields, and each is reported.
	require.Equal(t, keys*2, warned, "every unparseable timestamp must be reported")
}

// TestApplicationKeyBuilderSkipsDisabledServiceAccounts is the regression for a
// sync-wide outage: Datadog answers 404, not an empty list, for a disabled
// service account's application keys, and listApplicationKeyPage fails closed on
// 404. Because Datadog never deletes users -- only disables them -- one disabled
// service account made every application key in the organization permanently
// unsyncable. The walk must not visit them at all.
func TestApplicationKeyBuilderSkipsDisabledServiceAccounts(t *testing.T) {
	t.Parallel()

	const enabledID = "sa-enabled"
	const disabledID = "sa-disabled"
	usersPage := `[` +
		`{"id":"` + disabledID + `","attributes":{"service_account":true,"disabled":true,"status":"Disabled"}},` +
		`{"id":"` + enabledID + `","attributes":{"service_account":true,"disabled":false,"status":"Active"}}` +
		`]`

	var mu sync.Mutex
	visited := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		page := 0
		if raw := r.URL.Query().Get("page[number]"); raw != "" {
			_, _ = fmt.Sscanf(raw, "%d", &page)
		}
		if r.URL.Path == "/api/v2/users" {
			if page == 0 {
				_, _ = w.Write([]byte(`{"data":` + usersPage + `}`))
			} else {
				_, _ = w.Write([]byte(`{"data":[]}`))
			}
			return
		}
		const prefix = "/api/v2/service_accounts/"
		const suffix = "/application_keys"
		if strings.HasPrefix(r.URL.Path, prefix) && strings.HasSuffix(r.URL.Path, suffix) {
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), suffix)
			mu.Lock()
			visited[id]++
			mu.Unlock()
			if id == disabledID {
				// What Datadog actually does for a disabled service account.
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":["Not Found"]}`))
				return
			}
			if page == 0 {
				_, _ = w.Write([]byte(`{"data":` + appKeyPageJSON("live", 1) + `}`))
			} else {
				_, _ = w.Write([]byte(`{"data":[]}`))
			}
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	builder := newApplicationKeyBuilder(newLifecycleTestWrapper(server.URL))
	var synced []*v2.Resource
	token := ""
	for call := 0; call < 50; call++ {
		got, results, err := builder.List(context.Background(), nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		require.NoError(t, err, "a disabled service account must not fail the walk")
		synced = append(synced, got...)
		if results == nil || results.NextPageToken == "" {
			break
		}
		token = results.NextPageToken
	}

	mu.Lock()
	defer mu.Unlock()
	require.Zero(t, visited[disabledID], "the disabled service account must never be requested")
	require.Positive(t, visited[enabledID], "the enabled service account must still be walked")
	require.Len(t, synced, 1, "the enabled service account's application key must still sync")
}
