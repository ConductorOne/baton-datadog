package connector

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
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
		before := len(*requests)
		got, results, err := builder.List(ctx, nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		require.NoError(t, err)
		requestsPerCall = append(requestsPerCall, len(*requests)-before)
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
	require.Len(t, *requests, len(requestsPerCall), "one provider request per List call")

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
	for _, req := range *requests {
		require.NotContains(t, req.path, "human-1")
	}
}

// TestApplicationKeyBuilderListSkipsForbiddenServiceAccount: a 403 from
// ListServiceAccountApplicationKeys -- what an install whose Datadog role
// lacks service_account_write gets -- must skip that one service account and
// let the rest of the sync finish, not fail the whole sync (criteria R7).
func TestApplicationKeyBuilderListSkipsForbiddenServiceAccount(t *testing.T) {
	usersPages := []string{
		`[{"id":"sa-forbidden","type":"users","attributes":{"service_account":true}},` +
			`{"id":"sa-ok","type":"users","attributes":{"service_account":true}}]`,
	}
	appKeyPages := map[string][]string{"sa-ok": {appKeyPageJSON("okkey", 1)}}
	server, requests := newAppKeyListServer(t, usersPages, appKeyPages, map[string]bool{"sa-forbidden": true})
	defer server.Close()

	got, _ := drainAppKeyList(t, newApplicationKeyBuilder(newLifecycleTestWrapper(server.URL)), requests)

	require.Len(t, got, 1, "the readable service account's keys must still sync")
	require.Equal(t, "okkey-0", got[0].GetId().GetResource())

	attempted := false
	for _, req := range *requests {
		if strings.Contains(req.path, "sa-forbidden") {
			attempted = true
		}
	}
	require.True(t, attempted, "the forbidden service account must actually have been attempted")
}

// TestApplicationKeyBuilderListFailsHardOnUnexpectedError: only
// PermissionDenied/NotFound are skipped; any other provider error must still
// abort the sync rather than silently under-reporting keys.
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

// TestShouldLogSampled: the L7 schedule is the 1st, 10th and 100th occurrence,
// then every 1000th, and nothing else.
func TestShouldLogSampled(t *testing.T) {
	logged := map[int64]bool{}
	for n := int64(1); n <= 3000; n++ {
		if shouldLogSampled(n) {
			logged[n] = true
		}
	}
	for _, want := range []int64{1, 10, 100, 1000, 2000, 3000} {
		require.Truef(t, logged[want], "occurrence %d should be logged", want)
	}
	for _, notWant := range []int64{2, 9, 11, 99, 101, 999, 1001, 1999} {
		require.Falsef(t, logged[notWant], "occurrence %d should not be logged", notWant)
	}
	require.Len(t, logged, 6, "exactly 1, 10, 100, 1000, 2000, 3000 in the first 3000")
	require.False(t, shouldLogSampled(0), "a zero count is not an occurrence")
	require.False(t, shouldLogSampled(-1), "a negative count is not an occurrence")
}

// drainForSkipWarnings runs one full List walk with its own log sink and
// returns the skip-warning lines that walk emitted.
func drainForSkipWarnings(t *testing.T, builder *applicationKeyBuilder) []string {
	t.Helper()
	var logBuf bytes.Buffer
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&logBuf),
		zapcore.DebugLevel,
	)
	logger := zap.New(core)
	ctx := ctxzap.ToContext(context.Background(), logger)

	token := ""
	for call := 0; call < 200; call++ {
		require.Less(t, call, 199, "List did not terminate")
		_, results, err := builder.List(ctx, nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		require.NoError(t, err, "a 403 must never fail the sync")
		require.NotNil(t, results)
		if results.NextPageToken == "" {
			break
		}
		// Only the first call of a walk may carry an empty token; the reset in
		// List depends on that, so assert it rather than assuming it.
		require.NotEmpty(t, results.NextPageToken, "mid-walk token must never be empty")
		token = results.NextPageToken
	}
	require.NoError(t, logger.Sync())

	var skips []string
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		if line != "" && strings.Contains(line, "skipping application keys for service account") {
			skips = append(skips, line)
		}
	}
	return skips
}

// TestApplicationKeyBuilderListSamplesSkipWarning: when the configured Datadog
// role cannot read application keys org-wide, the skip warning must not fire
// once per service account (criteria L7). With 12 forbidden service accounts
// only the 1st and 10th are logged, each carrying total_occurrences.
//
// The counter also has to restart per walk. applicationKeyBuilder is built once
// per connector process (Datadog.ResourceSyncers runs inside
// connectorbuilder.NewConnector), so a counter that only ever climbed would let
// the first sync consume the 1/10/100 slots and leave every later sync silent
// until the running total reached 1000 -- which is worse than the noise the
// sampling exists to prevent. Draining twice proves the second walk gets its
// own schedule.
func TestApplicationKeyBuilderListSamplesSkipWarning(t *testing.T) {
	const serviceAccounts = 12
	entries := make([]string, 0, serviceAccounts)
	forbidden := map[string]bool{}
	for i := 0; i < serviceAccounts; i++ {
		id := fmt.Sprintf("sa-%02d", i)
		entries = append(entries, fmt.Sprintf(`{"id":"%s","type":"users","attributes":{"service_account":true}}`, id))
		forbidden[id] = true
	}
	usersPages := []string{"[" + strings.Join(entries, ",") + "]"}

	server, requests := newAppKeyListServer(t, usersPages, nil, forbidden)
	defer server.Close()

	builder := newApplicationKeyBuilder(newLifecycleTestWrapper(server.URL))

	for walk := 1; walk <= 2; walk++ {
		skips := drainForSkipWarnings(t, builder)
		require.Lenf(t, skips, 2, "walk %d: 12 skips must log only the 1st and 10th, not one line each", walk)
		for _, line := range skips {
			require.Containsf(t, line, "total_occurrences", "walk %d: a sampled warning must report the real count", walk)
		}
		require.Containsf(t, skips[0], `"total_occurrences":1`, "walk %d: first logged line is occurrence 1", walk)
		require.Containsf(t, skips[1], `"total_occurrences":10`, "walk %d: second logged line is occurrence 10", walk)
	}

	// Both walks attempted every service account.
	attempted := 0
	for _, req := range *requests {
		if strings.Contains(req.path, "/application_keys") {
			attempted++
		}
	}
	require.Equal(t, serviceAccounts*2, attempted, "every service account must be attempted on every walk")
}
