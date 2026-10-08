package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/crypto/providers/jwk"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func satIssueInput(requestID string) *connectorbuilder.CredentialIssueInput {
	return &connectorbuilder.CredentialIssueInput{
		IdentityID: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: "sa-1"},
		RequestID:  requestID,
		CredentialOptions: v2.CredentialIssueOptions_builder{
			SecretResourceTypeId: serviceAccountAccessTokenResourceType.Id,
			Token:                v2.CredentialIssueOptions_Token_builder{Scopes: []string{"requested_scope"}}.Build(),
		}.Build(),
	}
}

func TestServiceAccessTokenOptInRefusesBeforeMint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("provider contacted without opt-in: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	issuer := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), false, false)
	details, _, err := issuer.IssueCapabilityDetails(context.Background())
	require.NoError(t, err)
	for _, option := range details.GetOptions() {
		require.NotEqual(t, serviceAccountAccessTokenResourceType.Id, option.GetSecretResourceTypeId())
	}
	out, err := issuer.Issue(context.Background(), satIssueInput("old-executor"))
	require.Nil(t, out)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestServiceAccessTokenIssueSyncRenameAndRevoke(t *testing.T) {
	const tokenID = "sat-provider-id"
	const tokenValue = "ddsat_test-secret-value"
	const expiresAt = "2027-07-11T13:17:19Z"
	var mu sync.Mutex
	created := false
	postCount := 0
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("DD-API-KEY"); got != "connector-api-key" {
			t.Errorf("DD-API-KEY = %q", got)
		}
		if got := r.Header.Get("DD-APPLICATION-KEY"); got != "connector-app-key" {
			t.Errorf("DD-APPLICATION-KEY = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		path := "/api/v2/service_accounts/sa-1/access_tokens"
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/sa-1":
			_, _ = w.Write([]byte(`{"data":{"id":"sa-1","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users":
			if r.URL.Query().Get("page[number]") == "0" {
				_, _ = w.Write([]byte(`{"data":[{"id":"sa-1","type":"users","attributes":{"service_account":true}}]}`))
			} else {
				_, _ = w.Write([]byte(`{"data":[]}`))
			}
		case r.Method == http.MethodGet && r.URL.Path == path:
			if !created || deleted {
				_, _ = w.Write([]byte(`{"data":[]}`))
				return
			}
			name := "renamed-after-issue"
			if r.URL.Query().Has("filter") {
				name = "c1-req-sat"
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"` + tokenID + `","type":"service_access_tokens","attributes":{"name":"` + name + `","scopes":["granted_scope"],"expires_at":"` + expiresAt + `"},"relationships":{"owned_by":{"data":{"id":"sa-1","type":"service_account"}}}}]}`))
		case r.Method == http.MethodGet && r.URL.Path == path+"/"+tokenID:
			_, _ = w.Write([]byte(`{"data":{"id":"` + tokenID + `","type":"service_access_tokens","attributes":{"name":"renamed-after-issue","scopes":["granted_scope"],"expires_at":"` + expiresAt + `"},"relationships":{"owned_by":{"data":{"id":"sa-1","type":"service_account"}}}}}`))
		case r.Method == http.MethodPost && r.URL.Path == path:
			postCount++
			var request struct {
				Data struct {
					Type       string `json:"type"`
					Attributes struct {
						Name      string   `json:"name"`
						Scopes    []string `json:"scopes"`
						ExpiresAt *string  `json:"expires_at"`
					} `json:"attributes"`
				} `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			if request.Data.Type != "service_access_tokens" || request.Data.Attributes.Name != "c1-req-sat" || len(request.Data.Attributes.Scopes) != 1 || request.Data.Attributes.Scopes[0] != "requested_scope" || request.Data.Attributes.ExpiresAt != nil {
				t.Errorf("incorrect create request: %+v", request)
			}
			created = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"` + tokenID + `","type":"service_access_tokens","attributes":{"key":"` + tokenValue + `","name":"c1-req-sat","scopes":["granted_scope"],"expires_at":"` + expiresAt + `"},"relationships":{"owned_by":{"data":{"id":"sa-1","type":"service_account"}}}}}`))
		case r.Method == http.MethodDelete && r.URL.Path == path+"/"+tokenID:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)
	issuer := newCredentialUserBuilder(wrapper, false, false, true)
	details, _, err := issuer.IssueCapabilityDetails(context.Background())
	require.NoError(t, err)
	require.Len(t, details.GetOptions(), 1)
	require.Equal(t, v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_TOKEN, details.GetOptions()[0].GetOption())
	require.Equal(t, serviceAccountAccessTokenResourceType.Id, details.GetOptions()[0].GetSecretResourceTypeId())

	out, err := issuer.Issue(context.Background(), satIssueInput("req-sat"))
	require.NoError(t, err)
	require.Len(t, out.PlaintextData, 1)
	require.Equal(t, "service_access_token", out.PlaintextData[0].GetName())
	require.JSONEq(t, `{"key_value":"`+tokenValue+`","provider":"datadog","key_id":"`+tokenID+`","header_name":"Authorization","scopes":["granted_scope"]}`, string(out.PlaintextData[0].GetBytes()))
	require.NotContains(t, out.Secret.GetId().GetResource(), tokenValue)
	owner, parsedID, err := parseServiceAccessTokenHandle(out.Secret.GetId().GetResource())
	require.NoError(t, err)
	require.Equal(t, "sa-1", owner)
	require.Equal(t, tokenID, parsedID)
	require.Equal(t, "sa-1", out.Secret.GetParentResourceId().GetResource())
	trait := secretTraitOf(t, out.Secret)
	require.Equal(t, "datadog.service_access_token", trait.GetCredentialDetail())
	require.Equal(t, "sa-1", trait.GetIdentityId().GetResource())
	wantExpiry, err := time.Parse(time.RFC3339, expiresAt)
	require.NoError(t, err)
	require.Equal(t, wantExpiry, trait.GetExpiresAt().AsTime())
	scopes, present := profileScopes(t, out.Secret)
	require.True(t, present)
	require.Equal(t, []string{"granted_scope"}, scopes)

	_, err = issuer.Issue(context.Background(), satIssueInput("req-sat"))
	require.Equal(t, codes.AlreadyExists, status.Code(err))
	mu.Lock()
	require.Equal(t, 1, postCount)
	mu.Unlock()

	builder := newServiceAccessTokenBuilder(wrapper)
	token := ""
	var listed []*v2.Resource
	for range 5 {
		items, result, err := builder.List(context.Background(), nil, resource.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		require.NoError(t, err)
		listed = append(listed, items...)
		token = result.NextPageToken
		if token == "" {
			break
		}
	}
	require.Len(t, listed, 1)
	require.Equal(t, "renamed-after-issue", listed[0].GetDisplayName())
	require.Equal(t, out.Secret.GetId().GetResource(), listed[0].GetId().GetResource())
	got, err := wrapper.GetServiceAccountAccessToken(context.Background(), "sa-1", tokenID)
	require.NoError(t, err)
	require.Equal(t, tokenID, got.ID)
	require.Equal(t, "renamed-after-issue", got.Name)
	_, err = builder.Delete(context.Background(), out.Secret.GetId(), nil)
	require.NoError(t, err)
	mu.Lock()
	require.True(t, deleted)
	mu.Unlock()
}

func TestServiceAccessTokenRejectsMalformedHandle(t *testing.T) {
	for _, handle := range []string{"", "sat:", "sat:@@@@", "sat:" + strings.Repeat("A", 12)} {
		_, _, err := parseServiceAccessTokenHandle(handle)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
}

func TestServiceAccessTokenCreateIsSingleAttempt(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":["transient"]}`))
	}))
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)
	wrapper.GetOfficialClient().GetConfig().RetryConfiguration.EnableRetry = true
	wrapper.GetOfficialClient().GetConfig().RetryConfiguration.MaxRetries = 3
	_, err := wrapper.CreateServiceAccountAccessToken(context.Background(), "sa-1", "c1-req", []string{"dashboards_read"}, nil)
	require.Error(t, err)
	mu.Lock()
	require.Equal(t, 1, requests, "ambiguous create must never be retried by the transport")
	mu.Unlock()
}

func TestServiceAccessTokenUndeliverableCreateIsRevoked(t *testing.T) {
	var mu sync.Mutex
	var deleted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"created-without-key","type":"service_access_tokens","attributes":{"name":"c1-req"}}}`))
		case http.MethodDelete:
			if r.URL.Path != "/api/v2/service_accounts/sa-1/access_tokens/created-without-key" {
				t.Errorf("unexpected revoke path %s", r.URL.Path)
			}
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)
	_, err := wrapper.CreateServiceAccountAccessToken(context.Background(), "sa-1", "c1-req", []string{"dashboards_read"}, nil)
	require.Error(t, err)
	mu.Lock()
	require.True(t, deleted)
	mu.Unlock()
}

func TestServiceAccessTokenOwnerMismatchIsNotDelivered(t *testing.T) {
	var mu sync.Mutex
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"wrong-owner-id","type":"service_access_tokens","attributes":{"key":"ddsat_must-not-deliver","scopes":["dashboards_read"]},"relationships":{"owned_by":{"data":{"id":"another-sa","type":"service_account"}}}}}`))
		case http.MethodDelete:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)
	issued, err := wrapper.CreateServiceAccountAccessToken(context.Background(), "sa-1", "c1-req", []string{"dashboards_read"}, nil)
	require.Nil(t, issued)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "ddsat_must-not-deliver")
	mu.Lock()
	require.True(t, deleted, "an undeliverable token with a known ID must be revoked")
	mu.Unlock()
}

func TestServiceAccessTokenInventoryRejectsMismatchedOwner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		item := `{"id":"token-id","type":"service_access_tokens","attributes":{"name":"token"},"relationships":{"owned_by":{"data":{"id":"another-sa","type":"service_account"}}}}`
		if r.URL.Path == "/api/v2/service_accounts/sa-1/access_tokens/token-id" {
			_, _ = w.Write([]byte(`{"data":` + item + `}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[` + item + `]}`))
	}))
	defer server.Close()
	wrapper := newLifecycleTestWrapper(server.URL)
	_, err := wrapper.ListServiceAccountAccessTokens(context.Background(), "sa-1", 0, 100)
	require.Error(t, err)
	_, err = wrapper.GetServiceAccountAccessToken(context.Background(), "sa-1", "token-id")
	require.Error(t, err)
}

func TestServiceAccessTokenSDKIssueEncryptsAndRejectsUnadvertisedKind(t *testing.T) {
	var mu sync.Mutex
	providerCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		providerCalls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/sa-1":
			_, _ = w.Write([]byte(`{"data":{"id":"sa-1","type":"users","attributes":{"service_account":true}}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/service_accounts/sa-1/access_tokens":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/service_accounts/sa-1/access_tokens":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"sdk-token-id","type":"service_access_tokens","attributes":{"key":"ddsat_sdk-secret","name":"c1-sdk-test","scopes":["dashboards_read"]}}}`))
		default:
			t.Errorf("unexpected provider request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	encConfig, privateKey, err := (&jwk.JWKEncryptionProvider{}).GenerateKey(ctx)
	require.NoError(t, err)
	request := v2.IssueCredentialRequest_builder{
		IdentityId: v2.ResourceId_builder{ResourceType: userResourceType.Id, Resource: "sa-1"}.Build(),
		CredentialOptions: v2.CredentialIssueOptions_builder{
			SecretResourceTypeId: serviceAccountAccessTokenResourceType.Id,
			Token:                v2.CredentialIssueOptions_Token_builder{Scopes: []string{"dashboards_read"}}.Build(),
		}.Build(),
		EncryptionConfigs: []*v2.EncryptionConfig{encConfig},
		RequestId:         "sdk-test",
	}.Build()

	without := &Datadog{wrapper: newLifecycleTestWrapper(server.URL), SyncSecrets: true}
	oldSDK, err := connectorbuilder.NewConnector(ctx, without)
	require.NoError(t, err)
	_, err = oldSDK.IssueCredential(ctx, request)
	require.Error(t, err)
	mu.Lock()
	require.Zero(t, providerCalls, "unadvertised native kind must fail before provider access")
	mu.Unlock()

	with := &Datadog{wrapper: newLifecycleTestWrapper(server.URL), SyncSecrets: true, SyncServiceAccountAccessTokens: true}
	nativeSDK, err := connectorbuilder.NewConnector(ctx, with)
	require.NoError(t, err)
	issued, err := nativeSDK.IssueCredential(ctx, request)
	require.NoError(t, err)
	require.Equal(t, serviceAccountAccessTokenResourceType.Id, issued.GetSecret().GetId().GetResourceType())
	require.Len(t, issued.GetEncryptedData(), 1)
	plaintext, err := (&jwk.JWKEncryptionProvider{}).Decrypt(ctx, issued.GetEncryptedData()[0], privateKey)
	require.NoError(t, err)
	require.Equal(t, "service_access_token", plaintext.GetName())
	require.JSONEq(t, `{"key_value":"ddsat_sdk-secret","provider":"datadog","key_id":"sdk-token-id","header_name":"Authorization","scopes":["dashboards_read"]}`, string(plaintext.GetBytes()))
}
