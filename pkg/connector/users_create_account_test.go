package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestCreateAccountConflict(t *testing.T) {
	const exact = `{"id":"existing-id","type":"users","attributes":{"email":"Person@Example.com","name":"Person","status":"Pending"}}`
	const partial = `{"id":"other-id","type":"users","attributes":{"email":"otherperson@example.com","name":"Other","status":"Active"}}`
	const service = `{"id":"service-id","type":"users","attributes":{"email":"person@example.com","name":"Service","status":"Active","service_account":true}}`
	tests := []struct {
		name         string
		createStatus int
		pages        []string
		wantCode     codes.Code
		wantMessage  string
		wantID       string
	}{
		{name: "exact match on later page", createStatus: 409, pages: []string{partial, exact}, wantID: "existing-id"},
		{name: "no exact match", createStatus: 409, pages: []string{partial}, wantCode: codes.AlreadyExists, wantMessage: "no user matches"},
		{name: "ambiguous including service account", createStatus: 409, pages: []string{exact, service}, wantCode: codes.AlreadyExists, wantMessage: "multiple users"},
		{name: "service account is not a human match", createStatus: 409, pages: []string{service}, wantCode: codes.AlreadyExists, wantMessage: "service account"},
		{name: "non conflict", createStatus: 403, wantCode: codes.PermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				require.Equal(t, "/api/v2/users", r.URL.Path)
				if r.Method == http.MethodPost {
					w.WriteHeader(tt.createStatus)
					_, _ = w.Write([]byte(`{"errors":["request failed"]}`))
					return
				}
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, fmt.Sprint(requests), r.URL.Query().Get("page[number]"))
				require.Empty(t, r.URL.Query().Get("filter"))
				if requests < len(tt.pages) {
					_, _ = fmt.Fprintf(w, `{"data":[%s]}`, tt.pages[requests])
				} else {
					_, _ = w.Write([]byte(`{"data":[]}`))
				}
				requests++
			}))
			defer server.Close()
			profile, err := structpb.NewStruct(map[string]interface{}{"email": "person@example.com"})
			require.NoError(t, err)
			response, _, _, err := newUserBuilder(newLifecycleTestWrapper(server.URL)).CreateAccount(context.Background(), &v2.AccountInfo{Profile: profile}, nil)
			if tt.wantCode != codes.OK {
				require.Error(t, err)
				require.Equal(t, tt.wantCode, status.Code(err))
				if tt.wantMessage != "" {
					require.Contains(t, err.Error(), tt.wantMessage)
				}
				require.Nil(t, response)
				if tt.createStatus != 409 {
					require.Zero(t, requests)
				}
				return
			}
			require.NoError(t, err)
			result, ok := response.(*v2.CreateAccountResponse_AlreadyExistsResult)
			require.True(t, ok)
			require.Equal(t, tt.wantID, result.GetResource().GetId().GetResource())
			require.Equal(t, v2.Status_RESOURCE_STATUS_PENDING, result.GetResource().GetStatus().GetStatus())
			require.Equal(t, "Pending", result.GetResource().GetStatus().GetDetails())
			require.Equal(t, len(tt.pages)+1, requests)
		})
	}
}

func TestUserResourceStatus(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		want v2.Status_ResourceStatus
	}{
		{"Pending", v2.Status_RESOURCE_STATUS_PENDING},
		{"Disabled", v2.Status_RESOURCE_STATUS_DISABLED},
		{"Active", v2.Status_RESOURCE_STATUS_ENABLED},
	} {
		t.Run(tt.raw, func(t *testing.T) {
			attributes := datadogV2.NewUserAttributes()
			attributes.SetEmail("person@example.com")
			attributes.SetName("Person")
			attributes.SetStatus(tt.raw)
			user := datadogV2.NewUser()
			user.SetId("user-id")
			user.SetAttributes(*attributes)
			resource, err := userResource(user)
			require.NoError(t, err)
			require.Equal(t, tt.want, resource.GetStatus().GetStatus())
			require.Equal(t, tt.raw, resource.GetStatus().GetDetails())
		})
	}
}
