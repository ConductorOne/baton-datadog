package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
)

// DatadogClient wraps the Datadog REST client to provide a clean interface for all endpoints.
// This client delegates to the DatadogRestClient which already handles HTTP response body closing correctly.
type DatadogClient struct {
	restClient     *DatadogRestClient
	officialClient *datadog.APIClient
	site           string
	apiKey         string
	appKey         string
}

// NewDatadogClient creates a new client that uses the custom REST client.
func NewDatadogClient(restClient *DatadogRestClient, officialClient *datadog.APIClient, site, apiKey, appKey string) *DatadogClient {
	return &DatadogClient{
		restClient:     restClient,
		officialClient: officialClient,
		site:           site,
		apiKey:         apiKey,
		appKey:         appKey,
	}
}

// GetRestClient returns the underlying REST client.
func (w *DatadogClient) GetRestClient() *DatadogRestClient {
	return w.restClient
}

// GetOfficialClient returns the underlying official Datadog API client for operations that need it.
func (w *DatadogClient) GetOfficialClient() *datadog.APIClient {
	return w.officialClient
}

// withAuthContext adds authentication context to the request context.
func (w *DatadogClient) withAuthContext(ctx context.Context) context.Context {
	ctx = context.WithValue(
		ctx,
		datadog.ContextAPIKeys,
		map[string]datadog.APIKey{
			"apiKeyAuth": {
				Key: w.apiKey,
			},
			"appKeyAuth": {
				Key: w.appKey,
			},
		},
	)

	ctx = context.WithValue(ctx,
		datadog.ContextServerVariables,
		map[string]string{
			"site": w.site,
		})

	return ctx
}

// CreateUser creates a Datadog user using the official V2 API client and closes the HTTP response body.
func (w *DatadogClient) CreateUser(ctx context.Context, req datadogV2.UserCreateRequest) (*datadogV2.UserResponse, error) {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewUsersApi(w.officialClient)
	resp, httpRes, err := api.CreateUser(ctx, req)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListUsers lists users using the REST client.
func (w *DatadogClient) ListUsers(ctx context.Context, params *datadogV2.ListUsersOptionalParameters) (*datadogV2.UsersResponse, error) {
	ctx = w.withAuthContext(ctx)
	usersApi := datadogV2.NewUsersApi(w.officialClient)
	var (
		resp    datadogV2.UsersResponse
		httpRes *http.Response
		err     error
	)
	if params != nil {
		resp, httpRes, err = usersApi.ListUsers(ctx, *params)
	} else {
		resp, httpRes, err = usersApi.ListUsers(ctx)
	}
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Validate validates API credentials using the REST client.
func (w *DatadogClient) Validate(ctx context.Context) (*datadogV1.AuthenticationValidationResponse, error) {
	// TODO: Implement in DatadogRestClient
	// For now, return error indicating this needs to be implemented
	return nil, fmt.Errorf("Validate not yet implemented in REST client")
}

// ListTeams lists teams using the REST client.
func (w *DatadogClient) ListTeams(ctx context.Context, params *datadogV2.ListTeamsOptionalParameters) (*datadogV2.TeamsResponse, error) {
	ctx = w.withAuthContext(ctx)
	teamsApi := datadogV2.NewTeamsApi(w.officialClient)
	var (
		resp    datadogV2.TeamsResponse
		httpRes *http.Response
		err     error
	)
	if params != nil {
		resp, httpRes, err = teamsApi.ListTeams(ctx, *params)
	} else {
		resp, httpRes, err = teamsApi.ListTeams(ctx)
	}
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListRoles lists roles using the REST client.
func (w *DatadogClient) ListRoles(ctx context.Context, params *datadogV2.ListRolesOptionalParameters) (*datadogV2.RolesResponse, error) {
	ctx = w.withAuthContext(ctx)
	rolesApi := datadogV2.NewRolesApi(w.officialClient)
	var (
		resp    datadogV2.RolesResponse
		httpRes *http.Response
		err     error
	)
	if params != nil {
		resp, httpRes, err = rolesApi.ListRoles(ctx, *params)
	} else {
		resp, httpRes, err = rolesApi.ListRoles(ctx)
	}
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListAPIKeys lists API keys using the REST client.
func (w *DatadogClient) ListAPIKeys(ctx context.Context, params *datadogV2.ListAPIKeysOptionalParameters) (*datadogV2.APIKeysResponse, error) {
	ctx = w.withAuthContext(ctx)
	keysApi := datadogV2.NewKeyManagementApi(w.officialClient)
	var (
		resp    datadogV2.APIKeysResponse
		httpRes *http.Response
		err     error
	)
	if params != nil {
		resp, httpRes, err = keysApi.ListAPIKeys(ctx, *params)
	} else {
		resp, httpRes, err = keysApi.ListAPIKeys(ctx)
	}
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Wrapper methods that handle HTTP response body closing automatically

// ListRoleUsers lists users for a specific role and automatically handles HTTP response body closing.
func (w *DatadogClient) ListRoleUsers(ctx context.Context, roleId string, params *datadogV2.ListRoleUsersOptionalParameters) (*datadogV2.UsersResponse, error) {
	ctx = w.withAuthContext(ctx)
	rolesApi := datadogV2.NewRolesApi(w.officialClient)
	users, httpRes, err := rolesApi.ListRoleUsers(ctx, roleId, *params)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	return &users, err
}

// AddUserToRole adds a user to a role and automatically handles HTTP response body closing.
func (w *DatadogClient) AddUserToRole(ctx context.Context, roleId string, body datadogV2.RelationshipToUser) (*datadogV2.UsersResponse, error) {
	ctx = w.withAuthContext(ctx)
	rolesApi := datadogV2.NewRolesApi(w.officialClient)
	resp, httpRes, err := rolesApi.AddUserToRole(ctx, roleId, body)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	return &resp, err
}

// RemoveUserFromRole removes a user from a role and automatically handles HTTP response body closing.
func (w *DatadogClient) RemoveUserFromRole(ctx context.Context, roleId string, body datadogV2.RelationshipToUser) (*datadogV2.UsersResponse, error) {
	ctx = w.withAuthContext(ctx)
	rolesApi := datadogV2.NewRolesApi(w.officialClient)
	resp, httpRes, err := rolesApi.RemoveUserFromRole(ctx, roleId, body)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	return &resp, err
}

// GetTeamMemberships gets team memberships and automatically handles HTTP response body closing.
func (w *DatadogClient) GetTeamMemberships(ctx context.Context, teamId string, params *datadogV2.GetTeamMembershipsOptionalParameters) (*datadogV2.UserTeamsResponse, error) {
	ctx = w.withAuthContext(ctx)
	teamsApi := datadogV2.NewTeamsApi(w.officialClient)
	memberships, httpRes, err := teamsApi.GetTeamMemberships(ctx, teamId, *params)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	return &memberships, err
}

// GetUser gets a user by ID and automatically handles HTTP response body closing.
func (w *DatadogClient) GetUser(ctx context.Context, userId string) (*datadogV2.UserResponse, error) {
	ctx = w.withAuthContext(ctx)
	usersApi := datadogV2.NewUsersApi(w.officialClient)
	user, httpRes, err := usersApi.GetUser(ctx, userId)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	return &user, err
}

// CreateTeamMembership creates a team membership and automatically handles HTTP response body closing.
func (w *DatadogClient) CreateTeamMembership(ctx context.Context, teamId string, body datadogV2.UserTeamRequest) (*datadogV2.UserTeamResponse, error) {
	ctx = w.withAuthContext(ctx)
	teamsApi := datadogV2.NewTeamsApi(w.officialClient)
	resp, httpRes, err := teamsApi.CreateTeamMembership(ctx, teamId, body)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	return &resp, err
}

// DeleteTeamMembership deletes a team membership and automatically handles HTTP response body closing.
func (w *DatadogClient) DeleteTeamMembership(ctx context.Context, teamId string, userId string) error {
	ctx = w.withAuthContext(ctx)
	teamsApi := datadogV2.NewTeamsApi(w.officialClient)
	httpRes, err := teamsApi.DeleteTeamMembership(ctx, teamId, userId)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	return err
}

// ValidateCredentials validates API credentials and automatically handles HTTP response body closing.
func (w *DatadogClient) ValidateCredentials(ctx context.Context) (*datadogV1.AuthenticationValidationResponse, error) {
	ctx = w.withAuthContext(ctx)
	api := datadogV1.NewAuthenticationApi(w.officialClient)
	resp, httpRes, err := api.Validate(ctx)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	return &resp, err
}

// UpdateUser updates a Datadog user. PATCH /api/v2/users/{user_id}. Requires the
// user_access_manage permission. UserUpdateAttributes exposes name, email, and disabled.
func (w *DatadogClient) UpdateUser(ctx context.Context, userId string, body datadogV2.UserUpdateRequest) (*datadogV2.UserResponse, error) {
	ctx = w.withAuthContext(ctx)
	usersApi := datadogV2.NewUsersApi(w.officialClient)
	resp, httpRes, err := usersApi.UpdateUser(ctx, userId, body)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// DisableUser soft-disables a Datadog user. DELETE /api/v2/users/{user_id}. Requires the
// user_access_manage permission. Datadog has no hard delete; this sets attributes.disabled = true.
func (w *DatadogClient) DisableUser(ctx context.Context, userId string) error {
	ctx = w.withAuthContext(ctx)
	usersApi := datadogV2.NewUsersApi(w.officialClient)
	httpRes, err := usersApi.DisableUser(ctx, userId)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	return err
}
