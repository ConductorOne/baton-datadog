package client

import (
	"context"
	"errors"
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
		return nil, wrapOfficialClientError("create user", httpRes, err)
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
		return nil, wrapOfficialClientError("list users", httpRes, err)
	}
	return &resp, nil
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
		return nil, wrapOfficialClientError("list teams", httpRes, err)
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
		return nil, wrapOfficialClientError("list roles", httpRes, err)
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
		return nil, wrapOfficialClientError("list API keys", httpRes, err)
	}
	return &resp, nil
}

type IssuedAPIKey struct {
	ID     string
	Secret string
}

func (w *DatadogClient) CreateAPIKey(ctx context.Context, name string) (*IssuedAPIKey, error) {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewKeyManagementApi(w.officialClient)
	attrs := *datadogV2.NewAPIKeyCreateAttributes(name)
	data := *datadogV2.NewAPIKeyCreateData(attrs, datadogV2.APIKEYSTYPE_API_KEYS)
	response, httpRes, err := api.CreateAPIKey(ctx, *datadogV2.NewAPIKeyCreateRequest(data))
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return nil, wrapOfficialClientError("create API key", httpRes, err)
	}
	if response.Data == nil || response.Data.Id == nil || response.Data.Attributes == nil || response.Data.Attributes.Key == nil || *response.Data.Attributes.Key == "" {
		return nil, fmt.Errorf("create API key response omitted id or key")
	}
	return &IssuedAPIKey{ID: *response.Data.Id, Secret: *response.Data.Attributes.Key}, nil
}

// FindAPIKeyByName returns an exact name match, if one exists. Datadog's filter
// is a string search, so compare the returned name exactly before treating it as
// an existing issuance.
func (w *DatadogClient) FindAPIKeyByName(ctx context.Context, name string) (*datadogV2.PartialAPIKey, error) {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewKeyManagementApi(w.officialClient)
	const pageSize = int64(100)
	for page := int64(0); ; page++ {
		params := *datadogV2.NewListAPIKeysOptionalParameters().WithFilter(name).WithPageSize(pageSize).WithPageNumber(page)
		response, httpRes, err := api.ListAPIKeys(ctx, params)
		if httpRes != nil {
			httpRes.Body.Close()
		}
		if err != nil {
			return nil, wrapOfficialClientError("find API key by name", httpRes, err)
		}
		for _, key := range response.GetData() {
			if key.Attributes != nil && key.Attributes.GetName() == name {
				return &key, nil
			}
		}
		if int64(len(response.GetData())) < pageSize {
			return nil, nil
		}
	}
}

func (w *DatadogClient) GetAPIKey(ctx context.Context, id string) (*datadogV2.APIKeyResponse, error) {
	// GET /api/v2/api_keys/{api_key_id}. Requires the api_keys_read permission.
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewKeyManagementApi(w.officialClient)
	response, httpRes, err := api.GetAPIKey(ctx, id)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return nil, wrapOfficialClientError("get API key", httpRes, err)
	}
	return &response, nil
}

func (w *DatadogClient) ValidateAPIKey(ctx context.Context, apiKey string) (bool, error) {
	ctx = context.WithValue(
		ctx,
		datadog.ContextAPIKeys,
		map[string]datadog.APIKey{
			"apiKeyAuth": {Key: apiKey},
		},
	)
	ctx = context.WithValue(ctx, datadog.ContextServerVariables, map[string]string{"site": w.site})
	// GET /api/v1/validate requires an API key and does not require an application key.
	api := datadogV1.NewAuthenticationApi(w.officialClient)
	response, httpRes, err := api.Validate(ctx)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return false, wrapOfficialClientError("validate API key", httpRes, err)
	}
	return response.GetValid(), nil
}

func (w *DatadogClient) DeleteAPIKey(ctx context.Context, id string) error {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewKeyManagementApi(w.officialClient)
	httpRes, err := api.DeleteAPIKey(ctx, id)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return wrapOfficialClientError("delete API key", httpRes, err)
	}
	return nil
}

// IssuedApplicationKey is the result of issuing a Datadog service-account
// application key: the provider handle (ID), the one-time plaintext secret,
// and the service-account id that owns it. ServiceAccountID is required at
// delete time -- DeleteServiceAccountApplicationKey has no lookup-by-id-alone
// form -- so callers must retain it (see application_key.go's Delete doc
// comment: it travels via ResourceDeleterV2Limited.Delete's parentResourceID
// parameter, not a packed handle string).
type IssuedApplicationKey struct {
	ID               string
	Secret           string
	ServiceAccountID string
}

// CreateServiceAccountApplicationKey issues a new application key scoped to
// and owned by the given Datadog service account. Scopes may be empty (an
// unscoped application key).
func (w *DatadogClient) CreateServiceAccountApplicationKey(ctx context.Context, serviceAccountID, name string, scopes []string) (*IssuedApplicationKey, error) {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewServiceAccountsApi(w.officialClient)
	attrs := *datadogV2.NewApplicationKeyCreateAttributes(name)
	if len(scopes) > 0 {
		attrs.SetScopes(scopes)
	}
	data := *datadogV2.NewApplicationKeyCreateData(attrs, datadogV2.APPLICATIONKEYSTYPE_APPLICATION_KEYS)
	response, httpRes, err := api.CreateServiceAccountApplicationKey(ctx, serviceAccountID, *datadogV2.NewApplicationKeyCreateRequest(data))
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return nil, wrapOfficialClientError("create service account application key", httpRes, err)
	}
	appKey := response.GetData()
	if appKey.Id == nil || appKey.Attributes == nil || appKey.Attributes.Key == nil || *appKey.Attributes.Key == "" {
		return nil, fmt.Errorf("create service account application key response omitted id or key")
	}
	return &IssuedApplicationKey{ID: *appKey.Id, Secret: *appKey.Attributes.Key, ServiceAccountID: serviceAccountID}, nil
}

// FindServiceAccountApplicationKeyByName returns an exact name match among a
// single service account's application keys, if one exists. Mirrors
// FindAPIKeyByName's exact-match-after-filter, paginated pattern, scoped to
// one service account instead of the whole org.
func (w *DatadogClient) FindServiceAccountApplicationKeyByName(ctx context.Context, serviceAccountID, name string) (*datadogV2.PartialApplicationKey, error) {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewServiceAccountsApi(w.officialClient)
	const pageSize = int64(100)
	// maxPages bounds this loop so a provider that ignores page[number] and
	// keeps returning full pages fails closed instead of spinning forever on
	// the Issue hot path. 10_000 pages (1M keys) is far beyond any real
	// service account's application-key count.
	const maxPages = int64(10_000)
	for page := int64(0); page < maxPages; page++ {
		params := *datadogV2.NewListServiceAccountApplicationKeysOptionalParameters().WithFilter(name).WithPageSize(pageSize).WithPageNumber(page)
		response, httpRes, err := api.ListServiceAccountApplicationKeys(ctx, serviceAccountID, params)
		if httpRes != nil {
			httpRes.Body.Close()
		}
		if err != nil {
			return nil, wrapOfficialClientError("find service account application key by name", httpRes, err)
		}
		for _, key := range response.GetData() {
			if key.Attributes != nil && key.Attributes.GetName() == name {
				return &key, nil
			}
		}
		if int64(len(response.GetData())) < pageSize {
			return nil, nil
		}
	}
	return nil, fmt.Errorf("find service account application key by name: exceeded %d pages without a short page", maxPages)
}

// ListServiceAccountApplicationKeys lists every application key owned by the
// given service account, one page at a time via pageNumber/pageSize.
func (w *DatadogClient) ListServiceAccountApplicationKeys(ctx context.Context, serviceAccountID string, pageNumber, pageSize int64) (*datadogV2.ListApplicationKeysResponse, error) {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewServiceAccountsApi(w.officialClient)
	params := *datadogV2.NewListServiceAccountApplicationKeysOptionalParameters().WithPageSize(pageSize).WithPageNumber(pageNumber)
	resp, httpRes, err := api.ListServiceAccountApplicationKeys(ctx, serviceAccountID, params)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return nil, wrapOfficialClientError("list service account application keys", httpRes, err)
	}
	return &resp, nil
}

// DeleteServiceAccountApplicationKey deletes an application key owned by the
// given service account. Unlike DeleteAPIKey, Datadog's API requires both the
// owning service-account id and the key id -- there is no delete-by-key-id-alone
// form for this credential type.
func (w *DatadogClient) DeleteServiceAccountApplicationKey(ctx context.Context, serviceAccountID, appKeyID string) error {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewServiceAccountsApi(w.officialClient)
	httpRes, err := api.DeleteServiceAccountApplicationKey(ctx, serviceAccountID, appKeyID)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return wrapOfficialClientError("delete service account application key", httpRes, err)
	}
	return nil
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
	if err != nil {
		return &users, wrapOfficialClientError("list role users", httpRes, err)
	}
	return &users, nil
}

// AddUserToRole adds a user to a role and automatically handles HTTP response body closing.
func (w *DatadogClient) AddUserToRole(ctx context.Context, roleId string, body datadogV2.RelationshipToUser) (*datadogV2.UsersResponse, error) {
	ctx = w.withAuthContext(ctx)
	rolesApi := datadogV2.NewRolesApi(w.officialClient)
	resp, httpRes, err := rolesApi.AddUserToRole(ctx, roleId, body)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return &resp, wrapOfficialClientError("add user to role", httpRes, err)
	}
	return &resp, nil
}

// RemoveUserFromRole removes a user from a role and automatically handles HTTP response body closing.
func (w *DatadogClient) RemoveUserFromRole(ctx context.Context, roleId string, body datadogV2.RelationshipToUser) (*datadogV2.UsersResponse, error) {
	ctx = w.withAuthContext(ctx)
	rolesApi := datadogV2.NewRolesApi(w.officialClient)
	resp, httpRes, err := rolesApi.RemoveUserFromRole(ctx, roleId, body)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil && httpRes != nil && httpRes.StatusCode == http.StatusNotFound {
		return &resp, errors.Join(ErrNotFound, err)
	}
	if err != nil {
		return &resp, wrapOfficialClientError("remove user from role", httpRes, err)
	}
	return &resp, nil
}

// GetTeamMemberships gets team memberships and automatically handles HTTP response body closing.
func (w *DatadogClient) GetTeamMemberships(ctx context.Context, teamId string, params *datadogV2.GetTeamMembershipsOptionalParameters) (*datadogV2.UserTeamsResponse, error) {
	ctx = w.withAuthContext(ctx)
	teamsApi := datadogV2.NewTeamsApi(w.officialClient)
	memberships, httpRes, err := teamsApi.GetTeamMemberships(ctx, teamId, *params)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return &memberships, wrapOfficialClientError("get team memberships", httpRes, err)
	}
	return &memberships, nil
}

// GetUser gets a user by ID and automatically handles HTTP response body closing.
func (w *DatadogClient) GetUser(ctx context.Context, userId string) (*datadogV2.UserResponse, error) {
	ctx = w.withAuthContext(ctx)
	usersApi := datadogV2.NewUsersApi(w.officialClient)
	user, httpRes, err := usersApi.GetUser(ctx, userId)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil && httpRes != nil && httpRes.StatusCode == http.StatusNotFound {
		return &user, errors.Join(ErrNotFound, err)
	}
	if err != nil {
		return &user, wrapOfficialClientError("get user", httpRes, err)
	}
	return &user, nil
}

// CreateTeamMembership creates a team membership and automatically handles HTTP response body closing.
func (w *DatadogClient) CreateTeamMembership(ctx context.Context, teamId string, body datadogV2.UserTeamRequest) (*datadogV2.UserTeamResponse, error) {
	ctx = w.withAuthContext(ctx)
	teamsApi := datadogV2.NewTeamsApi(w.officialClient)
	resp, httpRes, err := teamsApi.CreateTeamMembership(ctx, teamId, body)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return &resp, wrapOfficialClientError("create team membership", httpRes, err)
	}
	return &resp, nil
}

// DeleteTeamMembership deletes a team membership and automatically handles HTTP response body closing.
func (w *DatadogClient) DeleteTeamMembership(ctx context.Context, teamId string, userId string) error {
	ctx = w.withAuthContext(ctx)
	teamsApi := datadogV2.NewTeamsApi(w.officialClient)
	httpRes, err := teamsApi.DeleteTeamMembership(ctx, teamId, userId)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil && httpRes != nil && httpRes.StatusCode == http.StatusNotFound {
		return errors.Join(ErrNotFound, err)
	}
	if err != nil {
		return wrapOfficialClientError("delete team membership", httpRes, err)
	}
	return nil
}

// ValidateCredentials validates API credentials and automatically handles HTTP response body closing.
func (w *DatadogClient) ValidateCredentials(ctx context.Context) (*datadogV1.AuthenticationValidationResponse, error) {
	ctx = w.withAuthContext(ctx)
	api := datadogV1.NewAuthenticationApi(w.officialClient)
	resp, httpRes, err := api.Validate(ctx)
	if httpRes != nil {
		defer httpRes.Body.Close()
	}
	if err != nil {
		return &resp, wrapOfficialClientError("validate credentials", httpRes, err)
	}
	return &resp, nil
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
		return nil, wrapOfficialClientError("update user", httpRes, err)
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
	if err != nil {
		return wrapOfficialClientError("disable user", httpRes, err)
	}
	return nil
}
