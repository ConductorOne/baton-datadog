package connector

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	datadogV2 "github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/conductorone/baton-datadog/pkg/client"
)

const (
	scheduleOnCallRole = "on_call"
)

type scheduleBuilder struct {
	resourceType *v2.ResourceType
	client       *datadog.APIClient
	restClient   *client.DatadogRestClient
	site         string
	apiKey       string
	appKey       string
}

// Create a new connector resource for a Datadog on-call schedule.
func scheduleResource(schedule *client.OnCallSchedule) (*v2.Resource, error) {
	if schedule == nil {
		return nil, fmt.Errorf("schedule cannot be nil")
	}

	if schedule.ID == "" {
		return nil, fmt.Errorf("schedule ID cannot be empty")
	}

	profile := map[string]interface{}{
		"schedule_id":       schedule.ID,
		"schedule_name":     schedule.Attributes.Name,
		"schedule_type":     schedule.Type,
		"schedule_timezone": schedule.Attributes.TimeZone,
	}

	scheduleTraitOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	// Use a better display name - if name is empty, use ID
	displayName := schedule.Attributes.Name
	if displayName == "" {
		displayName = fmt.Sprintf("Schedule %s", schedule.ID)
	}

	ret, err := rs.NewGroupResource(
		displayName,
		scheduleResourceType,
		schedule.ID,
		scheduleTraitOptions,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create group resource: %w", err)
	}

	return ret, nil
}

// List returns all the on-call schedules from Datadog as resource objects.
func (s *scheduleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	// Simplified pagination handling
	var (
		pageNumber int64
		bag        *pagination.Bag
		err        error
	)

	inputToken := ""
	if pToken != nil {
		inputToken = pToken.Token
	}

	bag, pageNumber, err = parsePageToken(inputToken, parentResourceID)
	if err != nil {
		l.Error("Failed to parse pagination token", zap.Error(err))
		return nil, "", nil, fmt.Errorf("failed to parse pagination token: %w", err)
	}

	// Use constant page size
	pageSize := int64(client.PageSize)

	// Create paginated client
	paginatedClient := client.NewPaginatedClient(s.restClient)

	// Get schedules for current page only
	l.Debug("Fetching page", zap.Int64("page_number", pageNumber), zap.Int64("page_size", pageSize))

	opts := &client.PaginationOptions{
		PageSize:   int(pageSize),
		PageNumber: int(pageNumber),
	}

	schedulesResponse, paginationResult, err := paginatedClient.ListOnCallSchedulesPaginated(ctx, opts)
	if err != nil {
		l.Error("Failed to list on-call schedules with pagination", zap.Error(err))
		return nil, "", nil, fmt.Errorf("failed to list on-call schedules: %w", err)
	}

	// Process schedules from this page only
	var pageSchedules []*v2.Resource
	for _, schedule := range schedulesResponse.Data {
		sr, err := scheduleResource(&schedule)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to create schedule resource for schedule %s: %w", schedule.ID, err)
		}
		pageSchedules = append(pageSchedules, sr)
	}

	l.Debug("Processed page",
		zap.Int64("page_number", pageNumber),
		zap.Int("schedules_in_page", len(pageSchedules)),
		zap.Int("total_schedules_in_response", len(schedulesResponse.Data)))

	// Prepare next page token if there are more pages
	var nextToken string
	if paginationResult.HasNextPage() {
		nextPage := paginationResult.GetNextPageNumber()

		nextToken, err = getPageTokenFromPage(bag, int64(nextPage))
		if err != nil {
			l.Error("Failed to create next page token", zap.Error(err))
			return nil, "", nil, fmt.Errorf("failed to create next page token: %w", err)
		}
	}

	l.Info("Successfully listed schedules for page",
		zap.Int64("page_number", pageNumber),
		zap.Int("schedules_in_page", len(pageSchedules)),
		zap.Int64("page_size_used", pageSize),
		zap.Bool("has_next_page", paginationResult.HasNextPage()),
		zap.String("next_token", nextToken))

	// Return only the current page schedules with next page token
	return pageSchedules, nextToken, nil, nil
}

func (s *scheduleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return s.resourceType
}

func (s *scheduleBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	onCallOptions := populateScheduleOptions(resource.DisplayName, scheduleOnCallRole)
	onCallEntitlement := ent.NewPermissionEntitlement(resource, scheduleOnCallRole, onCallOptions...)

	rv = append(rv, onCallEntitlement)

	return rv, "", nil, nil
}

func (s *scheduleBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	// Validate input parameters
	if resource == nil {
		return nil, "", nil, fmt.Errorf("resource cannot be nil")
	}
	if resource.Id == nil {
		return nil, "", nil, fmt.Errorf("resource ID cannot be nil")
	}
	if resource.Id.Resource == "" {
		return nil, "", nil, fmt.Errorf("resource ID resource cannot be empty")
	}

	var rv []*v2.Grant

	// Create API context with authentication
	ctx = withAuthContext(ctx, s.apiKey, s.appKey, s.site)

	// Use Datadog V2 OnCall API
	oncallAPI := datadogV2.NewOnCallApi(s.client)

	// Get the current on-call user
	shift, resp, err := oncallAPI.GetScheduleOnCallUser(ctx, resource.Id.Resource)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		statusCode := 0
		if resp != nil {
			statusCode = resp.StatusCode
		}
		l.Error("Failed to get on-call user from Datadog",
			zap.Error(err),
			zap.String("schedule_id", resource.Id.Resource),
			zap.Int("status_code", statusCode))

		// Create a more specific error based on the response
		if resp != nil {
			return rv, "", nil, fmt.Errorf("HTTP request failed for operation %s with status %d: %w", "get_schedule_oncall_user", resp.StatusCode, err)
		}
		return rv, "", nil, fmt.Errorf("failed to get on-call user for schedule %s: %w", resource.Id.Resource, err)
	}

	if shift.Data == nil || shift.Data.Relationships == nil || shift.Data.Relationships.User == nil {
		l.Debug("No on-call user found for schedule", zap.String("schedule_id", resource.Id.Resource))
		return rv, "", nil, nil
	}

	userID := shift.Data.Relationships.User.Data.Id
	if userID == "" {
		l.Debug("No user ID found in shift data", zap.String("schedule_id", resource.Id.Resource))
		return rv, "", nil, nil
	}

	// Get user name from included section
	userName := userID
	for _, incl := range shift.Included {
		if incl.ScheduleUser != nil {
			su := incl.ScheduleUser
			if su.GetId() == userID {
				if attrs, ok := su.GetAttributesOk(); ok {
					if name := attrs.GetName(); name != "" {
						userName = name
					}
				}
			}
		}
	}

	// Create on-call entitlement
	onCallOptions := populateScheduleOptions(resource.DisplayName, scheduleOnCallRole)
	onCallEntitlement := ent.NewPermissionEntitlement(resource, scheduleOnCallRole, onCallOptions...)

	// Create principal resource reference for on-call user
	onCallPrincipal := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     userID,
		},
		DisplayName: userName,
	}

	// Create on-call grant
	onCallGrantID := fmt.Sprintf("%s:%s:%s", resource.Id.Resource, userID, scheduleOnCallRole)
	onCallGrant := &v2.Grant{
		Id:          onCallGrantID,
		Principal:   onCallPrincipal,
		Entitlement: onCallEntitlement,
	}

	rv = append(rv, onCallGrant)
	return rv, "", nil, nil
}

func populateScheduleOptions(name, permission string) []ent.EntitlementOption {
	options := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(fmt.Sprintf("%s Schedule %s", name, permission)),
		ent.WithDescription(fmt.Sprintf("%s role for %s Datadog on-call schedule", permission, name)),
	}
	return options
}

func newScheduleBuilder(apiClient *datadog.APIClient, site, apiKey, appKey string) (*scheduleBuilder, error) {
	// Validate input parameters
	if apiClient == nil {
		return nil, fmt.Errorf("API client cannot be nil")
	}
	if site == "" {
		return nil, fmt.Errorf("site cannot be empty")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("API key cannot be empty")
	}
	if appKey == "" {
		return nil, fmt.Errorf("application key cannot be empty")
	}

	restClient, err := client.NewDatadogRestClient(site, apiKey, appKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create REST client: %w", err)
	}

	return &scheduleBuilder{
		resourceType: scheduleResourceType,
		client:       apiClient,
		restClient:   restClient,
		site:         site,
		apiKey:       apiKey,
		appKey:       appKey,
	}, nil
}
