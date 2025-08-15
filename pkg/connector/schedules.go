package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	"github.com/conductorone/baton-datadog/pkg/client"
)

const (
	scheduleOnCallRole = "on_call"
)

type scheduleBuilder struct {
	resourceType *v2.ResourceType
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
		err        error
	)

	inputToken := ""
	if pToken != nil {
		inputToken = pToken.Token
	}

	_, pageNumber, err = parsePageToken(inputToken, parentResourceID)
	if err != nil {
		l.Error("Failed to parse pagination token", zap.Error(err))
		return nil, "", nil, fmt.Errorf("failed to parse pagination token: %w", err)
	}

	// Get schedules for current page only
	l.Debug("Fetching page", zap.Int64("page_number", pageNumber), zap.Int64("page_size", client.PageSize))

	opts := &client.PaginationOptions{
		PageSize:   client.PageSize,
		PageNumber: int(pageNumber),
	}

	schedules, paginationResult, err := s.restClient.ListOnCallSchedules(ctx, opts)
	if err != nil {
		l.Error("Failed to list on-call schedules with pagination", zap.Error(err))
		return nil, "", nil, fmt.Errorf("failed to list on-call schedules: %w", err)
	}

	// Process schedules from this page only
	var pageSchedules []*v2.Resource
	for _, schedule := range schedules {
		sr, err := scheduleResource(&schedule)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to create schedule resource for schedule %s: %w", schedule.ID, err)
		}
		pageSchedules = append(pageSchedules, sr)
	}

	l.Debug("Processed page",
		zap.Int64("page_number", pageNumber),
		zap.Int("schedules_in_page", len(pageSchedules)),
		zap.Int("total_schedules_in_response", len(schedules)))

	// Generate next page token using the client's pagination logic
	var nextToken string
	nextToken, err = paginationResult.GenerateNextPageToken(pageNumber)
	if err != nil {
		l.Error("Failed to generate next page token", zap.Error(err))
		return nil, "", nil, fmt.Errorf("failed to generate next page token: %w", err)
	}

	l.Info("Successfully listed schedules for page",
		zap.Int64("page_number", pageNumber),
		zap.Int("schedules_in_page", len(pageSchedules)),
		zap.Int64("page_size_used", int64(client.PageSize)),
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

	var rv []*v2.Grant

	// Get the current on-call user using our REST client
	shift, err := s.restClient.GetScheduleOnCallUser(ctx, resource.Id.Resource)
	if err != nil {
		l.Error("Failed to get on-call user from Datadog",
			zap.Error(err),
			zap.String("schedule_id", resource.Id.Resource))
		return rv, "", nil, fmt.Errorf("failed to get on-call user for schedule %s: %w", resource.Id.Resource, err)
	}

	if shift.Data.ID == "" {
		l.Debug("No on-call user found for schedule", zap.String("schedule_id", resource.Id.Resource))
		return rv, "", nil, nil
	}

	userID := shift.Data.ID
	// Extract base UUID without time ranges (first 36 characters of a standard UUID)
	if len(userID) > 36 {
		userID = userID[:36]
	}
	userName := userID

	// Use the name from attributes if available
	if shift.Data.Attributes.Name != "" {
		userName = shift.Data.Attributes.Name
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

func newScheduleBuilder(site, apiKey, appKey string) (*scheduleBuilder, error) {
	// Validate input parameters
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
		restClient:   restClient,
		site:         site,
		apiKey:       apiKey,
		appKey:       appKey,
	}, nil
}
