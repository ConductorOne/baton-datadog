package connector

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
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
	wrapper      *client.DatadogClient
}

// Create a new connector resource for a Datadog on-call schedule.
func scheduleResource(schedule *client.OnCallSchedule) (*v2.Resource, error) {
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

// parsePageTokenFromString parses a simple pagination string to extract the page number
func parsePageTokenFromString(token string) (int64, error) {
	if token == "" {
		return 0, nil // Start from page 0, not page 1
	}

	// If token is already a page number, parse it directly
	if pageNum, err := strconv.ParseInt(token, 10, 64); err == nil {
		return pageNum, nil
	}

	// If token has the "page:" prefix, extract the number
	if strings.HasPrefix(token, "page:") {
		pageStr := strings.TrimPrefix(token, "page:")
		return strconv.ParseInt(pageStr, 10, 64)
	}

	// Default to page 0 if we can't parse
	return 0, nil
}

// List returns all the on-call schedules from Datadog as resource objects.
func (s *scheduleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	// Parse the pagination token to get current page number
	var pageNumber int64
	var err error

	inputToken := ""
	if pToken != nil {
		inputToken = pToken.Token
	}

	l.Debug("List called with token", zap.String("input_token", inputToken))

	// Parse the simple pagination token directly
	pageNumber, err = parsePageTokenFromString(inputToken)
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

	schedules, nextPageNumber, annos, err := s.wrapper.GetRestClient().ListOnCallSchedules(ctx, opts)
	if err != nil {
		l.Error("Failed to list on-call schedules with pagination", zap.Error(err))
		return nil, "", annos, fmt.Errorf("failed to list on-call schedules: %w", err)
	}

	// Process schedules from this page only
	var pageSchedules []*v2.Resource
	for _, schedule := range schedules {
		sr, err := scheduleResource(schedule)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to create schedule resource for schedule %s: %w", schedule.ID, err)
		}
		pageSchedules = append(pageSchedules, sr)
	}

	l.Debug("Processed page",
		zap.Int64("page_number", pageNumber),
		zap.Int("schedules_in_page", len(pageSchedules)),
		zap.Int("total_schedules_in_response", len(schedules)),
		zap.String("next_page_number", nextPageNumber),
		zap.Bool("has_next_page", nextPageNumber != ""))

	// Generate next page token - return the complete pagination string
	var nextPageToken string
	if nextPageNumber != "" {
		// Simply return the next page number as the token
		nextPageToken = nextPageNumber
		l.Debug("Generated next page token", zap.String("next_page_token", nextPageToken))
	} else {
		l.Debug("No next page available - this should be the last page")
	}

	l.Debug("Returning page results",
		zap.Int("schedules_returned", len(pageSchedules)),
		zap.String("next_page_token", nextPageToken),
		zap.Bool("has_more_pages", nextPageToken != ""))

	// Return only the current page schedules with next page token
	return pageSchedules, nextPageToken, annos, nil
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
	shift, annos, err := s.wrapper.GetRestClient().GetScheduleOnCallUser(ctx, resource.Id.Resource)
	if err != nil {
		l.Error("Failed to get on-call user from Datadog",
			zap.Error(err),
			zap.String("schedule_id", resource.Id.Resource))
		return rv, "", annos, fmt.Errorf("failed to get on-call user for schedule %s: %w", resource.Id.Resource, err)
	}

	if shift.Data.ID == "" {
		l.Debug("No on-call user found for schedule", zap.String("schedule_id", resource.Id.Resource))
		return rv, "", annos, nil
	}

	userID := shift.Data.ID
	// Extract base UUID without time ranges (first 36 characters of a standard UUID)
	if len(userID) > 36 {
		userID = userID[:36]
	}

	// Create principal resource reference for on-call user
	onCallPrincipal := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     userID,
		},
	}

	onCallGrant := grant.NewGrant(resource, scheduleOnCallRole, onCallPrincipal)

	rv = append(rv, onCallGrant)
	return rv, "", annos, nil
}

func populateScheduleOptions(name, permission string) []ent.EntitlementOption {
	options := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(fmt.Sprintf("%s Schedule %s", name, permission)),
		ent.WithDescription(fmt.Sprintf("%s role for %s Datadog on-call schedule", permission, name)),
	}
	return options
}

func newScheduleBuilder(wrapper *client.DatadogClient) *scheduleBuilder {
	return &scheduleBuilder{
		resourceType: scheduleResourceType,
		wrapper:      wrapper,
	}
}
