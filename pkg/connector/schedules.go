package connector

import (
	"context"
	"fmt"
	"strconv"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
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

var _ connectorbuilder.ResourceSyncerV2 = &scheduleBuilder{}

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

	// Use a better display name - if name is empty, use ID
	displayName := schedule.Attributes.Name
	if displayName == "" {
		displayName = fmt.Sprintf("Schedule %s", schedule.ID)
	}

	ret, err := rs.NewGroupResource(
		displayName,
		scheduleResourceType,
		schedule.ID,
		nil,
		rs.WithResourceProfile(profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create group resource: %w", err)
	}

	return ret, nil
}

// parsePageTokenFromString parses a simple pagination string to extract the page number.
func parsePageTokenFromString(paginationToken string) (int64, error) {
	if paginationToken == "" {
		return 0, nil
	}

	// If token is already a page number, parse it directly
	pageNum, err := strconv.ParseInt(paginationToken, 10, 64)
	if err != nil {
		return 0, err
	}

	return pageNum, nil
}

// List returns all the on-call schedules from Datadog as resource objects.
func (s *scheduleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, syncOpts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	l.Debug("List called with token", zap.String("input_token", syncOpts.PageToken.Token))

	// Parse the simple pagination token directly
	pageNumber, err := parsePageTokenFromString(syncOpts.PageToken.Token)
	if err != nil {
		l.Error("Failed to parse pagination token", zap.Error(err))
		return nil, nil, fmt.Errorf("failed to parse pagination token: %w", err)
	}

	// Get schedules for current page only
	l.Debug("Fetching page", zap.Int64("page_number", pageNumber), zap.Int64("page_size", client.PageSize))

	opts := &client.PaginationOptions{
		PageSize:   client.PageSize,
		PageNumber: int(pageNumber),
	}

	schedules, nextPageToken, annos, err := s.wrapper.GetRestClient().ListOnCallSchedules(ctx, opts)
	if err != nil {
		l.Error("Failed to list on-call schedules with pagination", zap.Error(err))
		return nil, &rs.SyncOpResults{Annotations: annos}, fmt.Errorf("failed to list on-call schedules: %w", err)
	}

	// Process schedules from this page only
	var pageSchedules []*v2.Resource
	for _, schedule := range schedules {
		sr, err := scheduleResource(schedule)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create schedule resource for schedule %s: %w", schedule.ID, err)
		}
		pageSchedules = append(pageSchedules, sr)
	}

	l.Debug("Processed page",
		zap.Int64("page_number", pageNumber),
		zap.Int("schedules_in_page", len(pageSchedules)),
		zap.Int("total_schedules_in_response", len(schedules)),
		zap.String("next_page_number", nextPageToken),
		zap.Bool("has_next_page", nextPageToken != ""))

	if nextPageToken != "" {
		l.Debug("Generated next page token", zap.String("next_page_token", nextPageToken))
	} else {
		l.Debug("No next page available - this should be the last page")
	}

	l.Debug("Returning page results",
		zap.Int("schedules_returned", len(pageSchedules)),
		zap.String("next_page_token", nextPageToken),
		zap.Bool("has_more_pages", nextPageToken != ""))

	// Return only the current page schedules with next page token
	return pageSchedules, &rs.SyncOpResults{NextPageToken: nextPageToken, Annotations: annos}, nil
}

func (s *scheduleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return s.resourceType
}

func (s *scheduleBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	var rv []*v2.Entitlement

	onCallOptions := populateScheduleOptions(resource.DisplayName, scheduleOnCallRole)
	onCallEntitlement := ent.NewPermissionEntitlement(resource, scheduleOnCallRole, onCallOptions...)

	rv = append(rv, onCallEntitlement)

	return rv, nil, nil
}

func (s *scheduleBuilder) Grants(ctx context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	var rv []*v2.Grant

	// Get the current on-call user using our REST client
	shift, annos, err := s.wrapper.GetRestClient().GetScheduleOnCallUser(ctx, resource.Id.Resource)
	if err != nil {
		l.Error("Failed to get on-call user from Datadog",
			zap.Error(err),
			zap.String("schedule_id", resource.Id.Resource))
		return rv, &rs.SyncOpResults{Annotations: annos}, fmt.Errorf("failed to get on-call user for schedule %s: %w", resource.Id.Resource, err)
	}

	if shift.Data.ID == "" {
		l.Debug("No on-call user found for schedule", zap.String("schedule_id", resource.Id.Resource))
		return rv, &rs.SyncOpResults{Annotations: annos}, nil
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
	return rv, &rs.SyncOpResults{Annotations: annos}, nil
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
