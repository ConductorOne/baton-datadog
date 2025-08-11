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
		return nil, err
	}

	return ret, nil
}

// List returns all the on-call schedules from Datadog as resource objects.
func (s *scheduleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	// Use the REST client to get schedules
	schedulesResponse, err := s.restClient.ListOnCallSchedules(ctx)
	if err != nil {
		l.Error("Failed to list on-call schedules", zap.Error(err))
		return nil, "", nil, fmt.Errorf("error listing on-call schedules: %w", err)
	}

	var rv []*v2.Resource
	for _, schedule := range schedulesResponse.Data {
		sr, err := scheduleResource(&schedule)
		if err != nil {
			return nil, "", nil, fmt.Errorf("error creating schedule resource: %w", err)
		}
		rv = append(rv, sr)
	}

	// For now, we'll return empty next page token since the API doesn't seem to support pagination
	// In a real implementation, you would handle pagination based on the API response
	nextPageToken := ""

	return rv, nextPageToken, nil, nil
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

	// Create API context with authentication
	ctx = withAuthContext(ctx, s.apiKey, s.appKey, s.site)

	// Use Datadog V2 OnCall API
	oncallAPI := datadogV2.NewOnCallApi(s.client)

	// Get the current on-call user
	shift, resp, err := oncallAPI.GetScheduleOnCallUser(ctx, resource.Id.Resource)
	if err != nil {
		l.Error("Failed to get on-call user from Datadog",
			zap.Error(err),
			zap.String("schedule_id", resource.Id.Resource),
			zap.Int("status_code", resp.StatusCode))
		return rv, "", nil, nil
	}

	if shift.Data != nil && shift.Data.Relationships != nil && shift.Data.Relationships.User != nil {
		userID := shift.Data.Relationships.User.Data.Id

		if userID != "" {
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
		}
	} else {
		l.Debug("No on-call user found for schedule", zap.String("schedule_id", resource.Id.Resource))
	}

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

func newScheduleBuilder(apiClient *datadog.APIClient, site, apiKey, appKey string) *scheduleBuilder {
	return &scheduleBuilder{
		resourceType: scheduleResourceType,
		client:       apiClient,
		restClient:   client.NewDatadogRestClient(site, apiKey, appKey),
		site:         site,
		apiKey:       apiKey,
		appKey:       appKey,
	}
}
