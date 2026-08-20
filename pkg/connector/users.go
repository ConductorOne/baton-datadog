package connector

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userBuilder struct {
	resourceType *v2.ResourceType
	wrapper      *client.DatadogClient
}

type credentialUserBuilder struct{ *userBuilder }

func newCredentialUserBuilder(wrapper *client.DatadogClient) *credentialUserBuilder {
	return &credentialUserBuilder{userBuilder: newUserBuilder(wrapper)}
}

func (u *credentialUserBuilder) IssueCapabilityDetails(context.Context) (*v2.CredentialDetailsCredentialIssue, annotations.Annotations, error) {
	return v2.CredentialDetailsCredentialIssue_builder{
		Options: []*v2.CredentialIssueOptionDescriptor{v2.CredentialIssueOptionDescriptor_builder{
			Option:               v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_API_KEY,
			ResourceMode:         v2.CredentialResourceMode_CREDENTIAL_RESOURCE_MODE_DISCOVERABLE,
			SecretResourceTypeId: apiTokenResourceType.Id,
		}.Build()},
		PreferredOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_API_KEY,
	}.Build(), nil, nil
}

func (u *credentialUserBuilder) Issue(ctx context.Context, input *connectorbuilder.CredentialIssueInput) (*connectorbuilder.CredentialIssueOutput, error) {
	if input == nil || input.IdentityID == nil || input.IdentityID.GetResourceType() != userResourceType.Id {
		return nil, fmt.Errorf("baton-datadog: a Datadog user identity is required")
	}
	name := "c1-" + input.RequestID
	key, err := u.wrapper.CreateAPIKey(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("baton-datadog: create API key: %w", err)
	}
	secretTraitOptions := []rs.SecretTraitOption{
		rs.WithSecretCreatedByID(input.IdentityID),
		rs.WithSecretIdentityID(input.IdentityID),
		rs.WithSecretType(v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET),
		rs.WithSecretDetail("datadog.api_key"),
	}
	secret, err := rs.NewSecretResource(name, apiTokenResourceType, key.ID, secretTraitOptions)
	if err != nil {
		return nil, err
	}
	return &connectorbuilder.CredentialIssueOutput{
		Secret: secret,
		PlaintextData: []*v2.PlaintextData{
			v2.PlaintextData_builder{Name: "api_key", Bytes: []byte(key.Secret)}.Build(),
		},
		ResourceMode: v2.CredentialResourceMode_CREDENTIAL_RESOURCE_MODE_DISCOVERABLE,
	}, nil
}

var _ connectorbuilder.ResourceSyncerV2 = &userBuilder{}
var _ connectorbuilder.AccountManagerV2 = &userBuilder{}
var _ connectorbuilder.ResourceActionProvider = &userBuilder{}

// ResourceActions registers user-scoped actions. Only update_user lives here: it is
// reached through the generic "Perform connector action" step (which supplies a resource
// id), so resource-scoped registration is correct for it. enable_user / disable_user are
// registered globally in Datadog.GlobalActions instead, because C1's account-lifecycle
// pipeline resolves those schemas as global (resource_type_id="").
func (u *userBuilder) ResourceActions(ctx context.Context, registry actions.ActionRegistry) error {
	if err := registry.Register(ctx, updateUserActionSchema, u.updateUser); err != nil {
		return err
	}
	return nil
}

func (u *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return u.resourceType
}

// Create a new connector resource for a Datadog user.
func userResource(user *datadogV2.User) (*v2.Resource, error) {
	firstname, lastname := rs.SplitFullName(user.Attributes.GetName())
	profile := map[string]interface{}{
		"first_name": firstname,
		"last_name":  lastname,
		"login":      user.Attributes.GetEmail(),
		"user_id":    user.GetId(),
	}

	accountType := v2.UserTrait_ACCOUNT_TYPE_HUMAN
	rawStatus := user.Attributes.GetStatus()

	var status v2.Status_ResourceStatus
	switch rawStatus {
	case "Active":
		status = v2.Status_RESOURCE_STATUS_ENABLED
	case "Disabled":
		status = v2.Status_RESOURCE_STATUS_DISABLED
	case "Pending":
		// Pending users have been invited but haven't accepted yet, so they
		// don't have active access to Datadog. Keep the raw status as detail
		// so reviewers can tell them apart from actively disabled users.
		status = v2.Status_RESOURCE_STATUS_DISABLED
	default:
		status = v2.Status_RESOURCE_STATUS_UNSPECIFIED
	}

	if user.Attributes.GetServiceAccount() {
		accountType = v2.UserTrait_ACCOUNT_TYPE_SERVICE
	}

	userTraitOptions := []rs.UserTraitOption{
		rs.WithEmail(user.Attributes.GetEmail(), true),
		rs.WithAccountType(accountType),
	}

	ret, err := rs.NewUserResource(
		user.Attributes.GetName(),
		userResourceType,
		user.GetId(),
		userTraitOptions,
		rs.WithResourceProfile(profile),
		rs.WithResourceStatus(status, rawStatus),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// List returns all the users from the database as resource objects.
// Users include a UserTrait because they are the 'shape' of a standard user.
func (u *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	bag, page, err := parsePageToken(opts.PageToken.Token, &v2.ResourceId{ResourceType: u.resourceType.Id})
	if err != nil {
		return nil, nil, err
	}

	users, err := u.wrapper.ListUsers(ctx, datadogV2.NewListUsersOptionalParameters().WithPageNumber(page))
	if err != nil {
		return nil, nil, fmt.Errorf("error listing users: %w", err)
	}

	var rv []*v2.Resource
	for _, user := range users.GetData() {
		userCopy := user
		ur, err := userResource(&userCopy)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating user resource: %w", err)
		}
		rv = append(rv, ur)
	}

	nextPageToken := ""
	if len(users.GetData()) != 0 {
		nextPageToken, err = getPageTokenFromPage(bag, page+1)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-datadog: failed to get token from page: %w", err)
		}
	}

	return rv, &rs.SyncOpResults{NextPageToken: nextPageToken}, nil
}

// Entitlements always returns an empty slice for users.
func (u *userBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (u *userBuilder) Grants(ctx context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func newUserBuilder(wrapper *client.DatadogClient) *userBuilder {
	return &userBuilder{
		resourceType: userResourceType,
		wrapper:      wrapper,
	}
}

// CreateAccountCapabilityDetails declares the supported credential options for account creation.
func (u *userBuilder) CreateAccountCapabilityDetails(ctx context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
	}, nil, nil
}

// CreateAccount creates a Datadog user via the V2 Users API.
func (u *userBuilder) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.LocalCredentialOptions,
) (
	connectorbuilder.CreateAccountResponse,
	[]*v2.PlaintextData,
	annotations.Annotations,
	error,
) {
	// Parse inputs
	pMap := accountInfo.GetProfile().AsMap()
	email, ok := pMap["email"].(string)
	if !ok || strings.TrimSpace(email) == "" {
		return nil, nil, nil, fmt.Errorf("email is required")
	}
	name, _ := pMap["name"].(string)
	title, _ := pMap["title"].(string)

	// Build create request
	attrs := datadogV2.NewUserCreateAttributes(email)
	if strings.TrimSpace(name) != "" {
		attrs.SetName(name)
	}
	if strings.TrimSpace(title) != "" {
		attrs.SetTitle(title)
	}
	data := datadogV2.NewUserCreateData(*attrs, datadogV2.USERSTYPE_USERS)
	req := datadogV2.NewUserCreateRequest(*data)

	// Create user
	createdUserResp, err := u.wrapper.CreateUser(ctx, *req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating Datadog user: %w", err)
	}

	createdUser := createdUserResp.GetData()

	// Build Baton resource
	res, err := userResource(&createdUser)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to build user resource: %w", err)
	}

	return &v2.CreateAccountResponse_SuccessResult{
		Resource: res,
	}, nil, nil, nil
}
