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
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type userBuilder struct {
	resourceType *v2.ResourceType
	wrapper      *client.DatadogClient
}

type credentialUserBuilder struct {
	*userBuilder
	// offerOrgAPIKey advertises organization API keys as a second issuance
	// kind. It follows the allow-org-api-key-deletion grant because the SDK
	// refuses to register an issuance descriptor whose secret resource type
	// has no ResourceDeleterV2: without the grant this connector cannot revoke
	// an org key, so it must not mint one either.
	offerOrgAPIKey bool
	// offerServiceAccountAppKey follows the
	// sync-service-account-application-keys grant, for the same reason: that
	// grant is what registers the application-key syncer, and the syncer is
	// what carries the deleter the SDK requires behind this descriptor.
	offerServiceAccountAppKey bool
}

func newCredentialUserBuilder(wrapper *client.DatadogClient, offerOrgAPIKey, offerServiceAccountAppKey bool) *credentialUserBuilder {
	return &credentialUserBuilder{
		userBuilder:               newUserBuilder(wrapper),
		offerOrgAPIKey:            offerOrgAPIKey,
		offerServiceAccountAppKey: offerServiceAccountAppKey,
	}
}

// IssueCapabilityDetails advertises the credential kinds this connector mints.
// Both are the API_KEY shape and they are distinguished only by
// secret_resource_type_id, which is what that field is for: the closed Option
// enum names the shape a caller asks for, the open resource type id names the
// kind that comes back. Datadog's two kinds are genuinely different
// credentials -- a service-account application key is scoped to and owned by
// one identity, an organization API key is owned by the org and by nobody in
// it -- so they must stay two descriptors. Collapsing them would leave a
// caller unable to say which one it wants, and the SDK unable to check that
// the resource Issue returns is the one that was requested.
//
// The service-account application key is marked preferred: it is the only
// issuance mapping with an honest owner, so it is the default when a caller
// asks for the API_KEY shape without choosing a kind.
func (u *credentialUserBuilder) IssueCapabilityDetails(context.Context) (*v2.CredentialDetailsCredentialIssue, annotations.Annotations, error) {
	options := []*v2.CredentialIssueOptionDescriptor{}
	if u.offerServiceAccountAppKey {
		options = append(options, v2.CredentialIssueOptionDescriptor_builder{
			Option:               v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_API_KEY,
			ResourceMode:         v2.CredentialResourceMode_CREDENTIAL_RESOURCE_MODE_DISCOVERABLE,
			SecretResourceTypeId: serviceAccountApplicationKeyResourceType.Id,
			CustomScopesAllowed:  true,
			// Preferred only where it can be: exactly one descriptor per shape
			// may set it, and it must be set whenever several share a shape.
			Preferred: u.offerOrgAPIKey,
		}.Build())
	}
	if u.offerOrgAPIKey {
		options = append(options, v2.CredentialIssueOptionDescriptor_builder{
			Option:       v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_API_KEY,
			ResourceMode: v2.CredentialResourceMode_CREDENTIAL_RESOURCE_MODE_DISCOVERABLE,
			// deletableAPITokenResourceType, not apiTokenResourceType: they
			// share an id, and this is the variant registered whenever this
			// descriptor is advertised.
			SecretResourceTypeId: deletableAPITokenResourceType.Id,
			// Datadog organization API keys carry no scopes. Advertising none
			// and disallowing custom ones makes the SDK reject a scoped
			// request for this kind before it reaches Issue.
		}.Build())
	}
	return v2.CredentialDetailsCredentialIssue_builder{
		Options:         options,
		PreferredOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_API_KEY,
	}.Build(), nil, nil
}

// Issue dispatches on the credential kind the caller selected. The oneof arm
// of CredentialIssueOptions gives the shape (API_KEY) and
// secret_resource_type_id gives the kind within it; the SDK has already
// resolved that pair against IssueCapabilityDetails and rejected anything not
// advertised, so this switch only has to route. It deliberately does not fall
// back to a default arm: an unrecognised kind is a protocol mismatch, and
// minting the wrong kind of Datadog credential is not a recoverable guess.
//
// Issue is not retried automatically. A failure anywhere in it -- the
// duplicate-issuance lookup, the mint itself, or the trait construction after
// it -- fails the issuance outright and a human has to re-drive the request.
// That is why the lookups it depends on are single-request rather than paged
// walks, and why a mint whose result cannot be returned is cleaned up on the
// spot: there is no later attempt to recover from either.
func (u *credentialUserBuilder) Issue(ctx context.Context, input *connectorbuilder.CredentialIssueInput) (*connectorbuilder.CredentialIssueOutput, error) {
	if input == nil || input.IdentityID == nil || input.IdentityID.GetResourceType() != userResourceType.Id {
		return nil, status.Error(codes.InvalidArgument, "baton-datadog: a Datadog user identity is required")
	}
	switch secretResourceTypeID := input.CredentialOptions.GetSecretResourceTypeId(); secretResourceTypeID {
	case serviceAccountApplicationKeyResourceType.Id:
		if !u.offerServiceAccountAppKey {
			return nil, status.Error(codes.FailedPrecondition,
				"baton-datadog: service account application key issuance requires sync-service-account-application-keys, which also provides the revoke path")
		}
		return u.issueServiceAccountApplicationKey(ctx, input)
	case apiTokenResourceType.Id:
		if !u.offerOrgAPIKey {
			return nil, status.Error(codes.FailedPrecondition,
				"baton-datadog: organization API key issuance requires allow-org-api-key-deletion, which also provides the revoke path")
		}
		return u.issueOrganizationAPIKey(ctx, input)
	default:
		return nil, status.Errorf(codes.InvalidArgument,
			"baton-datadog: unsupported credential secret resource type %q", secretResourceTypeID)
	}
}

// issuedCredentialName is the provider-side name this connector gives a
// credential it mints. It is derived from the request id so a retried request
// finds the key its predecessor created instead of minting a second one.
func issuedCredentialName(requestID string) string {
	return "c1-" + requestID
}

// issueServiceAccountApplicationKey mints a Datadog service-account
// application key scoped to and owned by the target identity. Per SPEC-07 (the
// judged Datadog credential-issuance design) this is the honest issuance
// mapping: the key has a real non-human owner. It is gated on a live re-check
// that the target is actually a Datadog service account, since its user record
// may have changed since it was last synced.
func (u *credentialUserBuilder) issueServiceAccountApplicationKey(ctx context.Context, input *connectorbuilder.CredentialIssueInput) (*connectorbuilder.CredentialIssueOutput, error) {
	serviceAccountID := input.IdentityID.GetResource()

	userResp, err := u.wrapper.GetUser(ctx, serviceAccountID)
	if err != nil {
		if client.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "baton-datadog: Datadog user %q not found", serviceAccountID)
		}
		return nil, fmt.Errorf("baton-datadog: look up Datadog user %q: %w", serviceAccountID, err)
	}
	if !userResp.GetData().Attributes.GetServiceAccount() {
		return nil, status.Errorf(codes.InvalidArgument, "baton-datadog: Datadog user %q is not a service account; credential issuance only targets service accounts", serviceAccountID)
	}

	name := issuedCredentialName(input.RequestID)
	existing, err := u.wrapper.FindServiceAccountApplicationKeyByName(ctx, serviceAccountID, name)
	if err != nil {
		return nil, fmt.Errorf("baton-datadog: look up application key for request %q: %w", input.RequestID, err)
	}
	if existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "baton-datadog: application key for request %q may already exist; refusing to issue a duplicate", input.RequestID)
	}

	scopes := input.CredentialOptions.GetApiKey().GetScopes()
	key, err := u.wrapper.CreateServiceAccountApplicationKey(ctx, serviceAccountID, name, scopes)
	if err != nil {
		return nil, fmt.Errorf("baton-datadog: create service account application key: %w", err)
	}

	secretTraitOptions := []rs.SecretTraitOption{
		rs.WithSecretCreatedByID(input.IdentityID),
		rs.WithSecretIdentityID(input.IdentityID),
		rs.WithSecretType(v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET),
		rs.WithSecretDetail("datadog.service_account_application_key"),
	}
	// Carry the key's scopes on the freshly issued resource so a vended key
	// reports what it can do immediately, rather than only after the next sync
	// rebuilds it. key.Scopes is what Datadog echoed back rather than what was
	// requested, so this agrees with what the syncer will later produce for the
	// same key instead of drifting from it.
	resourceOptions := append([]rs.ResourceOption{rs.WithParentResourceID(input.IdentityID)},
		applicationKeyProfileOptions(key.Scopes)...)
	secret, err := rs.NewSecretResource(name, serviceAccountApplicationKeyResourceType, key.ID, secretTraitOptions, resourceOptions...)
	if err != nil {
		if deleteErr := u.wrapper.DeleteServiceAccountApplicationKey(ctx, serviceAccountID, key.ID); deleteErr != nil {
			ctxzap.Extract(ctx).Warn("failed to clean up Datadog service account application key after resource construction error",
				zap.String("service_account_id", serviceAccountID),
				zap.String("application_key_id", key.ID),
				zap.Error(deleteErr),
			)
		}
		return nil, fmt.Errorf("baton-datadog: build service account application key secret resource: %w", err)
	}
	return &connectorbuilder.CredentialIssueOutput{
		Secret: secret,
		PlaintextData: []*v2.PlaintextData{
			v2.PlaintextData_builder{Name: "application_key", Bytes: []byte(key.Secret)}.Build(),
		},
		ResourceMode: v2.CredentialResourceMode_CREDENTIAL_RESOURCE_MODE_DISCOVERABLE,
	}, nil
}

// issueOrganizationAPIKey mints a Datadog organization API key
// (POST /api/v2/api_keys). This is the second, deliberately non-default
// issuance kind: the key is org-wide and Datadog records its creator, not an
// owner, so the identity on the returned SecretTrait is the identity the key
// was vended TO rather than a provider-side owner Datadog would enforce. The
// key is unscoped -- a Datadog organization API key carries no scopes at all,
// which is exactly why it must stay a separate kind from a service-account
// application key rather than a variation of one.
func (u *credentialUserBuilder) issueOrganizationAPIKey(ctx context.Context, input *connectorbuilder.CredentialIssueInput) (*connectorbuilder.CredentialIssueOutput, error) {
	// The SDK rejects requested scopes for this descriptor before Issue runs
	// (it advertises no scopes and disallows custom ones). Re-checking here
	// keeps the arm correct for a caller that reaches Issue directly, and
	// fails closed rather than silently minting an unscoped key for a request
	// that asked for a scoped one.
	if scopes := input.CredentialOptions.GetApiKey().GetScopes(); len(scopes) != 0 {
		return nil, status.Error(codes.InvalidArgument,
			"baton-datadog: Datadog organization API keys cannot be scoped; request a service account application key for a scoped credential")
	}

	name := issuedCredentialName(input.RequestID)
	existing, err := u.wrapper.FindAPIKeyByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("baton-datadog: look up organization API key for request %q: %w", input.RequestID, err)
	}
	if existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "baton-datadog: organization API key for request %q may already exist; refusing to issue a duplicate", input.RequestID)
	}

	key, err := u.wrapper.CreateAPIKey(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("baton-datadog: create organization API key: %w", err)
	}

	secretTraitOptions := []rs.SecretTraitOption{
		rs.WithSecretCreatedByID(input.IdentityID),
		rs.WithSecretIdentityID(input.IdentityID),
		rs.WithSecretType(v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET),
		rs.WithSecretDetail("datadog.api_key"),
	}
	// No parent resource id: an organization API key hangs off the
	// organization, not off the identity it was vended to, and the syncer
	// (apiTokenBuilder.List) builds these keys without a parent too. Claiming
	// the user as a parent here would make the issued resource disagree with
	// the same key on its next sync.
	secret, err := rs.NewSecretResource(name, deletableAPITokenResourceType, key.ID, secretTraitOptions)
	if err != nil {
		if deleteErr := u.wrapper.DeleteAPIKey(ctx, key.ID); deleteErr != nil {
			ctxzap.Extract(ctx).Warn("failed to clean up Datadog organization API key after resource construction error",
				zap.String("api_key_id", key.ID),
				zap.Error(deleteErr),
			)
		}
		return nil, fmt.Errorf("baton-datadog: build organization API key secret resource: %w", err)
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
var _ connectorbuilder.CredentialIssuerLimited = &credentialUserBuilder{}
var _ connectorbuilder.CredentialIssuerV2 = &credentialUserBuilder{}
var _ connectorbuilder.AccountManagerV2 = &credentialUserBuilder{}
var _ connectorbuilder.ResourceActionProvider = &credentialUserBuilder{}

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
