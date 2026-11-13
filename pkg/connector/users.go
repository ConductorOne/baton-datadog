package connector

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/conductorone/baton-datadog/local_vendor/baton-multipass-sdk/pkg/multipass"
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
	// apiBaseURL is the Datadog API endpoint an issued key authenticates
	// against: the configured base-url override when set, otherwise the
	// endpoint the site implies. It is resolved by the caller that knows the
	// configuration, not here.
	apiBaseURL string
}

func newCredentialUserBuilder(wrapper *client.DatadogClient, offerOrgAPIKey, offerServiceAccountAppKey bool, apiBaseURL string) *credentialUserBuilder {
	return &credentialUserBuilder{
		userBuilder:               newUserBuilder(wrapper),
		offerOrgAPIKey:            offerOrgAPIKey,
		offerServiceAccountAppKey: offerServiceAccountAppKey,
		apiBaseURL:                apiBaseURL,
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
//
// This legacy CredentialIssuer stays registered for the app-key issuer's sake.
// baton-sdk v0.44.2 advertises CAPABILITY_CREDENTIAL_ENCRYPTION_JWE_XWING_V1 on
// the user resource type only when a CredentialIssuer exists for it. Only the
// user-bound app-key issuer depends on that: c1's JWE admission check applies
// to issuers bound to an identity, and the org API key issuer passes without it.
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
//
// The returned secret's CreatedById is deliberately left unset, for the same
// reason applicationKeyResource leaves it unset on sync: Datadog's
// application-key API never reports who created a key, only who owns it
// (see application_key.go's applicationKeyResource doc comment). This
// connector's own credential-issuance call is not evidence to the contrary --
// it authenticates as the connector's configured Datadog principal, not as
// the service account -- so recording the service account as creator here
// would repeat the same unsupported claim the sync path used to make.
func (u *credentialUserBuilder) issueServiceAccountApplicationKey(ctx context.Context, input *connectorbuilder.CredentialIssueInput) (*connectorbuilder.CredentialIssueOutput, error) {
	serviceAccountID := input.IdentityID.GetResource()

	name := issuedCredentialName(input.RequestID)
	key, plaintext, err := u.mintServiceAccountApplicationKey(ctx, serviceAccountID, name, input.RequestID, input.CredentialOptions.GetApiKey().GetScopes())
	if err != nil {
		return nil, err
	}
	secret, err := u.applicationKeyResource(ctx, name, key, input.IdentityID)
	if err != nil {
		return nil, err
	}
	return &connectorbuilder.CredentialIssueOutput{
		Secret:        secret,
		PlaintextData: []*v2.PlaintextData{plaintext},
		ResourceMode:  v2.CredentialResourceMode_CREDENTIAL_RESOURCE_MODE_DISCOVERABLE,
	}, nil
}

// scopesOrNil dereferences Datadog's nullable scopes list; nil stays nil, so
// omitempty leaves "scopes" out.
func scopesOrNil(scopes *[]string) []string {
	if scopes == nil {
		return nil
	}
	return *scopes
}

// issueOrganizationAPIKey mints a Datadog organization API key
// (POST /api/v2/api_keys). This is the second, deliberately non-default
// issuance kind: the key is org-wide and Datadog records its creator, not an
// owner, so the identity on the returned SecretTrait is the identity the key
// was vended TO rather than a provider-side owner Datadog would enforce. The
// key is unscoped -- a Datadog organization API key carries no scopes at all,
// which is exactly why it must stay a separate kind from a service-account
// application key rather than a variation of one.
//
// CreatedById comes from Datadog's own relationships.created_by on the create
// response (see IssuedAPIKey.CreatedByUserID), the same field
// apiTokenBuilder.List reads on sync -- never from input.IdentityID. This
// call authenticates as the connector's configured Datadog principal, not as
// the requesting/receiving identity, so Datadog will typically attribute the
// key to that principal rather than to whoever it was vended to; recipient
// and creator are frequently different actors here, not just in an edge
// case. When the response reports no creator, CreatedById is left unset
// rather than defaulting to the recipient.
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
	key, plaintext, err := u.mintOrganizationAPIKey(ctx, name, input.RequestID)
	if err != nil {
		return nil, err
	}
	secretResource, err := u.organizationAPIKeyResource(ctx, name, key, input.IdentityID)
	if err != nil {
		return nil, err
	}
	return &connectorbuilder.CredentialIssueOutput{
		Secret:        secretResource,
		PlaintextData: []*v2.PlaintextData{plaintext},
		ResourceMode:  v2.CredentialResourceMode_CREDENTIAL_RESOURCE_MODE_DISCOVERABLE,
	}, nil
}

// discardOrganizationAPIKey revokes an organization API key whose plaintext
// cannot be returned. Issuance is not retried automatically, so a mint whose
// result never reaches the caller would otherwise be an orphaned live
// credential nobody holds. A failed delete is logged rather than returned: the
// original error is what the caller needs to see, and the key id is what lets
// an operator clean up by hand.
func (u *credentialUserBuilder) discardOrganizationAPIKey(ctx context.Context, keyID string) {
	if deleteErr := u.wrapper.DeleteAPIKey(ctx, keyID); deleteErr != nil {
		ctxzap.Extract(ctx).Warn("failed to clean up Datadog organization API key after issuance error",
			zap.String("api_key_id", keyID),
			zap.Error(deleteErr),
		)
	}
}

// discardServiceAccountApplicationKey revokes a service account application key
// whose plaintext cannot be returned. Same reasoning as
// discardOrganizationAPIKey: issuance is not retried, so a mint that never
// reaches the caller would otherwise be an orphaned live credential.
func (u *credentialUserBuilder) discardServiceAccountApplicationKey(ctx context.Context, serviceAccountID, keyID string) {
	if deleteErr := u.wrapper.DeleteServiceAccountApplicationKey(ctx, serviceAccountID, keyID); deleteErr != nil {
		ctxzap.Extract(ctx).Warn("failed to clean up Datadog service account application key after issuance error",
			zap.String("service_account_id", serviceAccountID),
			zap.String("application_key_id", keyID),
			zap.Error(deleteErr),
		)
	}
}

// mintOrganizationAPIKey mints an organization API key called name and renders
// its plaintext. IssueCredential and the issuer action both call it, so the
// create call and the discard-on-encode-failure behave the same on both paths.
// On an error before the create call nothing was minted. If the plaintext
// cannot be encoded after the create, the key exists and is discarded on a
// best-effort basis; a failed discard is only logged.
//
// A non-empty requestID (the legacy path) refuses a key that already carries
// name. An empty requestID means no duplicate guard: the issuer action passes ""
// because it names every key afresh.
func (u *credentialUserBuilder) mintOrganizationAPIKey(ctx context.Context, name, requestID string) (*client.IssuedAPIKey, *v2.PlaintextData, error) {
	if requestID != "" {
		existing, err := u.wrapper.FindAPIKeyByName(ctx, name)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-datadog: look up organization API key for request %q: %w", requestID, err)
		}
		if existing != nil {
			return nil, nil, status.Errorf(codes.AlreadyExists, "baton-datadog: organization API key for request %q may already exist; refusing to issue a duplicate", requestID)
		}
	}

	key, err := u.wrapper.CreateAPIKey(ctx, name)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: create organization API key: %w", err)
	}

	// Multipass rejects nulls, so the optional api_key_v2 fields use omitempty.
	plaintext, err := multipass.Plaintext(datadogAPIKeyFieldName, multipass.APIKeyV2{
		KeyValue:   key.Secret,
		KeyID:      key.ID,
		Provider:   datadogProviderName,
		BaseURL:    u.apiBaseURL,
		HeaderName: datadogAPIKeyHeaderName,
	})
	if err != nil {
		u.discardOrganizationAPIKey(ctx, key.ID)
		return nil, nil, fmt.Errorf("baton-datadog: encode organization API key plaintext: %w", err)
	}
	return key, plaintext, nil
}

// organizationAPIKeyResource builds the secret resource for a freshly minted
// organization API key, discarding the key if it cannot be built. identityID is
// the identity the key is vended to; it is nil when the caller names none.
func (u *credentialUserBuilder) organizationAPIKeyResource(ctx context.Context, name string, key *client.IssuedAPIKey, identityID *v2.ResourceId) (*v2.Resource, error) {
	secretTraitOptions := []rs.SecretTraitOption{
		rs.WithSecretType(v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET),
		rs.WithSecretDetail("datadog.api_key"),
	}
	if identityID != nil {
		secretTraitOptions = append(secretTraitOptions, rs.WithSecretIdentityID(identityID))
	}
	if key.CreatedByUserID != "" {
		secretTraitOptions = append(secretTraitOptions, rs.WithSecretCreatedByID(&v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     key.CreatedByUserID,
		}))
	}
	// No parent resource id: an organization API key hangs off the
	// organization, not off the identity it was vended to, and the syncer
	// (apiTokenBuilder.List) builds these keys without a parent too. Claiming
	// the user as a parent here would make the issued resource disagree with
	// the same key on its next sync.
	secretResource, err := rs.NewSecretResource(name, deletableAPITokenResourceType, key.ID, secretTraitOptions)
	if err != nil {
		u.discardOrganizationAPIKey(ctx, key.ID)
		return nil, fmt.Errorf("baton-datadog: build organization API key secret resource: %w", err)
	}
	return secretResource, nil
}

// mintServiceAccountApplicationKey is the application key equivalent: it
// re-checks that the target is still a service account, optionally refuses a
// duplicate request (non-empty requestID, as in mintOrganizationAPIKey), mints,
// and renders the plaintext.
func (u *credentialUserBuilder) mintServiceAccountApplicationKey(
	ctx context.Context,
	serviceAccountID, name, requestID string,
	scopes []string,
) (*client.IssuedApplicationKey, *v2.PlaintextData, error) {
	userResp, err := u.wrapper.GetUser(ctx, serviceAccountID)
	if err != nil {
		if client.IsNotFound(err) {
			return nil, nil, status.Errorf(codes.NotFound, "baton-datadog: Datadog user %q not found", serviceAccountID)
		}
		return nil, nil, fmt.Errorf("baton-datadog: look up Datadog user %q: %w", serviceAccountID, err)
	}
	if !userResp.GetData().Attributes.GetServiceAccount() {
		return nil, nil, status.Errorf(codes.InvalidArgument, "baton-datadog: Datadog user %q is not a service account; credential issuance only targets service accounts", serviceAccountID)
	}

	if requestID != "" {
		existing, err := u.wrapper.FindServiceAccountApplicationKeyByName(ctx, serviceAccountID, name)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-datadog: look up application key for request %q: %w", requestID, err)
		}
		if existing != nil {
			return nil, nil, status.Errorf(codes.AlreadyExists, "baton-datadog: application key for request %q may already exist; refusing to issue a duplicate", requestID)
		}
	}

	key, err := u.wrapper.CreateServiceAccountApplicationKey(ctx, serviceAccountID, name, scopes)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: create service account application key: %w", err)
	}

	// Multipass rejects nulls, so the optional api_key_v2 fields use omitempty.
	// key.Scopes is nil when Datadog did not report scopes, which leaves
	// "scopes" out entirely rather than asserting the key is unscoped.
	plaintext, err := multipass.Plaintext(datadogApplicationKeyFieldName, multipass.APIKeyV2{
		KeyValue:   key.Secret,
		KeyID:      key.ID,
		Provider:   datadogProviderName,
		BaseURL:    u.apiBaseURL,
		HeaderName: datadogApplicationKeyHeaderName,
		Scopes:     scopesOrNil(key.Scopes),
	})
	if err != nil {
		u.discardServiceAccountApplicationKey(ctx, serviceAccountID, key.ID)
		return nil, nil, fmt.Errorf("baton-datadog: encode service account application key plaintext: %w", err)
	}
	return key, plaintext, nil
}

// applicationKeyResource builds the secret resource for a freshly minted
// application key, discarding the key if it cannot be built. The key's scopes
// are carried on it so a vended key reports what it can do immediately rather
// than after the next sync. key.Scopes is what Datadog echoed back, so this
// agrees with what the syncer later produces for the same key.
//
// CreatedById is deliberately left unset, for the reason applicationKeyResource
// in application_key.go leaves it unset on sync: Datadog never reports who
// created an application key, only who owns it.
func (u *credentialUserBuilder) applicationKeyResource(ctx context.Context, name string, key *client.IssuedApplicationKey, identityID *v2.ResourceId) (*v2.Resource, error) {
	secretTraitOptions := []rs.SecretTraitOption{
		rs.WithSecretIdentityID(identityID),
		rs.WithSecretType(v2.SecretTrait_CREDENTIAL_TYPE_STATIC_SECRET),
		rs.WithSecretDetail("datadog.service_account_application_key"),
	}
	resourceOptions := append([]rs.ResourceOption{rs.WithParentResourceID(identityID)},
		applicationKeyProfileOptions(key.Scopes)...)
	secret, err := rs.NewSecretResource(name, serviceAccountApplicationKeyResourceType, key.ID, secretTraitOptions, resourceOptions...)
	if err != nil {
		u.discardServiceAccountApplicationKey(ctx, key.ServiceAccountID, key.ID)
		return nil, fmt.Errorf("baton-datadog: build service account application key secret resource: %w", err)
	}
	return secret, nil
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
