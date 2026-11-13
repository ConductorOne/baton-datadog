package connector

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
	"time"

	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// Each secret resource type carries one issuer: a resource-scoped
// ACTION_TYPE_RESOURCE_CREATE action that mints the key. C1 recognizes it as a
// credential issuer by its schema alone: the action type, the one secret return
// field whose content type is a Multipass type, and the resource return that
// carries the created secret. Revoking an issued key is the resource delete the
// secret's syncer already provides.

const (
	ActionIssueOrganizationAPIKey           = "issue_organization_api_key"
	ActionIssueServiceAccountApplicationKey = "issue_service_account_application_key"

	// actionArgServiceAccountID is the identity an application key is issued
	// for: a Datadog service account, which is a user resource.
	actionArgServiceAccountID = "service_account_id"
	// actionArgScopes is the application key's one provider input. Datadog
	// application keys accept a free-form scope list.
	actionArgScopes = "scopes"

	// actionReturnResource is the created secret resource, carrying its
	// SecretTrait.
	actionReturnResource = "resource"

	datadogIssueOrgKeyActionDisplayName = "Issue Datadog organization API key"
	datadogIssueAppKeyActionDisplayName = "Issue Datadog service account application key"
)

// resourceReturnField declares the created secret resource.
func resourceReturnField() *configv1.Field {
	return configv1.Field_builder{
		Name:          actionReturnResource,
		DisplayName:   "Secret resource",
		Description:   "The created key, so it can be revoked.",
		IsRequired:    true,
		ResourceField: configv1.ResourceField_builder{}.Build(),
	}.Build()
}

// organizationAPIKeyActionSchema is the organization API key issuer. An
// organization key belongs to the organization, so it takes no arguments.
func organizationAPIKeyActionSchema() *v2.BatonActionSchema {
	secret := organizationAPIKeyOutput()
	secret.SetIsRequired(true)
	return v2.BatonActionSchema_builder{
		Name:        ActionIssueOrganizationAPIKey,
		DisplayName: datadogIssueOrgKeyActionDisplayName,
		Description: "Creates a Datadog organization API key and returns it as a Multipass api_key_v2 secret.",
		ReturnTypes: []*configv1.Field{secret, resourceReturnField()},
		ActionType:  []v2.ActionType{v2.ActionType_ACTION_TYPE_RESOURCE_CREATE},
	}.Build()
}

// serviceAccountApplicationKeyActionSchema is the application key issuer. The
// service account argument is the one subject, constrained to the user type.
func serviceAccountApplicationKeyActionSchema() *v2.BatonActionSchema {
	secret := serviceAccountApplicationKeyOutput()
	secret.SetIsRequired(true)
	return v2.BatonActionSchema_builder{
		Name:        ActionIssueServiceAccountApplicationKey,
		DisplayName: datadogIssueAppKeyActionDisplayName,
		Description: "Creates an application key for a Datadog service account and returns it as a Multipass api_key_v2 secret.",
		Arguments: []*configv1.Field{
			configv1.Field_builder{
				Name:        actionArgServiceAccountID,
				DisplayName: "Service account",
				Description: "The Datadog service account that owns the key.",
				IsRequired:  true,
				ResourceIdField: configv1.ResourceIdField_builder{
					Rules: configv1.ResourceIDRules_builder{
						AllowedResourceTypeIds: []string{userResourceType.Id},
					}.Build(),
				}.Build(),
			}.Build(),
			configv1.Field_builder{
				Name:             actionArgScopes,
				DisplayName:      "Scopes",
				Description:      "Application key scopes. Must not be empty. Omit for an unscoped key.",
				StringSliceField: configv1.StringSliceField_builder{}.Build(),
			}.Build(),
		},
		ReturnTypes: []*configv1.Field{secret, resourceReturnField()},
		ActionType:  []v2.ActionType{v2.ActionType_ACTION_TYPE_RESOURCE_CREATE},
	}.Build()
}

// registerOrganizationAPIKeyIssuer registers the organization key issuer on the
// registry of the organization API key resource type.
func (u *credentialUserBuilder) registerOrganizationAPIKeyIssuer(ctx context.Context, registry actions.ActionRegistry) error {
	if err := actions.RegisterWithSecrets(ctx, registry, organizationAPIKeyActionSchema(), u.issueOrganizationAPIKeyAction); err != nil {
		return fmt.Errorf("baton-datadog: failed to register %s action: %w", ActionIssueOrganizationAPIKey, err)
	}
	return nil
}

// registerServiceAccountApplicationKeyIssuer registers the application key
// issuer on the registry of the application key resource type.
func (u *credentialUserBuilder) registerServiceAccountApplicationKeyIssuer(ctx context.Context, registry actions.ActionRegistry) error {
	if err := actions.RegisterWithSecrets(ctx, registry, serviceAccountApplicationKeyActionSchema(), u.issueServiceAccountApplicationKeyAction); err != nil {
		return fmt.Errorf("baton-datadog: failed to register %s action: %w", ActionIssueServiceAccountApplicationKey, err)
	}
	return nil
}

// issueOrganizationAPIKeyAction mints an organization API key. Datadog reports
// no expiry for one, so the returned SecretTrait carries none and C1's offering
// duration alone decides when it is revoked.
func (u *credentialUserBuilder) issueOrganizationAPIKeyAction(
	ctx context.Context,
	args *structpb.Struct,
) (*structpb.Struct, []*v2.PlaintextData, annotations.Annotations, error) {
	name, err := newIssuedKeyName(time.Now(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	key, plaintext, err := u.mintOrganizationAPIKey(ctx, name, "")
	if err != nil {
		return nil, nil, nil, err
	}
	secret, err := u.organizationAPIKeyResource(ctx, name, key, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	result, plaintexts, annos, err := issueActionResult(secret, plaintext)
	if err != nil {
		// The key exists but its result cannot be returned: nobody would hold it.
		u.discardOrganizationAPIKey(ctx, key.ID)
	}
	return result, plaintexts, annos, err
}

// issueServiceAccountApplicationKeyAction mints an application key for the
// service account the request names.
func (u *credentialUserBuilder) issueServiceAccountApplicationKeyAction(
	ctx context.Context,
	args *structpb.Struct,
) (*structpb.Struct, []*v2.PlaintextData, annotations.Annotations, error) {
	serviceAccount, err := actions.RequireResourceIDArg(args, actionArgServiceAccountID)
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.InvalidArgument, "baton-datadog: %v", err)
	}
	if serviceAccount.GetResourceType() != userResourceType.Id || serviceAccount.GetResource() == "" {
		return nil, nil, nil, status.Errorf(codes.InvalidArgument, "baton-datadog: %s must be a %s resource", actionArgServiceAccountID, userResourceType.Id)
	}
	var scopes []string
	// A null scopes is absent, as in the SDK. Absent mints an unscoped key with
	// the service account's full permissions, so a value that is present but
	// unreadable or empty is refused rather than silently widened to that.
	if v, present := args.GetFields()[actionArgScopes]; present {
		if _, isNull := v.GetKind().(*structpb.Value_NullValue); !isNull {
			requested, ok := actions.GetStringSliceArg(args, actionArgScopes)
			if !ok {
				return nil, nil, nil, status.Errorf(codes.InvalidArgument, "baton-datadog: %s must be a list of strings", actionArgScopes)
			}
			if len(requested) == 0 {
				return nil, nil, nil, status.Errorf(codes.InvalidArgument, "baton-datadog: %s must be a non-empty list of strings; omit it for an unscoped key", actionArgScopes)
			}
			scopes = requested
		}
	}
	name, err := newIssuedKeyName(time.Now(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	key, plaintext, err := u.mintServiceAccountApplicationKey(ctx, serviceAccount.GetResource(), name, "", scopes)
	if err != nil {
		return nil, nil, nil, err
	}
	secret, err := u.applicationKeyResource(ctx, name, key, serviceAccount)
	if err != nil {
		return nil, nil, nil, err
	}
	result, plaintexts, annos, err := issueActionResult(secret, plaintext)
	if err != nil {
		// The key exists but its result cannot be returned: nobody would hold it.
		u.discardServiceAccountApplicationKey(ctx, key.ServiceAccountID, key.ID)
	}
	return result, plaintexts, annos, err
}

// issueActionResult builds the handler result: the created secret as a resource
// return, and the plaintext. The ciphertext's schema is checked against the
// secret return field's content type, which the SDK does not copy from the
// schema, so the plaintext must already carry it.
func issueActionResult(
	secret *v2.Resource,
	plaintext *v2.PlaintextData,
) (*structpb.Struct, []*v2.PlaintextData, annotations.Annotations, error) {
	field, err := actions.NewResourceReturnField(actionReturnResource, secret)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("baton-datadog: build issuer resource return: %w", err)
	}
	return actions.NewReturnValues(true, field), []*v2.PlaintextData{plaintext}, nil, nil
}

// issuedKeyNameSuffixLen is the length of the random suffix of an action-issued
// key name: 6 base32 characters, 30 bits.
const issuedKeyNameSuffixLen = 6

// newIssuedKeyName names a key the issuer actions mint: c1-<UTC time>-<random>,
// e.g. c1-20260102T150405Z-k3x9qa. Every call gets a fresh name, which avoids name
// collisions; the issuer has no duplicate guard of its own and relies on C1
// dispatching the action once.
func newIssuedKeyName(now time.Time, random io.Reader) (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", fmt.Errorf("baton-datadog: generate key name: %w", err)
	}
	suffix := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))[:issuedKeyNameSuffixLen]
	return "c1-" + now.UTC().Format("20060102T150405Z") + "-" + suffix, nil
}
