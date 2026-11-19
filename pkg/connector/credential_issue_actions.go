package connector

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	configv1 "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/segmentio/ksuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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
	// actionArgScopes controls permissions on application keys.
	actionArgScopes     = "scopes"
	actionArgNamePrefix = "name_prefix"

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
// organization key belongs to the organization, so it takes no subject.
func organizationAPIKeyActionSchema() *v2.BatonActionSchema {
	secret := organizationAPIKeyOutput()
	secret.SetIsRequired(true)
	return v2.BatonActionSchema_builder{
		Name:        ActionIssueOrganizationAPIKey,
		DisplayName: datadogIssueOrgKeyActionDisplayName,
		Description: "Creates a Datadog organization API key and returns it as a Multipass api_key_v2 secret.",
		Arguments:   []*configv1.Field{namePrefixField()},
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
			namePrefixField(),
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
				Name:        actionArgScopes,
				DisplayName: "Scopes",
				Description: "An empty scope list issues an unscoped key with the service account's full permissions.",
				StringSliceField: configv1.StringSliceField_builder{
					Rules: configv1.RepeatedStringRules_builder{
						// Explicit zero lets schema consumers distinguish allowed empty lists from unspecified bounds.
						MinItems:      proto.Uint64(0),
						ValidateEmpty: true,
					}.Build(),
				}.Build(),
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
	name, err := actionKeyName(args)
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
	// Empty lists deliberately request an unscoped key; omitted/null retain the
	// SDK's absence convention. Malformed values must never fall back to unscoped.
	if v, present := args.GetFields()[actionArgScopes]; present {
		if _, isNull := v.GetKind().(*structpb.Value_NullValue); !isNull {
			requested, ok := actions.GetStringSliceArg(args, actionArgScopes)
			if !ok {
				return nil, nil, nil, status.Errorf(codes.InvalidArgument, "baton-datadog: %s must be a list of strings", actionArgScopes)
			}
			scopes = requested
		}
	}
	name, err := actionKeyName(args)
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

const (
	issuedKeyNameDefaultPrefix = "c1"
	// maxNamePrefixLen bounds the admin-supplied prefix, in Unicode code points.
	maxNamePrefixLen = 64
	// namePrefixPattern is an advisory pattern that accepts a superset of what
	// validNamePrefix accepts. It uses only \xHH escapes, so Go (RE2/POSIX) and
	// ECMAScript consumers both compile it. It is a negated class that excludes
	// ASCII and Latin-1 non-letters; every code point from U+00C0 up, and the
	// letters U+00AA, U+00B5 and U+00BA, pass as a possible letter, mark or digit.
	// The first character also excludes digits, "_" and "-". The length bound is
	// in code points, which is why the schema sets no MaxLen (it counts bytes).
	// validNamePrefix, called by actionKeyName, enforces.
	namePrefixPattern = `^[^\x00-\x40\x5B-\x60\x7B-\xA9\xAB-\xB4\xB6-\xB9\xBB-\xBF][^\x00-\x2C\x2E\x2F\x3A-\x40\x5B-\x5E\x60\x7B-\xA9\xAB-\xB4\xB6-\xB9\xBB-\xBF]{0,63}$`
)

// namePrefixField is the name_prefix argument of both issuers.
func namePrefixField() *configv1.Field {
	return configv1.Field_builder{
		Name:        actionArgNamePrefix,
		DisplayName: "Key name prefix",
		Description: fmt.Sprintf("Optional. Start of the key name, which is <prefix>-<KSUID>. "+
			"1 to %d characters: a letter, then letters, combining marks, digits, _ or -, in any script; case is kept. "+
			"Blank or omitted uses %s.", maxNamePrefixLen, issuedKeyNameDefaultPrefix),
		StringField: configv1.StringField_builder{
			DefaultValue: issuedKeyNameDefaultPrefix,
			Rules: configv1.StringRules_builder{
				MinLen:  proto.Uint64(1),
				Pattern: proto.String(namePrefixPattern),
			}.Build(),
		}.Build(),
	}.Build()
}

// validNamePrefix reports whether s is 1 to maxNamePrefixLen code points: a
// letter, then letters, combining marks, digits, _ or -. There is no Unicode
// normalization, so the prefix is used as given.
func validNamePrefix(s string) bool {
	if n := utf8.RuneCountInString(s); n < 1 || n > maxNamePrefixLen {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if !unicode.IsLetter(r) && !unicode.IsMark(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// actionKeyName reads the optional name_prefix and returns the key name to
// mint. Absent, null or blank means the default.
func actionKeyName(args *structpb.Struct) (string, error) {
	prefix := issuedKeyNameDefaultPrefix
	if v, present := args.GetFields()[actionArgNamePrefix]; present {
		if _, isNull := v.GetKind().(*structpb.Value_NullValue); !isNull {
			sv, ok := v.GetKind().(*structpb.Value_StringValue)
			if !ok {
				return "", status.Errorf(codes.InvalidArgument, "baton-datadog: %s must be a string", actionArgNamePrefix)
			}
			if trimmed := strings.TrimSpace(sv.StringValue); trimmed != "" {
				prefix = trimmed
			}
		}
	}
	if !validNamePrefix(prefix) {
		return "", status.Errorf(codes.InvalidArgument,
			"baton-datadog: %s must be 1 to %d characters: a letter, then letters, combining marks, digits, _ or -", actionArgNamePrefix, maxNamePrefixLen)
	}
	return newIssuedKeyName(prefix)
}

// newIssuedKeyName names a key the issuer actions mint: <prefix>-<KSUID>, e.g.
// c1-0ujsswThIGTUYm2K8FjOOfXtY1K. Every call gets a fresh name, which avoids name
// collisions; the issuer has no duplicate guard of its own and relies on C1
// dispatching the action once.
func newIssuedKeyName(prefix string) (string, error) {
	id, err := newKSUID()
	if err != nil {
		return "", status.Errorf(codes.Internal, "baton-datadog: generate key name: %v", err)
	}
	return prefix + "-" + id.String(), nil
}

// newKSUID is ksuid.NewRandom, a variable so tests can inject a failure.
// ksuid.New would panic if the system random source failed.
var newKSUID = ksuid.NewRandom
