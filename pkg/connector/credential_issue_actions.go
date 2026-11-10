package connector

import (
	"context"
	"fmt"

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

	// actionArgTicketID is tagged ticketIDTag, so C1 fills it with the ticket the
	// key is issued for. It names the key (see issuedCredentialName), which is
	// how a retried request finds the key its predecessor created.
	actionArgTicketID = "ticket_id"
	// actionArgServiceAccountID is the identity an application key is issued
	// for: a Datadog service account, which is a user resource.
	actionArgServiceAccountID = "service_account_id"
	// actionArgScopes is the application key's one provider input. Datadog
	// application keys accept a free-form scope list.
	actionArgScopes = "scopes"

	// actionReturnResource is the created secret resource, carrying its
	// SecretTrait.
	actionReturnResource = "resource"

	// ticketIDTag marks the argument C1 fills with the ticket ID.
	ticketIDTag = "c1.ticket_id"

	datadogIssueOrgKeyActionDisplayName = "Issue Datadog organization API key"
	datadogIssueAppKeyActionDisplayName = "Issue Datadog service account application key"
)

func ticketIDArgument() *configv1.Field {
	return configv1.Field_builder{
		Name:        actionArgTicketID,
		DisplayName: "Ticket ID",
		Description: "The ticket the key is issued for. Names the key in Datadog.",
		IsRequired:  true,
		Tags:        []string{ticketIDTag},
		StringField: configv1.StringField_builder{}.Build(),
	}.Build()
}

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
// organization key belongs to the organization, so it names no subject.
func organizationAPIKeyActionSchema() *v2.BatonActionSchema {
	secret := organizationAPIKeyOutput()
	secret.SetIsRequired(true)
	return v2.BatonActionSchema_builder{
		Name:        ActionIssueOrganizationAPIKey,
		DisplayName: datadogIssueOrgKeyActionDisplayName,
		Description: "Creates a Datadog organization API key and returns it as a Multipass api_key_v2 secret.",
		Arguments:   []*configv1.Field{ticketIDArgument()},
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
			ticketIDArgument(),
			configv1.Field_builder{
				Name:             actionArgScopes,
				DisplayName:      "Scopes",
				Description:      "Application key scopes. Omit for an unscoped key.",
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
	ticketID, err := ticketIDArg(args)
	if err != nil {
		return nil, nil, nil, err
	}
	key, plaintext, err := u.mintOrganizationAPIKey(ctx, ticketID)
	if err != nil {
		return nil, nil, nil, err
	}
	secret, err := u.organizationAPIKeyResource(ctx, issuedCredentialName(ticketID), key, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return issueActionResult(ctx, u.discardOrganizationAPIKeyFunc(key.ID), secret, plaintext)
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
	ticketID, err := ticketIDArg(args)
	if err != nil {
		return nil, nil, nil, err
	}
	var scopes []string
	if requested, ok := actions.GetStringSliceArg(args, actionArgScopes); ok {
		scopes = requested
	}

	key, plaintext, err := u.mintServiceAccountApplicationKey(ctx, serviceAccount.GetResource(), ticketID, scopes)
	if err != nil {
		return nil, nil, nil, err
	}
	secret, err := u.applicationKeyResource(ctx, issuedCredentialName(ticketID), key, serviceAccount)
	if err != nil {
		return nil, nil, nil, err
	}
	return issueActionResult(ctx, u.discardApplicationKeyFunc(key.ServiceAccountID, key.ID), secret, plaintext)
}

func (u *credentialUserBuilder) discardOrganizationAPIKeyFunc(keyID string) func(context.Context) {
	return func(ctx context.Context) { u.discardOrganizationAPIKey(ctx, keyID) }
}

func (u *credentialUserBuilder) discardApplicationKeyFunc(serviceAccountID, keyID string) func(context.Context) {
	return func(ctx context.Context) { u.discardServiceAccountApplicationKey(ctx, serviceAccountID, keyID) }
}

func ticketIDArg(args *structpb.Struct) (string, error) {
	ticketID, ok := actions.GetStringArg(args, actionArgTicketID)
	if !ok || ticketID == "" {
		return "", status.Errorf(codes.InvalidArgument, "baton-datadog: missing required argument %s", actionArgTicketID)
	}
	return ticketID, nil
}

// issueActionResult builds the handler result: the created secret as a resource
// return, and the plaintext. The ciphertext's schema is checked against the
// secret return field's content type, which the SDK does not copy from the
// schema, so the plaintext must already carry it.
func issueActionResult(
	ctx context.Context,
	discard func(context.Context),
	secret *v2.Resource,
	plaintext *v2.PlaintextData,
) (*structpb.Struct, []*v2.PlaintextData, annotations.Annotations, error) {
	field, err := actions.NewResourceReturnField(actionReturnResource, secret)
	if err != nil {
		// The key exists but its result cannot be returned: nobody would hold it.
		discard(ctx)
		return nil, nil, nil, fmt.Errorf("baton-datadog: build issuer resource return: %w", err)
	}
	return actions.NewReturnValues(true, field), []*v2.PlaintextData{plaintext}, nil, nil
}
