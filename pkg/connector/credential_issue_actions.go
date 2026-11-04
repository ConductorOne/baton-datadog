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

// The credential-issue actions register Datadog's two issuers with the SDK's
// CREDENTIAL_ISSUE action type, so C1 discovers and dispatches issuance the same
// way it would for any action. The schemas come from the descriptors the
// connector already advertises for IssueCredential, so the advertised shape, the
// declared output type and the arguments cannot drift from what Issue produces.
//
// The arguments and return fields the SDK fixes are used by name through its
// constants: identity_id, request_id, secret_resource_id. Only the provider
// inputs Datadog genuinely has are added.

const (
	ActionIssueOrganizationAPIKeyAction           = "issue_organization_api_key"
	ActionIssueServiceAccountApplicationKeyAction = "issue_service_account_application_key"

	// actionArgScopes is the application key's one provider input. Datadog
	// application keys accept a free-form scope list when the descriptor allows
	// custom scopes, which this one does.
	actionArgScopes = "scopes"

	datadogIssueOrgKeyActionDisplayName = "Issue Datadog organization API key"
	datadogIssueAppKeyActionDisplayName = "Issue Datadog service account application key"
)

// registerCredentialIssueActions registers the two issuers as CREDENTIAL_ISSUE
// actions. Each is gated on the same operator grant that gates its
// IssueCredential kind: advertising an issuer whose revoke path the connector
// does not have would mint credentials it cannot clean up.
func (d *Datadog) registerCredentialIssueActions(ctx context.Context, registry actions.ActionRegistry) error {
	if d.AllowOrgAPIKeyDeletion {
		u := newCredentialUserBuilder(d.wrapper, true, false, d.apiBaseURL())
		schema, err := actions.CredentialIssueSchema(
			ActionIssueOrganizationAPIKeyAction,
			organizationAPIKeyDescriptor(),
		)
		if err != nil {
			return fmt.Errorf("baton-datadog: build %s schema: %w", ActionIssueOrganizationAPIKeyAction, err)
		}
		schema.SetDisplayName(datadogIssueOrgKeyActionDisplayName)
		if err := actions.RegisterWithSecrets(ctx, registry, schema, u.issueOrganizationAPIKeyAction); err != nil {
			return fmt.Errorf("baton-datadog: failed to register %s action: %w", ActionIssueOrganizationAPIKeyAction, err)
		}
	}

	if d.SyncSecrets && d.SyncServiceAccountApplicationKeys {
		u := newCredentialUserBuilder(d.wrapper, false, true, d.apiBaseURL())
		schema, err := actions.CredentialIssueSchema(
			ActionIssueServiceAccountApplicationKeyAction,
			serviceAccountApplicationKeyDescriptor(),
			// Free-form on purpose: the descriptor sets CustomScopesAllowed, so
			// C1 narrows what a requester may ask for, not the connector.
			configv1.Field_builder{
				Name:             actionArgScopes,
				Description:      "Application key scopes. Omit for an unscoped key.",
				StringSliceField: configv1.StringSliceField_builder{}.Build(),
			}.Build(),
		)
		if err != nil {
			return fmt.Errorf("baton-datadog: build %s schema: %w", ActionIssueServiceAccountApplicationKeyAction, err)
		}
		schema.SetDisplayName(datadogIssueAppKeyActionDisplayName)
		if err := actions.RegisterWithSecrets(ctx, registry, schema, u.issueServiceAccountApplicationKeyAction); err != nil {
			return fmt.Errorf("baton-datadog: failed to register %s action: %w", ActionIssueServiceAccountApplicationKeyAction, err)
		}
	}
	return nil
}

// issueOrganizationAPIKeyAction mints an organization API key and returns the
// SDK's standard fields. There is no expiry: a Datadog organization API key does
// not carry one, and the descriptor advertises no expiry capability, so the SDK
// does not declare the argument.
func (u *credentialUserBuilder) issueOrganizationAPIKeyAction(
	ctx context.Context,
	args *structpb.Struct,
) (*structpb.Struct, []*v2.PlaintextData, annotations.Annotations, error) {
	identityID, requestID, err := credentialIssueActionArgs(args)
	if err != nil {
		return nil, nil, nil, err
	}

	key, plaintext, err := u.mintOrganizationAPIKey(ctx, requestID)
	if err != nil {
		return nil, nil, nil, err
	}

	// The identity is recorded on the secret by CredentialIssueResource, from
	// the request; the key itself belongs to the organization, which is why the
	// mint does not parent it to the identity.
	_ = identityID
	return credentialIssueActionResponse(key.ID), []*v2.PlaintextData{plaintext}, nil, nil
}

// issueServiceAccountApplicationKeyAction mints an application key for the
// identity the request names. That identity is the service account, exactly as
// IssueCredential treats it, so no separate argument is invented for it.
func (u *credentialUserBuilder) issueServiceAccountApplicationKeyAction(
	ctx context.Context,
	args *structpb.Struct,
) (*structpb.Struct, []*v2.PlaintextData, annotations.Annotations, error) {
	identityID, requestID, err := credentialIssueActionArgs(args)
	if err != nil {
		return nil, nil, nil, err
	}

	var scopes []string
	if requested, ok := actions.GetStringSliceArg(args, actionArgScopes); ok {
		scopes = requested
	}

	serviceAccountID := identityID.GetResource()
	key, plaintext, err := u.mintServiceAccountApplicationKey(ctx, serviceAccountID, requestID, scopes)
	if err != nil {
		return nil, nil, nil, err
	}
	return credentialIssueActionResponse(key.ID), []*v2.PlaintextData{plaintext}, nil, nil
}

// credentialIssueActionArgs reads the two arguments the SDK fixes for every
// credential-issue action.
func credentialIssueActionArgs(args *structpb.Struct) (*v2.ResourceId, string, error) {
	identityID, err := actions.RequireResourceIDArg(args, actions.ArgIdentityID)
	if err != nil {
		return nil, "", status.Errorf(codes.InvalidArgument, "baton-datadog: %v", err)
	}
	if identityID.GetResource() == "" {
		return nil, "", status.Errorf(codes.InvalidArgument, "baton-datadog: %s has no resource id", actions.ArgIdentityID)
	}
	requestID, ok := actions.GetStringArg(args, actions.ArgRequestID)
	if !ok || requestID == "" {
		return nil, "", status.Errorf(codes.InvalidArgument, "baton-datadog: missing required argument %s", actions.ArgRequestID)
	}
	return identityID, requestID, nil
}

// credentialIssueActionResponse builds the public half of a credential-issue
// action result. secret_resource_id is the revoke handle and the only field the
// SDK requires; expires_at is left out because neither Datadog key kind has a
// provider expiry.
func credentialIssueActionResponse(secretResourceID string) *structpb.Struct {
	// The only value is a plain string, so marshalling cannot fail; the empty
	// struct is the fallback rather than returning nil into the action manager.
	response, err := structpb.NewStruct(map[string]any{
		actions.ReturnSecretResourceID: secretResourceID,
	})
	if err != nil {
		return &structpb.Struct{}
	}
	return response
}
