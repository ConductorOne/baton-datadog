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

// This file is a prototype: it vends Datadog keys through baton custom actions
// instead of through IssueCredential, so the two paths can be compared. It
// shares the minting and plaintext helpers with Issue, so the credential a
// caller receives is the same either way; what differs is the delivery
// mechanism.
//
// The handler returns the key once, as PlaintextData, which the action manager
// encrypts. The public response carries only what a caller needs to identify
// the key for revocation later, never the key itself.

const (
	ActionIssueOrganizationAPIKey           = "issue_organization_api_key"
	ActionIssueServiceAccountApplicationKey = "issue_service_account_application_key"
	actionArgRequestID                      = "request_id"
	actionArgServiceAccountID               = "service_account_id"
	actionArgScopes                         = "scopes"
	actionPublicKeyID                       = "key_id"
	actionPublicSecretResourceTypeID        = "secret_resource_type_id"
	actionPublicSecretResourceID            = "secret_resource_id"
	actionPublicParentResourceTypeID        = "parent_resource_type_id"
	actionPublicParentResourceID            = "parent_resource_id"
	datadogVendOrgKeyDisplayName            = "Issue Datadog organization API key"
	datadogVendAppKeyDisplayName            = "Issue Datadog service account application key"
)

var issueOrganizationAPIKeyActionSchema = &v2.BatonActionSchema{
	Name:        ActionIssueOrganizationAPIKey,
	DisplayName: datadogVendOrgKeyDisplayName,
	Description: "Vend a Datadog organization API key. Returns the key once, plus what is needed to revoke it.",
	Arguments: []*configv1.Field{
		{
			Name:        actionArgRequestID,
			DisplayName: "Request ID",
			Description: "Idempotency key. The key is named c1-<request_id>, and an existing key for the same request is refused.",
			IsRequired:  true,
			Field:       &configv1.Field_StringField{},
		},
	},
	ReturnTypes: []*configv1.Field{
		organizationAPIKeyOutput(),
		{Name: actionPublicKeyID, DisplayName: "Datadog key ID", Field: &configv1.Field_StringField{}},
		{Name: actionPublicSecretResourceTypeID, DisplayName: "Secret resource type", Field: &configv1.Field_StringField{}},
		{Name: actionPublicSecretResourceID, DisplayName: "Secret resource ID", Field: &configv1.Field_StringField{}},
	},
}

var issueServiceAccountApplicationKeyActionSchema = &v2.BatonActionSchema{
	Name:        ActionIssueServiceAccountApplicationKey,
	DisplayName: datadogVendAppKeyDisplayName,
	Description: "Vend a Datadog service account application key, optionally scoped. Returns the key once, plus what is needed to revoke it.",
	Arguments: []*configv1.Field{
		{
			Name:        actionArgRequestID,
			DisplayName: "Request ID",
			Description: "Idempotency key. The key is named c1-<request_id>, and an existing key for the same request is refused.",
			IsRequired:  true,
			Field:       &configv1.Field_StringField{},
		},
		{
			Name:        actionArgServiceAccountID,
			DisplayName: "Service account ID",
			Description: "Datadog user ID of the service account the key belongs to.",
			IsRequired:  true,
			Field:       &configv1.Field_StringField{},
		},
		{
			Name:        actionArgScopes,
			DisplayName: "Scopes",
			Description: "Optional application key scopes. Omitted means the key carries no scope list.",
			Field:       &configv1.Field_StringSliceField{},
		},
	},
	ReturnTypes: []*configv1.Field{
		serviceAccountApplicationKeyOutput(),
		{Name: actionPublicKeyID, DisplayName: "Datadog key ID", Field: &configv1.Field_StringField{}},
		{Name: actionPublicSecretResourceTypeID, DisplayName: "Secret resource type", Field: &configv1.Field_StringField{}},
		{Name: actionPublicSecretResourceID, DisplayName: "Secret resource ID", Field: &configv1.Field_StringField{}},
		// The key belongs to its service account, and Delete needs both halves.
		{Name: actionPublicParentResourceTypeID, DisplayName: "Parent resource type", Field: &configv1.Field_StringField{}},
		{Name: actionPublicParentResourceID, DisplayName: "Parent resource ID", Field: &configv1.Field_StringField{}},
	},
}

// registerVendingActions registers the prototype actions. Each is gated on the
// same operator grant that gates the corresponding Issue kind: advertising an
// action that can mint a credential the connector cannot revoke would be worse
// than the Issue path, which the SDK already refuses in that case.
func (d *Datadog) registerVendingActions(ctx context.Context, registry actions.ActionRegistry) error {
	if d.AllowOrgAPIKeyDeletion {
		if err := actions.RegisterWithSecrets(ctx, registry, issueOrganizationAPIKeyActionSchema,
			newCredentialUserBuilder(d.wrapper, true, false, d.apiBaseURL()).issueOrganizationAPIKeyAction); err != nil {
			return fmt.Errorf("baton-datadog: failed to register %s action: %w", ActionIssueOrganizationAPIKey, err)
		}
	}
	if d.SyncSecrets && d.SyncServiceAccountApplicationKeys {
		if err := actions.RegisterWithSecrets(ctx, registry, issueServiceAccountApplicationKeyActionSchema,
			newCredentialUserBuilder(d.wrapper, false, true, d.apiBaseURL()).issueServiceAccountApplicationKeyAction); err != nil {
			return fmt.Errorf("baton-datadog: failed to register %s action: %w", ActionIssueServiceAccountApplicationKey, err)
		}
	}
	return nil
}

func (u *credentialUserBuilder) issueOrganizationAPIKeyAction(
	ctx context.Context,
	args *structpb.Struct,
) (*structpb.Struct, []*v2.PlaintextData, annotations.Annotations, error) {
	requestID, err := requestIDFromArgs(args)
	if err != nil {
		return nil, nil, nil, err
	}

	key, plaintext, err := u.mintOrganizationAPIKey(ctx, requestID)
	if err != nil {
		return nil, nil, nil, err
	}

	return actionSecretResponse(key.ID, deletableAPITokenResourceType.Id, key.ID, "", ""),
		[]*v2.PlaintextData{plaintext}, nil, nil
}

func (u *credentialUserBuilder) issueServiceAccountApplicationKeyAction(
	ctx context.Context,
	args *structpb.Struct,
) (*structpb.Struct, []*v2.PlaintextData, annotations.Annotations, error) {
	requestID, err := requestIDFromArgs(args)
	if err != nil {
		return nil, nil, nil, err
	}
	serviceAccountID, ok := actions.GetStringArg(args, actionArgServiceAccountID)
	if !ok || serviceAccountID == "" {
		return nil, nil, nil, status.Errorf(codes.InvalidArgument,
			"baton-datadog: missing required argument %s", actionArgServiceAccountID)
	}
	var scopes []string
	if requested, ok := actions.GetStringSliceArg(args, actionArgScopes); ok {
		scopes = requested
	}

	key, plaintext, err := u.mintServiceAccountApplicationKey(ctx, serviceAccountID, requestID, scopes)
	if err != nil {
		return nil, nil, nil, err
	}

	// applicationKeyBuilder.Delete takes the bare key id as resourceID and the
	// service account as parentResourceID, so the response has to name both the
	// same way; a composite id would be looked up as a key that does not exist.
	return actionSecretResponse(key.ID, serviceAccountApplicationKeyResourceType.Id, key.ID,
			userResourceType.Id, serviceAccountID),
		[]*v2.PlaintextData{plaintext}, nil, nil
}

// requestIDFromArgs reads the idempotency key every vending action requires.
func requestIDFromArgs(args *structpb.Struct) (string, error) {
	requestID, ok := actions.GetStringArg(args, actionArgRequestID)
	if !ok || requestID == "" {
		return "", status.Errorf(codes.InvalidArgument, "baton-datadog: missing required argument %s", actionArgRequestID)
	}
	return requestID, nil
}

// actionSecretResponse builds the public half of a vending action's result:
// enough to identify the credential for revocation, and nothing that reveals it.
// The parent fields are omitted when empty, since an organization API key has no
// parent resource.
func actionSecretResponse(keyID, secretResourceTypeID, secretResourceID, parentTypeID, parentResourceID string) *structpb.Struct {
	fields := map[string]any{
		actionPublicKeyID:                keyID,
		actionPublicSecretResourceTypeID: secretResourceTypeID,
		actionPublicSecretResourceID:     secretResourceID,
	}
	if parentTypeID != "" {
		fields[actionPublicParentResourceTypeID] = parentTypeID
	}
	if parentResourceID != "" {
		fields[actionPublicParentResourceID] = parentResourceID
	}
	response, err := structpb.NewStruct(fields)
	if err != nil {
		// The values are plain strings, so this cannot fail; returning an empty
		// struct rather than nil keeps the handler's contract regardless.
		return &structpb.Struct{}
	}
	return response
}
