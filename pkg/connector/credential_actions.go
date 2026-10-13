package connector

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	config "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ActionIssueServiceAccountApplicationKey = "issue_service_account_application_key"
	ActionIssueOrganizationAPIKey           = "issue_organization_api_key"
	ActionIssueServiceAccountAccessToken    = "issue_service_account_access_token"
)

var issuanceRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// The action schema is public metadata. Every secret value is delivered only as
// encrypted data by RegisterWithSecrets; issued_resource carries the stable
// provider handle used by the existing inventory and delete paths.
func issuanceActionSchema(name, displayName, secretName string, scopes *config.Field) *v2.BatonActionSchema {
	requestIDRules := &config.StringRules{}
	requestIDRules.SetPattern(`^[A-Za-z0-9_-]{1,128}$`)
	arguments := []*config.Field{
		{Name: "user_id", DisplayName: "User", Description: "Approved Datadog user identity", Field: &config.Field_ResourceIdField{ResourceIdField: &config.ResourceIdField{Rules: &config.ResourceIDRules{AllowedResourceTypeIds: []string{userResourceType.Id}}}}, IsRequired: true},
		{Name: "request_id", DisplayName: "Request ID", Description: "Stable credential ticket identifier", Field: &config.Field_StringField{StringField: &config.StringField{Rules: requestIDRules}}, IsRequired: true},
	}
	if scopes != nil {
		arguments = append(arguments, scopes)
	}
	return &v2.BatonActionSchema{
		Name: name, DisplayName: displayName,
		Description: "Issue a Datadog credential for the approved identity.",
		ActionType:  []v2.ActionType{v2.ActionType_ACTION_TYPE_DYNAMIC},
		Arguments:   arguments,
		ReturnTypes: []*config.Field{
			{Name: "success", DisplayName: "Success", Field: &config.Field_BoolField{BoolField: &config.BoolField{}}},
			{Name: "issued_resource", DisplayName: "Issued Resource", Field: &config.Field_ResourceField{ResourceField: &config.ResourceField{}}, IsRequired: true},
			{Name: secretName, DisplayName: "Credential", Field: &config.Field_StringField{StringField: &config.StringField{}}, IsRequired: true, IsSecret: true},
		},
	}
}

func issuanceScopeField(required bool) *config.Field {
	rules := &config.RepeatedStringRules{Unique: true, ValidateEmpty: true}
	itemRules := &config.StringRules{}
	itemRules.SetMinLen(1)
	rules.SetItemRules(itemRules)
	if required {
		rules.SetMinItems(1)
		rules.SetIsRequired(true)
	}
	return &config.Field{Name: "scopes", DisplayName: "Scopes", Description: "Datadog permission scopes", Field: &config.Field_StringSliceField{StringSliceField: &config.StringSliceField{Rules: rules}}, IsRequired: required}
}

func validateIssuanceScopes(scopes []string, required bool) error {
	if err := field.ValidateRepeatedStringRules(issuanceScopeField(required).GetStringSliceField().GetRules(), scopes, "scopes"); err != nil {
		return err
	}
	for _, scope := range scopes {
		if strings.TrimSpace(scope) == "" {
			return fmt.Errorf("scopes must contain nonblank values")
		}
	}
	return nil
}

func (u *credentialUserBuilder) ResourceActions(ctx context.Context, registry actions.ActionRegistry) error {
	if err := u.userBuilder.ResourceActions(ctx, registry); err != nil {
		return err
	}
	if u.offerServiceAccountAppKey {
		if err := actions.RegisterWithSecrets(ctx, registry, issuanceActionSchema(ActionIssueServiceAccountApplicationKey, "Issue Service Account Application Key", "application_key", issuanceScopeField(false)), u.issueAction(serviceAccountApplicationKeyResourceType.Id)); err != nil {
			return err
		}
		if err := actions.RegisterWithSecrets(ctx, registry, issuanceActionSchema(ActionIssueServiceAccountAccessToken, "Issue Service Account Access Token", "service_access_token", issuanceScopeField(true)), u.issueAction(serviceAccountAccessTokenResourceType.Id)); err != nil {
			return err
		}
	}
	if u.offerOrgAPIKey {
		if err := actions.RegisterWithSecrets(ctx, registry, issuanceActionSchema(ActionIssueOrganizationAPIKey, "Issue Organization API Key", "api_key", nil), u.issueAction(apiTokenResourceType.Id)); err != nil {
			return err
		}
	}
	return nil
}

func (u *credentialUserBuilder) issueAction(kind string) actions.ActionHandlerWithSecrets {
	return func(ctx context.Context, args *structpb.Struct) (*structpb.Struct, []*v2.PlaintextData, annotations.Annotations, error) {
		for key := range args.GetFields() {
			if key != "user_id" && key != "request_id" && key != "scopes" {
				return nil, nil, nil, status.Errorf(codes.InvalidArgument, "baton-datadog: unsupported issuance argument %q", key)
			}
		}
		identity, ok := actions.GetResourceIDArg(args, "user_id")
		if !ok || identity.GetResourceType() != userResourceType.Id || identity.GetResource() == "" {
			return nil, nil, nil, status.Error(codes.InvalidArgument, "baton-datadog: user_id must be a Datadog user resource id")
		}
		requestID, ok := actions.GetStringArg(args, "request_id")
		if !ok || !issuanceRequestIDPattern.MatchString(requestID) {
			return nil, nil, nil, status.Error(codes.InvalidArgument, "baton-datadog: request_id must be 1-128 letters, digits, underscores, or hyphens")
		}
		var scopes []string
		if args != nil && args.GetFields()["scopes"] != nil {
			if kind == apiTokenResourceType.Id {
				return nil, nil, nil, status.Error(codes.InvalidArgument, "baton-datadog: organization API keys do not accept scopes")
			}
			scopes, ok = actions.GetStringSliceArg(args, "scopes")
			if !ok {
				return nil, nil, nil, status.Error(codes.InvalidArgument, "baton-datadog: scopes must be strings")
			}
		}
		if kind == serviceAccountAccessTokenResourceType.Id || kind == serviceAccountApplicationKeyResourceType.Id {
			if err := validateIssuanceScopes(scopes, kind == serviceAccountAccessTokenResourceType.Id); err != nil {
				return nil, nil, nil, status.Errorf(codes.InvalidArgument, "baton-datadog: invalid scopes: %v", err)
			}
		}
		options := v2.CredentialIssueOptions_builder{SecretResourceTypeId: kind}
		if kind == serviceAccountAccessTokenResourceType.Id {
			options.Token = v2.CredentialIssueOptions_Token_builder{Scopes: scopes}.Build()
		} else {
			options.ApiKey = v2.CredentialIssueOptions_ApiKey_builder{Scopes: scopes}.Build()
		}
		issued, err := u.issueWithFormat(ctx, &connectorbuilder.CredentialIssueInput{IdentityID: identity, RequestID: requestID, CredentialOptions: options.Build()}, true)
		if err != nil {
			return nil, nil, nil, err
		}
		resource, err := actions.NewResourceReturnField("issued_resource", issued.Secret)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("baton-datadog: encode issued resource: %w", err)
		}
		for _, plaintext := range issued.PlaintextData {
			plaintext.SetSchema("api_key_v2")
		}
		return actions.NewReturnValues(true, resource), issued.PlaintextData, issued.Annotations, nil
	}
}
