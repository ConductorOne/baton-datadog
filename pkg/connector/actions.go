package connector

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	config "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ActionEnableUser  = "enable_user"
	ActionDisableUser = "disable_user"
	ActionUpdateUser  = "update_user"
)

var (
	enableUserActionSchema = &v2.BatonActionSchema{
		Name:        ActionEnableUser,
		DisplayName: "Enable User",
		Description: "Re-enables a previously disabled Datadog user. Sets attributes.disabled to false.",
		Arguments: []*config.Field{
			{
				Name:        "user_id",
				DisplayName: "User ID",
				Description: "The Datadog user to enable.",
				Field: &config.Field_ResourceIdField{
					ResourceIdField: &config.ResourceIdField{
						Rules: &config.ResourceIDRules{
							AllowedResourceTypeIds: []string{userResourceType.Id},
						},
					},
				},
				IsRequired: true,
			},
		},
		ReturnTypes: []*config.Field{
			{Name: "success", DisplayName: "Success", Field: &config.Field_BoolField{}},
		},
		ActionType: []v2.ActionType{v2.ActionType_ACTION_TYPE_ACCOUNT_ENABLE},
	}

	disableUserActionSchema = &v2.BatonActionSchema{
		Name:        ActionDisableUser,
		DisplayName: "Disable User",
		Description: "Disables a Datadog user. Datadog has no hard delete; this soft-disables the account (attributes.disabled = true) and can be reversed with enable_user.",
		Arguments: []*config.Field{
			{
				Name:        "user_id",
				DisplayName: "User ID",
				Description: "The Datadog user to disable.",
				Field: &config.Field_ResourceIdField{
					ResourceIdField: &config.ResourceIdField{
						Rules: &config.ResourceIDRules{
							AllowedResourceTypeIds: []string{userResourceType.Id},
						},
					},
				},
				IsRequired: true,
			},
		},
		ReturnTypes: []*config.Field{
			{Name: "success", DisplayName: "Success", Field: &config.Field_BoolField{}},
		},
		ActionType: []v2.ActionType{v2.ActionType_ACTION_TYPE_ACCOUNT_DISABLE},
	}

	updateUserActionSchema = &v2.BatonActionSchema{
		Name:        ActionUpdateUser,
		DisplayName: "Update User",
		Description: "Updates a Datadog user's profile. At least one of name or email must be provided.",
		Arguments: []*config.Field{
			{
				Name:        "user_id",
				DisplayName: "User ID",
				Description: "The Datadog user to update.",
				Field: &config.Field_ResourceIdField{
					ResourceIdField: &config.ResourceIdField{
						Rules: &config.ResourceIDRules{
							AllowedResourceTypeIds: []string{userResourceType.Id},
						},
					},
				},
				IsRequired: true,
			},
			{
				Name:        "name",
				DisplayName: "Name",
				Description: "New display name for the user.",
				Field:       &config.Field_StringField{},
			},
			{
				Name:        "email",
				DisplayName: "Email",
				Description: "New email address for the user.",
				Field:       &config.Field_StringField{},
			},
		},
		ReturnTypes: []*config.Field{
			{Name: "success", DisplayName: "Success", Field: &config.Field_BoolField{}},
		},
		ActionType: []v2.ActionType{v2.ActionType_ACTION_TYPE_ACCOUNT_UPDATE_PROFILE},
	}
)

func userIDFromArgs(args *structpb.Struct) (string, error) {
	rid, ok := actions.GetResourceIDArg(args, "user_id")
	if !ok {
		return "", status.Error(codes.InvalidArgument, "baton-datadog: missing required argument user_id")
	}
	if rid.GetResource() == "" {
		return "", status.Error(codes.InvalidArgument, "baton-datadog: user_id cannot be empty")
	}
	return rid.GetResource(), nil
}

func (u *userBuilder) enableUser(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	userID, err := userIDFromArgs(args)
	if err != nil {
		return nil, nil, err
	}

	attrs := datadogV2.NewUserUpdateAttributes()
	attrs.SetDisabled(false)
	data := datadogV2.NewUserUpdateData(*attrs, userID, datadogV2.USERSTYPE_USERS)
	req := datadogV2.NewUserUpdateRequest(*data)

	if _, err := u.wrapper.UpdateUser(ctx, userID, *req); err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: failed to enable user %s: %w", userID, err)
	}
	return actions.NewReturnValues(true), nil, nil
}

func (u *userBuilder) disableUser(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	userID, err := userIDFromArgs(args)
	if err != nil {
		return nil, nil, err
	}

	user, err := u.wrapper.GetUser(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: failed to look up user %s: %w", userID, err)
	}
	if user.GetData().Attributes.GetDisabled() {
		return actions.NewReturnValues(true), nil, nil
	}

	if err := u.wrapper.DisableUser(ctx, userID); err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: failed to disable user %s: %w", userID, err)
	}
	return actions.NewReturnValues(true), nil, nil
}

func (u *userBuilder) updateUser(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	userID, err := userIDFromArgs(args)
	if err != nil {
		return nil, nil, err
	}

	name, _ := actions.GetStringArg(args, "name")
	email, _ := actions.GetStringArg(args, "email")
	if name == "" && email == "" {
		return nil, nil, status.Error(codes.InvalidArgument, "baton-datadog: update_user requires at least one of name or email")
	}

	attrs := datadogV2.NewUserUpdateAttributes()
	if name != "" {
		attrs.SetName(name)
	}
	if email != "" {
		attrs.SetEmail(email)
	}
	data := datadogV2.NewUserUpdateData(*attrs, userID, datadogV2.USERSTYPE_USERS)
	req := datadogV2.NewUserUpdateRequest(*data)

	if _, err := u.wrapper.UpdateUser(ctx, userID, *req); err != nil {
		return nil, nil, fmt.Errorf("baton-datadog: failed to update user %s: %w", userID, err)
	}
	return actions.NewReturnValues(true), nil, nil
}
