// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: c1/connector/v2/annotation_trait.proto

package v2

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type UserTrait_AccountType int32

const (
	UserTrait_ACCOUNT_TYPE_UNSPECIFIED UserTrait_AccountType = 0
	UserTrait_ACCOUNT_TYPE_HUMAN       UserTrait_AccountType = 1
	UserTrait_ACCOUNT_TYPE_SERVICE     UserTrait_AccountType = 2
	UserTrait_ACCOUNT_TYPE_SYSTEM      UserTrait_AccountType = 3
)

// Enum value maps for UserTrait_AccountType.
var (
	UserTrait_AccountType_name = map[int32]string{
		0: "ACCOUNT_TYPE_UNSPECIFIED",
		1: "ACCOUNT_TYPE_HUMAN",
		2: "ACCOUNT_TYPE_SERVICE",
		3: "ACCOUNT_TYPE_SYSTEM",
	}
	UserTrait_AccountType_value = map[string]int32{
		"ACCOUNT_TYPE_UNSPECIFIED": 0,
		"ACCOUNT_TYPE_HUMAN":       1,
		"ACCOUNT_TYPE_SERVICE":     2,
		"ACCOUNT_TYPE_SYSTEM":      3,
	}
)

func (x UserTrait_AccountType) Enum() *UserTrait_AccountType {
	p := new(UserTrait_AccountType)
	*p = x
	return p
}

func (x UserTrait_AccountType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (UserTrait_AccountType) Descriptor() protoreflect.EnumDescriptor {
	return file_c1_connector_v2_annotation_trait_proto_enumTypes[0].Descriptor()
}

func (UserTrait_AccountType) Type() protoreflect.EnumType {
	return &file_c1_connector_v2_annotation_trait_proto_enumTypes[0]
}

func (x UserTrait_AccountType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use UserTrait_AccountType.Descriptor instead.
func (UserTrait_AccountType) EnumDescriptor() ([]byte, []int) {
	return file_c1_connector_v2_annotation_trait_proto_rawDescGZIP(), []int{0, 0}
}

type UserTrait_Status_Status int32

const (
	UserTrait_Status_STATUS_UNSPECIFIED UserTrait_Status_Status = 0
	UserTrait_Status_STATUS_ENABLED     UserTrait_Status_Status = 1
	UserTrait_Status_STATUS_DISABLED    UserTrait_Status_Status = 2
	UserTrait_Status_STATUS_DELETED     UserTrait_Status_Status = 3
)

// Enum value maps for UserTrait_Status_Status.
var (
	UserTrait_Status_Status_name = map[int32]string{
		0: "STATUS_UNSPECIFIED",
		1: "STATUS_ENABLED",
		2: "STATUS_DISABLED",
		3: "STATUS_DELETED",
	}
	UserTrait_Status_Status_value = map[string]int32{
		"STATUS_UNSPECIFIED": 0,
		"STATUS_ENABLED":     1,
		"STATUS_DISABLED":    2,
		"STATUS_DELETED":     3,
	}
)

func (x UserTrait_Status_Status) Enum() *UserTrait_Status_Status {
	p := new(UserTrait_Status_Status)
	*p = x
	return p
}

func (x UserTrait_Status_Status) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (UserTrait_Status_Status) Descriptor() protoreflect.EnumDescriptor {
	return file_c1_connector_v2_annotation_trait_proto_enumTypes[1].Descriptor()
}

func (UserTrait_Status_Status) Type() protoreflect.EnumType {
	return &file_c1_connector_v2_annotation_trait_proto_enumTypes[1]
}

func (x UserTrait_Status_Status) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use UserTrait_Status_Status.Descriptor instead.
func (UserTrait_Status_Status) EnumDescriptor() ([]byte, []int) {
	return file_c1_connector_v2_annotation_trait_proto_rawDescGZIP(), []int{0, 1, 0}
}

type AppTrait_AppFlag int32

const (
	AppTrait_APP_FLAG_UNSPECIFIED AppTrait_AppFlag = 0
	AppTrait_APP_FLAG_HIDDEN      AppTrait_AppFlag = 1
	AppTrait_APP_FLAG_INACTIVE    AppTrait_AppFlag = 2
	AppTrait_APP_FLAG_SAML        AppTrait_AppFlag = 3
	AppTrait_APP_FLAG_OIDC        AppTrait_AppFlag = 4
	AppTrait_APP_FLAG_BOOKMARK    AppTrait_AppFlag = 5
)

// Enum value maps for AppTrait_AppFlag.
var (
	AppTrait_AppFlag_name = map[int32]string{
		0: "APP_FLAG_UNSPECIFIED",
		1: "APP_FLAG_HIDDEN",
		2: "APP_FLAG_INACTIVE",
		3: "APP_FLAG_SAML",
		4: "APP_FLAG_OIDC",
		5: "APP_FLAG_BOOKMARK",
	}
	AppTrait_AppFlag_value = map[string]int32{
		"APP_FLAG_UNSPECIFIED": 0,
		"APP_FLAG_HIDDEN":      1,
		"APP_FLAG_INACTIVE":    2,
		"APP_FLAG_SAML":        3,
		"APP_FLAG_OIDC":        4,
		"APP_FLAG_BOOKMARK":    5,
	}
)

func (x AppTrait_AppFlag) Enum() *AppTrait_AppFlag {
	p := new(AppTrait_AppFlag)
	*p = x
	return p
}

func (x AppTrait_AppFlag) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AppTrait_AppFlag) Descriptor() protoreflect.EnumDescriptor {
	return file_c1_connector_v2_annotation_trait_proto_enumTypes[2].Descriptor()
}

func (AppTrait_AppFlag) Type() protoreflect.EnumType {
	return &file_c1_connector_v2_annotation_trait_proto_enumTypes[2]
}

func (x AppTrait_AppFlag) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AppTrait_AppFlag.Descriptor instead.
func (AppTrait_AppFlag) EnumDescriptor() ([]byte, []int) {
	return file_c1_connector_v2_annotation_trait_proto_rawDescGZIP(), []int{3, 0}
}

type UserTrait struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Emails      []*UserTrait_Email    `protobuf:"bytes,1,rep,name=emails,proto3" json:"emails,omitempty"`
	Status      *UserTrait_Status     `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"`
	Profile     *structpb.Struct      `protobuf:"bytes,3,opt,name=profile,proto3" json:"profile,omitempty"`
	Icon        *AssetRef             `protobuf:"bytes,4,opt,name=icon,proto3" json:"icon,omitempty"`
	AccountType UserTrait_AccountType `protobuf:"varint,5,opt,name=account_type,json=accountType,proto3,enum=c1.connector.v2.UserTrait_AccountType" json:"account_type,omitempty"`
	// The user's login
	Login string `protobuf:"bytes,6,opt,name=login,proto3" json:"login,omitempty"`
	// Any additional login aliases for the user
	LoginAliases []string               `protobuf:"bytes,7,rep,name=login_aliases,json=loginAliases,proto3" json:"login_aliases,omitempty"`
	CreatedAt    *timestamppb.Timestamp `protobuf:"bytes,8,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	LastLogin    *timestamppb.Timestamp `protobuf:"bytes,9,opt,name=last_login,json=lastLogin,proto3" json:"last_login,omitempty"`
	MfaStatus    *UserTrait_MFAStatus   `protobuf:"bytes,10,opt,name=mfa_status,json=mfaStatus,proto3" json:"mfa_status,omitempty"`
	SsoStatus    *UserTrait_SSOStatus   `protobuf:"bytes,11,opt,name=sso_status,json=ssoStatus,proto3" json:"sso_status,omitempty"`
}

func (x *UserTrait) Reset() {
	*x = UserTrait{}
	if protoimpl.UnsafeEnabled {
		mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserTrait) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserTrait) ProtoMessage() {}

func (x *UserTrait) ProtoReflect() protoreflect.Message {
	mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserTrait.ProtoReflect.Descriptor instead.
func (*UserTrait) Descriptor() ([]byte, []int) {
	return file_c1_connector_v2_annotation_trait_proto_rawDescGZIP(), []int{0}
}

func (x *UserTrait) GetEmails() []*UserTrait_Email {
	if x != nil {
		return x.Emails
	}
	return nil
}

func (x *UserTrait) GetStatus() *UserTrait_Status {
	if x != nil {
		return x.Status
	}
	return nil
}

func (x *UserTrait) GetProfile() *structpb.Struct {
	if x != nil {
		return x.Profile
	}
	return nil
}

func (x *UserTrait) GetIcon() *AssetRef {
	if x != nil {
		return x.Icon
	}
	return nil
}

func (x *UserTrait) GetAccountType() UserTrait_AccountType {
	if x != nil {
		return x.AccountType
	}
	return UserTrait_ACCOUNT_TYPE_UNSPECIFIED
}

func (x *UserTrait) GetLogin() string {
	if x != nil {
		return x.Login
	}
	return ""
}

func (x *UserTrait) GetLoginAliases() []string {
	if x != nil {
		return x.LoginAliases
	}
	return nil
}

func (x *UserTrait) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *UserTrait) GetLastLogin() *timestamppb.Timestamp {
	if x != nil {
		return x.LastLogin
	}
	return nil
}

func (x *UserTrait) GetMfaStatus() *UserTrait_MFAStatus {
	if x != nil {
		return x.MfaStatus
	}
	return nil
}

func (x *UserTrait) GetSsoStatus() *UserTrait_SSOStatus {
	if x != nil {
		return x.SsoStatus
	}
	return nil
}

type GroupTrait struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Icon    *AssetRef        `protobuf:"bytes,1,opt,name=icon,proto3" json:"icon,omitempty"`
	Profile *structpb.Struct `protobuf:"bytes,2,opt,name=profile,proto3" json:"profile,omitempty"`
}

func (x *GroupTrait) Reset() {
	*x = GroupTrait{}
	if protoimpl.UnsafeEnabled {
		mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GroupTrait) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GroupTrait) ProtoMessage() {}

func (x *GroupTrait) ProtoReflect() protoreflect.Message {
	mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GroupTrait.ProtoReflect.Descriptor instead.
func (*GroupTrait) Descriptor() ([]byte, []int) {
	return file_c1_connector_v2_annotation_trait_proto_rawDescGZIP(), []int{1}
}

func (x *GroupTrait) GetIcon() *AssetRef {
	if x != nil {
		return x.Icon
	}
	return nil
}

func (x *GroupTrait) GetProfile() *structpb.Struct {
	if x != nil {
		return x.Profile
	}
	return nil
}

type RoleTrait struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Profile *structpb.Struct `protobuf:"bytes,1,opt,name=profile,proto3" json:"profile,omitempty"`
}

func (x *RoleTrait) Reset() {
	*x = RoleTrait{}
	if protoimpl.UnsafeEnabled {
		mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoleTrait) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoleTrait) ProtoMessage() {}

func (x *RoleTrait) ProtoReflect() protoreflect.Message {
	mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoleTrait.ProtoReflect.Descriptor instead.
func (*RoleTrait) Descriptor() ([]byte, []int) {
	return file_c1_connector_v2_annotation_trait_proto_rawDescGZIP(), []int{2}
}

func (x *RoleTrait) GetProfile() *structpb.Struct {
	if x != nil {
		return x.Profile
	}
	return nil
}

type AppTrait struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HelpUrl string             `protobuf:"bytes,1,opt,name=help_url,json=helpUrl,proto3" json:"help_url,omitempty"`
	Icon    *AssetRef          `protobuf:"bytes,2,opt,name=icon,proto3" json:"icon,omitempty"`
	Logo    *AssetRef          `protobuf:"bytes,3,opt,name=logo,proto3" json:"logo,omitempty"`
	Profile *structpb.Struct   `protobuf:"bytes,4,opt,name=profile,proto3" json:"profile,omitempty"`
	Flags   []AppTrait_AppFlag `protobuf:"varint,5,rep,packed,name=flags,proto3,enum=c1.connector.v2.AppTrait_AppFlag" json:"flags,omitempty"`
}

func (x *AppTrait) Reset() {
	*x = AppTrait{}
	if protoimpl.UnsafeEnabled {
		mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AppTrait) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AppTrait) ProtoMessage() {}

func (x *AppTrait) ProtoReflect() protoreflect.Message {
	mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AppTrait.ProtoReflect.Descriptor instead.
func (*AppTrait) Descriptor() ([]byte, []int) {
	return file_c1_connector_v2_annotation_trait_proto_rawDescGZIP(), []int{3}
}

func (x *AppTrait) GetHelpUrl() string {
	if x != nil {
		return x.HelpUrl
	}
	return ""
}

func (x *AppTrait) GetIcon() *AssetRef {
	if x != nil {
		return x.Icon
	}
	return nil
}

func (x *AppTrait) GetLogo() *AssetRef {
	if x != nil {
		return x.Logo
	}
	return nil
}

func (x *AppTrait) GetProfile() *structpb.Struct {
	if x != nil {
		return x.Profile
	}
	return nil
}

func (x *AppTrait) GetFlags() []AppTrait_AppFlag {
	if x != nil {
		return x.Flags
	}
	return nil
}

type UserTrait_Email struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address string `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	// Indicates if this is the user's primary email. Only one entry can be marked as primary.
	IsPrimary bool `protobuf:"varint,2,opt,name=is_primary,json=isPrimary,proto3" json:"is_primary,omitempty"`
}

func (x *UserTrait_Email) Reset() {
	*x = UserTrait_Email{}
	if protoimpl.UnsafeEnabled {
		mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserTrait_Email) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserTrait_Email) ProtoMessage() {}

func (x *UserTrait_Email) ProtoReflect() protoreflect.Message {
	mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserTrait_Email.ProtoReflect.Descriptor instead.
func (*UserTrait_Email) Descriptor() ([]byte, []int) {
	return file_c1_connector_v2_annotation_trait_proto_rawDescGZIP(), []int{0, 0}
}

func (x *UserTrait_Email) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *UserTrait_Email) GetIsPrimary() bool {
	if x != nil {
		return x.IsPrimary
	}
	return false
}

type UserTrait_Status struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Status  UserTrait_Status_Status `protobuf:"varint,1,opt,name=status,proto3,enum=c1.connector.v2.UserTrait_Status_Status" json:"status,omitempty"`
	Details string                  `protobuf:"bytes,2,opt,name=details,proto3" json:"details,omitempty"`
}

func (x *UserTrait_Status) Reset() {
	*x = UserTrait_Status{}
	if protoimpl.UnsafeEnabled {
		mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserTrait_Status) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserTrait_Status) ProtoMessage() {}

func (x *UserTrait_Status) ProtoReflect() protoreflect.Message {
	mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserTrait_Status.ProtoReflect.Descriptor instead.
func (*UserTrait_Status) Descriptor() ([]byte, []int) {
	return file_c1_connector_v2_annotation_trait_proto_rawDescGZIP(), []int{0, 1}
}

func (x *UserTrait_Status) GetStatus() UserTrait_Status_Status {
	if x != nil {
		return x.Status
	}
	return UserTrait_Status_STATUS_UNSPECIFIED
}

func (x *UserTrait_Status) GetDetails() string {
	if x != nil {
		return x.Details
	}
	return ""
}

type UserTrait_MFAStatus struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MfaEnabled bool `protobuf:"varint,1,opt,name=mfa_enabled,json=mfaEnabled,proto3" json:"mfa_enabled,omitempty"`
}

func (x *UserTrait_MFAStatus) Reset() {
	*x = UserTrait_MFAStatus{}
	if protoimpl.UnsafeEnabled {
		mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserTrait_MFAStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserTrait_MFAStatus) ProtoMessage() {}

func (x *UserTrait_MFAStatus) ProtoReflect() protoreflect.Message {
	mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserTrait_MFAStatus.ProtoReflect.Descriptor instead.
func (*UserTrait_MFAStatus) Descriptor() ([]byte, []int) {
	return file_c1_connector_v2_annotation_trait_proto_rawDescGZIP(), []int{0, 2}
}

func (x *UserTrait_MFAStatus) GetMfaEnabled() bool {
	if x != nil {
		return x.MfaEnabled
	}
	return false
}

type UserTrait_SSOStatus struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SsoEnabled bool `protobuf:"varint,1,opt,name=sso_enabled,json=ssoEnabled,proto3" json:"sso_enabled,omitempty"`
}

func (x *UserTrait_SSOStatus) Reset() {
	*x = UserTrait_SSOStatus{}
	if protoimpl.UnsafeEnabled {
		mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserTrait_SSOStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserTrait_SSOStatus) ProtoMessage() {}

func (x *UserTrait_SSOStatus) ProtoReflect() protoreflect.Message {
	mi := &file_c1_connector_v2_annotation_trait_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserTrait_SSOStatus.ProtoReflect.Descriptor instead.
func (*UserTrait_SSOStatus) Descriptor() ([]byte, []int) {
	return file_c1_connector_v2_annotation_trait_proto_rawDescGZIP(), []int{0, 3}
}

func (x *UserTrait_SSOStatus) GetSsoEnabled() bool {
	if x != nil {
		return x.SsoEnabled
	}
	return false
}

var File_c1_connector_v2_annotation_trait_proto protoreflect.FileDescriptor

var file_c1_connector_v2_annotation_trait_proto_rawDesc = []byte{
	0x0a, 0x26, 0x63, 0x31, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2f, 0x76,
	0x32, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x72, 0x61,
	0x69, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x63, 0x31, 0x2e, 0x63, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61,
	0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1b, 0x63, 0x31, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2f,
	0x76, 0x32, 0x2f, 0x61, 0x73, 0x73, 0x65, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xfa,
	0x08, 0x0a, 0x09, 0x55, 0x73, 0x65, 0x72, 0x54, 0x72, 0x61, 0x69, 0x74, 0x12, 0x38, 0x0a, 0x06,
	0x65, 0x6d, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x63,
	0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x55,
	0x73, 0x65, 0x72, 0x54, 0x72, 0x61, 0x69, 0x74, 0x2e, 0x45, 0x6d, 0x61, 0x69, 0x6c, 0x52, 0x06,
	0x65, 0x6d, 0x61, 0x69, 0x6c, 0x73, 0x12, 0x43, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x63, 0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x72, 0x61,
	0x69, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01,
	0x02, 0x10, 0x01, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x31, 0x0a, 0x07, 0x70,
	0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53,
	0x74, 0x72, 0x75, 0x63, 0x74, 0x52, 0x07, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x12, 0x2d,
	0x0a, 0x04, 0x69, 0x63, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x63,
	0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x41,
	0x73, 0x73, 0x65, 0x74, 0x52, 0x65, 0x66, 0x52, 0x04, 0x69, 0x63, 0x6f, 0x6e, 0x12, 0x53, 0x0a,
	0x0c, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x26, 0x2e, 0x63, 0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x72, 0x61, 0x69, 0x74, 0x2e,
	0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x54, 0x79, 0x70, 0x65, 0x42, 0x08, 0xfa, 0x42, 0x05,
	0x82, 0x01, 0x02, 0x10, 0x01, 0x52, 0x0b, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x54, 0x79,
	0x70, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x12, 0x23, 0x0a, 0x0d, 0x6c, 0x6f, 0x67, 0x69,
	0x6e, 0x5f, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x65, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x0c, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x41, 0x6c, 0x69, 0x61, 0x73, 0x65, 0x73, 0x12, 0x39, 0x0a,
	0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x39, 0x0a, 0x0a, 0x6c, 0x61, 0x73, 0x74,
	0x5f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x6c, 0x61, 0x73, 0x74, 0x4c, 0x6f,
	0x67, 0x69, 0x6e, 0x12, 0x43, 0x0a, 0x0a, 0x6d, 0x66, 0x61, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x63, 0x31, 0x2e, 0x63, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x72,
	0x61, 0x69, 0x74, 0x2e, 0x4d, 0x46, 0x41, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x09, 0x6d,
	0x66, 0x61, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x43, 0x0a, 0x0a, 0x73, 0x73, 0x6f, 0x5f,
	0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x63,
	0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x55,
	0x73, 0x65, 0x72, 0x54, 0x72, 0x61, 0x69, 0x74, 0x2e, 0x53, 0x53, 0x4f, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x52, 0x09, 0x73, 0x73, 0x6f, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x1a, 0x49, 0x0a,
	0x05, 0x45, 0x6d, 0x61, 0x69, 0x6c, 0x12, 0x21, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x60, 0x01,
	0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x1d, 0x0a, 0x0a, 0x69, 0x73, 0x5f,
	0x70, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x69,
	0x73, 0x50, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x1a, 0xdc, 0x01, 0x0a, 0x06, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x12, 0x4a, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x28, 0x2e, 0x63, 0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x54, 0x72, 0x61, 0x69, 0x74, 0x2e,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x42, 0x08, 0xfa,
	0x42, 0x05, 0x82, 0x01, 0x02, 0x10, 0x01, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12,
	0x27, 0x0a, 0x07, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x42, 0x0d, 0xfa, 0x42, 0x0a, 0x72, 0x08, 0x20, 0x01, 0x28, 0x80, 0x08, 0xd0, 0x01, 0x01, 0x52,
	0x07, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x22, 0x5d, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x12, 0x16, 0x0a, 0x12, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x55, 0x4e, 0x53,
	0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x12, 0x0a, 0x0e, 0x53, 0x54,
	0x41, 0x54, 0x55, 0x53, 0x5f, 0x45, 0x4e, 0x41, 0x42, 0x4c, 0x45, 0x44, 0x10, 0x01, 0x12, 0x13,
	0x0a, 0x0f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x44, 0x49, 0x53, 0x41, 0x42, 0x4c, 0x45,
	0x44, 0x10, 0x02, 0x12, 0x12, 0x0a, 0x0e, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x44, 0x45,
	0x4c, 0x45, 0x54, 0x45, 0x44, 0x10, 0x03, 0x1a, 0x2c, 0x0a, 0x09, 0x4d, 0x46, 0x41, 0x53, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x6d, 0x66, 0x61, 0x5f, 0x65, 0x6e, 0x61, 0x62,
	0x6c, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x6d, 0x66, 0x61, 0x45, 0x6e,
	0x61, 0x62, 0x6c, 0x65, 0x64, 0x1a, 0x2c, 0x0a, 0x09, 0x53, 0x53, 0x4f, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x73, 0x6f, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x73, 0x73, 0x6f, 0x45, 0x6e, 0x61, 0x62,
	0x6c, 0x65, 0x64, 0x22, 0x76, 0x0a, 0x0b, 0x41, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x54, 0x79,
	0x70, 0x65, 0x12, 0x1c, 0x0a, 0x18, 0x41, 0x43, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x5f, 0x54, 0x59,
	0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00,
	0x12, 0x16, 0x0a, 0x12, 0x41, 0x43, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x5f, 0x54, 0x59, 0x50, 0x45,
	0x5f, 0x48, 0x55, 0x4d, 0x41, 0x4e, 0x10, 0x01, 0x12, 0x18, 0x0a, 0x14, 0x41, 0x43, 0x43, 0x4f,
	0x55, 0x4e, 0x54, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x53, 0x45, 0x52, 0x56, 0x49, 0x43, 0x45,
	0x10, 0x02, 0x12, 0x17, 0x0a, 0x13, 0x41, 0x43, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x5f, 0x54, 0x59,
	0x50, 0x45, 0x5f, 0x53, 0x59, 0x53, 0x54, 0x45, 0x4d, 0x10, 0x03, 0x22, 0x6e, 0x0a, 0x0a, 0x47,
	0x72, 0x6f, 0x75, 0x70, 0x54, 0x72, 0x61, 0x69, 0x74, 0x12, 0x2d, 0x0a, 0x04, 0x69, 0x63, 0x6f,
	0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x63, 0x31, 0x2e, 0x63, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x41, 0x73, 0x73, 0x65, 0x74, 0x52,
	0x65, 0x66, 0x52, 0x04, 0x69, 0x63, 0x6f, 0x6e, 0x12, 0x31, 0x0a, 0x07, 0x70, 0x72, 0x6f, 0x66,
	0x69, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75,
	0x63, 0x74, 0x52, 0x07, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x22, 0x3e, 0x0a, 0x09, 0x52,
	0x6f, 0x6c, 0x65, 0x54, 0x72, 0x61, 0x69, 0x74, 0x12, 0x31, 0x0a, 0x07, 0x70, 0x72, 0x6f, 0x66,
	0x69, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75,
	0x63, 0x74, 0x52, 0x07, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x22, 0x9a, 0x03, 0x0a, 0x08,
	0x41, 0x70, 0x70, 0x54, 0x72, 0x61, 0x69, 0x74, 0x12, 0x35, 0x0a, 0x08, 0x68, 0x65, 0x6c, 0x70,
	0x5f, 0x75, 0x72, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1a, 0xfa, 0x42, 0x17, 0x72,
	0x15, 0x20, 0x01, 0x28, 0x80, 0x08, 0x3a, 0x08, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,
	0xd0, 0x01, 0x01, 0x88, 0x01, 0x01, 0x52, 0x07, 0x68, 0x65, 0x6c, 0x70, 0x55, 0x72, 0x6c, 0x12,
	0x2d, 0x0a, 0x04, 0x69, 0x63, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e,
	0x63, 0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e,
	0x41, 0x73, 0x73, 0x65, 0x74, 0x52, 0x65, 0x66, 0x52, 0x04, 0x69, 0x63, 0x6f, 0x6e, 0x12, 0x2d,
	0x0a, 0x04, 0x6c, 0x6f, 0x67, 0x6f, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x63,
	0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x76, 0x32, 0x2e, 0x41,
	0x73, 0x73, 0x65, 0x74, 0x52, 0x65, 0x66, 0x52, 0x04, 0x6c, 0x6f, 0x67, 0x6f, 0x12, 0x31, 0x0a,
	0x07, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x52, 0x07, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65,
	0x12, 0x37, 0x0a, 0x05, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0e, 0x32,
	0x21, 0x2e, 0x63, 0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x76,
	0x32, 0x2e, 0x41, 0x70, 0x70, 0x54, 0x72, 0x61, 0x69, 0x74, 0x2e, 0x41, 0x70, 0x70, 0x46, 0x6c,
	0x61, 0x67, 0x52, 0x05, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x22, 0x8c, 0x01, 0x0a, 0x07, 0x41, 0x70,
	0x70, 0x46, 0x6c, 0x61, 0x67, 0x12, 0x18, 0x0a, 0x14, 0x41, 0x50, 0x50, 0x5f, 0x46, 0x4c, 0x41,
	0x47, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12,
	0x13, 0x0a, 0x0f, 0x41, 0x50, 0x50, 0x5f, 0x46, 0x4c, 0x41, 0x47, 0x5f, 0x48, 0x49, 0x44, 0x44,
	0x45, 0x4e, 0x10, 0x01, 0x12, 0x15, 0x0a, 0x11, 0x41, 0x50, 0x50, 0x5f, 0x46, 0x4c, 0x41, 0x47,
	0x5f, 0x49, 0x4e, 0x41, 0x43, 0x54, 0x49, 0x56, 0x45, 0x10, 0x02, 0x12, 0x11, 0x0a, 0x0d, 0x41,
	0x50, 0x50, 0x5f, 0x46, 0x4c, 0x41, 0x47, 0x5f, 0x53, 0x41, 0x4d, 0x4c, 0x10, 0x03, 0x12, 0x11,
	0x0a, 0x0d, 0x41, 0x50, 0x50, 0x5f, 0x46, 0x4c, 0x41, 0x47, 0x5f, 0x4f, 0x49, 0x44, 0x43, 0x10,
	0x04, 0x12, 0x15, 0x0a, 0x11, 0x41, 0x50, 0x50, 0x5f, 0x46, 0x4c, 0x41, 0x47, 0x5f, 0x42, 0x4f,
	0x4f, 0x4b, 0x4d, 0x41, 0x52, 0x4b, 0x10, 0x05, 0x42, 0x36, 0x5a, 0x34, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x6e, 0x64, 0x75, 0x63, 0x74, 0x6f, 0x72,
	0x6f, 0x6e, 0x65, 0x2f, 0x62, 0x61, 0x74, 0x6f, 0x6e, 0x2d, 0x73, 0x64, 0x6b, 0x2f, 0x70, 0x62,
	0x2f, 0x63, 0x31, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2f, 0x76, 0x32,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_c1_connector_v2_annotation_trait_proto_rawDescOnce sync.Once
	file_c1_connector_v2_annotation_trait_proto_rawDescData = file_c1_connector_v2_annotation_trait_proto_rawDesc
)

func file_c1_connector_v2_annotation_trait_proto_rawDescGZIP() []byte {
	file_c1_connector_v2_annotation_trait_proto_rawDescOnce.Do(func() {
		file_c1_connector_v2_annotation_trait_proto_rawDescData = protoimpl.X.CompressGZIP(file_c1_connector_v2_annotation_trait_proto_rawDescData)
	})
	return file_c1_connector_v2_annotation_trait_proto_rawDescData
}

var file_c1_connector_v2_annotation_trait_proto_enumTypes = make([]protoimpl.EnumInfo, 3)
var file_c1_connector_v2_annotation_trait_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_c1_connector_v2_annotation_trait_proto_goTypes = []interface{}{
	(UserTrait_AccountType)(0),    // 0: c1.connector.v2.UserTrait.AccountType
	(UserTrait_Status_Status)(0),  // 1: c1.connector.v2.UserTrait.Status.Status
	(AppTrait_AppFlag)(0),         // 2: c1.connector.v2.AppTrait.AppFlag
	(*UserTrait)(nil),             // 3: c1.connector.v2.UserTrait
	(*GroupTrait)(nil),            // 4: c1.connector.v2.GroupTrait
	(*RoleTrait)(nil),             // 5: c1.connector.v2.RoleTrait
	(*AppTrait)(nil),              // 6: c1.connector.v2.AppTrait
	(*UserTrait_Email)(nil),       // 7: c1.connector.v2.UserTrait.Email
	(*UserTrait_Status)(nil),      // 8: c1.connector.v2.UserTrait.Status
	(*UserTrait_MFAStatus)(nil),   // 9: c1.connector.v2.UserTrait.MFAStatus
	(*UserTrait_SSOStatus)(nil),   // 10: c1.connector.v2.UserTrait.SSOStatus
	(*structpb.Struct)(nil),       // 11: google.protobuf.Struct
	(*AssetRef)(nil),              // 12: c1.connector.v2.AssetRef
	(*timestamppb.Timestamp)(nil), // 13: google.protobuf.Timestamp
}
var file_c1_connector_v2_annotation_trait_proto_depIdxs = []int32{
	7,  // 0: c1.connector.v2.UserTrait.emails:type_name -> c1.connector.v2.UserTrait.Email
	8,  // 1: c1.connector.v2.UserTrait.status:type_name -> c1.connector.v2.UserTrait.Status
	11, // 2: c1.connector.v2.UserTrait.profile:type_name -> google.protobuf.Struct
	12, // 3: c1.connector.v2.UserTrait.icon:type_name -> c1.connector.v2.AssetRef
	0,  // 4: c1.connector.v2.UserTrait.account_type:type_name -> c1.connector.v2.UserTrait.AccountType
	13, // 5: c1.connector.v2.UserTrait.created_at:type_name -> google.protobuf.Timestamp
	13, // 6: c1.connector.v2.UserTrait.last_login:type_name -> google.protobuf.Timestamp
	9,  // 7: c1.connector.v2.UserTrait.mfa_status:type_name -> c1.connector.v2.UserTrait.MFAStatus
	10, // 8: c1.connector.v2.UserTrait.sso_status:type_name -> c1.connector.v2.UserTrait.SSOStatus
	12, // 9: c1.connector.v2.GroupTrait.icon:type_name -> c1.connector.v2.AssetRef
	11, // 10: c1.connector.v2.GroupTrait.profile:type_name -> google.protobuf.Struct
	11, // 11: c1.connector.v2.RoleTrait.profile:type_name -> google.protobuf.Struct
	12, // 12: c1.connector.v2.AppTrait.icon:type_name -> c1.connector.v2.AssetRef
	12, // 13: c1.connector.v2.AppTrait.logo:type_name -> c1.connector.v2.AssetRef
	11, // 14: c1.connector.v2.AppTrait.profile:type_name -> google.protobuf.Struct
	2,  // 15: c1.connector.v2.AppTrait.flags:type_name -> c1.connector.v2.AppTrait.AppFlag
	1,  // 16: c1.connector.v2.UserTrait.Status.status:type_name -> c1.connector.v2.UserTrait.Status.Status
	17, // [17:17] is the sub-list for method output_type
	17, // [17:17] is the sub-list for method input_type
	17, // [17:17] is the sub-list for extension type_name
	17, // [17:17] is the sub-list for extension extendee
	0,  // [0:17] is the sub-list for field type_name
}

func init() { file_c1_connector_v2_annotation_trait_proto_init() }
func file_c1_connector_v2_annotation_trait_proto_init() {
	if File_c1_connector_v2_annotation_trait_proto != nil {
		return
	}
	file_c1_connector_v2_asset_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_c1_connector_v2_annotation_trait_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserTrait); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_c1_connector_v2_annotation_trait_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GroupTrait); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_c1_connector_v2_annotation_trait_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoleTrait); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_c1_connector_v2_annotation_trait_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AppTrait); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_c1_connector_v2_annotation_trait_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserTrait_Email); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_c1_connector_v2_annotation_trait_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserTrait_Status); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_c1_connector_v2_annotation_trait_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserTrait_MFAStatus); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_c1_connector_v2_annotation_trait_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserTrait_SSOStatus); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_c1_connector_v2_annotation_trait_proto_rawDesc,
			NumEnums:      3,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_c1_connector_v2_annotation_trait_proto_goTypes,
		DependencyIndexes: file_c1_connector_v2_annotation_trait_proto_depIdxs,
		EnumInfos:         file_c1_connector_v2_annotation_trait_proto_enumTypes,
		MessageInfos:      file_c1_connector_v2_annotation_trait_proto_msgTypes,
	}.Build()
	File_c1_connector_v2_annotation_trait_proto = out.File
	file_c1_connector_v2_annotation_trait_proto_rawDesc = nil
	file_c1_connector_v2_annotation_trait_proto_goTypes = nil
	file_c1_connector_v2_annotation_trait_proto_depIdxs = nil
}