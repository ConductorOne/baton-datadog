package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"google.golang.org/protobuf/types/known/structpb"
)

// schemaByName indexes action schemas by their action name.
func schemaByName(schemas []*v2.BatonActionSchema) map[string]*v2.BatonActionSchema {
	out := make(map[string]*v2.BatonActionSchema, len(schemas))
	for _, s := range schemas {
		out[s.GetName()] = s
	}
	return out
}

// TestLifecycleActionsAreGlobal verifies that enable_user and disable_user register as
// global actions (resource_type_id="") so C1's account-lifecycle pipeline can resolve
// them, while update_user stays scoped to the "user" resource type. See CXH-1491.
func TestLifecycleActionsAreGlobal(t *testing.T) {
	ctx := context.Background()

	mgr := actions.NewActionManager(ctx)

	// Global actions: registered directly on the connector (wrapper is unused for
	// schema registration, so a nil-wrapper connector is fine here).
	d := &Datadog{}
	if err := d.GlobalActions(ctx, mgr); err != nil {
		t.Fatalf("GlobalActions returned error: %v", err)
	}

	// Resource-scoped actions: registered via the user builder's type registry.
	userRegistry, err := mgr.GetTypeRegistry(ctx, userResourceType.Id)
	if err != nil {
		t.Fatalf("GetTypeRegistry returned error: %v", err)
	}
	u := newUserBuilder(nil)
	if err := u.ResourceActions(ctx, userRegistry); err != nil {
		t.Fatalf("ResourceActions returned error: %v", err)
	}

	// Global registry (resource_type_id="") must expose enable/disable with an empty
	// resource type, and must NOT surface update_user as a global action.
	global, _, err := mgr.ListActionSchemas(ctx, "")
	if err != nil {
		t.Fatalf("ListActionSchemas(global) returned error: %v", err)
	}
	byName := schemaByName(global)

	for _, name := range []string{ActionEnableUser, ActionDisableUser} {
		s, ok := byName[name]
		if !ok {
			t.Fatalf("expected %q to be registered", name)
		}
		if s.GetResourceTypeId() != "" {
			t.Errorf("%q must be global (resource_type_id=\"\"), got %q", name, s.GetResourceTypeId())
		}
	}

	// update_user must be scoped to the user resource type.
	userSchemas, _, err := mgr.ListActionSchemas(ctx, userResourceType.Id)
	if err != nil {
		t.Fatalf("ListActionSchemas(user) returned error: %v", err)
	}
	userByName := schemaByName(userSchemas)

	upd, ok := userByName[ActionUpdateUser]
	if !ok {
		t.Fatalf("expected %q to be registered under resource type %q", ActionUpdateUser, userResourceType.Id)
	}
	if upd.GetResourceTypeId() != userResourceType.Id {
		t.Errorf("%q must be scoped to %q, got %q", ActionUpdateUser, userResourceType.Id, upd.GetResourceTypeId())
	}

	// The lifecycle actions must not also be registered as user-scoped, or the
	// duplicate would reintroduce the resource-scoped record C1 can't find globally.
	if _, ok := userByName[ActionEnableUser]; ok {
		t.Errorf("%q should not be registered as a user-scoped action", ActionEnableUser)
	}
	if _, ok := userByName[ActionDisableUser]; ok {
		t.Errorf("%q should not be registered as a user-scoped action", ActionDisableUser)
	}
}

// TestDisableUserNotFoundFails verifies that a GetUser 404 during disable_user
// propagates as an error rather than reporting success, matching enable_user's
// behavior for the same input. See CXH-2184: previously any 404 from GetUser
// (not only a truly-deleted user) short-circuited to success:true without ever
// issuing the DELETE that performs the soft-disable.
func TestDisableUserNotFoundFails(t *testing.T) {
	const userID = "deadbeef-0000-4000-8000-000000000000"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":["Not found"]}`))
	}))
	defer server.Close()

	cfg := datadog.NewConfiguration()
	cfg.Servers = datadog.ServerConfigurations{{URL: server.URL}}
	wrapper := client.NewDatadogClient(nil, datadog.NewAPIClient(cfg), "example.com", "api-key", "app-key")
	d := &Datadog{wrapper: wrapper}

	args, err := structpb.NewStruct(map[string]interface{}{"user_id": userID})
	if err != nil {
		t.Fatalf("failed to build args: %v", err)
	}

	_, _, err = d.disableUser(context.Background(), args)
	if err == nil {
		t.Fatal("disableUser returned nil error for a 404 GetUser response, want an error")
	}
}
