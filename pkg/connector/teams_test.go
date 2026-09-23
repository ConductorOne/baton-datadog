package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

func testMembership(userID string, role datadogV2.UserTeamRole) datadogV2.UserTeam {
	m := datadogV2.NewUserTeam("membership-"+userID, datadogV2.USERTEAMTYPE_TEAM_MEMBERSHIPS)
	rel := datadogV2.NewUserTeamRelationships()
	rel.SetUser(*datadogV2.NewRelationshipToUserTeamUser(
		*datadogV2.NewRelationshipToUserTeamUserData(userID, datadogV2.USERTEAMUSERTYPE_USERS),
	))
	m.SetRelationships(*rel)
	attrs := datadogV2.NewUserTeamAttributes()
	if role != "" {
		attrs.SetRole(role)
	}
	m.SetAttributes(*attrs)
	return *m
}

// Grants builds a grant straight from the user ID carried in each membership,
// with no per-membership GetUser lookup. A membership whose user was deleted
// (formerly a GetUser 404 that failed the whole page) still yields a grant; the
// next sync surfaces the deletion. The users endpoint must never be hit.
func TestTeamGrantsBuildFromMembershipUserID(t *testing.T) {
	const (
		teamID   = "team-1"
		memberID = "user-member"
		adminID  = "user-admin"
		staleID  = "user-stale"
	)

	memberships := datadogV2.NewUserTeamsResponse()
	memberships.SetData([]datadogV2.UserTeam{
		testMembership(memberID, ""),
		testMembership(adminID, datadogV2.USERTEAMROLE_ADMIN),
		testMembership(staleID, ""),
	})
	membershipsBody, err := json.Marshal(memberships)
	if err != nil {
		t.Fatalf("marshal memberships response: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/team/" + teamID + "/memberships":
			_, _ = w.Write(membershipsBody)
		default:
			t.Errorf("unexpected request path (GetUser should not be called): %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := datadog.NewConfiguration()
	cfg.Servers = datadog.ServerConfigurations{{URL: server.URL}}
	wrapper := client.NewDatadogClient(nil, datadog.NewAPIClient(cfg), "example.com", "api-key", "app-key")
	builder := newTeamBuilder(wrapper)

	resource := &v2.Resource{Id: &v2.ResourceId{ResourceType: teamResourceType.Id, Resource: teamID}}
	grants, _, err := builder.Grants(context.Background(), resource, rs.SyncOpAttrs{PageToken: pagination.Token{}})
	if err != nil {
		t.Fatalf("Grants returned error, want nil: %v", err)
	}

	member := map[string]bool{}
	admin := map[string]bool{}
	for _, g := range grants {
		id := g.Principal.Id.Resource
		switch {
		case strings.HasSuffix(g.Entitlement.Id, ":"+memberRole):
			member[id] = true
		case strings.HasSuffix(g.Entitlement.Id, ":"+adminRole):
			admin[id] = true
		}
	}
	for _, id := range []string{memberID, adminID, staleID} {
		if !member[id] {
			t.Errorf("missing %q member grant for %q", memberRole, id)
		}
	}
	if !admin[adminID] {
		t.Errorf("missing %q grant for %q", adminRole, adminID)
	}
	if len(grants) != 4 {
		t.Fatalf("got %d grants, want 4 (3 member + 1 admin)", len(grants))
	}
}

func testTeamWrapper(baseURL string) *client.DatadogClient {
	cfg := datadog.NewConfiguration()
	cfg.Servers = datadog.ServerConfigurations{{URL: baseURL}}
	return client.NewDatadogClient(nil, datadog.NewAPIClient(cfg), "example.com", "api-key", "app-key")
}

func teamEntitlement(teamID, slug string) *v2.Entitlement {
	return &v2.Entitlement{
		Slug:     slug,
		Resource: &v2.Resource{Id: &v2.ResourceId{ResourceType: teamResourceType.Id, Resource: teamID}},
	}
}

// A 409 from CreateTeamMembership on the admin entitlement means the user is
// already on the team as a member; the connector must PATCH the role rather than
// report GrantAlreadyExists (which would drop the promotion silently).
func TestTeamGrantAdminOn409PromotesViaPatch(t *testing.T) {
	const (
		teamID = "team-1"
		userID = "user-1"
	)

	var postCalls, patchCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/team/"+teamID+"/memberships":
			postCalls++
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"errors":["already a member"]}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v2/team/"+teamID+"/memberships/"+userID:
			patchCalls++
			_, _ = w.Write([]byte(`{"data":{"type":"team_memberships","id":"m-1"}}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	builder := newTeamBuilder(testTeamWrapper(server.URL))
	principal := &v2.Resource{Id: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: userID}}

	annos, err := builder.Grant(context.Background(), principal, teamEntitlement(teamID, adminRole))
	if err != nil {
		t.Fatalf("Grant returned error, want nil: %v", err)
	}
	if postCalls != 1 || patchCalls != 1 {
		t.Fatalf("want 1 POST + 1 PATCH, got %d POST + %d PATCH", postCalls, patchCalls)
	}
	if annos.Contains(&v2.GrantAlreadyExists{}) {
		t.Errorf("admin promotion applied a change, should not report GrantAlreadyExists")
	}
}

// A 409 on the member entitlement means the user is already a member: report
// GrantAlreadyExists and never PATCH.
func TestTeamGrantMemberOn409IsAlreadyExists(t *testing.T) {
	const (
		teamID = "team-1"
		userID = "user-1"
	)

	var patchCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/team/"+teamID+"/memberships":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"errors":["already a member"]}`))
		case r.Method == http.MethodPatch:
			patchCalls++
			t.Errorf("member grant must not PATCH")
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	builder := newTeamBuilder(testTeamWrapper(server.URL))
	principal := &v2.Resource{Id: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: userID}}

	annos, err := builder.Grant(context.Background(), principal, teamEntitlement(teamID, memberRole))
	if err != nil {
		t.Fatalf("Grant returned error, want nil: %v", err)
	}
	if patchCalls != 0 {
		t.Fatalf("member 409 must not PATCH, got %d PATCH calls", patchCalls)
	}
	if !annos.Contains(&v2.GrantAlreadyExists{}) {
		t.Errorf("member 409 should report GrantAlreadyExists")
	}
}
