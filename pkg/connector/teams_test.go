package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

func testMembership(userID string) datadogV2.UserTeam {
	m := datadogV2.NewUserTeam("membership-"+userID, datadogV2.USERTEAMTYPE_TEAM_MEMBERSHIPS)
	rel := datadogV2.NewUserTeamRelationships()
	rel.SetUser(*datadogV2.NewRelationshipToUserTeamUser(
		*datadogV2.NewRelationshipToUserTeamUserData(userID, datadogV2.USERTEAMUSERTYPE_USERS),
	))
	m.SetRelationships(*rel)
	m.SetAttributes(*datadogV2.NewUserTeamAttributes())
	return *m
}

func testUserResponseBody(t *testing.T, userID, name, email string) []byte {
	t.Helper()
	resp := datadogV2.NewUserResponse()
	u := datadogV2.NewUser()
	u.SetId(userID)
	attrs := datadogV2.NewUserAttributes()
	attrs.SetName(name)
	attrs.SetEmail(email)
	attrs.SetStatus("Active")
	u.SetAttributes(*attrs)
	resp.SetData(*u)
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal user response: %v", err)
	}
	return body
}

// A membership pointing at a user that no longer exists (GetUser 404) must be
// skipped so the rest of the team's grants still sync, rather than failing the
// whole page.
func TestTeamGrantsSkipsStaleMembership(t *testing.T) {
	const (
		teamID  = "team-1"
		validID = "user-valid"
		staleID = "user-stale"
	)

	memberships := datadogV2.NewUserTeamsResponse()
	memberships.SetData([]datadogV2.UserTeam{testMembership(validID), testMembership(staleID)})
	membershipsBody, err := json.Marshal(memberships)
	if err != nil {
		t.Fatalf("marshal memberships response: %v", err)
	}
	validUserBody := testUserResponseBody(t, validID, "Valid User", "valid@example.com")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/team/" + teamID + "/memberships":
			_, _ = w.Write(membershipsBody)
		case "/api/v2/users/" + validID:
			_, _ = w.Write(validUserBody)
		case "/api/v2/users/" + staleID:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["user not found"]}`))
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := datadog.NewConfiguration()
	cfg.Servers = datadog.ServerConfigurations{{URL: server.URL}}
	wrapper := client.NewDatadogClient(nil, datadog.NewAPIClient(cfg), "example.com", "api-key", "app-key")
	builder := newTeamBuilder(wrapper)

	resource := &v2.Resource{Id: &v2.ResourceId{ResourceType: teamResourceType.Id, Resource: teamID}}
	grants, _, _, err := builder.Grants(context.Background(), resource, &pagination.Token{})
	if err != nil {
		t.Fatalf("Grants returned error, want nil (stale membership should be skipped): %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("got %d grants, want 1 (valid member only, stale skipped)", len(grants))
	}
	if got := grants[0].Principal.Id.Resource; got != validID {
		t.Fatalf("grant principal = %q, want %q", got, validID)
	}
}
