package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestKeyNamePrefixLimits(t *testing.T) {
	for _, tc := range []struct {
		name         string
		resourceType string
		prefix       string
		valid        bool
	}{
		{"org ASCII boundary", apiTokenResourceType.Id, strings.Repeat("a", 232), true},
		{"org ASCII too long", apiTokenResourceType.Id, strings.Repeat("a", 233), false},
		{"org Unicode boundary", apiTokenResourceType.Id, strings.Repeat("é", 232), true},
		{"org Unicode too long", apiTokenResourceType.Id, strings.Repeat("é", 233), false},
		{"org emoji boundary", apiTokenResourceType.Id, strings.Repeat("😀", 232), true},
		{"app ASCII boundary", serviceAccountApplicationKeyResourceType.Id, strings.Repeat("a", 232), true},
		{"app ASCII too long", serviceAccountApplicationKeyResourceType.Id, strings.Repeat("a", 233), false},
		{"app Unicode boundary", serviceAccountApplicationKeyResourceType.Id, strings.Repeat("é", 116), true},
		{"app Unicode too long", serviceAccountApplicationKeyResourceType.Id, strings.Repeat("é", 117), false},
		{"app emoji boundary", serviceAccountApplicationKeyResourceType.Id, strings.Repeat("😀", 58), true},
		{"app emoji too long", serviceAccountApplicationKeyResourceType.Id, strings.Repeat("😀", 59), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			declared := namePrefixField(tc.resourceType)
			require.Equal(t, "c1", declared.GetStringField().GetDefaultValue())
			require.False(t, declared.GetIsRequired(), "omitting the prefix preserves generated names")
			schemaErr := field.ValidateStringRules(declared.GetStringField().GetRules(), tc.prefix, actionArgNamePrefix)
			name, err := actionKeyName(&structpb.Struct{Fields: map[string]*structpb.Value{actionArgNamePrefix: structpb.NewStringValue(tc.prefix)}}, tc.resourceType)
			if !tc.valid {
				require.Error(t, schemaErr)
				require.Equal(t, codes.InvalidArgument, status.Code(err))
				return
			}
			require.NoError(t, schemaErr)
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(name, tc.prefix+"-"))
			if tc.resourceType == apiTokenResourceType.Id {
				require.Equal(t, 256, utf8.RuneCountInString(name))
			} else {
				require.Equal(t, 256, len(name))
			}
		})
	}
}

func TestKeyNamePrefixPresence(t *testing.T) {
	for _, resourceType := range []string{apiTokenResourceType.Id, serviceAccountApplicationKeyResourceType.Id} {
		t.Run(resourceType, func(t *testing.T) {
			name, err := actionKeyName(&structpb.Struct{}, resourceType)
			require.NoError(t, err)
			require.Regexp(t, `^c1-\d{8}T\d{6}Z-[a-z2-7]{6}$`, name)
			for _, value := range []*structpb.Value{
				structpb.NewStringValue(""), structpb.NewNullValue(), structpb.NewNumberValue(3), structpb.NewBoolValue(false), structpb.NewListValue(&structpb.ListValue{}),
			} {
				_, err = actionKeyName(&structpb.Struct{Fields: map[string]*structpb.Value{actionArgNamePrefix: value}}, resourceType)
				require.Equal(t, codes.InvalidArgument, status.Code(err), "explicit invalid values cannot silently use the default")
			}
		})
	}
}

func TestIssuerCustomNamePrefixReachesProvider(t *testing.T) {
	for _, resourceType := range []string{apiTokenResourceType.Id, serviceAccountApplicationKeyResourceType.Id} {
		t.Run(resourceType, func(t *testing.T) {
			names := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet && r.URL.Path == "/api/v2/users/"+testServiceAccountID {
					_, _ = w.Write([]byte(`{"data":{"id":"` + testServiceAccountID + `","type":"users","attributes":{"service_account":true}}}`))
					return
				}
				path, keyType := "/api/v2/api_keys", "api_keys"
				if resourceType == serviceAccountApplicationKeyResourceType.Id {
					path, keyType = "/api/v2/service_accounts/"+testServiceAccountID+"/application_keys", "application_keys"
				}
				if r.Method != http.MethodPost || r.URL.Path != path {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				var body struct {
					Data struct {
						Attributes struct {
							Name string `json:"name"`
						} `json:"attributes"`
					} `json:"data"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode key creation: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				names <- body.Data.Attributes.Name
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"id":         "issued-id",
						"type":       keyType,
						"attributes": map[string]any{"name": body.Data.Attributes.Name, "key": "test-secret"},
					},
				})
			}))
			defer server.Close()
			issuer := newCredentialUserBuilder(newLifecycleTestWrapper(server.URL), true, true, testAPIBaseURL)
			args := &structpb.Struct{Fields: map[string]*structpb.Value{actionArgNamePrefix: structpb.NewStringValue("team-prod")}}
			var err error
			if resourceType == apiTokenResourceType.Id {
				_, _, _, err = issuer.issueOrganizationAPIKeyAction(context.Background(), args)
			} else {
				args.Fields[actionArgServiceAccountID] = subjectArg(t, userResourceType.Id, testServiceAccountID)
				_, _, _, err = issuer.issueServiceAccountApplicationKeyAction(context.Background(), args)
			}
			require.NoError(t, err)
			select {
			case name := <-names:
				require.Regexp(t, `^team-prod-\d{8}T\d{6}Z-[a-z2-7]{6}$`, name)
			default:
				t.Fatal("issuer did not create a key")
			}
		})
	}
}

func TestKeyNamePrefixRejectsControlCharacters(t *testing.T) {
	for _, resourceType := range []string{apiTokenResourceType.Id, serviceAccountApplicationKeyResourceType.Id} {
		for _, tc := range []struct {
			name   string
			prefix string
		}{
			{"newline bypass", strings.Repeat("a", 100) + "\n" + strings.Repeat("a", 300)},
			{"newline", "a\nb"},
			{"carriage return", "a\rb"},
			{"tab", "a\tb"},
			{"NUL", "a\x00b"},
			{"DEL", "a\x7fb"},
			{"C1 NEL", "a\u0085b"},
			{"leading newline", "\nab"},
			{"trailing newline", "ab\n"},
		} {
			t.Run(resourceType+"/"+tc.name, func(t *testing.T) {
				_, err := actionKeyName(&structpb.Struct{Fields: map[string]*structpb.Value{actionArgNamePrefix: structpb.NewStringValue(tc.prefix)}}, resourceType)
				require.Equal(t, codes.InvalidArgument, status.Code(err))
			})
		}
	}
}

func TestOrgKeyNamePrefixPatternCompilesPOSIX(t *testing.T) {
	pattern := namePrefixField(apiTokenResourceType.Id).GetStringField().GetRules().GetPattern()
	re, err := regexp.CompilePOSIX(pattern)
	require.NoError(t, err)
	require.True(t, re.MatchString("team-prod"))
	require.False(t, re.MatchString("a\x7fb"))
}
