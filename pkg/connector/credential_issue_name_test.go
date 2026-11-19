package connector

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func prefixArgs(v *structpb.Value) *structpb.Struct {
	return &structpb.Struct{Fields: map[string]*structpb.Value{actionArgNamePrefix: v}}
}

// namePrefixCases is the parser table. The advisory schema pattern must accept
// every valid case.
var namePrefixCases = map[string]struct {
	prefix string
	valid  bool
}{
	"default":              {"c1", true},
	"single letter":        {"a", true},
	"accented":             {"caf\u00e9", true},
	"cjk":                  {"\u65e5\u672c", true},
	"mixed scripts":        {"\u00dcn\u00efc\u00f6d\u00e9_x-1", true},
	"combining mark":       {"e\u0301", true},
	"latin-1 letters":      {"\u00aa\u00b5\u00ba", true},
	"latin-1 letter tail":  {"a\u00b5", true},
	"mixed case":           {"Team_A-ci", true},
	"64 cjk runes":         {strings.Repeat("\u65e5", maxNamePrefixLen), true},
	"65 cjk runes":         {strings.Repeat("\u65e5", maxNamePrefixLen+1), false},
	"64 ascii":             {strings.Repeat("a", maxNamePrefixLen), true},
	"65 ascii":             {strings.Repeat("a", maxNamePrefixLen+1), false},
	"leading digit":        {"9abc", false},
	"leading underscore":   {"_a", false},
	"leading dash":         {"-a", false},
	"leading mark":         {"\u0301a", false},
	"space":                {"a b", false},
	"newline":              {"a\nb", false},
	"tab":                  {"a\tb", false},
	"carriage return":      {"a\rb", false},
	"NUL":                  {"a\x00b", false},
	"DEL":                  {"a\x7fb", false},
	"C1 NEL":               {"a\u0085b", false},
	"dot":                  {"a.b", false},
	"emoji":                {"\U0001F642", false},
	"trailing emoji":       {"a\U0001F642", false},
	"leading newline form": {"9\na", false},
}

func TestKeyNamePrefixParser(t *testing.T) {
	for name, tc := range namePrefixCases {
		t.Run(name, func(t *testing.T) {
			got, err := actionKeyName(prefixArgs(structpb.NewStringValue(tc.prefix)))
			if !tc.valid {
				require.Equal(t, codes.InvalidArgument, status.Code(err))
				return
			}
			require.NoError(t, err)
			require.Regexp(t, `^`+regexp.QuoteMeta(tc.prefix)+`-[0-9A-Za-z]{27}$`, got)
		})
	}
}

func TestKeyNamePrefixDefaultsAndTypes(t *testing.T) {
	for name, args := range map[string]*structpb.Struct{
		"absent":     {},
		"empty":      prefixArgs(structpb.NewStringValue("")),
		"whitespace": prefixArgs(structpb.NewStringValue("  \t ")),
		"null":       prefixArgs(structpb.NewNullValue()),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := actionKeyName(args)
			require.NoError(t, err)
			require.Regexp(t, `^c1-[0-9A-Za-z]{27}$`, got)
		})
	}
	for name, v := range map[string]*structpb.Value{
		"number": structpb.NewNumberValue(3), "bool": structpb.NewBoolValue(false), "list": structpb.NewListValue(&structpb.ListValue{}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := actionKeyName(prefixArgs(v))
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
	got, err := actionKeyName(prefixArgs(structpb.NewStringValue("  Team_A  ")))
	require.NoError(t, err)
	require.Regexp(t, `^Team_A-[0-9A-Za-z]{27}$`, got, "trimmed, case kept")
}

func TestKeyNamePrefixSchema(t *testing.T) {
	declared := namePrefixField()
	require.Equal(t, actionArgNamePrefix, declared.GetName())
	require.False(t, declared.GetIsRequired(), "omitting the prefix uses the default")
	require.Contains(t, declared.GetDescription(), "KSUID")
	sf := declared.GetStringField()
	require.Equal(t, "c1", sf.GetDefaultValue())
	rules := sf.GetRules()
	require.EqualValues(t, 1, rules.GetMinLen())
	require.False(t, rules.HasMaxLen(), "MaxLen counts bytes and would reject 64 CJK characters")
	require.False(t, rules.GetValidateEmpty())
	require.False(t, rules.GetIsRequired())
	require.Equal(t, namePrefixPattern, rules.GetPattern())
}

// The advisory pattern is a superset of the parser: it must accept every
// prefix the parser accepts, or the schema would turn valid input away.
func TestKeyNamePrefixPatternAcceptsEveryParserAcceptedCase(t *testing.T) {
	re := regexp.MustCompilePOSIX(namePrefixPattern)
	rules := namePrefixField().GetStringField().GetRules()
	for name, tc := range namePrefixCases {
		if tc.valid {
			require.True(t, re.MatchString(tc.prefix), name)
			require.NoError(t, field.ValidateStringRules(rules, tc.prefix, actionArgNamePrefix), name)
		}
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
			args := prefixArgs(structpb.NewStringValue("team-prod"))
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
				require.Regexp(t, `^team-prod-[0-9A-Za-z]{27}$`, name)
			default:
				t.Fatal("issuer did not create a key")
			}
		})
	}
}

// Every rune the parser accepts, alone or after "a", must match the advisory
// pattern, so the schema never turns away a valid prefix.
func TestNamePrefixPatternSupersetOfParserForEveryRune(t *testing.T) {
	re := regexp.MustCompilePOSIX(namePrefixPattern)
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		for _, s := range []string{string(r), "a" + string(r)} {
			if validNamePrefix(s) && !re.MatchString(s) {
				t.Fatalf("pattern rejects %q (U+%04X) that the parser accepts", s, r)
			}
		}
	}
}

func TestNewKSUIDFailureIsInternal(t *testing.T) {
	prev := newKSUID
	newKSUID = func() (ksuid.KSUID, error) { return ksuid.KSUID{}, errors.New("entropy exhausted") }
	t.Cleanup(func() { newKSUID = prev })

	_, err := newIssuedKeyName("c1")
	require.Equal(t, codes.Internal, status.Code(err))
	require.ErrorContains(t, err, "baton-datadog: ")
	require.ErrorContains(t, err, "entropy exhausted")
}
