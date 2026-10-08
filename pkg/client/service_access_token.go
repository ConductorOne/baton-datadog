package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
)

// The pinned Datadog Go client does not generate the newer service access
// token endpoints. These types cover only the documented request and response
// fields that this connector uses; transport, auth, server selection and retry
// still go through its configured official APIClient.
type ServiceAccessToken struct {
	ID         string
	Name       string
	Scopes     []string
	CreatedAt  *time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

type IssuedServiceAccessToken struct {
	ServiceAccessToken
	Key string
}

type serviceAccessTokenJSON struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Name       string     `json:"name"`
		Key        string     `json:"key"`
		Scopes     []string   `json:"scopes"`
		CreatedAt  *time.Time `json:"created_at"`
		ExpiresAt  *time.Time `json:"expires_at"`
		LastUsedAt *time.Time `json:"last_used_at"`
	} `json:"attributes"`
}

func (v serviceAccessTokenJSON) token() ServiceAccessToken {
	return ServiceAccessToken{
		ID: v.ID, Name: v.Attributes.Name, Scopes: v.Attributes.Scopes,
		CreatedAt: v.Attributes.CreatedAt, ExpiresAt: v.Attributes.ExpiresAt,
		LastUsedAt: v.Attributes.LastUsedAt,
	}
}

func (w *DatadogClient) serviceAccessTokenRequest(ctx context.Context, method, path string, body any, query url.Values) ([]byte, error) {
	ctx = w.withAuthContext(ctx)
	// Use a generated operation on the same service-account API for server
	// selection. An install's configured base URL and Datadog site still apply.
	base, err := w.officialClient.GetConfig().ServerURLWithContext(ctx, "v2.ServiceAccountsApi.ListServiceAccountApplicationKeys")
	if err != nil {
		return nil, fmt.Errorf("resolve Datadog service account API URL: %w", err)
	}
	headers := map[string]string{"Accept": "application/json"}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}
	datadog.SetAuthKeys(ctx, &headers,
		[2]string{"apiKeyAuth", "DD-API-KEY"},
		[2]string{"appKeyAuth", "DD-APPLICATION-KEY"})
	request, err := w.officialClient.PrepareRequest(ctx, base+path, method, body, headers, query, url.Values{}, nil)
	if err != nil {
		return nil, fmt.Errorf("prepare Datadog service access token request: %w", err)
	}
	var resp *http.Response
	if method == http.MethodPost {
		// Issuance is not idempotent. APIClient.CallAPI may retry a POST when
		// retry is enabled, so execute this request exactly once.
		resp, err = w.officialClient.GetConfig().HTTPClient.Do(request)
	} else {
		resp, err = w.officialClient.CallAPI(request)
	}
	if err != nil || resp == nil {
		return nil, wrapOfficialClientError("service access token request", resp, err)
	}
	defer resp.Body.Close()
	bytes, err := datadog.ReadBody(resp)
	if err != nil {
		return nil, wrapOfficialClientError("read service access token response", resp, err)
	}
	if resp.StatusCode >= 300 {
		return nil, wrapOfficialClientError("service access token request", resp, fmt.Errorf("Datadog returned HTTP %d", resp.StatusCode))
	}
	return bytes, nil
}

func serviceAccessTokenPath(serviceAccountID string) string {
	return "/api/v2/service_accounts/" + url.PathEscape(serviceAccountID) + "/access_tokens"
}

func (w *DatadogClient) CreateServiceAccountAccessToken(ctx context.Context, serviceAccountID, name string, scopes []string, expiresAt *time.Time) (*IssuedServiceAccessToken, error) {
	attrs := struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}{Name: name, Scopes: scopes, ExpiresAt: expiresAt}
	body := map[string]any{"data": map[string]any{"type": "service_access_tokens", "attributes": attrs}}
	bytes, err := w.serviceAccessTokenRequest(ctx, http.MethodPost, serviceAccessTokenPath(serviceAccountID), body, nil)
	if err != nil {
		return nil, err
	}
	var response struct {
		Data serviceAccessTokenJSON `json:"data"`
	}
	if err := json.Unmarshal(bytes, &response); err != nil {
		return nil, fmt.Errorf("decode Datadog service access token create response: %w", err)
	}
	data := response.Data
	if data.Type != "service_access_tokens" || data.ID == "" || data.Attributes.Key == "" {
		if data.ID != "" {
			if revokeErr := w.RevokeServiceAccountAccessToken(ctx, serviceAccountID, data.ID); revokeErr != nil {
				return nil, fmt.Errorf("Datadog service access token create response omitted type, id or key; revoke of undeliverable token %q failed: %w", data.ID, revokeErr)
			}
		}
		return nil, fmt.Errorf("Datadog service access token create response omitted type, id or key")
	}
	return &IssuedServiceAccessToken{ServiceAccessToken: data.token(), Key: data.Attributes.Key}, nil
}

func (w *DatadogClient) GetServiceAccountAccessToken(ctx context.Context, serviceAccountID, tokenID string) (*ServiceAccessToken, error) {
	bytes, err := w.serviceAccessTokenRequest(ctx, http.MethodGet, serviceAccessTokenPath(serviceAccountID)+"/"+url.PathEscape(tokenID), nil, nil)
	if err != nil {
		return nil, err
	}
	var response struct {
		Data serviceAccessTokenJSON `json:"data"`
	}
	if err := json.Unmarshal(bytes, &response); err != nil {
		return nil, fmt.Errorf("decode Datadog service access token get response: %w", err)
	}
	if response.Data.Type != "service_access_tokens" || response.Data.ID != tokenID {
		return nil, fmt.Errorf("Datadog service access token get response did not match requested token")
	}
	token := response.Data.token()
	return &token, nil
}

func (w *DatadogClient) ListServiceAccountAccessTokens(ctx context.Context, serviceAccountID string, page, pageSize int64) ([]ServiceAccessToken, error) {
	query := url.Values{"page[number]": {fmt.Sprint(page)}, "page[size]": {fmt.Sprint(pageSize)}}
	bytes, err := w.serviceAccessTokenRequest(ctx, http.MethodGet, serviceAccessTokenPath(serviceAccountID), nil, query)
	if err != nil {
		return nil, err
	}
	var response struct {
		Data []serviceAccessTokenJSON `json:"data"`
	}
	if err := json.Unmarshal(bytes, &response); err != nil {
		return nil, fmt.Errorf("decode Datadog service access token list response: %w", err)
	}
	out := make([]ServiceAccessToken, 0, len(response.Data))
	for _, data := range response.Data {
		if data.Type != "service_access_tokens" || data.ID == "" {
			return nil, fmt.Errorf("Datadog service access token list response omitted type or id")
		}
		out = append(out, data.token())
	}
	return out, nil
}

// FindServiceAccountAccessTokenByName refuses a full first page: a filtered
// response may have more entries, so absence cannot be inferred from it.
func (w *DatadogClient) FindServiceAccountAccessTokenByName(ctx context.Context, serviceAccountID, name string) (*ServiceAccessToken, error) {
	query := url.Values{"filter": {name}, "page[number]": {"0"}, "page[size]": {fmt.Sprint(nameSearchPageSize)}}
	bytes, err := w.serviceAccessTokenRequest(ctx, http.MethodGet, serviceAccessTokenPath(serviceAccountID), nil, query)
	if err != nil {
		return nil, err
	}
	var response struct {
		Data []serviceAccessTokenJSON `json:"data"`
	}
	if err := json.Unmarshal(bytes, &response); err != nil {
		return nil, fmt.Errorf("decode Datadog service access token search response: %w", err)
	}
	for _, data := range response.Data {
		if data.Type != "service_access_tokens" || data.ID == "" {
			return nil, fmt.Errorf("Datadog service access token search response omitted type or id")
		}
		if data.Attributes.Name == name {
			token := data.token()
			return &token, nil
		}
	}
	if len(response.Data) >= int(nameSearchPageSize) {
		return nil, fmt.Errorf("Datadog service access token search returned a full page without exact match")
	}
	return nil, nil
}

func (w *DatadogClient) RevokeServiceAccountAccessToken(ctx context.Context, serviceAccountID, tokenID string) error {
	_, err := w.serviceAccessTokenRequest(ctx, http.MethodDelete, serviceAccessTokenPath(serviceAccountID)+"/"+url.PathEscape(tokenID), nil, nil)
	return err
}
