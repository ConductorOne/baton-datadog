package client

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
)

// IssuedServiceAccessToken contains the one-time key and provider metadata.
type IssuedServiceAccessToken struct {
	ID        string
	Key       string
	Name      string
	Scopes    []string
	ExpiresAt *time.Time
}

func (w *DatadogClient) CreateServiceAccountAccessToken(ctx context.Context, serviceAccountID, name string, scopes []string, expiresAt *time.Time) (*IssuedServiceAccessToken, error) {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewServiceAccountsApi(w.officialClient)
	attrs := *datadogV2.NewServiceAccountAccessTokenCreateAttributes(name, scopes)
	if expiresAt != nil {
		attrs.SetExpiresAt(*expiresAt)
	}
	data := *datadogV2.NewServiceAccountAccessTokenCreateData(attrs, datadogV2.SERVICEACCESSTOKENSTYPE_SERVICE_ACCESS_TOKENS)
	resp, httpResp, err := api.CreateServiceAccountAccessToken(ctx, serviceAccountID, *datadogV2.NewServiceAccountAccessTokenCreateRequest(data))
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, wrapOfficialClientError("create service account access token", httpResp, err)
	}
	token := resp.Data
	if token == nil || token.Id == nil || *token.Id == "" || token.Attributes == nil || token.Attributes.Key == nil || *token.Attributes.Key == "" {
		return nil, fmt.Errorf("create service account access token response omitted id or key")
	}
	return &IssuedServiceAccessToken{
		ID:        *token.Id,
		Key:       *token.Attributes.Key,
		Name:      token.Attributes.GetName(),
		Scopes:    token.Attributes.Scopes,
		ExpiresAt: token.Attributes.ExpiresAt.Get(),
	}, nil
}

func (w *DatadogClient) ListServiceAccountAccessTokens(ctx context.Context, serviceAccountID string, page, pageSize int64) (*datadogV2.ListServiceAccessTokensResponse, error) {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewServiceAccountsApi(w.officialClient)
	params := *datadogV2.NewListServiceAccountAccessTokensOptionalParameters().WithPageNumber(page).WithPageSize(pageSize)
	resp, httpResp, err := api.ListServiceAccountAccessTokens(ctx, serviceAccountID, params)
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, wrapOfficialClientError("list service account access tokens", httpResp, err)
	}
	return &resp, nil
}

// FindServiceAccountAccessTokenByName refuses a full filtered page because a
// retried mint must not mistake a truncated result for absence.
func (w *DatadogClient) FindServiceAccountAccessTokenByName(ctx context.Context, serviceAccountID, name string) (*datadogV2.ServiceAccessToken, error) {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewServiceAccountsApi(w.officialClient)
	params := *datadogV2.NewListServiceAccountAccessTokensOptionalParameters().WithFilter(name).WithPageNumber(0).WithPageSize(nameSearchPageSize)
	resp, httpResp, err := api.ListServiceAccountAccessTokens(ctx, serviceAccountID, params)
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return nil, wrapOfficialClientError("find service account access token by name", httpResp, err)
	}
	for _, token := range resp.GetData() {
		if token.Attributes != nil && token.Attributes.GetName() == name {
			return &token, nil
		}
	}
	if len(resp.GetData()) >= int(nameSearchPageSize) {
		return nil, fmt.Errorf("find service account access token by name: filter %q returned a full page without an exact match", name)
	}
	return nil, nil
}

func (w *DatadogClient) RevokeServiceAccountAccessToken(ctx context.Context, serviceAccountID, tokenID string) error {
	ctx = w.withAuthContext(ctx)
	api := datadogV2.NewServiceAccountsApi(w.officialClient)
	httpResp, err := api.RevokeServiceAccountAccessToken(ctx, serviceAccountID, tokenID)
	if httpResp != nil {
		defer httpResp.Body.Close()
	}
	if err != nil {
		return wrapOfficialClientError("revoke service account access token", httpResp, err)
	}
	return nil
}
