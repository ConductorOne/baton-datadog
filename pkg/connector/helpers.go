package connector

import (
	"context"
	"fmt"
	"strconv"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

func annotationsForUserResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.SkipEntitlementsAndGrants{})
	return annos
}

func withAuthContext(ctx context.Context, apiKey, appKey, site string) context.Context {
	ctx = context.WithValue(
		ctx,
		datadog.ContextAPIKeys,
		map[string]datadog.APIKey{
			"apiKeyAuth": {
				Key: apiKey,
			},
			"appKeyAuth": {
				Key: appKey,
			},
		},
	)

	ctx = context.WithValue(ctx,
		datadog.ContextServerVariables,
		map[string]string{
			"site": site,
		})

	return ctx
}

func parsePageToken(i string, resourceID *v2.ResourceId) (*pagination.Bag, int64, error) {
	if i == "" {
		// Return default values for empty token
		b := &pagination.Bag{}

		if resourceID != nil {
			// Use the provided resource ID
			b.Push(pagination.PageState{
				ResourceTypeID: resourceID.ResourceType,
				ResourceID:     resourceID.Resource,
			})
		} else {
			b.Push(pagination.PageState{
				ResourceTypeID: "",
				ResourceID:     "",
			})
		}
		return b, 0, nil
	}

	b := &pagination.Bag{}
	err := b.Unmarshal(i)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal pagination token: %w", err)
	}

	if b.Current() == nil {
		// Use default values if resourceID is nil
		if resourceID != nil {
			// Use the provided resource ID
			b.Push(pagination.PageState{
				ResourceTypeID: resourceID.ResourceType,
				ResourceID:     resourceID.Resource,
			})
		} else {
			b.Push(pagination.PageState{
				ResourceTypeID: "",
				ResourceID:     "",
			})
		}
	}

	page, err := getPageFromPageToken(b.PageToken())
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get page from token: %w", err)
	}

	return b, page, nil
}

func getPageFromPageToken(token string) (int64, error) {
	if token == "" {
		return 0, nil
	}

	page, err := strconv.ParseInt(token, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse page number from token: %w", err)
	}

	return page, nil
}

func getPageTokenFromPage(bag *pagination.Bag, page int64) (string, error) {
	if bag == nil {
		return "", fmt.Errorf("pagination bag cannot be nil")
	}

	if page < 0 {
		return "", fmt.Errorf("page number cannot be negative")
	}

	nextPage := fmt.Sprintf("%d", page)
	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return "", fmt.Errorf("failed to generate next page token: %w", err)
	}

	return pageToken, nil
}
