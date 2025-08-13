package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	// PageSize is the page size for pagination (maximum permitido por la API de Datadog: 100).
	PageSize = 100
)

// PaginationOptions contains the options for pagination.
type PaginationOptions struct {
	PageSize   int
	PageNumber int
}

// PaginationResult contains the result of a page and pagination metadata.
type PaginationResult struct {
	Data       interface{}
	NextPage   *int
	Total      int
	PageNumber int
	PageSize   int
	LastNumber int
}

// PaginatedClient extends the REST client with pagination functionality.
type PaginatedClient struct {
	*DatadogRestClient
}

// NewPaginatedClient creates a new client with pagination capabilities.
func NewPaginatedClient(client *DatadogRestClient) *PaginatedClient {
	return &PaginatedClient{
		DatadogRestClient: client,
	}
}

// ListOnCallSchedulesPaginated lists all on-call schedules with pagination.
func (c *PaginatedClient) ListOnCallSchedulesPaginated(ctx context.Context, opts *PaginationOptions) (*OnCallSchedulesResponse, *PaginationResult, error) {
	l := ctxzap.Extract(ctx)

	// Set default options
	if opts == nil {
		opts = &PaginationOptions{
			PageSize:   PageSize, // Default page size
			PageNumber: 0,        // First page
		}
	}

	// Build the URL with pagination parameters
	baseURL := fmt.Sprintf(datadogAPIBaseURL, c.site)
	apiURL := fmt.Sprintf("%s%s", baseURL, onCallSchedulesEndpoint)

	// Add pagination parameters
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing URL: %w", err)
	}

	q := u.Query()
	q.Set("page[size]", strconv.Itoa(opts.PageSize))
	q.Set("page[number]", strconv.Itoa(opts.PageNumber))
	u.RawQuery = q.Encode()

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		l.Error("Failed to create HTTP request", zap.Error(err))
		return nil, nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)

	// Make the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		l.Error("Failed to make HTTP request", zap.Error(err))
		return nil, nil, fmt.Errorf("error making HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Verify the status code
	if resp.StatusCode != http.StatusOK {
		l.Error("HTTP request failed", zap.Int("status_code", resp.StatusCode))
		return nil, nil, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	// Parse the response
	var schedulesResponse OnCallSchedulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&schedulesResponse); err != nil {
		l.Error("Failed to decode response", zap.Error(err))
		return nil, nil, fmt.Errorf("error decoding response: %w", err)
	}

	// Create pagination result
	paginationResult := &PaginationResult{
		Data:       schedulesResponse.Data,
		NextPage:   schedulesResponse.Meta.Page.NextNumber,
		Total:      schedulesResponse.Meta.Page.Total,
		PageNumber: schedulesResponse.Meta.Page.Number,
		PageSize:   schedulesResponse.Meta.Page.Size,
		LastNumber: schedulesResponse.Meta.Page.LastNumber,
	}

	return &schedulesResponse, paginationResult, nil
}

// ListAllOnCallSchedules lists all on-call schedules automatically paginating.
func (c *PaginatedClient) ListAllOnCallSchedules(ctx context.Context) ([]OnCallSchedule, error) {
	l := ctxzap.Extract(ctx)

	var allSchedules []OnCallSchedule
	pageNumber := 0

	for {
		l.Debug("Fetching page", zap.Int("page_number", pageNumber), zap.Int("page_size", PageSize))

		opts := &PaginationOptions{
			PageSize:   PageSize,
			PageNumber: pageNumber,
		}

		response, paginationResult, err := c.ListOnCallSchedulesPaginated(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("error fetching page %d: %w", pageNumber, err)
		}

		// Add the schedules from this page
		allSchedules = append(allSchedules, response.Data...)

		// Check if there are more pages
		if paginationResult.NextPage == nil {
			l.Debug("No more pages available", zap.Int("total_schedules", len(allSchedules)))
			break
		}

		// Go to the next page
		pageNumber = *paginationResult.NextPage

		// Check that we are not in an infinite loop
		if pageNumber > paginationResult.LastNumber {
			l.Warn("Page number exceeds last page, stopping pagination",
				zap.Int("page_number", pageNumber),
				zap.Int("last_number", paginationResult.LastNumber))
			break
		}
	}

	l.Info("Successfully fetched all schedules",
		zap.Int("total_schedules", len(allSchedules)),
		zap.Int("total_pages", pageNumber+1))

	return allSchedules, nil
}

// HasNextPage checks if there is a next page available.
func (pr *PaginationResult) HasNextPage() bool {
	return pr.NextPage != nil
}

// GetNextPageNumber returns the number of the next page.
func (pr *PaginationResult) GetNextPageNumber() int {
	if pr.NextPage != nil {
		return *pr.NextPage
	}
	return -1
}

// IsLastPage checks if it is the last page.
func (pr *PaginationResult) IsLastPage() bool {
	return pr.NextPage == nil
}
