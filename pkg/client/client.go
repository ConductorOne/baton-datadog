package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	pbv2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

const (
	datadogAPIBaseURL       = "https://%s"
	onCallSchedulesEndpoint = "/api/v2/on-call/schedules"
	// PageSize is the page size for pagination (maximum allowed by Datadog API: 100).
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
	HasMore    bool
}

// datadogErrorItem represents an individual error item within the "errors" array returned by the API.
type datadogErrorItem struct {
	Status string `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// datadogErrorResponse represents the complete error payload.
type datadogErrorResponse struct {
	Errors []datadogErrorItem `json:"errors"`
}

// Message concatenates all errors into a single readable string.
func (d *datadogErrorResponse) Message() string {
	if d == nil || len(d.Errors) == 0 {
		return ""
	}

	parts := make([]string, 0, len(d.Errors))
	for _, e := range d.Errors {
		// Format: "<status> <title>: <detail>"
		if e.Status != "" {
			parts = append(parts, fmt.Sprintf("%s %s: %s", e.Status, e.Title, e.Detail))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s", e.Title, e.Detail))
		}
	}
	return strings.Join(parts, "; ")
}

// DatadogRestClient is a client for Datadog REST API.
// that is not available in the official client library.
type DatadogRestClient struct {
	httpClient *http.Client
	site       string
	apiKey     string
	appKey     string
}

// DatadogClientInterface defines the interface for Datadog client operations.
type DatadogClientInterface interface {
	ListOnCallSchedules(ctx context.Context, opts *PaginationOptions) ([]OnCallSchedule, *PaginationResult, error)
	GetScheduleOnCallUser(ctx context.Context, scheduleID string) (*OnCallUserResponse, error)
}

// Ensure DatadogRestClient implements DatadogClientInterface.
var _ DatadogClientInterface = (*DatadogRestClient)(nil)

// NewDatadogRestClient creates a new instance of the REST client.
func NewDatadogRestClient(site, apiKey, appKey string) (*DatadogRestClient, error) {
	// Validate input parameters
	if site == "" {
		return nil, fmt.Errorf("site cannot be empty")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("API key cannot be empty")
	}
	if appKey == "" {
		return nil, fmt.Errorf("application key cannot be empty")
	}

	// Provide a non-nil logger to avoid silent failures when logging is enabled.
	httpClient, err := uhttp.NewClient(context.Background(), uhttp.WithLogger(true, zap.L()))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	return &DatadogRestClient{
		httpClient: httpClient,
		site:       site,
		apiKey:     apiKey,
		appKey:     appKey,
	}, nil
}

// doRequest is a helper function that handles the common HTTP request logic.
func (c *DatadogRestClient) doRequest(ctx context.Context, method, endpoint string, body interface{}, result interface{}) error {
	// Build the URL - check if endpoint is already a full URL
	var apiURL string
	if strings.HasPrefix(endpoint, "http") {
		apiURL = endpoint
	} else {
		baseURL := fmt.Sprintf(datadogAPIBaseURL, c.site)
		baseUrlParsed, err := url.Parse(baseURL)
		if err != nil {
			return fmt.Errorf("error parsing base URL: %w", err)
		}

		endpointParsed, err := url.Parse(endpoint)
		if err != nil {
			return fmt.Errorf("error parsing endpoint: %w", err)
		}

		apiURL = baseUrlParsed.ResolveReference(endpointParsed).String()
	}

	// Create the request based on whether body is provided
	var req *http.Request
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		req, err = http.NewRequestWithContext(ctx, method, apiURL, strings.NewReader(string(jsonBody)))
		if err != nil {
			return fmt.Errorf("error creating HTTP request: %w", err)
		}
	} else {
		var err error
		req, err = http.NewRequestWithContext(ctx, method, apiURL, nil)
		if err != nil {
			return fmt.Errorf("error creating HTTP request: %w", err)
		}
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)

	// Prepare helpers for rate-limit tracking and rich error handling.
	var rlDesc pbv2.RateLimitDescription
	var ddErr datadogErrorResponse

	// Create a BaseHttpClient so we can leverage uhttp options.
	baseClient := uhttp.NewBaseHttpClient(c.httpClient)

	// Execute the request with the desired options.
	resp, err := baseClient.Do(
		req,
		uhttp.WithRatelimitData(&rlDesc),
		uhttp.WithErrorResponse(&ddErr),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Parse the response if result is provided.
	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("error decoding response: %w", err)
		}
	}

	return nil
}

func (c *DatadogRestClient) fetchSchedulePage(ctx context.Context, pageNumber, pageSize int) (*OnCallSchedulesResponse, error) {
	if pageSize == 0 {
		pageSize = PageSize
	}

	baseURL := fmt.Sprintf(datadogAPIBaseURL, c.site)
	baseUrlParsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing base URL: %w", err)
	}

	endpointParsed, err := url.Parse(onCallSchedulesEndpoint)
	if err != nil {
		return nil, fmt.Errorf("error parsing endpoint: %w", err)
	}

	apiURL := baseUrlParsed.ResolveReference(endpointParsed).String()

	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL: %w", err)
	}

	q := u.Query()
	q.Set("page[size]", strconv.Itoa(pageSize))
	q.Set("page[number]", strconv.Itoa(pageNumber))
	u.RawQuery = q.Encode()

	var schedulesResponse OnCallSchedulesResponse
	if err := c.doRequest(ctx, http.MethodGet, u.String(), nil, &schedulesResponse); err != nil {
		return nil, err
	}

	return &schedulesResponse, nil
}

// buildPaginationResult converts the raw API response into the PaginationResult
// used internally by the client.
func buildPaginationResult(resp *OnCallSchedulesResponse) *PaginationResult {
	if resp == nil {
		return nil
	}

	return &PaginationResult{
		Data:       resp.Data,
		NextPage:   resp.Meta.Page.NextNumber,
		Total:      resp.Meta.Page.Total,
		PageNumber: resp.Meta.Page.Number,
		PageSize:   resp.Meta.Page.Size,
		LastNumber: resp.Meta.Page.LastNumber,
		HasMore:    resp.Meta.Page.NextNumber != nil,
	}
}

// ListOnCallSchedules lists on-call schedules with optional pagination.
func (c *DatadogRestClient) ListOnCallSchedules(ctx context.Context, opts *PaginationOptions) ([]OnCallSchedule, *PaginationResult, error) {
	// Validate options: from ahora siempre se esperan opciones válidas.
	if opts == nil {
		return nil, nil, fmt.Errorf("pagination options cannot be nil")
	}

	// Aplicar valores por defecto si fuera necesario.
	if opts.PageSize == 0 {
		opts.PageSize = PageSize
	}

	l := ctxzap.Extract(ctx)
	l.Debug("Fetching on-call schedules page", zap.Int("page_number", opts.PageNumber), zap.Int("page_size", opts.PageSize))

	// Obtener la página solicitada.
	schedulesResp, err := c.fetchSchedulePage(ctx, opts.PageNumber, opts.PageSize)
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching schedules: %w", err)
	}

	paginationResult := buildPaginationResult(schedulesResp)
	return schedulesResp.Data, paginationResult, nil
}

// GetScheduleOnCallUser gets the user who is currently on-call for a specific schedule.
func (c *DatadogRestClient) GetScheduleOnCallUser(ctx context.Context, scheduleID string) (*OnCallUserResponse, error) {
	// Validate scheduleID
	if scheduleID == "" {
		return nil, fmt.Errorf("schedule ID cannot be empty")
	}

	endpoint := fmt.Sprintf("/api/v2/on-call/schedules/%s/on-call", scheduleID)
	var onCallUserResponse OnCallUserResponse
	err := c.doRequest(ctx, http.MethodGet, endpoint, nil, &onCallUserResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to get on-call user for schedule %s: %w", scheduleID, err)
	}
	return &onCallUserResponse, nil
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
