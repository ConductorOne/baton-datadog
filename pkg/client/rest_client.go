package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	pbv2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

const (
	DefaultBaseURL          = "https://api.%s"
	OnCallSchedulesEndpoint = "/api/v2/on-call/schedules"
	OnCallUserEndpoint      = "/api/v2/on-call/schedules/%s/on-call"

	// PageSize is the page size for pagination.
	// note: (docs stand that the maximum allowed by Datadog API is 100, but we can only get pages with 50 elements).
	PageSize = 50
)

// PaginationOptions contains the options for pagination.
type PaginationOptions struct {
	PageSize   int
	PageNumber int
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
	httpClient *uhttp.BaseHttpClient
	baseURL    string
	apiKey     string
	appKey     string
}

// DatadogClientInterface defines the interface for Datadog client operations.
type DatadogClientInterface interface {
	ListOnCallSchedules(ctx context.Context, opts *PaginationOptions) ([]*OnCallSchedule, string, annotations.Annotations, error)
	GetScheduleOnCallUser(ctx context.Context, scheduleID string) (*OnCallUserResponse, annotations.Annotations, error)
}

// Ensure DatadogRestClient implements DatadogClientInterface.
var _ DatadogClientInterface = (*DatadogRestClient)(nil)

// NewDatadogRestClient creates a new instance of the REST client.
// If baseURL is empty, it will be constructed from site using DefaultBaseURL.
func NewDatadogRestClient(ctx context.Context, site string, apiKey string, appKey string, baseURL string) (*DatadogRestClient, error) {
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, err
	}

	uhttpClient, err := uhttp.NewBaseHttpClientWithContext(ctx, httpClient)
	if err != nil {
		return nil, err
	}

	// Use provided baseURL or construct from site
	effectiveBaseURL := baseURL
	if effectiveBaseURL == "" {
		effectiveBaseURL = fmt.Sprintf(DefaultBaseURL, site)
	}

	return &DatadogRestClient{
		httpClient: uhttpClient,
		baseURL:    effectiveBaseURL,
		apiKey:     apiKey,
		appKey:     appKey,
	}, nil
}

// doRequest is a helper function that handles the common HTTP request logic.
func (c *DatadogRestClient) doRequest(
	ctx context.Context,
	method string,
	endpoint string,
	body interface{},
	result interface{},
	opts ...ReqOpt,
) (annotations.Annotations, error) {
	baseUrl, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, err
	}

	endpointParsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	urlAddress := baseUrl.ResolveReference(endpointParsed)

	var reqOptions []uhttp.RequestOption

	if body != nil {
		reqOptions = append(reqOptions, uhttp.WithJSONBody(body))
	}

	req, err := c.httpClient.NewRequest(ctx, method, urlAddress, reqOptions...)
	if err != nil {
		return nil, err
	}

	for _, opt := range opts {
		req = opt(req)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)

	// Prepare helpers for rate-limit tracking and rich error handling.
	var rateLimitDescription pbv2.RateLimitDescription
	var datadogError datadogErrorResponse
	var doOptions []uhttp.DoOption

	if result != nil {
		doOptions = append(doOptions, uhttp.WithJSONResponse(result))
	}
	doOptions = append(doOptions, uhttp.WithRatelimitData(&rateLimitDescription))
	doOptions = append(doOptions, uhttp.WithErrorResponse(&datadogError))

	// Execute the request with the desired options.
	resp, err := c.httpClient.Do(
		req,
		doOptions...,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	annos := annotations.Annotations{}
	annos.WithRateLimiting(&rateLimitDescription)

	return annos, nil
}

func (c *DatadogRestClient) fetchSchedulePage(ctx context.Context, pageNumber, pageSize int) (*OnCallSchedulesResponse, annotations.Annotations, error) {
	var schedulesResponse OnCallSchedulesResponse
	annos, err := c.doRequest(ctx, http.MethodGet, OnCallSchedulesEndpoint, nil, &schedulesResponse, WithPageSize(pageSize), WithPage(pageNumber))
	if err != nil {
		return nil, annos, err
	}

	return &schedulesResponse, annos, nil
}

// ListOnCallSchedules lists on-call schedules with optional pagination.
func (c *DatadogRestClient) ListOnCallSchedules(ctx context.Context, opts *PaginationOptions) ([]*OnCallSchedule, string, annotations.Annotations, error) {
	// Validate options: from now on, always expect valid options.
	if opts == nil {
		return nil, "", nil, fmt.Errorf("pagination options cannot be nil")
	}

	l := ctxzap.Extract(ctx)
	l.Debug("Fetching on-call schedules page", zap.Int("page_number", opts.PageNumber), zap.Int("page_size", opts.PageSize))

	// Get the requested page.
	schedulesResp, annos, err := c.fetchSchedulePage(ctx, opts.PageNumber, opts.PageSize)
	if err != nil {
		return nil, "", annos, fmt.Errorf("error fetching schedules: %w", err)
	}

	// Log the full pagination metadata for debugging
	l.Debug("Datadog API pagination response",
		zap.Any("meta_page", schedulesResp.Meta.Page),
		zap.Int("data_count", len(schedulesResp.Data)))

	var nextPageNumber string
	if schedulesResp.Meta.Page.NextNumber != nil {
		nextPageNumber = strconv.Itoa(*schedulesResp.Meta.Page.NextNumber)
	}

	l.Debug("Generated next page token", zap.String("next_page_token", nextPageNumber))
	return schedulesResp.Data, nextPageNumber, annos, nil
}

// GetScheduleOnCallUser gets the user who is currently on-call for a specific schedule.
func (c *DatadogRestClient) GetScheduleOnCallUser(ctx context.Context, scheduleID string) (*OnCallUserResponse, annotations.Annotations, error) {
	// Validate scheduleID
	if scheduleID == "" {
		return nil, nil, fmt.Errorf("schedule ID cannot be empty")
	}

	endpoint := fmt.Sprintf(OnCallUserEndpoint, scheduleID)
	var onCallUserResponse OnCallUserResponse
	annos, err := c.doRequest(ctx, http.MethodGet, endpoint, nil, &onCallUserResponse)
	if err != nil {
		return nil, annos, fmt.Errorf("failed to get on-call user for schedule %s: %w", scheduleID, err)
	}
	return &onCallUserResponse, annos, nil
}
