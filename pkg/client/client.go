package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	datadogAPIBaseURL       = "https://%s"
	onCallSchedulesEndpoint = "/api/v2/on-call/schedules"
)

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
	ListOnCallSchedules(ctx context.Context) ([]OnCallSchedule, string, annotations.Annotations, error)
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

	httpClient, err := uhttp.NewClient(context.Background(), uhttp.WithLogger(true, nil))
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
	l := ctxzap.Extract(ctx)

	// Build the URL
	baseURL := fmt.Sprintf(datadogAPIBaseURL, c.site)
	apiURL := fmt.Sprintf("%s%s", baseURL, endpoint)

	// Create the request
	var req *http.Request
	var err error
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			l.Error("Failed to marshal request body", zap.Error(err))
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		req, err = http.NewRequestWithContext(ctx, method, apiURL, strings.NewReader(string(jsonBody)))
		if err != nil {
			l.Error("Failed to create HTTP request", zap.Error(err))
			return fmt.Errorf("failed to create HTTP request: %w", err)
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, method, apiURL, nil)
		if err != nil {
			l.Error("Failed to create HTTP request", zap.Error(err))
			return fmt.Errorf("failed to create HTTP request: %w", err)
		}
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)

	// Make the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		l.Error("Failed to make HTTP request", zap.Error(err))
		return fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Handle different HTTP status codes
	if err := c.handleHTTPResponse(resp, endpoint); err != nil {
		return err
	}

	// Parse the response if result is provided
	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			l.Error("Failed to decode response", zap.Error(err))
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// handleHTTPResponse handles different HTTP response status codes.
func (c *DatadogRestClient) handleHTTPResponse(resp *http.Response, endpoint string) error {
	// Check if status code indicates success (2xx range)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Handle specific error cases
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("authentication failed with status %d", resp.StatusCode)
	case http.StatusForbidden:
		return fmt.Errorf("authorization failed with status %d", resp.StatusCode)
	case http.StatusNotFound:
		return fmt.Errorf("resource not found with status %d", resp.StatusCode)
	case http.StatusTooManyRequests:
		return fmt.Errorf("rate limit exceeded with status %d", resp.StatusCode)
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return fmt.Errorf("server error with status %d", resp.StatusCode)
	default:
		// For other error status codes, create a generic error
		return fmt.Errorf("HTTP request failed with status %d", resp.StatusCode)
	}
}

// ListOnCallSchedules lists all on-call schedules.
func (c *DatadogRestClient) ListOnCallSchedules(ctx context.Context) ([]OnCallSchedule, string, annotations.Annotations, error) {
	var schedulesResponse OnCallSchedulesResponse
	err := c.doRequest(ctx, http.MethodGet, onCallSchedulesEndpoint, nil, &schedulesResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list on-call schedules: %w", err)
	}

	// Extract next page token from meta information
	nextPageToken := ""
	if schedulesResponse.Meta.Page.NextNumber != nil {
		nextPageToken = strconv.Itoa(*schedulesResponse.Meta.Page.NextNumber)
	}

	return schedulesResponse.Data, nextPageToken, nil, nil
}

// ListOnCallSchedulesSimple is a simplified version that returns just the schedules without pagination.
// This is useful for testing and cases where pagination is not needed.
func (c *DatadogRestClient) ListOnCallSchedulesSimple(ctx context.Context) ([]OnCallSchedule, error) {
	schedules, _, _, err := c.ListOnCallSchedules(ctx)
	return schedules, err
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
