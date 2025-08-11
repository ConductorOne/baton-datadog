package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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

// NewDatadogRestClient creates a new instance of the REST client.
func NewDatadogRestClient(site, apiKey, appKey string) *DatadogRestClient {
	return &DatadogRestClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		site:   site,
		apiKey: apiKey,
		appKey: appKey,
	}
}

// ListOnCallSchedules lists all on-call schedules.
func (c *DatadogRestClient) ListOnCallSchedules(ctx context.Context) (*OnCallSchedulesResponse, error) {
	l := ctxzap.Extract(ctx)

	// Build the URL.
	baseURL := fmt.Sprintf(datadogAPIBaseURL, c.site)
	apiURL := fmt.Sprintf("%s%s", baseURL, onCallSchedulesEndpoint)

	// Create the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		l.Error("Failed to create HTTP request", zap.Error(err))
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Add headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)

	// Make the request.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		l.Error("Failed to make HTTP request", zap.Error(err))
		return nil, fmt.Errorf("error making HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Verify the status code.
	if resp.StatusCode != http.StatusOK {
		l.Error("HTTP request failed", zap.Int("status_code", resp.StatusCode))
		return nil, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	// Parse the response.
	var schedulesResponse OnCallSchedulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&schedulesResponse); err != nil {
		l.Error("Failed to decode response", zap.Error(err))
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &schedulesResponse, nil
}

// GetScheduleOnCallUser gets the user who is currently on-call for a specific schedule.
func (c *DatadogRestClient) GetScheduleOnCallUser(ctx context.Context, scheduleID string) (*OnCallUserResponse, error) {
	l := ctxzap.Extract(ctx)

	// Build the URL
	baseURL := fmt.Sprintf(datadogAPIBaseURL, c.site)
	apiURL := fmt.Sprintf("%s/api/v2/on-call/schedules/%s/on-call", baseURL, scheduleID)

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		l.Error("Failed to create HTTP request", zap.Error(err))
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)

	// Make the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		l.Error("Failed to make HTTP request", zap.Error(err))
		return nil, fmt.Errorf("error making HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Verify the status code
	if resp.StatusCode != http.StatusOK {
		l.Error("HTTP request failed", zap.Int("status_code", resp.StatusCode))
		return nil, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	// Parse the response
	var onCallUserResponse OnCallUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&onCallUserResponse); err != nil {
		l.Error("Failed to decode response", zap.Error(err))
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &onCallUserResponse, nil
}
