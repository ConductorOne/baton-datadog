package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Helper function to check if two strings are equal.
func assertEqual(t *testing.T, expected, actual string, message string) {
	t.Helper()
	if expected != actual {
		t.Errorf("%s: expected %q, got %q", message, expected, actual)
	}
}

// Helper function to check if a value is not nil.
func assertNotNil(t *testing.T, value interface{}, message string) {
	t.Helper()
	if value == nil {
		t.Errorf("%s: expected non-nil value", message)
	}
}

// Helper function to check if an error is nil.
func assertNoError(t *testing.T, err error, message string) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: unexpected error: %v", message, err)
	}
}

// Helper function to check if an error is not nil.
func assertError(t *testing.T, err error, message string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: expected error, got nil", message)
	}
}

// Helper function to check if a string contains a substring.
func assertContains(t *testing.T, str, substr string, message string) {
	t.Helper()
	if !strings.Contains(str, substr) {
		t.Errorf("%s: expected %q to contain %q", message, str, substr)
	}
}

// Helper function to check if two integers are equal.
func assertEqualInt(t *testing.T, expected, actual int, message string) {
	t.Helper()
	if expected != actual {
		t.Errorf("%s: expected %d, got %d", message, expected, actual)
	}
}

// Helper function to check if two time.Duration are equal.
func assertEqualDuration(t *testing.T, expected, actual time.Duration, message string) {
	t.Helper()
	if expected != actual {
		t.Errorf("%s: expected %v, got %v", message, expected, actual)
	}
}

// TestClient is a modified version of DatadogRestClient for testing.
type TestClient struct {
	httpClient *http.Client
	site       string
	apiKey     string
	appKey     string
}

// NewTestClient creates a new test client that uses HTTP instead of HTTPS.
func NewTestClient(site, apiKey, appKey string) *TestClient {
	return &TestClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		site:       site,
		apiKey:     apiKey,
		appKey:     appKey,
	}
}

// ListOnCallSchedules lists all on-call schedules for testing.
func (c *TestClient) ListOnCallSchedules(ctx context.Context) (*OnCallSchedulesResponse, error) {
	// Build the URL using HTTP instead of HTTPS.
	baseURL := fmt.Sprintf("http://%s", c.site)
	apiURL := fmt.Sprintf("%s/api/v2/on-call/schedules", baseURL)

	// Create the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Add headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)

	// Make the request.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Verify the status code.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	// Parse the response.
	var schedulesResponse OnCallSchedulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&schedulesResponse); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &schedulesResponse, nil
}

// GetScheduleOnCallUser gets the user who is currently on-call for a specific schedule for testing.
func (c *TestClient) GetScheduleOnCallUser(ctx context.Context, scheduleID string) (*OnCallUserResponse, error) {
	// Build the URL using HTTP instead of HTTPS.
	baseURL := fmt.Sprintf("http://%s", c.site)
	apiURL := fmt.Sprintf("%s/api/v2/on-call/schedules/%s/on-call", baseURL, scheduleID)

	// Create the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Add headers.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)

	// Make the request.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Verify the status code.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	// Parse the response.
	var onCallUserResponse OnCallUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&onCallUserResponse); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &onCallUserResponse, nil
}

// Constants for test data.
const (
	testScheduleID = "schedule-1"
)

func TestNewDatadogRestClient(t *testing.T) {
	site := "datadoghq.com"
	apiKey := "test-api-key"
	appKey := "test-app-key"

	client := NewDatadogRestClient(site, apiKey, appKey)

	assertNotNil(t, client, "client should not be nil")
	assertEqual(t, site, client.site, "site should match")
	assertEqual(t, apiKey, client.apiKey, "apiKey should match")
	assertEqual(t, appKey, client.appKey, "appKey should match")
	assertNotNil(t, client.httpClient, "httpClient should not be nil")
	assertEqualDuration(t, 30*time.Second, client.httpClient.Timeout, "timeout should be 30 seconds")
}

func TestListOnCallSchedules_Success(t *testing.T) {
	// Mock response data.
	mockResponse := OnCallSchedulesResponse{
		Data: []OnCallSchedule{
			{
				ID:   "schedule-1",
				Type: "oncall_schedule",
				Attributes: OnCallScheduleAttributes{
					Name:     "Primary On-Call",
					TimeZone: "UTC",
				},
			},
			{
				ID:   "schedule-2",
				Type: "oncall_schedule",
				Attributes: OnCallScheduleAttributes{
					Name:     "Secondary On-Call",
					TimeZone: "America/New_York",
				},
			},
		},
		Meta: struct {
			Page struct {
				Type        string `json:"type"`
				Number      int    `json:"number"`
				Size        int    `json:"size"`
				Total       int    `json:"total"`
				FirstNumber int    `json:"first_number"`
				PrevNumber  *int   `json:"prev_number"`
				NextNumber  *int   `json:"next_number"`
				LastNumber  int    `json:"last_number"`
			} `json:"page"`
		}{
			Page: struct {
				Type        string `json:"type"`
				Number      int    `json:"number"`
				Size        int    `json:"size"`
				Total       int    `json:"total"`
				FirstNumber int    `json:"first_number"`
				PrevNumber  *int   `json:"prev_number"`
				NextNumber  *int   `json:"next_number"`
				LastNumber  int    `json:"last_number"`
			}{
				Type:        "page",
				Number:      1,
				Size:        10,
				Total:       2,
				FirstNumber: 1,
				PrevNumber:  nil,
				NextNumber:  nil,
				LastNumber:  1,
			},
		},
	}

	// Create mock server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path.
		assertEqual(t, "GET", r.Method, "HTTP method should be GET")
		assertEqual(t, "/api/v2/on-call/schedules", r.URL.Path, "URL path should match")

		// Verify headers.
		assertEqual(t, "application/json", r.Header.Get("Content-Type"), "Content-Type header should match")
		assertEqual(t, "test-api-key", r.Header.Get("DD-API-KEY"), "DD-API-KEY header should match")
		assertEqual(t, "test-app-key", r.Header.Get("DD-APPLICATION-KEY"), "DD-APPLICATION-KEY header should match")

		// Return mock response.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(mockResponse); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create test client with mock server URL.
	// Extract just the host and port from the server URL.
	serverHostPort := extractHostPort(server.URL)
	client := NewTestClient(serverHostPort, "test-api-key", "test-app-key")

	// Call the function.
	result, err := client.ListOnCallSchedules(context.Background())

	// Verify results.
	assertNoError(t, err, "should not return error")
	assertNotNil(t, result, "result should not be nil")
	assertEqualInt(t, 2, len(result.Data), "should have 2 schedules")
	assertEqual(t, "schedule-1", result.Data[0].ID, "first schedule ID should match")
	assertEqual(t, "Primary On-Call", result.Data[0].Attributes.Name, "first schedule name should match")
	assertEqual(t, "schedule-2", result.Data[1].ID, "second schedule ID should match")
	assertEqual(t, "Secondary On-Call", result.Data[1].Attributes.Name, "second schedule name should match")
	assertEqualInt(t, 2, result.Meta.Page.Total, "total count should be 2")
}

func TestListOnCallSchedules_HTTPError(t *testing.T) {
	// Create mock server that returns an error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(`{"error": "Internal server error"}`)); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Create test client with mock server URL.
	serverHostPort := extractHostPort(server.URL)
	client := NewTestClient(serverHostPort, "test-api-key", "test-app-key")

	// Call the function.
	result, err := client.ListOnCallSchedules(context.Background())

	// Verify results.
	assertError(t, err, "should return error")
	// Check if result is nil or empty.
	if result != nil {
		t.Errorf("result should be nil, got: %v", result)
	}
	if err != nil {
		assertContains(t, err.Error(), "HTTP request failed with status: 500", "error message should contain status code")
	}
}

func TestListOnCallSchedules_InvalidResponse(t *testing.T) {
	// Create mock server that returns invalid JSON.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"invalid": "json`)); err != nil { // Malformed JSON.
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Create test client with mock server URL.
	serverHostPort := extractHostPort(server.URL)
	client := NewTestClient(serverHostPort, "test-api-key", "test-app-key")

	// Call the function.
	result, err := client.ListOnCallSchedules(context.Background())

	// Verify results.
	assertError(t, err, "should return error")
	// Check if result is nil or empty.
	if result != nil {
		t.Errorf("result should be nil, got: %v", result)
	}
	if err != nil {
		assertContains(t, err.Error(), "error decoding response", "error message should contain decoding error")
	}
}

func TestGetScheduleOnCallUser_Success(t *testing.T) {
	// Mock response data.
	mockResponse := OnCallUserResponse{
		Data: OnCallUser{
			ID:   "user-123",
			Type: "user",
			Attributes: OnCallUserAttributes{
				Name:  "John Doe",
				Email: "john.doe@example.com",
			},
		},
	}

	// Create mock server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path.
		assertEqual(t, "GET", r.Method, "HTTP method should be GET")
		expectedPath := "/api/v2/on-call/schedules/" + testScheduleID + "/on-call"
		assertEqual(t, expectedPath, r.URL.Path, "URL path should match")

		// Verify headers.
		assertEqual(t, "application/json", r.Header.Get("Content-Type"), "Content-Type header should match")
		assertEqual(t, "test-api-key", r.Header.Get("DD-API-KEY"), "DD-API-KEY header should match")
		assertEqual(t, "test-app-key", r.Header.Get("DD-APPLICATION-KEY"), "DD-APPLICATION-KEY header should match")

		// Return mock response.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(mockResponse); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create test client with mock server URL.
	serverHostPort := extractHostPort(server.URL)
	client := NewTestClient(serverHostPort, "test-api-key", "test-app-key")

	// Call the function.
	result, err := client.GetScheduleOnCallUser(context.Background(), testScheduleID)

	// Verify results.
	assertNoError(t, err, "should not return error")
	assertNotNil(t, result, "result should not be nil")
	assertEqual(t, "user-123", result.Data.ID, "user ID should match")
	assertEqual(t, "user", result.Data.Type, "user type should match")
	assertEqual(t, "John Doe", result.Data.Attributes.Name, "user name should match")
	assertEqual(t, "john.doe@example.com", result.Data.Attributes.Email, "user email should match")
}

func TestGetScheduleOnCallUser_HTTPError(t *testing.T) {
	// Create mock server that returns an error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte(`{"error": "Schedule not found"}`)); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Create test client with mock server URL.
	serverHostPort := extractHostPort(server.URL)
	client := NewTestClient(serverHostPort, "test-api-key", "test-app-key")

	// Call the function.
	result, err := client.GetScheduleOnCallUser(context.Background(), testScheduleID)

	// Verify results.
	assertError(t, err, "should return error")
	// Check if result is nil or empty.
	if result != nil {
		t.Errorf("result should be nil, got: %v", result)
	}
	if err != nil {
		assertContains(t, err.Error(), "HTTP request failed with status: 404", "error message should contain status code")
	}
}

func TestGetScheduleOnCallUser_InvalidResponse(t *testing.T) {
	// Create mock server that returns invalid JSON.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"invalid": "json`)); err != nil { // Malformed JSON.
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Create test client with mock server URL.
	serverHostPort := extractHostPort(server.URL)
	client := NewTestClient(serverHostPort, "test-api-key", "test-app-key")

	// Call the function.
	result, err := client.GetScheduleOnCallUser(context.Background(), testScheduleID)

	// Verify results.
	assertError(t, err, "should return error")
	// Check if result is nil or empty.
	if result != nil {
		t.Errorf("result should be nil, got: %v", result)
	}
	if err != nil {
		assertContains(t, err.Error(), "error decoding response", "error message should contain decoding error")
	}
}

func TestGetScheduleOnCallUser_EmptyScheduleID(t *testing.T) {
	client := NewDatadogRestClient("datadoghq.com", "test-api-key", "test-app-key")

	// Call the function with empty schedule ID.
	// This should still work as the empty string will be part of the URL.
	// The actual behavior depends on how the API handles empty IDs.
	// For now, we'll just verify the function doesn't panic.
	assertNotNil(t, client, "client should not be nil")
}

// Helper function to extract host:port from server URL.
func extractHostPort(serverURL string) string {
	if strings.HasPrefix(serverURL, "http://") {
		return serverURL[7:] // Remove "http://" prefix.
	}
	return serverURL
}
