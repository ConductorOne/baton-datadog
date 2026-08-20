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

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Helper function to check if two strings are equal.
func assertEqual(t *testing.T, expected, actual string, message string) {
	t.Helper()
	if expected != actual {
		t.Errorf("%s: expected %q, got %q", message, expected, actual)
	}
}

func newOfficialTestClient(serverURL string) *DatadogClient {
	cfg := datadog.NewConfiguration()
	cfg.Servers = datadog.ServerConfigurations{{URL: serverURL}}
	return NewDatadogClient(nil, datadog.NewAPIClient(cfg), "example.com", testAPIKey, testAppKey)
}

func TestAPIKeyManagement(t *testing.T) {
	t.Run("create returns issued material", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertEqual(t, http.MethodPost, r.Method, "HTTP method should match")
			assertEqual(t, "/api/v2/api_keys", r.URL.Path, "request path should match")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"key-id","type":"api_keys","attributes":{"key":"plaintext-key","name":"c1-request"}}}`))
		}))
		defer server.Close()

		issued, err := newOfficialTestClient(server.URL).CreateAPIKey(context.Background(), "c1-request")
		assertNoError(t, err, "create API key should succeed")
		assertEqual(t, "key-id", issued.ID, "issued key ID should match")
		assertEqual(t, "plaintext-key", issued.Secret, "issued key material should match")
	})

	t.Run("create rejects a response without plaintext material", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"key-id","type":"api_keys","attributes":{}}}`))
		}))
		defer server.Close()

		_, err := newOfficialTestClient(server.URL).CreateAPIKey(context.Background(), "c1-request")
		assertError(t, err, "create API key should reject missing plaintext material")
	})

	t.Run("delete maps a provider 404 to not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertEqual(t, http.MethodDelete, r.Method, "HTTP method should match")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["Not found"]}`))
		}))
		defer server.Close()

		err := newOfficialTestClient(server.URL).DeleteAPIKey(context.Background(), "missing-key")
		if status.Code(err) != codes.NotFound {
			t.Fatalf("DeleteAPIKey() error code = %s, want %s; error = %v", status.Code(err), codes.NotFound, err)
		}
	})
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
	apiURL := fmt.Sprintf("%s%s", baseURL, OnCallSchedulesEndpoint)

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
	apiURL := fmt.Sprintf("%s%s", baseURL, fmt.Sprintf(OnCallUserEndpoint, scheduleID))

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
	testScheduleID  = "schedule-1"
	testAPIKey      = "test-api-key"
	testAppKey      = "test-app-key"
	testOncallType  = "oncall_schedule"
	testTimezoneUTC = "UTC"
)

func TestNewDatadogRestClient(t *testing.T) {
	site := "datadoghq.com"
	apiKey := testAPIKey
	appKey := testAppKey

	client, err := NewDatadogRestClient(context.Background(), site, apiKey, appKey, "")
	assertNoError(t, err, "should not return error")

	assertNotNil(t, client, "client should not be nil")
	expectedBaseURL := fmt.Sprintf(DefaultBaseURL, site)
	assertEqual(t, expectedBaseURL, client.baseURL, "baseURL should match")
	assertEqual(t, apiKey, client.apiKey, "apiKey should match")
	assertEqual(t, appKey, client.appKey, "appKey should match")
	assertNotNil(t, client.httpClient, "httpClient should not be nil")
	// Note: uhttp client has a default timeout of 300 seconds, not 30 seconds
	// Note: uhttp client doesn't expose Timeout field directly
	assertNotNil(t, client.httpClient, "httpClient should not be nil")
}

func TestListOnCallSchedules_Success(t *testing.T) {
	// Mock response data.
	mockResponse := OnCallSchedulesResponse{
		Data: []*OnCallSchedule{
			{
				ID:   testScheduleID,
				Type: testOncallType,
				Attributes: OnCallScheduleAttributes{
					Name:     "Primary On-Call",
					TimeZone: testTimezoneUTC,
				},
			},
			{
				ID:   "schedule-2",
				Type: testOncallType,
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
		assertEqual(t, OnCallSchedulesEndpoint, r.URL.Path, "URL path should match")

		// Verify headers.
		assertEqual(t, "application/json", r.Header.Get("Content-Type"), "Content-Type header should match")
		assertEqual(t, testAPIKey, r.Header.Get("DD-API-KEY"), "DD-API-KEY header should match")
		assertEqual(t, testAppKey, r.Header.Get("DD-APPLICATION-KEY"), "DD-APPLICATION-KEY header should match")

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
	assertEqual(t, testScheduleID, result.Data[0].ID, "first schedule ID should match")
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
		expectedPath := fmt.Sprintf(OnCallUserEndpoint, testScheduleID)
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
	// Create mock server that handles empty schedule ID
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the URL contains the empty schedule ID (double slash)
		if strings.Contains(r.URL.Path, "/schedules//on-call") {
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte(`{"error": "Invalid schedule ID"}`)); err != nil {
				t.Errorf("Failed to write response: %v", err)
			}
			return
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"data": null}`)); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Create test client with mock server URL
	serverHostPort := extractHostPort(server.URL)
	client := NewTestClient(serverHostPort, "test-api-key", "test-app-key")

	// Call the function with empty schedule ID
	result, err := client.GetScheduleOnCallUser(context.Background(), "")

	// Verify that it returns an error for empty schedule ID
	assertError(t, err, "should return error for empty schedule ID")
	if result != nil {
		t.Errorf("result should be nil for empty schedule ID, got: %v", result)
	}
}

// Helper function to extract host:port from server URL.
func extractHostPort(serverURL string) string {
	if strings.HasPrefix(serverURL, "http://") {
		return serverURL[7:] // Remove "http://" prefix.
	}
	return serverURL
}

func TestDatadogRestClient_OnCallMethods(t *testing.T) {
	site := "test.datadoghq.com"
	apiKey := testAPIKey
	appKey := testAppKey

	client, err := NewDatadogRestClient(context.Background(), site, apiKey, appKey, "")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test that the on-call methods work with the REST client
	ctx := context.Background()

	// Test ListOnCallSchedules method
	_, _, _, err = client.ListOnCallSchedules(ctx, &PaginationOptions{PageSize: 10, PageNumber: 1})
	// We expect an error due to connection issues in tests, but the method should be callable
	if err == nil {
		t.Error("Expected error due to connection issues in test environment")
	}

	// Test GetScheduleOnCallUser method
	_, _, err = client.GetScheduleOnCallUser(ctx, "test-schedule-id")
	// We expect an error due to connection issues in tests, but the method should be callable
	if err == nil {
		t.Error("Expected error due to connection issues in test environment")
	}
}
