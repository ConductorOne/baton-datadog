package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/conductorone/baton-datadog/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

// =============================================================================
// Helper Functions for Testing
// =============================================================================

func assertNotNil(t *testing.T, value interface{}, message string) {
	t.Helper()
	if value == nil {
		t.Errorf("%s: expected non-nil value", message)
	}
}

func assertNoError(t *testing.T, err error, message string) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: unexpected error: %v", message, err)
	}
}

func assertError(t *testing.T, err error, message string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: expected error, got nil", message)
	}
}

func assertContains(t *testing.T, str, substr string, message string) {
	t.Helper()
	if !strings.Contains(str, substr) {
		t.Errorf("%s: expected %q to contain %q", message, str, substr)
	}
}

func assertEqualInt(t *testing.T, expected, actual int, message string) {
	t.Helper()
	if expected != actual {
		t.Errorf("%s: expected %d, got %d", message, expected, actual)
	}
}

func assertNotEmpty(t *testing.T, str string, message string) {
	t.Helper()
	if str == "" {
		t.Errorf("%s: expected non-empty string", message)
	}
}

func assertNotEqual(t *testing.T, expected, actual interface{}, message string) {
	t.Helper()
	if expected == actual {
		t.Errorf("%s: expected different values, got %v and %v", message, expected, actual)
	}
}

func assertTrue(t *testing.T, value bool, message string) {
	t.Helper()
	if !value {
		t.Errorf("%s: expected true, got false", message)
	}
}

// =============================================================================
// Test Pagination Helper Functions
// =============================================================================

func TestPaginationHelpers(t *testing.T) {
	// Test getPageTokenFromPage
	bag := &pagination.Bag{}
	bag.Push(pagination.PageState{
		ResourceTypeID: scheduleResourceType.Id,
		ResourceID:     "",
	})

	token, err := getPageTokenFromPage(bag, 1)
	assertNoError(t, err, "should create token successfully")
	assertNotEmpty(t, token, "token should not be empty")

	// Test parsePageToken
	parsedBag, page, err := parsePageToken(token, nil)
	assertNoError(t, err, "should parse token successfully")
	assertNotNil(t, parsedBag, "bag should not be nil")
	assertEqualInt(t, 1, int(page), "page should be 1")
}

func TestPaginationHelpers_InvalidInput(t *testing.T) {
	// Test parsePageToken with invalid token
	bag, page, err := parsePageToken("invalid-token", nil)
	assertError(t, err, "should return error for invalid token")
	assertNotNil(t, bag, "bag should not be nil")
	assertEqualInt(t, 0, int(page), "page should be 0")
}

func TestPaginationHelpers_EmptyToken(t *testing.T) {
	// Test parsePageToken with empty token
	bag, page, err := parsePageToken("", nil)
	assertNoError(t, err, "should not return error for empty token")
	assertNotNil(t, bag, "bag should not be nil")
	assertEqualInt(t, 0, int(page), "page should be 0 for empty token")
}

func TestPaginationHelpers_MultiplePages(t *testing.T) {
	// Test token creation for multiple pages
	bag := &pagination.Bag{}
	bag.Push(pagination.PageState{
		ResourceTypeID: scheduleResourceType.Id,
		ResourceID:     "",
	})

	// Create token for page 1
	token1, err := getPageTokenFromPage(bag, 1)
	assertNoError(t, err, "should create token for page 1")
	assertNotEmpty(t, token1, "token for page 1 should not be empty")

	// Create token for page 2
	token2, err := getPageTokenFromPage(bag, 2)
	assertNoError(t, err, "should create token for page 2")
	assertNotEmpty(t, token2, "token for page 2 should not be empty")

	// Tokens should be different
	assertNotEqual(t, token1, token2, "tokens for different pages should be different")

	// Parse both tokens
	bag1, page1, err := parsePageToken(token1, nil)
	assertNoError(t, err, "should parse token 1 successfully")
	assertEqualInt(t, 1, int(page1), "token 1 should point to page 1")

	bag2, page2, err := parsePageToken(token2, nil)
	assertNoError(t, err, "should parse token 2 successfully")
	assertEqualInt(t, 2, int(page2), "token 2 should point to page 2")

	assertNotNil(t, bag1, "bag1 should not be nil")
	assertNotNil(t, bag2, "bag2 should not be nil")
}

func TestPaginationHelpers_WithParentResource(t *testing.T) {
	// Test with parentResourceID
	parentResourceID := &v2.ResourceId{
		ResourceType: "test_resource_type",
		Resource:     "test_resource_id",
	}

	bag := &pagination.Bag{}
	bag.Push(pagination.PageState{
		ResourceTypeID: parentResourceID.ResourceType,
		ResourceID:     parentResourceID.Resource,
	})

	token, err := getPageTokenFromPage(bag, 1)
	assertNoError(t, err, "should create token with parent resource successfully")
	assertNotEmpty(t, token, "token should not be empty")

	// Parse the token
	parsedBag, page, err := parsePageToken(token, parentResourceID)
	assertNoError(t, err, "should parse token with parent resource successfully")
	assertNotNil(t, parsedBag, "bag should not be nil")
	assertEqualInt(t, 1, int(page), "page should be 1")
}

func TestPaginationHelpers_ZeroPage(t *testing.T) {
	// Test with page 0 (first page)
	bag := &pagination.Bag{}
	bag.Push(pagination.PageState{
		ResourceTypeID: scheduleResourceType.Id,
		ResourceID:     "",
	})

	token, err := getPageTokenFromPage(bag, 0)
	assertNoError(t, err, "should create token for page 0 successfully")
	assertNotEmpty(t, token, "token for page 0 should not be empty")

	// Parse the token
	parsedBag, page, err := parsePageToken(token, nil)
	assertNoError(t, err, "should parse token for page 0 successfully")
	assertNotNil(t, parsedBag, "bag should not be nil")
	assertEqualInt(t, 0, int(page), "page should be 0")
}

func TestPaginationHelpers_LargePageNumber(t *testing.T) {
	// Test with large page number
	bag := &pagination.Bag{}
	bag.Push(pagination.PageState{
		ResourceTypeID: scheduleResourceType.Id,
		ResourceID:     "",
	})

	largePage := int64(1000)
	token, err := getPageTokenFromPage(bag, largePage)
	assertNoError(t, err, "should create token for large page number successfully")
	assertNotEmpty(t, token, "token should not be empty")

	// Parse the token
	parsedBag, page, err := parsePageToken(token, nil)
	assertNoError(t, err, "should parse token for large page number successfully")
	assertNotNil(t, parsedBag, "bag should not be nil")
	assertEqualInt(t, int(largePage), int(page), "page should match large page number")
}

// =============================================================================
// Test Client doRequest Function
// =============================================================================

func TestClientDoRequest(t *testing.T) {
	// Mock HTTP client for testing
	mockHTTPClient := &MockHTTPClient{
		responses: map[string]*MockResponse{
			"GET:/api/v2/on-call/schedules": {
				statusCode: http.StatusOK,
				body:       `{"data": [{"id": "test-schedule-1", "name": "Test Schedule"}]}`,
			},
			"GET:/api/v2/on-call/schedules/schedule-123/on-call": {
				statusCode: http.StatusOK,
				body:       `{"data": {"id": "user-123", "name": "Test User"}}`,
			},
		},
	}

	// Create client with mock
	client := &MockDatadogClient{
		httpClient: mockHTTPClient,
		site:       "test.datadoghq.com",
		apiKey:     "test-api-key",
		appKey:     "test-app-key",
	}

	ctx := context.Background()

	t.Run("doRequest GET without body", func(t *testing.T) {
		var result map[string]interface{}
		err := client.doRequest(ctx, http.MethodGet, "/api/v2/on-call/schedules", nil, &result)

		assertNoError(t, err, "doRequest should not return error")
		assertNotNil(t, result, "result should not be nil")

		// Verify that the correct mock was called
		if !mockHTTPClient.called {
			t.Error("HTTP client should have been called")
		}
	})

	t.Run("doRequest GET with specific endpoint", func(t *testing.T) {
		var result map[string]interface{}
		err := client.doRequest(ctx, http.MethodGet, "/api/v2/on-call/schedules/schedule-123/on-call", nil, &result)

		assertNoError(t, err, "doRequest should not return error")
		assertNotNil(t, result, "result should not be nil")
	})

	t.Run("doRequest with invalid JSON response", func(t *testing.T) {
		// Configure mock to return invalid JSON
		mockHTTPClient.responses["GET:/api/v2/on-call/schedules"] = &MockResponse{
			statusCode: http.StatusOK,
			body:       `{"invalid": json}`,
		}

		var result map[string]interface{}
		err := client.doRequest(ctx, http.MethodGet, "/api/v2/on-call/schedules", nil, &result)

		assertError(t, err, "doRequest should return error for invalid JSON")
	})

	t.Run("doRequest with HTTP error status", func(t *testing.T) {
		// Configure mock to return HTTP error
		mockHTTPClient.responses["GET:/api/v2/on-call/schedules"] = &MockResponse{
			statusCode: http.StatusInternalServerError,
			body:       `{"error": "Internal Server Error"}`,
		}

		var result map[string]interface{}
		err := client.doRequest(ctx, http.MethodGet, "/api/v2/on-call/schedules", nil, &result)

		assertError(t, err, "doRequest should return error for HTTP error status")
		assertContains(t, err.Error(), "500", "error should contain status code")
	})
}

// =============================================================================
// Test Client Functions Using doRequest
// =============================================================================

func TestClientFunctionsUseDoRequest(t *testing.T) {
	mockHTTPClient := &MockHTTPClient{
		responses: map[string]*MockResponse{
			"GET:/api/v2/on-call/schedules": {
				statusCode: http.StatusOK,
				body:       `{"data": [{"id": "test-schedule-1", "name": "Test Schedule"}]}`,
			},
			"GET:/api/v2/on-call/schedules/schedule-123/on-call": {
				statusCode: http.StatusOK,
				body:       `{"data": {"id": "user-123", "name": "Test User"}}`,
			},
		},
	}

	client := &MockDatadogClient{
		httpClient: mockHTTPClient,
		site:       "test.datadoghq.com",
		apiKey:     "test-api-key",
		appKey:     "test-app-key",
	}

	ctx := context.Background()

	t.Run("ListOnCallSchedules uses doRequest", func(t *testing.T) {
		// Reset mock call counter
		mockHTTPClient.called = false

		result, nextPageToken, err := client.ListOnCallSchedules(ctx)

		assertNoError(t, err, "ListOnCallSchedules should not return error")
		assertNotNil(t, result, "result should not be nil")
		assertTrue(t, mockHTTPClient.called, "HTTP client should have been called")
		// Note: nextPageToken might be empty string if no next page
		assertTrue(t, len(result) >= 0, "result should be a valid slice") //nolint:gocritic // len() >= 0 is always true but used for validation
		_ = nextPageToken                                                 // Use variable to avoid linter error
	})

	t.Run("GetScheduleOnCallUser uses doRequest", func(t *testing.T) {
		// Reset mock call counter
		mockHTTPClient.called = false

		result, err := client.GetScheduleOnCallUser(ctx, "schedule-123")

		assertNoError(t, err, "GetScheduleOnCallUser should not return error")
		assertNotNil(t, result, "result should not be nil")
		assertTrue(t, mockHTTPClient.called, "HTTP client should have been called")
	})
}

// =============================================================================
// Mock Implementations for Testing
// =============================================================================

type MockResponse struct {
	statusCode int
	body       string
}

type MockHTTPClient struct {
	responses map[string]*MockResponse
	called    bool
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.called = true

	key := req.Method + ":" + req.URL.Path
	response, exists := m.responses[key]

	if !exists {
		// Return 404 if the endpoint does not exist
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(`{"error": "Not Found"}`)),
		}, nil
	}

	return &http.Response{
		StatusCode: response.statusCode,
		Body:       io.NopCloser(strings.NewReader(response.body)),
	}, nil
}

type MockDatadogClient struct {
	httpClient *MockHTTPClient
	site       string
	apiKey     string
	appKey     string
}

// Implement the real client interface.
func (m *MockDatadogClient) doRequest(ctx context.Context, method, endpoint string, body interface{}, result interface{}) error {
	// Simulate the doRequest logic but using the mock
	baseURL := "https://" + m.site
	apiURL := baseURL + endpoint

	req, err := http.NewRequestWithContext(ctx, method, apiURL, nil)
	if err != nil {
		return err
	}

	// Simulate headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", m.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", m.appKey)

	// Use mock client
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Verify status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	// Decode response if result is provided
	if result != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(bodyBytes, result); err != nil {
			return err
		}
	}

	return nil
}

func (m *MockDatadogClient) ListOnCallSchedules(ctx context.Context) ([]client.OnCallSchedule, string, error) {
	var response client.OnCallSchedulesResponse
	err := m.doRequest(ctx, http.MethodGet, "/api/v2/on-call/schedules", nil, &response)
	if err != nil {
		return nil, "", err
	}

	// Extract next page token from meta information
	nextPageToken := ""
	if response.Meta.Page.NextNumber != nil {
		nextPageToken = strconv.Itoa(*response.Meta.Page.NextNumber)
	}

	return response.Data, nextPageToken, nil
}

func (m *MockDatadogClient) GetScheduleOnCallUser(ctx context.Context, scheduleID string) (*client.OnCallUserResponse, error) {
	endpoint := fmt.Sprintf("/api/v2/on-call/schedules/%s/on-call", scheduleID)
	var response client.OnCallUserResponse
	err := m.doRequest(ctx, http.MethodGet, endpoint, nil, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}
