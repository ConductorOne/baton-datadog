package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestPaginatedClient is a test client that uses HTTP instead of HTTPS.
type TestPaginatedClient struct {
	httpClient *http.Client
	site       string
	apiKey     string
	appKey     string
}

// ListOnCallSchedulesPaginated implements pagination for tests using HTTP.
func (c *TestPaginatedClient) ListOnCallSchedulesPaginated(ctx context.Context, opts *PaginationOptions) (*OnCallSchedulesResponse, *PaginationResult, error) {
	// Set default options if not provided
	if opts == nil {
		opts = &PaginationOptions{
			PageSize:   PageSize, // Default page size
			PageNumber: 0,        // First page
		}
	}

	// Build the URL using HTTP for tests
	baseURL := fmt.Sprintf("http://%s", c.site)
	apiURL := fmt.Sprintf("%s/api/v2/on-call/schedules", baseURL)

	// Add pagination parameters
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing URL: %w", err)
	}

	q := u.Query()
	q.Set("page[size]", fmt.Sprintf("%d", opts.PageSize))
	q.Set("page[number]", fmt.Sprintf("%d", opts.PageNumber))
	u.RawQuery = q.Encode()

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)

	// Make the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error making HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Verify the status code
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	// Parse the response
	var schedulesResponse OnCallSchedulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&schedulesResponse); err != nil {
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

func TestPaginationOptions_DefaultValues(t *testing.T) {
	opts := &PaginationOptions{}

	// The default values should be 0
	if opts.PageSize != 0 {
		t.Errorf("Expected PageSize to be 0, got %d", opts.PageSize)
	}
	if opts.PageNumber != 0 {
		t.Errorf("Expected PageNumber to be 0, got %d", opts.PageNumber)
	}
}

func TestPaginationResult_Methods(t *testing.T) {
	// Case with next page
	resultWithNext := &PaginationResult{
		Data:       []OnCallSchedule{},
		NextPage:   &[]int{1}[0],
		Total:      100,
		PageNumber: 0,
		PageSize:   50,
		LastNumber: 1,
	}

	if !resultWithNext.HasNextPage() {
		t.Error("Expected HasNextPage to return true when NextPage is not nil")
	}

	if resultWithNext.GetNextPageNumber() != 1 {
		t.Errorf("Expected GetNextPageNumber to return 1, got %d", resultWithNext.GetNextPageNumber())
	}

	if resultWithNext.IsLastPage() {
		t.Error("Expected IsLastPage to return false when NextPage is not nil")
	}

	if resultWithNext.GetTotalPages() != 2 {
		t.Errorf("Expected GetTotalPages to return 2, got %d", resultWithNext.GetTotalPages())
	}

	// Case without next page (last page)
	resultWithoutNext := &PaginationResult{
		Data:       []OnCallSchedule{},
		NextPage:   nil,
		Total:      100,
		PageNumber: 1,
		PageSize:   50,
		LastNumber: 1,
	}

	if resultWithoutNext.HasNextPage() {
		t.Error("Expected HasNextPage to return false when NextPage is nil")
	}

	if resultWithoutNext.GetNextPageNumber() != -1 {
		t.Errorf("Expected GetNextPageNumber to return -1, got %d", resultWithoutNext.GetNextPageNumber())
	}

	if !resultWithoutNext.IsLastPage() {
		t.Error("Expected IsLastPage to return true when NextPage is nil")
	}
}

func TestListOnCallSchedulesPaginated_WithPagination(t *testing.T) {
	// Mock response with pagination
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
				Type:        "number_size",
				Number:      0,
				Size:        2,
				Total:       5,
				FirstNumber: 0,
				PrevNumber:  nil,
				NextNumber:  &[]int{1}[0],
				LastNumber:  2,
			},
		},
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that the pagination parameters are present
		pageSize := r.URL.Query().Get("page[size]")
		pageNumber := r.URL.Query().Get("page[number]")

		if pageSize == "" {
			t.Error("Expected page[size] parameter to be present")
		}
		if pageNumber == "" {
			t.Error("Expected page[number] parameter to be present")
		}

		// Verify that the page size is 2
		if pageSize != "2" {
			t.Errorf("Expected page[size] to be '2', got '%s'", pageSize)
		}

		// Verify that the page number is 0
		if pageNumber != "0" {
			t.Errorf("Expected page[number] to be '0', got '%s'", pageNumber)
		}

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(mockResponse); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create test client
	serverHostPort := extractHostPort(server.URL)

	// Create test paginated client that uses HTTP for mock servers
	paginatedClient := &TestPaginatedClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		site:       serverHostPort,
		apiKey:     "test-api-key",
		appKey:     "test-app-key",
	}

	// Call the function with pagination
	opts := &PaginationOptions{
		PageSize:   2,
		PageNumber: 0,
	}

	response, paginationResult, err := paginatedClient.ListOnCallSchedulesPaginated(context.Background(), opts)

	// Verify results
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if response == nil {
		t.Error("Expected response to not be nil")
	}

	if paginationResult == nil {
		t.Error("Expected paginationResult to not be nil")
		return
	}

	// Verify pagination data
	if paginationResult.Total != 5 {
		t.Errorf("Expected Total to be 5, got %d", paginationResult.Total)
	}

	if paginationResult.PageNumber != 0 {
		t.Errorf("Expected PageNumber to be 0, got %d", paginationResult.PageNumber)
	}

	if paginationResult.PageSize != 2 {
		t.Errorf("Expected PageSize to be 2, got %d", paginationResult.PageSize)
	}

	if paginationResult.LastNumber != 2 {
		t.Errorf("Expected LastNumber to be 2, got %d", paginationResult.LastNumber)
	}

	// Verify that there is a next page
	if !paginationResult.HasNextPage() {
		t.Error("Expected HasNextPage to return true")
	}

	if paginationResult.GetNextPageNumber() != 1 {
		t.Errorf("Expected GetNextPageNumber to return 1, got %d", paginationResult.GetNextPageNumber())
	}

	// Verify that it is not the last page
	if paginationResult.IsLastPage() {
		t.Error("Expected IsLastPage to return false")
	}

	// Verify total pages calculation
	expectedTotalPages := 3 // (5 total + 2 size - 1) / 2 size = 3
	if paginationResult.GetTotalPages() != expectedTotalPages {
		t.Errorf("Expected GetTotalPages to return %d, got %d", expectedTotalPages, paginationResult.GetTotalPages())
	}
}

func TestListOnCallSchedulesPaginated_DefaultOptions(t *testing.T) {
	// Mock response for first page
	mockResponse := OnCallSchedulesResponse{
		Data: []OnCallSchedule{
			{
				ID:   "schedule-1",
				Type: "oncall_schedule",
				Attributes: OnCallScheduleAttributes{
					Name:     "Test Schedule",
					TimeZone: "UTC",
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
				Type:        "number_size",
				Number:      0,
				Size:        100,
				Total:       1,
				FirstNumber: 0,
				PrevNumber:  nil,
				NextNumber:  nil,
				LastNumber:  0,
			},
		},
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify default parameters
		pageSize := r.URL.Query().Get("page[size]")
		pageNumber := r.URL.Query().Get("page[number]")

		if pageSize != "100" {
			t.Errorf("Expected default page[size] to be '100', got '%s'", pageSize)
		}
		if pageNumber != "0" {
			t.Errorf("Expected default page[number] to be '0', got '%s'", pageNumber)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(mockResponse); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create test client
	serverHostPort := extractHostPort(server.URL)

	// Create test paginated client that uses HTTP for mock servers
	paginatedClient := &TestPaginatedClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		site:       serverHostPort,
		apiKey:     "test-api-key",
		appKey:     "test-app-key",
	}

	// Call the function without options (should use default values)
	response, paginationResult, err := paginatedClient.ListOnCallSchedulesPaginated(context.Background(), nil)

	// Verify results
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if response == nil {
		t.Error("Expected response to not be nil")
	}

	if paginationResult == nil {
		t.Error("Expected paginationResult to not be nil")
	}

	// Verify that it is the last page
	if !paginationResult.IsLastPage() {
		t.Error("Expected IsLastPage to return true for single page result")
	}

	if paginationResult.GetNextPageNumber() != -1 {
		t.Errorf("Expected GetNextPageNumber to return -1 for last page, got %d", paginationResult.GetNextPageNumber())
	}
}

// GetTotalPages calculates the total number of pages (helper for unit tests).
func (pr *PaginationResult) GetTotalPages() int {
	if pr.PageSize == 0 {
		return 0
	}
	return (pr.Total + pr.PageSize - 1) / pr.PageSize
}
