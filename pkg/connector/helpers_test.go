package connector

import (
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
)

func TestHasMoreAPIKeyPages(t *testing.T) {
	// Cases where meta is absent: fall back to count-based heuristic.
	tests := []struct {
		name     string
		res      *datadogV2.APIKeysResponse
		page     int64
		count    int64
		pageSize int64
		want     bool
	}{
		{name: "nil response with data", res: nil, page: 0, count: 10, pageSize: 100, want: true},
		{name: "nil response empty", res: nil, page: 0, count: 0, pageSize: 100, want: false},
		{name: "without meta full page", res: &datadogV2.APIKeysResponse{}, page: 0, count: 100, pageSize: 100, want: true},
		{name: "without meta partial page", res: &datadogV2.APIKeysResponse{}, page: 0, count: 50, pageSize: 100, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasMoreAPIKeyPages(tt.res, tt.page, tt.count, tt.pageSize)
			if got != tt.want {
				t.Errorf("hasMoreAPIKeyPages() = %v, want %v", got, tt.want)
			}
		})
	}

	// Authoritative total (HasTotalFilteredCount set to a real value).
	metaWithTotal := func(total int64) *datadogV2.APIKeysResponse {
		page := datadogV2.NewAPIKeysResponseMetaPage()
		page.SetTotalFilteredCount(total)
		return &datadogV2.APIKeysResponse{
			Meta: &datadogV2.APIKeysResponseMeta{Page: page},
		}
	}

	if !hasMoreAPIKeyPages(metaWithTotal(250), 0, 100, 100) {
		t.Error("page 0 of 250: expected more")
	}
	if !hasMoreAPIKeyPages(metaWithTotal(250), 1, 100, 100) {
		t.Error("page 1 of 250: expected more")
	}
	if hasMoreAPIKeyPages(metaWithTotal(250), 2, 50, 100) {
		t.Error("page 2 of 250 with 50: expected done")
	}

	// Meta with nil page: count-based, same as "no meta".
	nilPage := &datadogV2.APIKeysResponse{Meta: &datadogV2.APIKeysResponseMeta{}}
	if !hasMoreAPIKeyPages(nilPage, 0, 100, 100) {
		t.Error("nil page, 100 items: expected true (count-based)")
	}
	if hasMoreAPIKeyPages(nilPage, 0, 0, 100) {
		t.Error("nil page, 0 items: expected false")
	}
}
