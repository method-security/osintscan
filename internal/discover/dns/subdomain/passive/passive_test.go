package subdomain

import (
	"context"
	"reflect"
	"testing"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
)

func TestExtractChildDomainsKeepsRecursionInScope(t *testing.T) {
	names := []string{
		"example.com", "api.example.com", "deep.api.example.com", "WWW.EXAMPLE.COM.",
		"deep.api.other.com", "api.notexample.com", "example.com.evil.test",
	}
	for _, tt := range []struct {
		depth int
		want  []string
	}{
		{0, nil},
		{1, []string{"api.example.com"}},
		{2, []string{"deep.api.example.com"}},
	} {
		got := extractChildDomains(names, " Example.COM. ", tt.depth, map[string]bool{"www.example.com": true})
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("depth %d: got %v, want %v", tt.depth, got, tt.want)
		}
	}
}

func TestDiscoverDomainsParallelHandlesNonPositiveWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, workers := range []int{0, -1} {
		results := discoverDomainsParallel(ctx, []string{"api.example.com"}, dnsfern.DiscoverDnsSubdomainPassiveConfig{}, false, true, workers)
		if len(results) != 1 || results[0].domain != "api.example.com" || len(results[0].errors) != 1 || results[0].errors[0] != context.Canceled.Error() {
			t.Fatalf("workers %d: expected cancellation to be reported, got %+v", workers, results)
		}
	}
}
