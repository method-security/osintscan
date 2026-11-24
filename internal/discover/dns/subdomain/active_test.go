package subdomain

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Method-Security/osintscan/utils"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func TestSystemResolverBypassesPoolAdmission(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []string
	}{
		{name: "no explicit resolvers"},
		{name: "empty resolver address", addresses: []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			ctx, closePool := utils.WithDNSConnectionPool(parent)
			defer closePool()
			const rawResolver = "127.0.0.1:53"
			// Exhaust the four lookup permits. System lookups must not wait
			// for permits belonging to the custom-resolver socket pool.
			for i := 0; i < 4; i++ {
				release, err := utils.AcquireDNSLookupCapacity(ctx, rawResolver)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			}
			resolvers := utils.GetResolvers(tc.addresses, svc1log.FromContext(ctx))
			// Literal addresses exercise LookupHost without external DNS or
			// depending on the machine's resolver configuration.
			candidates := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8"}
			var wg sync.WaitGroup
			var mu sync.Mutex
			var subdomains []string
			found := testPermutations(ctx, candidates, resolvers, make(chan struct{}, 8), &wg, &mu, map[string]struct{}{}, &subdomains, 1, 1, 0, []string{rawResolver})
			if len(found) != len(candidates) {
				t.Fatalf("system resolver was blocked by pool admission: found %d of %d candidates (context: %v)", len(found), len(candidates), ctx.Err())
			}
		})
	}
}
