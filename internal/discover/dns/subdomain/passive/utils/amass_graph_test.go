package utils

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/caffix/netmap"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

// These operations are used inside Amass itself, beyond osintscan's result reader.
func TestAmassGraphRelations(t *testing.T) {
	for _, kind := range []string{"CNAME", "PTR", "NS", "MX"} {
		t.Run(kind, func(t *testing.T) {
			graph := newAmassTestGraph(t)
			ctx := context.Background()
			source, target := "alias.example.com", "host.other.test"
			var err error
			var found bool
			switch kind {
			case "CNAME":
				err = graph.UpsertCNAME(ctx, source, target)
				found = graph.IsCNAMENode(ctx, source, time.Time{})
			case "PTR":
				err = graph.UpsertPTR(ctx, source, target)
				found = graph.IsPTRNode(ctx, source, time.Time{})
			case "NS":
				err = graph.UpsertNS(ctx, source, target)
				found = graph.IsNSNode(ctx, target, time.Time{})
			case "MX":
				err = graph.UpsertMX(ctx, source, target)
				found = graph.IsMXNode(ctx, target, time.Time{})
			}
			if err != nil {
				t.Fatalf("store %s relation: %v", kind, err)
			}
			if !found {
				t.Fatalf("stored %s relation was not recognized by netmap", kind)
			}
			if graph.IsCNAMENode(ctx, "missing.example.com", time.Time{}) ||
				graph.IsPTRNode(ctx, "missing.example.com", time.Time{}) ||
				graph.IsNSNode(ctx, "missing.example.com", time.Time{}) ||
				graph.IsMXNode(ctx, "missing.example.com", time.Time{}) {
				t.Fatal("missing node unexpectedly has a relation")
			}
		})
	}
}

func TestAmassGraphKnownNamesUseValueAssets(t *testing.T) {
	graph := newAmassTestGraph(t)
	root, err := graph.UpsertFQDN(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := graph.DB.Create(root, "node", domain.FQDN{Name: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	assets, err := graph.DB.FindByScope([]oam.Asset{domain.FQDN{Name: "example.com"}}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	foundChild := false
	for _, asset := range assets {
		// Amass readNamesFromDatabase and linkNodesToApexes assert this exact type.
		fqdn, ok := asset.Asset.(domain.FQDN)
		if !ok {
			t.Fatalf("Amass cannot consume decoded asset type %T", asset.Asset)
		}
		if fqdn.Name == "api.example.com" {
			foundChild = true
		}
	}
	if !foundChild {
		t.Fatal("stored child was not available for Amass known-name reuse")
	}
}

func TestAmassGraphAddressResolution(t *testing.T) {
	for _, kind := range []string{"A", "AAAA", "CNAME", "SRV"} {
		t.Run(kind, func(t *testing.T) {
			graph := newAmassTestGraph(t)
			ctx := context.Background()
			name, address := "host.example.com", "192.0.2.10"
			var err error
			if kind == "AAAA" {
				address = "2001:db8::10"
				err = graph.UpsertAAAA(ctx, name, address)
			} else {
				err = graph.UpsertA(ctx, name, address)
			}
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "CNAME":
				err = graph.UpsertCNAME(ctx, "alias.example.com", name)
				name = "alias.example.com"
			case "SRV":
				err = graph.UpsertSRV(ctx, "_service._tcp.example.com", name)
				name = "_service._tcp.example.com"
			}
			if err != nil {
				t.Fatal(err)
			}
			pairs, err := graph.NamesToAddrs(ctx, time.Time{}, name)
			if err != nil {
				t.Fatalf("resolve stored %s relation: %v", kind, err)
			}
			if len(pairs) != 1 || pairs[0].FQDN.Name != name || pairs[0].Addr.Address.String() != address {
				t.Fatalf("expected %s -> %s, got %+v", name, address, pairs)
			}
		})
	}
}

func TestAmassGraphInfrastructureRoundTrip(t *testing.T) {
	graph := newAmassTestGraph(t)
	ctx := context.Background()
	if err := graph.UpsertInfrastructure(ctx, 64512, "test network", "192.0.2.10", "192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	if got := graph.ReadASDescription(ctx, 64512, time.Time{}); got != "test network" {
		t.Fatalf("lost AS description: %q", got)
	}
	if got := graph.ReadASPrefixes(ctx, 64512, time.Time{}); !reflect.DeepEqual(got, []string{"192.0.2.0/24"}) {
		t.Fatalf("lost AS prefixes: %v", got)
	}
}

func newAmassTestGraph(t *testing.T) *netmap.Graph {
	t.Helper()
	graph := netmap.NewGraph("local", filepath.Join(t.TempDir(), "amass.sqlite"), "")
	if graph == nil {
		t.Fatal("failed to create Amass graph")
	}
	return graph
}
