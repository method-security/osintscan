package utils

import (
	"context"
	"errors"
	"reflect"
	"testing"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	assettypes "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func TestAmassScopeBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name   string
		target string
		names  []string
		want   []string
	}{
		{
			name: "target_itself_is_allowed", target: "example.com",
			names: []string{"example.com"}, want: []string{"example.com"},
		},
		{
			name: "descendants_at_multiple_depths_are_allowed", target: "example.com",
			names: []string{"api.example.com", "deep.api.example.com"},
			want:  []string{"api.example.com", "deep.api.example.com"},
		},
		{
			name: "unrelated_domains_are_rejected", target: "example.com",
			names: []string{"other.com", "api.other.com", "example.net"}, want: []string{},
		},
		{
			name: "suffix_without_label_boundary_is_rejected", target: "example.com",
			names: []string{"notexample.com", "api.notexample.com", "bad-example.com"}, want: []string{},
		},
		{
			name: "target_followed_by_another_domain_is_rejected", target: "example.com",
			names: []string{"example.com.evil.test", "api.example.com.evil.test"}, want: []string{},
		},
		{
			name: "nested_target_does_not_expand_to_parent", target: "api.example.com",
			names: []string{"example.com", "api.example.com", "deep.api.example.com"},
			want:  []string{"api.example.com", "deep.api.example.com"},
		},
		{
			name: "nested_target_does_not_expand_to_siblings", target: "api.example.com",
			names: []string{"www.example.com", "deep.www.example.com", "notapi.example.com", "api.example.com.evil.test"},
			want:  []string{},
		},
		{
			name: "normalization_preserves_scope_and_removes_duplicates", target: " Example.COM. ",
			names: []string{"EXAMPLE.COM.", "example.com", " API.EXAMPLE.COM. ", "api.example.com", " API.OTHER.COM. "},
			want:  []string{"api.example.com", "example.com"},
		},
		{
			name: "wildcards_empty_labels_and_url_like_names_are_rejected", target: "example.com",
			names: []string{"*.example.com", "bad..example.com", ".example.com", "https://api.example.com", "bad/example.com", "bad\\api.example.com", "bad\tapi.example.com", "api.example.com.."},
			want:  []string{},
		},
		{
			name: "multi_label_public_suffix_does_not_widen_scope", target: "example.co.uk",
			names: []string{"co.uk", "other.co.uk", "notexample.co.uk", "api.other.co.uk", "example.co.uk", "api.example.co.uk"},
			want:  []string{"api.example.co.uk", "example.co.uk"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := buildAmassConfig(dnsfern.DiscoverDnsSubdomainPassiveConfig{Domain: tt.target}, svc1log.FromContext(context.Background()))
			if got := cfg.Domains(); !reflect.DeepEqual(got, []string{NormalizeDomain(tt.target)}) {
				t.Fatalf("Amass scope widened: got %v", got)
			}
			if !cfg.Passive || cfg.Recursive {
				t.Fatal("expected passive enumeration with Amass recursion disabled")
			}
			assets := make([]*assettypes.Asset, 0, len(tt.names))
			for _, name := range tt.names {
				assets = append(assets, &assettypes.Asset{Asset: domain.FQDN{Name: name}})
			}
			if got := scopedAmassSubdomains(assets, tt.target); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("scope violation: got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScopedAmassSubdomains(t *testing.T) {
	assets := []*assettypes.Asset{nil, {}}
	for _, name := range []string{
		"example.com", "EXAMPLE.COM.", "api.example.com", "API.EXAMPLE.COM.",
		"deep.api.example.com", "other.com", "notexample.com", "api.notexample.com",
		"example.com.evil.test", "*.example.com", "bad..example.com",
	} {
		assets = append(assets, &assettypes.Asset{Asset: domain.FQDN{Name: name}})
	}
	for _, tt := range []struct {
		target string
		want   []string
	}{
		{" Example.COM. ", []string{"api.example.com", "deep.api.example.com", "example.com"}},
		{"api.example.com", []string{"api.example.com", "deep.api.example.com"}},
		{"unknown.test", []string{}},
		{"", []string{}},
	} {
		t.Run(tt.target, func(t *testing.T) {
			if got := scopedAmassSubdomains(assets, tt.target); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAmassRejectsInvalidScopeBeforeStarting(t *testing.T) {
	for _, target := range []string{"", " ", "localhost", "example..com"} {
		t.Run(target, func(t *testing.T) {
			_, err := GetSubdomainsPassiveWithAmass(context.Background(), dnsfern.DiscoverDnsSubdomainPassiveConfig{Domain: target})
			if err == nil {
				t.Fatal("expected invalid domain error")
			}
		})
	}
}

func TestAmassHonorsCanceledContextBeforeStarting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := GetSubdomainsPassiveWithAmass(ctx, dnsfern.DiscoverDnsSubdomainPassiveConfig{Domain: "example.com"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}
