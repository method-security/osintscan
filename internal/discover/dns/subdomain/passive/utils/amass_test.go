package utils

import (
	"context"
	"errors"
	"reflect"
	"testing"

	dnsfern "github.com/Method-Security/osintscan/generated/go/discover/dns"
	assettypes "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
)

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
		{" Example.COM. ", []string{"api.example.com", "deep.api.example.com"}},
		{"api.example.com", []string{"deep.api.example.com"}},
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
