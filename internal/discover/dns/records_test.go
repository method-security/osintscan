package dns

import (
	"reflect"
	"testing"

	"github.com/Method-Security/osintscan/generated/go/common"
	"github.com/miekg/dns"
)

func TestNormalizeDnsxResolversTrimsAndNormalizesAddresses(t *testing.T) {
	input := []string{" 8.8.8.8 ", " tcp:1.1.1.1 ", "udp:9.9.9.9:5353 "}
	expected := []string{"udp:8.8.8.8:53", "tcp:1.1.1.1:53", "udp:9.9.9.9:5353"}

	actual := normalizeDnsxResolvers(input, false)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

func TestNormalizeDnsxResolversForcesTCP(t *testing.T) {
	input := []string{"udp:8.8.8.8", "tcp:1.1.1.1", "9.9.9.9"}
	expected := []string{"tcp:8.8.8.8:53", "tcp:1.1.1.1:53", "tcp:9.9.9.9:53"}

	actual := normalizeDnsxResolvers(input, true)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

// TestMiekgDNSQueryTypeConstants guards the miekg/dns type constants that
// DiscoverDomainDNSRecords queries with. These are wire-format values fixed by
// IANA, so a dependency bump that changes one would silently send the wrong
// question type rather than fail to compile.
func TestMiekgDNSQueryTypeConstants(t *testing.T) {
	expected := map[string]uint16{
		"A":     1,
		"NS":    2,
		"CNAME": 5,
		"SOA":   6,
		"PTR":   12,
		"MX":    15,
		"TXT":   16,
		"AAAA":  28,
		"SRV":   33,
		"CAA":   257,
	}
	actual := map[string]uint16{
		"A":     dns.TypeA,
		"NS":    dns.TypeNS,
		"CNAME": dns.TypeCNAME,
		"SOA":   dns.TypeSOA,
		"PTR":   dns.TypePTR,
		"MX":    dns.TypeMX,
		"TXT":   dns.TypeTXT,
		"AAAA":  dns.TypeAAAA,
		"SRV":   dns.TypeSRV,
		"CAA":   dns.TypeCAA,
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

func TestSplitDnsxResolverProtoSeparatesKnownPrefixes(t *testing.T) {
	for _, tc := range []struct {
		input     string
		wantProto string
		wantHost  string
	}{
		{"tcp:1.1.1.1", "tcp:", "1.1.1.1"},
		{"udp:8.8.8.8:5353", "udp:", "8.8.8.8:5353"},
		{"9.9.9.9", "", "9.9.9.9"},
		{"9.9.9.9:53", "", "9.9.9.9:53"},
	} {
		proto, host := splitDnsxResolverProto(tc.input)
		if proto != tc.wantProto || host != tc.wantHost {
			t.Fatalf("splitDnsxResolverProto(%q) = (%q, %q), want (%q, %q)",
				tc.input, proto, host, tc.wantProto, tc.wantHost)
		}
	}
}

func TestFilterDNSRecordsByType(t *testing.T) {
	records := []*common.DnsRecord{
		{Name: "example.com", Type: common.DnsRecordTypeA, Value: "1.2.3.4"},
		{Name: "example.com", Type: common.DnsRecordTypeMx, Value: "mail.example.com"},
		{Name: "example.com", Type: common.DnsRecordTypeTxt, Value: "v=spf1 -all"},
	}

	values := func(in []*common.DnsRecord) []string {
		out := []string{}
		for _, record := range in {
			out = append(out, string(record.Type))
		}
		return out
	}

	for _, tc := range []struct {
		name  string
		types []common.DnsRecordType
		want  []string
	}{
		{"no types returns everything", nil, []string{"A", "MX", "TXT"}},
		{"ALL returns everything", []common.DnsRecordType{common.DnsRecordTypeAll}, []string{"A", "MX", "TXT"}},
		{"ALL alongside a narrower type still returns everything",
			[]common.DnsRecordType{common.DnsRecordTypeMx, common.DnsRecordTypeAll}, []string{"A", "MX", "TXT"}},
		{"single type filters", []common.DnsRecordType{common.DnsRecordTypeMx}, []string{"MX"}},
		{"multiple types filter", []common.DnsRecordType{common.DnsRecordTypeA, common.DnsRecordTypeTxt}, []string{"A", "TXT"}},
		{"unmatched type yields nothing", []common.DnsRecordType{common.DnsRecordTypeSrv}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := values(filterDNSRecordsByType(records, tc.types))
			if !reflect.DeepEqual(actual, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, actual)
			}
		})
	}
}
