package subdomain

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/Method-Security/osintscan/utils"
	"github.com/miekg/dns"
)

func TestActiveDiscoveryReusesUDPSocketsAcrossLookupPaths(t *testing.T) {
	var mu sync.Mutex
	peers := make(map[string]struct{})
	types := make(map[uint16]int)
	words := []string{"dangling"}
	hosts := make(map[string]bool)
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("host%d", i)
		words = append(words, name)
		hosts[name+".example.test."] = true
	}
	resolver := startWildcardTestDNSServer(t, func(w dns.ResponseWriter, req *dns.Msg) {
		mu.Lock()
		peers[w.RemoteAddr().String()] = struct{}{}
		types[req.Question[0].Qtype]++
		mu.Unlock()
		response := new(dns.Msg)
		response.SetReply(req)
		response.RecursionAvailable = true
		q := req.Question[0]
		if hosts[q.Name] && q.Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.10")}}
		} else if q.Name == "dangling.example.test." && q.Qtype == dns.TypeCNAME {
			response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "missing.example.test."}}
		} else {
			response.Rcode = dns.RcodeNameError
			response.Ns = []dns.RR{wildcardTestSOA()}
		}
		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write: %v", err)
		}
	})
	found, err := getSubdomainsActive(context.Background(), "example.test", words, 32, 1, 1, 0, 1, []string{resolver})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != len(words) {
		t.Fatalf("found %d candidates, want %d", len(found), len(words))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(peers) > 8 {
		t.Fatalf("used %d UDP source ports for one resolver, want <=8", len(peers))
	}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
		if types[qtype] == 0 {
			t.Fatalf("no %s queries observed", dns.TypeToString[qtype])
		}
	}
}

func TestPooledUDPTruncationFallsBackToTCP(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(req)
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			response.Truncated = true
		} else {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.10")}}
		}
		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write: %v", err)
		}
	})
	for _, server := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() {
			if err := server.ActivateAndServe(); err != nil {
				t.Errorf("serve: %v", err)
			}
		}()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	ctx, closePool := utils.WithDNSConnectionPool(context.Background())
	defer closePool()
	msg := new(dns.Msg)
	msg.SetQuestion("host.example.test.", dns.TypeA)
	response, err := exchangeDNSWithFallbackContext(ctx, msg, tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if response.Truncated || len(response.Answer) != 1 {
		t.Fatalf("expected full TCP response, got %v", response)
	}
}
