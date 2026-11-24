package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSPoolBoundCancellationAndCleanup(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	ctx, closePool := WithDNSConnectionPool(context.Background())
	defer closePool()
	leases := make([]net.Conn, 0, dnsSocketsPerResolver)
	for i := 0; i < dnsSocketsPerResolver; i++ {
		conn, err := DialDNSContext(ctx, "udp", server.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, conn)
		defer func() { _ = conn.Close() }()
	}
	waiting, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := DialDNSContext(waiting, "udp", server.LocalAddr().String()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected bounded pool wait to expire, got %v", err)
	}
	addr := leases[0].LocalAddr().String()
	_ = leases[0].Close()
	reused, err := DialDNSContext(ctx, "udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reused.Close() }()
	if reused.LocalAddr().String() != addr {
		t.Fatal("lease did not reuse the released socket")
	}
	closePool()
	if _, err := reused.Write([]byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("active socket survived cleanup: %v", err)
	}
	if _, err := DialDNSContext(ctx, "udp", server.LocalAddr().String()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed pool accepted query: %v", err)
	}
}

func TestDNSPoolDiscardsTimedOutSocket(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	ctx, closePool := WithDNSConnectionPool(context.Background())
	defer closePool()
	conn, err := DialDNSContext(ctx, "udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	lease := conn.(*dnsSocketLease)
	_ = conn.SetReadDeadline(time.Now())
	if _, err := conn.Read(make([]byte, 512)); err == nil {
		t.Fatal("expected read timeout")
	}
	_ = conn.Close()
	if _, err := lease.Conn.Write([]byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("timed-out socket was not discarded: %v", err)
	}
}

func TestDNSPoolParentCancellationClosesSockets(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, closePool := WithDNSConnectionPool(parent)
	defer closePool()
	conn, err := DialDNSContext(ctx, "udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	result := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 512)); result <- err }()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected socket closure, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt active read")
	}
}

// Queueing must happen outside Resolver.Dial, whose context already includes
// the attempt timeout. Hold every socket longer than that timeout, then verify
// an admitted lookup still gets to query the DNS server successfully.
func TestDNSLookupCapacityWaitPrecedesAttemptTimeout(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	server := &dns.Server{PacketConn: packet, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(req)
		response.RecursionAvailable = true
		if req.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
		}
		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write response: %v", err)
		}
	})}
	go func() {
		if err := server.ActivateAndServe(); err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	<-ready
	defer func() { _ = server.Shutdown() }()
	parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx, closePool := WithDNSConnectionPool(parent)
	defer closePool()
	address := packet.LocalAddr().String()
	var releases []func()
	var connections []net.Conn
	for i := 0; i < dnsSocketsPerResolver/2; i++ {
		release, err := AcquireDNSLookupCapacity(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
		defer release()
		for j := 0; j < 2; j++ {
			conn, err := DialDNSContext(ctx, "udp", address)
			if err != nil {
				t.Fatal(err)
			}
			connections = append(connections, conn)
			defer func() { _ = conn.Close() }()
		}
	}
	dialed := make(chan struct{}, 10)
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		dialed <- struct{}{}
		attempt, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		return DialDNSContext(attempt, network, address)
	}}
	result := make(chan error, 1)
	go func() {
		release, err := AcquireDNSLookupCapacity(ctx, address)
		if err != nil {
			result <- err
			return
		}
		defer release()
		ips, err := resolver.LookupHost(ctx, "host.example.test.")
		if err == nil && (len(ips) != 1 || ips[0] != "192.0.2.1") {
			err = fmt.Errorf("unexpected addresses: %v", ips)
		}
		result <- err
	}()
	select {
	case <-dialed:
		t.Fatal("DNS attempt began while lookup capacity was exhausted")
	case err := <-result:
		t.Fatalf("lookup finished before capacity was released: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	for _, release := range releases {
		release()
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("queued lookup did not finish")
	}
}

func TestDNSLookupCapacityWaitRespectsCancellation(t *testing.T) {
	ctx, closePool := WithDNSConnectionPool(context.Background())
	defer closePool()
	for i := 0; i < dnsSocketsPerResolver/2; i++ {
		release, err := AcquireDNSLookupCapacity(ctx, "127.0.0.1:53")
		if err != nil {
			t.Fatal(err)
		}
		defer release()
	}
	// A saturated resolver must not block an independent resolver.
	release, err := AcquireDNSLookupCapacity(ctx, "127.0.0.2:53")
	if err != nil {
		t.Fatal(err)
	}
	release()
	waiting, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := AcquireDNSLookupCapacity(waiting, "127.0.0.1:53"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	closePool()
	if _, err := AcquireDNSLookupCapacity(ctx, "127.0.0.1:53"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected closed pool, got %v", err)
	}
}
