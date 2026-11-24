package utils

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
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
