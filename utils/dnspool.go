package utils

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// UDP sockets are leased exclusively for one DNS exchange. Keeping this bound
// independent of worker count limits the scan's NAT/firewall flow footprint.
const dnsSocketsPerResolver = 8

type dnsPoolKey struct{}
type dnsSocketPool struct {
	mu      sync.Mutex
	buckets map[string]chan net.Conn
	lookups map[string]chan struct{}
	sockets map[net.Conn]struct{}
	closed  bool
	done    chan struct{}
}

// WithDNSConnectionPool scopes reusable UDP sockets to a scan. Close must be
// called when the scan finishes; cancellation also closes outstanding sockets.
func WithDNSConnectionPool(ctx context.Context) (context.Context, func()) {
	p := &dnsSocketPool{buckets: make(map[string]chan net.Conn), lookups: make(map[string]chan struct{}), sockets: make(map[net.Conn]struct{}), done: make(chan struct{})}
	stop := context.AfterFunc(ctx, p.close)
	return context.WithValue(ctx, dnsPoolKey{}, p), func() { stop(); p.close() }
}

func (p *dnsSocketPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	close(p.done)
	for conn := range p.sockets {
		_ = conn.Close()
	}
}

// AcquireDNSLookupCapacity waits before LookupHost starts its per-attempt
// timeout. Each admitted candidate may issue A and AAAA queries concurrently.
// Hold the permit through any CNAME fallback. Wildcard probes run between
// candidate batches, so they do not compete with these admitted lookups.
func AcquireDNSLookupCapacity(ctx context.Context, address string) (func(), error) {
	p, ok := ctx.Value(dnsPoolKey{}).(*dnsSocketPool)
	if !ok {
		return func() {}, nil
	}
	address = NormalizeDNSAddress(address)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	slots := p.lookups[address]
	if slots == nil {
		slots = make(chan struct{}, dnsSocketsPerResolver/2)
		p.lookups[address] = slots
	}
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, net.ErrClosed
	case slots <- struct{}{}:
	}
	if err := ctx.Err(); err != nil {
		<-slots
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(func() { <-slots }) }, nil
}

// DialDNSContext uses the scan pool for UDP, retaining ordinary TCP dialing for
// fallback. Callers must close each lease after its exchange.
func DialDNSContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	p, ok := ctx.Value(dnsPoolKey{}).(*dnsSocketPool)
	if !ok || (network != "udp" && network != "udp4" && network != "udp6") {
		return d.DialContext(ctx, network, address)
	}
	key := network + ":" + address
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	bucket := p.buckets[key]
	if bucket == nil {
		bucket = make(chan net.Conn, dnsSocketsPerResolver)
		for i := 0; i < dnsSocketsPerResolver; i++ {
			bucket <- nil
		}
		p.buckets[key] = bucket
	}
	p.mu.Unlock()
	var conn net.Conn
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, net.ErrClosed
	case conn = <-bucket:
	}
	if err := ctx.Err(); err != nil {
		bucket <- conn
		return nil, err
	}
	if conn == nil {
		var err error
		conn, err = d.DialContext(ctx, network, address)
		if err != nil {
			bucket <- nil
			return nil, err
		}
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		bucket <- nil
		return nil, net.ErrClosed
	}
	p.sockets[conn] = struct{}{}
	p.mu.Unlock()
	return &dnsSocketLease{Conn: conn, pool: p, bucket: bucket}, nil
}

type dnsSocketLease struct {
	net.Conn
	pool   *dnsSocketPool
	bucket chan net.Conn
	failed atomic.Bool
	once   sync.Once
}

func (c *dnsSocketLease) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		c.failed.Store(true)
	}
	return n, err
}
func (c *dnsSocketLease) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		c.failed.Store(true)
	}
	return n, err
}

// PacketConn identifies this lease as datagram transport to net.Resolver and dns.Conn.
func (c *dnsSocketLease) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}
func (c *dnsSocketLease) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }
func (c *dnsSocketLease) Close() error {
	c.once.Do(func() {
		c.pool.mu.Lock()
		defer c.pool.mu.Unlock()
		conn := c.Conn
		if c.failed.Load() || c.pool.closed {
			_ = conn.Close()
			delete(c.pool.sockets, conn)
			conn = nil
		} else if err := conn.SetDeadline(time.Time{}); err != nil {
			_ = conn.Close()
			delete(c.pool.sockets, conn)
			conn = nil
		}
		c.bucket <- conn
	})
	return nil
}
