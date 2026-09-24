package socks5

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	udpPendingLimit  = 64
	udpDNSWorkers    = 4
	udpDNSCacheLimit = 256
	// NameResolver supplies no TTL. This is a short, per-association reuse
	// interval, not a claim about the authoritative DNS TTL.
	udpDNSReuse = 30 * time.Second
)

type udpDelivery struct {
	name string
	port int
	buf  *[]byte
	size int
}

type udpResolution struct {
	name string
	ip   net.IP
	err  error
}

type udpCachedName struct {
	ip    netip.Addr
	until time.Time
}

// udpDispatcher serializes outbound accounting and delivery. IP traffic keeps
// its synchronous path; only unresolved names need a queue. Packets
// waiting for the same name retain arrival order and share one lookup.
// At most 64 packets and four lookups can be outstanding per association.
type udpDispatcher struct {
	ctx        context.Context
	cancel     context.CancelFunc
	input      chan udpDelivery
	slots      chan struct{}
	done       chan struct{}
	sendMu     sync.Mutex
	sendPacket func([]byte, netip.AddrPort) bool
}

func newUDPDispatcher(ctx context.Context, resolve func(context.Context, string) (net.IP, error), send func([]byte, netip.AddrPort) bool, flush func()) *udpDispatcher {
	ctx, cancel := context.WithCancel(ctx)
	d := &udpDispatcher{ctx: ctx, cancel: cancel, input: make(chan udpDelivery, udpPendingLimit), slots: make(chan struct{}, udpPendingLimit), done: make(chan struct{}), sendPacket: send}
	go d.run(resolve, flush)
	return d
}

// submit never waits for DNS or queue space. UDP overload drops a datagram,
// rather than allocating an unbounded backlog or stalling the frame reader.
// Callers must check destination rules before submitting.
func (d *udpDispatcher) submit(addr *AddrSpec, payload []byte) bool {
	if d.ctx.Err() != nil {
		return false
	}
	// No copy, queue or DNS scheduling on the IP path. A burst of IP
	// datagrams must not be dropped because the DNS backlog is full.
	if addr.FQDN == "" {
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			// Neither a name nor an address, which a header spells as a name
			// of length zero. Sent as it was, the kernel read the
			// unspecified address as this host.
			return false
		}
		return d.send(payload, netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)))
	}
	select {
	case d.slots <- struct{}{}:
	default:
		return false
	}
	p := udpBufPool.Get().(*[]byte)
	copy(*p, payload)
	job := udpDelivery{name: addr.FQDN, port: addr.Port, buf: p, size: len(payload)}
	select {
	case d.input <- job:
		return true
	case <-d.ctx.Done():
		d.release(job)
		return false
	}
}

// Close is called only after the submitting reader has stopped.
func (d *udpDispatcher) close() {
	d.cancel()
	<-d.done
	for {
		select {
		case job := <-d.input:
			d.release(job)
		default:
			return
		}
	}
}

func (d *udpDispatcher) release(job udpDelivery) {
	udpBufPool.Put(job.buf)
	<-d.slots
}

func (d *udpDispatcher) run(resolve func(context.Context, string) (net.IP, error), flush func()) {
	defer close(d.done)
	defer func() { d.sendMu.Lock(); defer d.sendMu.Unlock(); flush() }()
	defer d.cancel()
	results := make(chan udpResolution, udpDNSWorkers)
	var workers sync.WaitGroup
	defer func() { d.cancel(); workers.Wait() }()
	pending := make(map[string][]udpDelivery)
	defer func() {
		for _, jobs := range pending {
			for _, job := range jobs {
				d.release(job)
			}
		}
	}()
	cache := make(map[string]udpCachedName)
	// A fixed ring gives bounded eviction work; no cache-size scan per packet.
	var names [udpDNSCacheLimit]string
	next := 0
	deliver := func(job udpDelivery, ip netip.Addr) bool {
		defer d.release(job)
		if d.ctx.Err() != nil {
			return false
		}
		return d.send((*job.buf)[:job.size], netip.AddrPortFrom(ip, uint16(job.port)))
	}
	for {
		select {
		case <-d.ctx.Done():
			return
		case job := <-d.input:

			if jobs, ok := pending[job.name]; ok {
				pending[job.name] = append(jobs, job)
				continue
			}
			if cached, ok := cache[job.name]; ok && time.Now().Before(cached.until) {
				if !deliver(job, cached.ip) {
					return
				}
				continue
			}
			if len(pending) >= udpDNSWorkers {
				d.release(job)
				continue
			}
			pending[job.name] = []udpDelivery{job}
			workers.Go(func() {
				ip, err := resolve(d.ctx, job.name)
				select {
				case results <- udpResolution{job.name, ip, err}:
				case <-d.ctx.Done():
				}
			})
		case result := <-results:
			jobs := pending[result.name]
			delete(pending, result.name)
			ip, resolved := netip.AddrFromSlice(result.ip)
			resolved = resolved && result.err == nil
			if resolved {
				ip = ip.Unmap()
				if _, ok := cache[result.name]; !ok {
					delete(cache, names[next])
					names[next] = result.name
					next = (next + 1) % len(names)
				}
				cache[result.name] = udpCachedName{ip: ip, until: time.Now().Add(udpDNSReuse)}
			}
			for i, job := range jobs {
				if !resolved {
					d.release(job)
					continue
				}
				if !deliver(job, ip) {
					for _, rest := range jobs[i+1:] {
						d.release(rest)
					}
					return
				}
			}
		}
	}
}

// The DNS dispatcher and the IP reader share the same meter. Keep that
// accounting serialized and never forward packets after quota cancellation.
func (d *udpDispatcher) send(payload []byte, addr netip.AddrPort) bool {
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	if d.ctx.Err() != nil {
		return false
	}
	if !d.sendPacket(payload, addr) {
		d.cancel()
		return false
	}
	return true
}

func (s *Server) datagramResolver(budget time.Duration) func(context.Context, string) (net.IP, error) {
	if budget <= 0 {
		budget = 5 * time.Second
	}
	return func(ctx context.Context, name string) (net.IP, error) {
		return s.resolveWithin(ctx, budget, name)
	}
}
