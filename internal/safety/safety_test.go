package safety

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.9.9.9", "0.0.0.0", "10.1.2.3", "172.16.0.1",
		"172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"198.18.0.1", "224.0.0.1", "255.255.255.255",
		"::1", "::", "fe80::1", "fc00::1", "fd00::abcd", "ff02::1",
		"::ffff:127.0.0.1", // IPv4-mapped loopback
		"::ffff:10.0.0.1",  // IPv4-mapped private
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q is not a valid IP", s)
		}
		if _, ok := BlockedIP(ip); !ok {
			t.Errorf("BlockedIP(%s) = allowed, want blocked", s)
		}
	}

	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q is not a valid IP", s)
		}
		if reason, ok := BlockedIP(ip); ok {
			t.Errorf("BlockedIP(%s) = blocked (%s), want allowed", s, reason)
		}
	}

	if _, ok := BlockedIP(nil); !ok {
		t.Error("a nil IP must be treated as blocked")
	}
}

func TestBlockedHostname(t *testing.T) {
	blocked := []string{
		"localhost", "LOCALHOST", "localhost.", "app.localhost",
		"printer.local", "db.internal", "metadata.google.internal",
		"host.home.arpa", "nas.lan", "", "   ",
	}
	for _, h := range blocked {
		if _, ok := BlockedHostname(h); !ok {
			t.Errorf("BlockedHostname(%q) = allowed, want blocked", h)
		}
	}

	// A name that merely contains a blocked word is fine.
	for _, h := range []string{"example.com", "api.github.com", "localhosting.com"} {
		if reason, ok := BlockedHostname(h); ok {
			t.Errorf("BlockedHostname(%q) = blocked (%s), want allowed", h, reason)
		}
	}
}

func TestCheckTargetIPLiterals(t *testing.T) {
	g := &Guard{}

	for _, host := range []string{"127.0.0.1", "169.254.169.254", "192.168.0.5", "::1"} {
		err := g.CheckTarget(context.Background(), host)
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Errorf("CheckTarget(%q) = %v, want *BlockedError", host, err)
		}
	}

	if err := g.CheckTarget(context.Background(), "8.8.8.8"); err != nil {
		t.Errorf("public literal was rejected: %v", err)
	}
}

func TestCheckTargetReservedNames(t *testing.T) {
	g := &Guard{}
	for _, host := range []string{"localhost", "db.internal", "router.lan"} {
		err := g.CheckTarget(context.Background(), host)
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Errorf("CheckTarget(%q) = %v, want *BlockedError", host, err)
		}
	}
}

// TestCheckTargetRejectsPrivateResolution uses a stub resolver so the test
// needs no network: a harmless-looking name that answers with a private
// address must still be refused.
func TestCheckTargetRejectsPrivateResolution(t *testing.T) {
	g := &Guard{Resolver: stubResolver(t, "10.0.0.7")}

	err := g.CheckTarget(context.Background(), "sneaky.example")
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v (%T), want *BlockedError", err, err)
	}
}

// A name answering with one public and one private address is refused too.
func TestCheckTargetRejectsMixedResolution(t *testing.T) {
	g := &Guard{Resolver: stubResolver(t, "93.184.216.34", "192.168.1.50")}

	err := g.CheckTarget(context.Background(), "mixed.example")
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v (%T), want *BlockedError", err, err)
	}
}

func TestCheckTargetAcceptsPublicResolution(t *testing.T) {
	g := &Guard{Resolver: stubResolver(t, "93.184.216.34")}

	if err := g.CheckTarget(context.Background(), "public.example"); err != nil {
		t.Fatalf("public name was rejected: %v", err)
	}
}

func TestCheckTargetUnresolvable(t *testing.T) {
	g := &Guard{
		ResolveTimeout: 2 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("no nameserver")
			},
		},
	}

	err := g.CheckTarget(context.Background(), "netpulse-nonexistent.invalid")
	if err == nil {
		t.Fatal("expected an error for an unresolvable name")
	}
	var blocked *BlockedError
	if errors.As(err, &blocked) {
		t.Error("an unresolvable name is invalid input, not a policy refusal")
	}
}

func TestAllowPrivateDisablesChecks(t *testing.T) {
	g := &Guard{AllowPrivate: true}

	for _, host := range []string{"127.0.0.1", "localhost", "10.0.0.1"} {
		if err := g.CheckTarget(context.Background(), host); err != nil {
			t.Errorf("development mode should allow %q: %v", host, err)
		}
	}
}

// TestDialerBlocksLoopback is the check that matters most: the connect-time
// hook must refuse a private address even when CheckTarget was never called,
// which is the situation DNS rebinding and redirects create.
func TestDialerBlocksLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	conn, err := (&Guard{}).Dialer().DialContext(context.Background(), "tcp", ln.Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("dialer connected to loopback, the Control hook did not fire")
	}

	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v (%T), want *BlockedError", err, err)
	}
}

func TestDialerAllowsLoopbackInDevelopmentMode(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	conn, err := (&Guard{AllowPrivate: true}).Dialer().
		DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("development mode should permit loopback: %v", err)
	}
	conn.Close()
}

// stubResolver returns a resolver that answers every lookup with fixed
// addresses, by running a tiny DNS server over a local UDP socket.
func stubResolver(t *testing.T, addrs ...string) *net.Resolver {
	t.Helper()

	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			t.Fatalf("test bug: %q is not a valid IP", a)
		}
		ips = append(ips, ip)
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go serveStubDNS(conn, ips)

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", conn.LocalAddr().String())
		},
	}
}

// serveStubDNS answers every query with the given addresses. It understands
// just enough of RFC 1035 to satisfy the Go resolver.
func serveStubDNS(conn net.PacketConn, ips []net.IP) {
	buf := make([]byte, 512)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		reply := buildStubReply(buf[:n], ips)
		if reply != nil {
			conn.WriteTo(reply, from)
		}
	}
}

func buildStubReply(query []byte, ips []net.IP) []byte {
	const headerLen = 12
	if len(query) < headerLen {
		return nil
	}

	// Walk the question name to find where the question section ends.
	offset := headerLen
	for offset < len(query) {
		labelLen := int(query[offset])
		if labelLen == 0 {
			offset++
			break
		}
		offset += labelLen + 1
	}
	if offset+4 > len(query) {
		return nil
	}
	qtype := uint16(query[offset])<<8 | uint16(query[offset+1])
	questionEnd := offset + 4

	// Answer A for qtype 1 and AAAA for qtype 28; anything else gets an empty
	// but successful reply so the resolver does not retry forever.
	var (
		answers []byte
		count   int
	)
	for _, ip := range ips {
		v4 := ip.To4()
		switch {
		case qtype == 1 && v4 != nil:
			answers = append(answers, stubRecord(1, v4)...)
			count++
		case qtype == 28 && v4 == nil:
			answers = append(answers, stubRecord(28, ip.To16())...)
			count++
		}
	}

	reply := make([]byte, 0, questionEnd+len(answers))
	reply = append(reply, query[:questionEnd]...)
	reply[2] = 0x81 // response, recursion desired
	reply[3] = 0x80 // recursion available, no error
	reply[6] = byte(count >> 8)
	reply[7] = byte(count)
	reply[8], reply[9] = 0, 0   // no authority records
	reply[10], reply[11] = 0, 0 // no additional records
	return append(reply, answers...)
}

// stubRecord builds one answer record using a compression pointer back to the
// question's name at offset 12.
func stubRecord(rrType uint16, data []byte) []byte {
	rec := []byte{
		0xc0, 0x0c, // name: pointer to offset 12
		byte(rrType >> 8), byte(rrType),
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		byte(len(data) >> 8), byte(len(data)),
	}
	return append(rec, data...)
}
