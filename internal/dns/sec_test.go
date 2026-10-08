package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/onlymaj/v2ray-client-go/internal/outbound"
)

// A label containing '.' must not alias the dotted name in the cache key.
func TestDottedLabelRejected(t *testing.T) {
	q := buildQuery(1, "x", typeA, 0)
	q = append(q[:headerLen], append([]byte{8}, "bank.com"...)...)
	q = append(q, 0, 0, typeA, 0, 1)
	if _, _, err := parseQuestion(q); err == nil {
		t.Fatal("label with '.' accepted")
	}
	for _, bad := range []string{"a\\b", "a b", "a\x00", "\xc3\xa9"} {
		q := append(append([]byte(nil), q[:headerLen]...), byte(len(bad)))
		q = append(append(q, bad...), 0, 0, typeA, 0, 1)
		if _, _, err := parseQuestion(q); err == nil {
			t.Errorf("label %q accepted", bad)
		}
	}
	if _, _, err := parseQuestion(buildQuery(1, "_dmarc.Ex-1.com", typeA, 0)); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
}

// Upstream responses must carry the query's ID, QR and question.
func TestAnswersMatchesQuestion(t *testing.T) {
	query := buildQuery(7, "a.example", typeA, 0)
	_, q, _ := parseQuestion(query)
	if !answers(query, q, buildAResponse(query, 60)) {
		t.Fatal("matching response rejected")
	}
	if answers(query, q, buildAResponse(buildQuery(7, "b.example", typeA, 0), 60)) {
		t.Fatal("response for another name accepted")
	}
	if answers(query, q, buildAResponse(buildQuery(8, "a.example", typeA, 0), 60)) {
		t.Fatal("response with another ID accepted")
	}
	if answers(query, q, query) {
		t.Fatal("query (QR=0) accepted as response")
	}
	formerr := append([]byte(nil), query[:headerLen]...)
	binary.BigEndian.PutUint16(formerr[2:], flagQR|rcodeFormErr)
	binary.BigEndian.PutUint16(formerr[4:], 0)
	if !answers(query, q, formerr) {
		t.Fatal("question-less error reply rejected")
	}
}

// RouteKey must see the upstream address Dial routes with.
func TestRouteKeyGetsUpstream(t *testing.T) {
	var got netip.Addr
	s := New(Options{
		Upstream: "192.0.2.53",
		Dial: func(context.Context, netip.Addr, string, outbound.Addr) (net.Conn, error) {
			return nil, errors.New("no")
		},
		RouteKey: func(_ netip.Addr, _ string, dst netip.Addr) string { got = dst; return "k" },
	})
	s.Exchange(context.Background(), netip.Addr{}, buildQuery(1, "a.example", typeA, 0))
	if got != netip.MustParseAddr("192.0.2.53") {
		t.Fatalf("RouteKey dst = %v", got)
	}
}
