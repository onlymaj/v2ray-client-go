package share

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const secUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// Links whose values would end up in request lines, headers or dial
// targets with control characters are reported, not returned.
func TestParseRejectsInjection(t *testing.T) {
	for _, q := range []string{
		"type=ws&path=%2F%20HTTP%2F1.1%0D%0AX-Inj%3A%201%0D%0A%0D%0AGET%20%2Fsmuggled",
		"type=ws&path=%2Fa%00",
		"type=ws&host=h%0D%0AEvil%3A%20yes",
		"type=ws&host=a%20b",
		"type=ws&sni=a%20b",
		"type=grpc&authority=a%20b",
		"type=grpc&authority=h%0D%0Ax",
		"type=grpc&serviceName=s%0Ax",
		"security=tls&alpn=h%002",
		"security=reality&pbk=k&spx=%2F%0D%0A",
	} {
		link := "vless://" + secUUID + "@h.example.com:443?" + q
		if c, err := Parse(link); err == nil {
			t.Errorf("%s: accepted: %+v", q, c)
		}
		if r := ParseBulk(link); len(r.Clients) != 0 || len(r.Errors) != 1 {
			t.Errorf("%s: bulk %+v", q, r)
		}
	}
	vm := vmessLink(`{"add":"h.example.com","port":443,"id":"` + secUUID + `","net":"ws","host":"h\r\nEvil: yes"}`)
	if _, err := Parse(vm); err == nil {
		t.Error("vmess host with CRLF accepted")
	}
}

func TestParseBulkLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxLinks+5; i++ {
		fmt.Fprintf(&b, "vless://%s@h%d.example.com:443\n", secUUID, i)
	}
	r := DecodeSubscription([]byte(b.String()))
	if len(r.Clients) != MaxLinks || len(r.Errors) != 1 || !strings.Contains(r.Errors[0].Err, "too many links") {
		t.Fatalf("clients=%d errors=%+v", len(r.Clients), r.Errors)
	}
}

// Round 8: the dialer lowercases the VMess cipher, so "scy":"NONE" sent
// plaintext while the UI, comparing exactly, showed no "unencrypted" badge.
// The cipher is stored in lower case and unknown ones are refused.
func TestVMessCipherCanonical(t *testing.T) {
	link := func(scy string) string {
		return vmessLink(`{"add":"h.example.com","port":443,"id":"` + secUUID + `","net":"tcp","scy":"` + scy + `"}`)
	}
	for in, want := range map[string]string{"NONE": "none", "Zero": "zero", "AES-128-GCM": "aes-128-gcm", "auto": "auto"} {
		c, err := Parse(link(in))
		if err != nil || c.Security != want {
			t.Errorf("scy %q: security %q, err %v; want %q", in, c.Security, err, want)
		}
	}
	if _, err := Parse(link("bogus")); err == nil {
		t.Error("unknown vmess cipher accepted")
	}
}

// Round 8: no field but the address had a length limit, so one subscription
// link could store megabytes in config.json (rewritten on every save).
func TestFieldLengthLimit(t *testing.T) {
	long := strings.Repeat("a", maxFieldLen+1)
	for _, l := range []string{
		"vless://" + secUUID + "@h.example.com:443?type=ws&path=/" + long + "#n",
		"vless://" + secUUID + "@h.example.com:443?type=tcp#" + long,
		vmessLink(`{"add":"h.example.com","port":443,"id":"` + secUUID + `","net":"ws","ps":"` + long + `"}`),
	} {
		if _, err := Parse(l); err == nil {
			t.Errorf("over-long field accepted: %.60s...", l)
		}
	}
	if _, err := Parse("vless://" + secUUID + "@h.example.com:443?type=ws&path=/" + long[:900] + "#n"); err != nil {
		t.Errorf("900-byte path refused: %v", err)
	}
}

// Round 15: a name could be 1 KiB, so 1000 links from a subscription put a
// megabyte of names (six after JSON escaping) in every config save.
func TestNameLengthLimit(t *testing.T) {
	link := "vless://" + secUUID + "@h.example.com:443?type=tcp#"
	if _, err := Parse(link + strings.Repeat("a", maxNameLen+1)); err == nil {
		t.Error("over-long name accepted")
	}
	if _, err := Parse(link + strings.Repeat("a", maxNameLen)); err != nil {
		t.Errorf("name at the limit refused: %v", err)
	}
}

// Round 17: parameters the query parser could not read (a ';', a bad
// escape) were dropped without a word, and with them security=tls or a
// setting that must be refused.
func TestVLESSUnparsableParametersRefused(t *testing.T) {
	base := "vless://" + secUUID + "@h.example.com:443?type=tcp&"
	for _, q := range []string{"security=tls;x=1", "security=tls%zz", "ech=AAAA;b", "pcs=ab%zz", "sni=a.example%zz"} {
		if c, err := Parse(base + q + "#n"); err == nil {
			t.Errorf("%s: accepted as tls=%q sni=%q", q, c.TLS, c.SNI)
		}
	}
	if _, err := Parse(base + "security=tls&sni=a.example#n"); err != nil {
		t.Errorf("valid link refused: %v", err)
	}
}

// Round 9: ParseBulk split the whole body into lines before counting
// links, so a 4 MB body of newlines (a few KB gzipped from a subscription
// server) allocated about 76 MB against a 32 MB memory limit.
func TestParseBulkManyLinesIsCheap(t *testing.T) {
	body := strings.Repeat("\n", 1<<20) + "vless://" + secUUID + "@h.example.com:443?type=tcp#last"
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	r := ParseBulk(body)
	runtime.ReadMemStats(&after)
	if len(r.Clients) != 1 || r.Clients[0].Name != "last" {
		t.Fatalf("result %+v", r)
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > 1<<20 {
		t.Fatalf("allocated %d bytes for 1 MB of empty lines", n)
	}
	if r := ParseBulk("x://a\n\nbad://\nvless://nope"); len(r.Errors) != 1 || r.Errors[0].Line != 4 {
		t.Fatalf("line numbers changed: %+v", r)
	}
}

// Round 10: a VLESS link asking for the HTTP header disguise on TCP was
// accepted and the setting dropped; the VMess parser already refused it.
func TestVLESSTCPHeaderRefused(t *testing.T) {
	const l = "vless://11111111-1111-1111-1111-111111111111@a.example:443?type=tcp&headerType="
	if _, err := Parse(l + "http#x"); err == nil {
		t.Fatal("headerType=http accepted")
	}
	if _, err := Parse(l + "none#x"); err != nil {
		t.Fatalf("headerType=none refused: %v", err)
	}
}

// Round 11: TLS settings the client does not implement (certificate pin,
// verification by another name, ECH) were dropped without a word, giving a
// weaker connection than the link's author asked for.
func TestVLESSUnsupportedTLSSettingsRefused(t *testing.T) {
	const l = "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=tls&sni=a.example"
	if _, err := Parse(l + "#x"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"pcs=ab12", "vcn=other.example", "ech=AEX"} {
		if _, err := Parse(l + "&" + p + "#x"); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}

// Round 26: lines of other schemes counted towards the link limit, so a
// list of many ss:// lines and a few usable links was refused whole.
func TestSkippedLinesDoNotCountAsLinks(t *testing.T) {
	text := strings.Repeat("ss://YWVzLTI1Ni1nY206cGFzcw@h.example:8388#x\n", MaxLinks+10) +
		"vless://b831381d-6324-4d53-ad4f-8cda48b30811@pinned.example:443?security=tls#x\n"
	r := ParseBulk(text)
	if len(r.Clients) != 1 || len(r.Errors) != 0 || r.Skipped != MaxLinks+10 {
		t.Fatalf("%d clients, %d errors, %d skipped", len(r.Clients), len(r.Errors), r.Skipped)
	}
}
