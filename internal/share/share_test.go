package share

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

const (
	realityVision = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&spx=%2F&type=tcp&headerType=none#Reality%20DE%20%F0%9F%87%A9%F0%9F%87%AA"
	vlessWS       = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?encryption=none&security=tls&sni=ws.example.com&alpn=h2%2Chttp%2F1.1&fp=firefox&type=ws&host=ws.example.com&path=%2Fray%3Fed%3D2048#WS TLS"
	vlessGRPC     = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:2053?encryption=none&security=tls&sni=grpc.example.com&type=grpc&serviceName=gsvc&mode=multi&allowInsecure=1#grpc%206"
)

func vmessLink(json string) string {
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(json))
}

var (
	vmessWS   = vmessLink(`{"v":"2","ps":"VMess WS","add":"vm.example.com","port":"443","id":"27848739-7e62-4138-9fd3-098a63964b6b","aid":"0","scy":"auto","net":"ws","type":"none","host":"vm.example.com","path":"/vmws","tls":"tls","sni":"vm.example.com","alpn":"http/1.1","fp":"chrome"}`)
	vmessGRPC = vmessLink(`{"v":2,"ps":"VMess gRPC","add":"198.51.100.7","port":8443,"id":"27848739-7e62-4138-9fd3-098a63964b6b","aid":0,"net":"grpc","type":"gun","host":"","path":"vmgrpc","tls":"tls","sni":"g.example.com"}`)
)

func TestParse(t *testing.T) {
	tests := []struct {
		link string
		want Client
	}{
		{realityVision, Client{
			Name: "Reality DE 🇩🇪", Protocol: "vless", Address: "203.0.113.10", Port: 443,
			ID: "b831381d-6324-4d53-ad4f-8cda48b30811", Flow: "xtls-rprx-vision", Encryption: "none",
			Network: "tcp", TLS: "reality", SNI: "www.microsoft.com", Fingerprint: "chrome",
			PublicKey: "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc", ShortID: "6ba85179e30d4fc2", SpiderX: "/",
		}},
		{vlessWS, Client{
			Name: "WS TLS", Protocol: "vless", Address: "cdn.example.com", Port: 443,
			ID: "b831381d-6324-4d53-ad4f-8cda48b30811", Encryption: "none", Network: "ws", TLS: "tls",
			SNI: "ws.example.com", Fingerprint: "firefox", ALPN: []string{"h2", "http/1.1"},
			Path: "/ray?ed=2048", Host: "ws.example.com",
		}},
		{vlessGRPC, Client{
			Name: "grpc 6", Protocol: "vless", Address: "2001:db8::1", Port: 2053,
			ID: "b831381d-6324-4d53-ad4f-8cda48b30811", Encryption: "none", Network: "grpc", TLS: "tls",
			SNI: "grpc.example.com", ServiceName: "gsvc", MultiMode: true,
		}},
		{vmessWS, Client{
			Name: "VMess WS", Protocol: "vmess", Address: "vm.example.com", Port: 443,
			ID: "27848739-7e62-4138-9fd3-098a63964b6b", Security: "auto", Network: "ws", TLS: "tls",
			SNI: "vm.example.com", Fingerprint: "chrome", ALPN: []string{"http/1.1"},
			Path: "/vmws", Host: "vm.example.com",
		}},
		{vmessGRPC, Client{
			Name: "VMess gRPC", Protocol: "vmess", Address: "198.51.100.7", Port: 8443,
			ID: "27848739-7e62-4138-9fd3-098a63964b6b", Security: "auto", Network: "grpc", TLS: "tls",
			SNI: "g.example.com", ServiceName: "vmgrpc",
		}},
	}
	for _, tt := range tests {
		got, err := Parse(tt.link)
		if err != nil {
			t.Fatalf("Parse(%.40s...): %v", tt.link, err)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Parse(%.40s...)\n got %+v\nwant %+v", tt.link, got, tt.want)
		}
		// Round trip through both the link export and a re-parse.
		link, err := got.Link()
		if err != nil {
			t.Fatalf("Link: %v", err)
		}
		again, err := Parse(link)
		if err != nil {
			t.Fatalf("re-Parse(%s): %v", link, err)
		}
		if !reflect.DeepEqual(again, got) {
			t.Errorf("round trip via %s\n got %+v\nwant %+v", link, again, got)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, link := range []string{
		vmessLink(`{"v":"2","ps":"old","add":"a.example","port":"443","id":"27848739-7e62-4138-9fd3-098a63964b6b","aid":"64","net":"tcp","tls":""}`),
		vmessLink(`{"v":"2","add":"a.example","port":"443","id":"x","aid":0,"net":"tcp","type":"http"}`),
		"vmess://not-base64!!",
		"vless://uuid@host.example:0?type=tcp",
		"vless://host.example:443",
		"vless://uuid@host.example:443?type=xhttp",
		"vless://uuid@host.example:443?security=reality",
	} {
		if _, err := Parse(link); err == nil {
			t.Errorf("Parse(%s) succeeded, want error", link)
		}
	}
	_, err := Parse(vmessLink(`{"add":"a","port":1,"id":"x","aid":"2","net":"tcp"}`))
	if err == nil || !strings.Contains(err.Error(), "legacy vmess not supported") {
		t.Errorf("aid!=0 error = %v", err)
	}
}

func TestParseBulk(t *testing.T) {
	text := strings.Join([]string{
		"# my servers",
		realityVision,
		"",
		"  " + vmessWS + "  ",
		"ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#ss",
		"trojan://pass@t.example:443#t",
		"vless://broken@:443",
		"hello world",
	}, "\r\n")
	r := ParseBulk(text)
	if len(r.Clients) != 2 || r.Skipped != 3 || len(r.Errors) != 1 {
		t.Fatalf("got %d clients, %d skipped, errors %+v", len(r.Clients), r.Skipped, r.Errors)
	}
	if r.Errors[0].Line != 7 {
		t.Errorf("error line = %d, want 7", r.Errors[0].Line)
	}
}

func TestDecodeSubscription(t *testing.T) {
	list := realityVision + "\n" + vmessGRPC + "\ntrojan://p@t.example:443\n"
	wrap := func(s string) string { // base64 line-wrapped at 76 columns
		var b strings.Builder
		for len(s) > 76 {
			b.WriteString(s[:76] + "\n")
			s = s[76:]
		}
		return b.String() + s
	}
	for name, body := range map[string]string{
		"std":       base64.StdEncoding.EncodeToString([]byte(list)),
		"std-raw":   base64.RawStdEncoding.EncodeToString([]byte(list)),
		"url":       base64.URLEncoding.EncodeToString([]byte(list)),
		"url-raw":   base64.RawURLEncoding.EncodeToString([]byte(list)),
		"wrapped":   wrap(base64.StdEncoding.EncodeToString([]byte(list))),
		"plaintext": list,
	} {
		r := DecodeSubscription([]byte(body))
		if len(r.Clients) != 2 || r.Skipped != 1 || len(r.Errors) != 0 {
			t.Errorf("%s: got %d clients, %d skipped, errors %+v", name, len(r.Clients), r.Skipped, r.Errors)
		}
	}
}

// A link must not be able to turn off certificate verification.
func TestInsecureParamsIgnored(t *testing.T) {
	for _, q := range []string{"allowInsecure=1", "insecure=1", "allowInsecure=true"} {
		c, err := Parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.example:443?security=tls&" + q + "#x")
		if err != nil {
			t.Fatal(err)
		}
		if c.AllowInsecure {
			t.Errorf("%s: AllowInsecure set from link", q)
		}
	}
	c, _ := Parse(vlessWS)
	c.AllowInsecure = true
	link, err := c.Link()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(link, "nsecure") {
		t.Errorf("export carries allowInsecure: %s", link)
	}
}
