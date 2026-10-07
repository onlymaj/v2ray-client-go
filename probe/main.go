// Command probe is the Milestone 1 feasibility check for RouterOS containers.
// It reports what netfilter support the container sees, installs a TCP
// REDIRECT in nat PREROUTING to its own listener, and answers every
// redirected connection with the SO_ORIGINAL_DST it read. Send traffic to it
// through a RouterOS route whose gateway is the container's veth address.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/onlymaj/v2ray-client-go/internal/inbound"
	"github.com/onlymaj/v2ray-client-go/internal/netfilter"
)

func main() {
	port := flag.Int("port", 12345, "transparent listener port")
	mode := flag.String("mode", "auto", "auto | nftables | iptables-legacy | none")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	report()

	ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	var inst *netfilter.Installed
	switch *mode {
	case "none":
	case "auto":
		inst, err = netfilter.Install(netfilter.Redirect{Port: uint16(*port), ExcludeDst: netfilter.LocalAddrs()})
	default:
		inst, err = netfilter.InstallWith(netfilter.Method(*mode), netfilter.Redirect{Port: uint16(*port), ExcludeDst: netfilter.LocalAddrs()})
	}
	if err != nil {
		log.Printf("RESULT redirect install FAILED: %v", err)
	} else if inst != nil {
		log.Printf("RESULT redirect installed via %s -> :%d", inst.Method, *port)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		if err := inst.Remove(); err != nil {
			log.Printf("remove rule: %v", err)
		}
		os.Exit(0)
	}()

	go func() {
		for range time.Tick(30 * time.Second) {
			log.Printf("rss %s", procStatus("VmRSS"))
		}
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go serve(c.(*net.TCPConn))
	}
}

func serve(c *net.TCPConn) {
	defer c.Close()
	od, err := inbound.OriginalDst(c)
	line := fmt.Sprintf("src=%s local=%s orig_dst=%v err=%v", c.RemoteAddr(), c.LocalAddr(), od, err)
	log.Printf("RESULT conn %s", line)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// Answer like an HTTP server so `/tool fetch` and curl print the result.
	br := bufio.NewReader(c)
	for {
		l, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(l) == "" {
			break
		}
	}
	body := line + "\n"
	fmt.Fprintf(c, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

func report() {
	var u syscall.Utsname
	_ = syscall.Uname(&u)
	b := make([]byte, 0, 65)
	for _, ch := range u.Release {
		if ch == 0 {
			break
		}
		b = append(b, byte(ch))
	}
	log.Printf("kernel %s uid=%d", b, os.Getuid())
	log.Printf("CapEff %s", procStatus("CapEff"))
	for _, f := range []string{"/proc/net/ip_tables_names", "/proc/net/ip_tables_targets", "/proc/net/nf_conntrack"} {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Printf("%s: %v", f, err)
			continue
		}
		s := strings.Fields(string(data))
		if len(s) > 20 {
			s = s[:20]
		}
		log.Printf("%s: %s", f, strings.Join(s, " "))
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			addrs, _ := i.Addrs()
			log.Printf("iface %s %v", i.Name, addrs)
		}
	}
}

func procStatus(key string) string {
	data, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, key+":") {
			return strings.TrimSpace(strings.TrimPrefix(l, key+":"))
		}
	}
	return "?"
}
