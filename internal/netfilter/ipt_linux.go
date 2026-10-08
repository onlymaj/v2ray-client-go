package netfilter

// Legacy x_tables: replace the whole "nat" table with IPT_SO_SET_REPLACE.
// Equivalent to an empty nat table plus
//
//	iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-ports PORT
//
// Struct layouts are from include/uapi/linux/netfilter_ipv4/ip_tables.h,
// x_tables.h and nf_nat.h, for 64-bit kernels (arm64 and amd64 match).
// The container gets its own network namespace, so owning the whole nat
// table is fine.

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	iptSoSetReplace = 64 // IPT_BASE_CTL
	iptSoGetInfo    = 64

	sizeofIptReplace = 96  // ... unsigned int num_counters; struct xt_counters *counters;
	sizeofIptEntry   = 112 // ipt_ip(84) nfcache(4) offsets(4) comefrom(4) counters(16)
	sizeofIptGetinfo = 84
	sizeofStdTarget  = 40 // XT_ALIGN(32 + sizeof(int))
	sizeofErrTarget  = 64 // XT_ALIGN(32 + 30)
	sizeofRedirTgt   = 56 // XT_ALIGN(32 + nf_nat_ipv4_multi_range_compat(20))

	nfIPPreRouting  = 0
	nfIPLocalIn     = 1
	nfIPLocalOut    = 3
	nfIPPostRouting = 4

	verdictAccept            = -1 - 1 // -NF_ACCEPT - 1, NF_ACCEPT = 1
	nfNatRangeProtoSpecified = 2
)

// entry builds one ipt_entry with the given target appended.
func iptEntry(proto uint16, target []byte) []byte {
	e := make([]byte, sizeofIptEntry+len(target))
	binary.LittleEndian.PutUint16(e[80:], proto)                              // ipt_ip.proto
	binary.LittleEndian.PutUint16(e[88:], sizeofIptEntry)                     // target_offset
	binary.LittleEndian.PutUint16(e[90:], uint16(sizeofIptEntry+len(target))) // next_offset
	copy(e[sizeofIptEntry:], target)
	return e
}

// target builds an xt_entry_target header (u16 size, name[29], u8 rev) + data.
func iptTarget(size int, name string, data []byte) []byte {
	t := make([]byte, size)
	binary.LittleEndian.PutUint16(t[0:], uint16(size))
	copy(t[2:31], name)
	copy(t[32:], data)
	return t
}

func stdAccept() []byte {
	var v [4]byte
	verdict := int32(verdictAccept)
	binary.LittleEndian.PutUint32(v[:], uint32(verdict))
	return iptTarget(sizeofStdTarget, "", v[:])
}

func installLegacy(r Redirect) (*Installed, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("raw socket: %w", err)
	}
	defer syscall.Close(fd)

	// IPT_SO_GET_INFO tells us how many counters the current table has; the
	// kernel requires num_counters to match on replace.
	info := make([]byte, sizeofIptGetinfo)
	copy(info, "nat")
	l := uint32(len(info))
	if _, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_IP, iptSoGetInfo,
		uintptr(unsafe.Pointer(&info[0])), uintptr(unsafe.Pointer(&l)), 0); e != 0 {
		return nil, fmt.Errorf("IPT_SO_GET_INFO nat: %w", e)
	}
	oldEntries := binary.LittleEndian.Uint32(info[76:])

	tbl, hooks, under, n := legacyNatTable(r.Port, r.ExcludeDst)
	if err := legacyReplace(fd, tbl, hooks, under, n, oldEntries); err != nil {
		return nil, err
	}
	return &Installed{Method: MethodLegacy, remove: func() error {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.IPPROTO_RAW)
		if err != nil {
			return err
		}
		defer syscall.Close(fd)
		tbl, hooks, under, empty := legacyNatTable(0, nil)
		return legacyReplace(fd, tbl, hooks, under, empty, n)
	}}, nil
}

// legacyNatTable lays out the entries and returns how many there are. With
// port 0 it produces the empty table (policies + ERROR only). Each excluded
// destination gets an ACCEPT entry ahead of the REDIRECT, because one
// ipt_entry can only negate a single address.
func legacyNatTable(port uint16, exclude []netip.Addr) (tbl []byte, hooks, under [5]uint32, n uint32) {
	add := func(e []byte) uint32 { off := uint32(len(tbl)); tbl = append(tbl, e...); n++; return off }

	if port != 0 {
		first := true
		for _, a := range exclude {
			if !a.Is4() {
				continue
			}
			e := iptEntry(syscall.IPPROTO_TCP, stdAccept())
			ip := a.As4()
			copy(e[4:8], ip[:])                        // ipt_ip.dst
			copy(e[12:16], []byte{255, 255, 255, 255}) // ipt_ip.dmsk
			off := add(e)
			if first {
				hooks[nfIPPreRouting], first = off, false
			}
		}
		// nf_nat_ipv4_multi_range_compat{rangesize=1, range[0]{flags, min_ip,
		// max_ip, min.tcp.port, max.tcp.port}}; ports are network byte order.
		data := make([]byte, 20)
		binary.LittleEndian.PutUint32(data[0:], 1)
		binary.LittleEndian.PutUint32(data[4:], nfNatRangeProtoSpecified)
		binary.BigEndian.PutUint16(data[16:], port)
		binary.BigEndian.PutUint16(data[18:], port)
		off := add(iptEntry(syscall.IPPROTO_TCP, iptTarget(sizeofRedirTgt, "REDIRECT", data)))
		if first {
			hooks[nfIPPreRouting] = off
		}
		under[nfIPPreRouting] = add(iptEntry(0, stdAccept()))
	} else {
		hooks[nfIPPreRouting] = add(iptEntry(0, stdAccept()))
		under[nfIPPreRouting] = hooks[nfIPPreRouting]
	}
	for _, h := range []int{nfIPLocalIn, nfIPLocalOut, nfIPPostRouting} {
		hooks[h] = add(iptEntry(0, stdAccept()))
		under[h] = hooks[h]
	}
	add(iptEntry(0, iptTarget(sizeofErrTarget, "ERROR", []byte("ERROR"))))
	return
}

func legacyReplace(fd int, tbl []byte, hooks, under [5]uint32, numEntries, oldEntries uint32) error {
	counters := make([]byte, 16*int(oldEntries)+16)
	b := make([]byte, sizeofIptReplace+len(tbl))
	copy(b, "nat")
	binary.LittleEndian.PutUint32(b[32:], 1<<nfIPPreRouting|1<<nfIPLocalIn|1<<nfIPLocalOut|1<<nfIPPostRouting)
	binary.LittleEndian.PutUint32(b[36:], numEntries)
	binary.LittleEndian.PutUint32(b[40:], uint32(len(tbl)))
	for i := 0; i < 5; i++ {
		binary.LittleEndian.PutUint32(b[44+4*i:], hooks[i])
		binary.LittleEndian.PutUint32(b[64+4*i:], under[i])
	}
	binary.LittleEndian.PutUint32(b[84:], oldEntries)
	binary.LittleEndian.PutUint64(b[88:], uint64(uintptr(unsafe.Pointer(&counters[0]))))
	copy(b[sizeofIptReplace:], tbl)

	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), syscall.SOL_IP, iptSoSetReplace,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	// b holds counters' address as a plain integer, invisible to the GC; keep
	// the buffer alive until the kernel has written the old counters into it.
	runtime.KeepAlive(counters)
	if e != 0 {
		return fmt.Errorf("IPT_SO_SET_REPLACE nat: %w", e)
	}
	return nil
}
