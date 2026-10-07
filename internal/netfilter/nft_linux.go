package netfilter

// nf_tables over raw netlink. Equivalent nft(8) commands:
//
//	nft add table ip v2rayclient
//	nft add chain ip v2rayclient prerouting '{ type nat hook prerouting priority dstnat; }'
//	nft add rule ip v2rayclient prerouting meta l4proto tcp ip daddr != OWN_ADDR ... redirect to :PORT
//
// Constants come from include/uapi/linux/netfilter/nf_tables.h and
// nfnetlink.h. nf_tables encodes integer attributes big-endian.

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

const (
	nftTable = "v2rayclient"
	nftChain = "prerouting"

	nfnlSubsysNFTables = 10
	nfnlMsgBatchBegin  = 0x10
	nfnlMsgBatchEnd    = 0x11
	nfprotoIPv4        = 2

	nftMsgNewTable = 0
	nftMsgDelTable = 2
	nftMsgNewChain = 3
	nftMsgNewRule  = 6

	nlaFNested = 0x8000

	nftaTableName = 1

	nftaChainTable  = 1
	nftaChainName   = 3
	nftaChainHook   = 4
	nftaChainPolicy = 5
	nftaChainType   = 7
	nftaHookHooknum = 1
	nftaHookPrio    = 2

	nftaRuleTable = 1
	nftaRuleChain = 2
	nftaRuleExprs = 4
	nftaListElem  = 1
	nftaExprName  = 1
	nftaExprData  = 2

	nftaMetaDreg   = 1
	nftaMetaKey    = 2
	nftMetaL4proto = 16

	nftaCmpSreg = 1
	nftaCmpOp   = 2
	nftaCmpData = 3
	nftCmpEq    = 0
	nftCmpNeq   = 1

	nftaPayloadDreg   = 1
	nftaPayloadBase   = 2
	nftaPayloadOffset = 3
	nftaPayloadLen    = 4
	nftPayloadNetwork = 1
	nftaDataVal       = 1
	nftaImmDreg       = 1
	nftaImmData       = 2
	nftaRedirMin      = 1

	nftReg1 = 1

	nfInetPreRouting = 0
	nfAccept         = 1
	nfIPPriNATDst    = -100
)

type nlattr []byte

func attr(typ uint16, data []byte) nlattr {
	l := 4 + len(data)
	b := make([]byte, (l+3)&^3)
	binary.LittleEndian.PutUint16(b[0:], uint16(l))
	binary.LittleEndian.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func attrStr(typ uint16, s string) nlattr { return attr(typ, append([]byte(s), 0)) }

func attrU32(typ uint16, v uint32) nlattr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return attr(typ, b[:])
}

func nest(typ uint16, children ...nlattr) nlattr {
	var data []byte
	for _, c := range children {
		data = append(data, c...)
	}
	return attr(typ|nlaFNested, data)
}

func expr(name string, data ...nlattr) nlattr {
	return nest(nftaListElem, attrStr(nftaExprName, name), nest(nftaExprData, data...))
}

// nlmsg builds a netlink header + nfgenmsg + attributes.
func nlmsg(typ, flags uint16, seq uint32, family uint8, resID uint16, attrs ...nlattr) []byte {
	body := []byte{family, 0, byte(resID >> 8), byte(resID)}
	for _, a := range attrs {
		body = append(body, a...)
	}
	b := make([]byte, 16, 16+len(body))
	binary.LittleEndian.PutUint32(b[0:], uint32(16+len(body)))
	binary.LittleEndian.PutUint16(b[4:], typ)
	binary.LittleEndian.PutUint16(b[6:], flags)
	binary.LittleEndian.PutUint32(b[8:], seq)
	return append(b, body...)
}

func nftType(msg uint16) uint16 { return nfnlSubsysNFTables<<8 | msg }

// nftBatch sends msgs wrapped in a batch and waits for one ACK per message.
func nftBatch(msgs ...func(seq uint32) []byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	seq := uint32(1)
	buf := nlmsg(nfnlMsgBatchBegin, syscall.NLM_F_REQUEST, seq, syscall.AF_UNSPEC, nfnlSubsysNFTables)
	for _, m := range msgs {
		seq++
		buf = append(buf, m(seq)...)
	}
	seq++
	buf = append(buf, nlmsg(nfnlMsgBatchEnd, syscall.NLM_F_REQUEST, seq, syscall.AF_UNSPEC, nfnlSubsysNFTables)...)
	if err := syscall.Sendto(fd, buf, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}

	want := len(msgs)
	rb := make([]byte, 1<<16)
	for want > 0 {
		n, _, err := syscall.Recvfrom(fd, rb, 0)
		if err != nil {
			return fmt.Errorf("netlink recv: %w", err)
		}
		nms, err := syscall.ParseNetlinkMessage(rb[:n])
		if err != nil {
			return err
		}
		for _, m := range nms {
			if m.Header.Type != syscall.NLMSG_ERROR || len(m.Data) < 4 {
				continue
			}
			want--
			if code := int32(binary.LittleEndian.Uint32(m.Data)); code != 0 {
				return fmt.Errorf("nf_tables seq %d: %w", m.Header.Seq, syscall.Errno(-code))
			}
		}
	}
	return nil
}

func installNFT(r Redirect) (*Installed, error) {
	const create = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_CREATE
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], r.Port)

	// Start from a clean table; ignore "does not exist".
	_ = removeNFT()

	// meta l4proto tcp, then one "ip daddr != a" per excluded address
	// (consecutive expressions are ANDed), then redirect.
	exprs := []nlattr{
		expr("meta", attrU32(nftaMetaDreg, nftReg1), attrU32(nftaMetaKey, nftMetaL4proto)),
		expr("cmp", attrU32(nftaCmpSreg, nftReg1), attrU32(nftaCmpOp, nftCmpEq),
			nest(nftaCmpData, attr(nftaDataVal, []byte{syscall.IPPROTO_TCP}))),
	}
	for _, a := range r.ExcludeDst {
		if !a.Is4() {
			continue
		}
		ip := a.As4()
		exprs = append(exprs,
			expr("payload", attrU32(nftaPayloadDreg, nftReg1), attrU32(nftaPayloadBase, nftPayloadNetwork),
				attrU32(nftaPayloadOffset, 16), attrU32(nftaPayloadLen, 4)), // IPv4 header daddr
			expr("cmp", attrU32(nftaCmpSreg, nftReg1), attrU32(nftaCmpOp, nftCmpNeq),
				nest(nftaCmpData, attr(nftaDataVal, ip[:]))))
	}
	exprs = append(exprs,
		expr("immediate", attrU32(nftaImmDreg, nftReg1), nest(nftaImmData, attr(nftaDataVal, port[:]))),
		expr("redir", attrU32(nftaRedirMin, nftReg1)))

	err := nftBatch(
		func(seq uint32) []byte {
			return nlmsg(nftType(nftMsgNewTable), create, seq, nfprotoIPv4, 0, attrStr(nftaTableName, nftTable))
		},
		func(seq uint32) []byte {
			prio := int32(nfIPPriNATDst)
			return nlmsg(nftType(nftMsgNewChain), create, seq, nfprotoIPv4, 0,
				attrStr(nftaChainTable, nftTable),
				attrStr(nftaChainName, nftChain),
				nest(nftaChainHook, attrU32(nftaHookHooknum, nfInetPreRouting), attrU32(nftaHookPrio, uint32(prio))),
				attrU32(nftaChainPolicy, nfAccept),
				attrStr(nftaChainType, "nat"))
		},
		func(seq uint32) []byte {
			return nlmsg(nftType(nftMsgNewRule), create|syscall.NLM_F_APPEND, seq, nfprotoIPv4, 0,
				attrStr(nftaRuleTable, nftTable),
				attrStr(nftaRuleChain, nftChain),
				nest(nftaRuleExprs, exprs...))
		},
	)
	if err != nil {
		return nil, err
	}
	return &Installed{Method: MethodNFT, remove: removeNFT}, nil
}

func removeNFT() error {
	return nftBatch(func(seq uint32) []byte {
		return nlmsg(nftType(nftMsgDelTable), syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, seq, nfprotoIPv4, 0,
			attrStr(nftaTableName, nftTable))
	})
}
