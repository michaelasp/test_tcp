package main

// This package is only meaningful in Linux.

import (
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/michaelasp/test_tcp/inetdiag"
	"github.com/michaelasp/test_tcp/parser"
	"github.com/michaelasp/test_tcp/tcp"
)

// TODO - Figure out why we aren't seeing INET_DIAG_DCTCPINFO or INET_DIAG_BBRINFO messages.
func makeReq(inetType uint8) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest(inetdiag.SOCK_DIAG_BY_FAMILY, syscall.NLM_F_DUMP|syscall.NLM_F_REQUEST)
	msg := inetdiag.NewReqV2(inetType, syscall.IPPROTO_TCP,
		tcp.AllFlags & ^((1<<uint(tcp.SYN_RECV))|(1<<uint(tcp.TIME_WAIT))|(1<<uint(tcp.CLOSE))))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_MEMINFO - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_INFO - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_VEGASINFO - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_CONG - 1))

	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_TCLASS - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_TOS - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_SKMEMINFO - 1))
	msg.IDiagExt |= (1 << (inetdiag.INET_DIAG_SHUTDOWN - 1))

	req.AddData(msg)
	req.NlMsghdr.Type = inetdiag.SOCK_DIAG_BY_FAMILY
	req.NlMsghdr.Flags |= syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST
	return req
}

func processSingleMessage(m *syscall.NetlinkMessage, seq uint32, pid uint32) (*syscall.NetlinkMessage, bool, error) {
	if m.Header.Seq != seq {
		fmt.Printf("Wrong Seq nr %d, expected %d", m.Header.Seq, seq)

		return nil, false, inetdiag.ErrBadSequence
	}
	if m.Header.Pid != pid {
		fmt.Printf("Wrong pid %d, expected %d", m.Header.Pid, pid)

		return nil, false, inetdiag.ErrBadPid
	}
	if m.Header.Type == unix.NLMSG_DONE {
		return nil, false, nil
	}
	if m.Header.Type == unix.NLMSG_ERROR {
		native := nl.NativeEndian()
		if len(m.Data) < 4 {
			return nil, false, inetdiag.ErrBadMsgData
		}
		error := int32(native.Uint32(m.Data[0:4]))
		if error == 0 {
			return nil, false, nil
		}
		fmt.Println(syscall.Errno(-error))

	}
	if m.Header.Flags&unix.NLM_F_MULTI == 0 {
		return m, false, nil
	}
	return m, true, nil
}

func getSnapshots(req *nl.NetlinkRequest) ([]*parser.Snapshot, error) {
	var archives []*parser.ArchivalRecord
	var snps []*parser.Snapshot
	sockType := syscall.NETLINK_INET_DIAG
	s, err := nl.Subscribe(sockType)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err := s.Send(req); err != nil {
		return nil, err
	}
	pid, err := s.GetPid()
	if err != nil {
		return nil, err
	}
	// Adapted this from req.Execute in nl_linux.go
	for {
		done := false
		msgs, _, err := s.Receive()
		if err != nil {
			return nil, err
		}
		// TODO avoid the copy.
		for i := range msgs {
			m, shouldContinue, err := processSingleMessage(&msgs[i], req.Seq, pid)
			if err != nil {
				return nil, err
			}
			if m != nil {
				cur, err := parser.MakeArchivalRecord(m, false)
				if err != nil {
					return nil, err
				}
				archives = append(archives, cur)
			}
			if !shouldContinue {
				done = true
			}
		}
		if done {
			break
		}
	}
	for _, elem := range archives {
		_, snp, _ := parser.Decode(elem)
		if snp == nil {
			// fmt.Println(err)
			continue
		}
		src, _ := snp.InetDiagMsg.ID.IDiagDst.MarshalCSV()
		dst, _ := snp.InetDiagMsg.ID.IDiagSrc.MarshalCSV()
		fmt.Printf("Congestion window is %d, RTT is %d, src is %q, dest is %q, retransmits are %d \n",
			snp.TCPInfo.SndCwnd, snp.TCPInfo.RTT, src, dst, snp.TCPInfo.TotalRetrans)
		if snp.InetDiagMsg.IDiagRetrans != 0 {
			fmt.Println("eee")
		}
		snps = append(snps, snp)
	}
	return snps, nil
}

func main() {

	req6 := makeReq(syscall.AF_INET6)
	req := makeReq(syscall.AF_INET)
	_, err := getSnapshots(req6)
	if err != nil {
		fmt.Println("Error getting req6: ", err)
	}
	_, err = getSnapshots(req)
	if err != nil {
		fmt.Println("Error getting req: ", err)
	}

	return

}
