package main

// This package is only meaningful in Linux.

import (
	"encoding/json"
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"

	"github.com/michaelasp/test_tcp/inetdiag"
	"github.com/michaelasp/test_tcp/parser"
)

func getSnapshots(req *nl.NetlinkRequest) ([]*parser.Snapshot, error) {
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
snapshotLoop:
	for {

		msgs, _, err := s.Receive()
		if err != nil {
			return nil, err
		}
		// TODO avoid the copy.
		for i := range msgs {
			m, shouldContinue, err := inetdiag.ProcessMessage(&msgs[i], req.Seq, pid)
			if err != nil {
				return nil, err
			}
			if m != nil {
				cur, err := parser.MakeSnapShot(m, true)
				if cur == nil || err != nil {
					continue
				}
				snps = append(snps, cur)

			}
			if !shouldContinue {
				break snapshotLoop
			}
		}

	}
	return snps, nil
}

func main() {

	req6 := inetdiag.MakeReq(syscall.AF_INET6)
	req := inetdiag.MakeReq(syscall.AF_INET)
	_, err := getSnapshots(req6)
	if err != nil {
		fmt.Println("Error getting req6: ", err)
	}
	res, err := getSnapshots(req)
	if err != nil {
		fmt.Println("Error getting req6: ", err)
	}
	val, _ := json.MarshalIndent(res, "", "    ")
	fmt.Println(string(val))
	return

}
