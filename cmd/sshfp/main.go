package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/xor-gate/sshfp"
)

const zoneFile = `
shulgin.xor-gate.org. IN SSHFP 3 2 ac8433083780c0d58d9943a457912a552f2e80ce9ec60ca8ebc676c308ae30d3
`

func main() {
	mc, err := sshfp.NewMemoryCache(1024)
	if err != nil {
		log.Fatal(err)
	}

	entries, err := sshfp.ParseZone(strings.NewReader(zoneFile))
	if err == nil {
		mc.Add(entries...)
	}

	res, err := sshfp.NewResolver(sshfp.WithCache(mc), sshfp.WithDNSClientConfigFromFile("/etc/resolv.conf"))
	if err != nil {
		log.Fatal(err)
	}

	ssh := NewSSHClient(res.HostKeyCallback)
	ssh.SetPrivateKeyFromFile("/home/jjacobs/.ssh/id_ecdsa")
	err = ssh.Connect("jerry", "shulgin.xor-gate.org:6222")
	fmt.Println(err)
}
