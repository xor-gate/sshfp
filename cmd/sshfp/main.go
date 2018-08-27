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
		err = mc.Add(entries...)
		if err != nil {
			log.Fatal("unable to add entries from zone:", err)
		}
	}

	res, err := sshfp.NewResolver(sshfp.WithCache(mc), sshfp.WithDNSClientConfigFromFile("/etc/resolv.conf"))
	if err != nil {
		log.Fatal(err)
	}

	ssh := NewSSHClient(res.HostKeyCallback)
	err = ssh.SetPrivateKeyFromFile("/Users/jerry/.ssh/id_rsa")
	if err != nil {
		log.Fatal("unable to set private key from file:", err)
	}
	err = ssh.Connect("jerry", "shulgin.xor-gate.org:6222")
	fmt.Println(err)
}
