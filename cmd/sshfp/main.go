package main

import (
	"fmt"
	"log"
	"time"

	"github.com/xor-gate/sshfp"
)

func main() {
	mc, err := sshfp.NewMemoryCache(1024)
	if err != nil {
		log.Fatal(err)
	}

	res, err := sshfp.NewResolver(sshfp.WithCache(mc))
	if err != nil {
		log.Fatal(err)
	}

	ssh := NewSSHClient(res.HostKeyCallback)
	ssh.SetPrivateKeyFromFile("/Users/jerry/.ssh/id_rsa")
	err = ssh.Connect("jerry", "shulgin.xor-gate.org:6222")
	err = ssh.Connect("jerry", "shulgin.xor-gate.org:6222")
	time.Sleep(time.Second * 2)
	err = ssh.Connect("jerry", "shulgin.xor-gate.org:6222")
	err = ssh.Connect("jerry", "shulgin.xor-gate.org:6222")
	fmt.Println(err)
}
